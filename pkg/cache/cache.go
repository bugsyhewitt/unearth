// Package cache provides the on-disk SQLite result cache with per-entry
// time-to-live. It implements techniques.CacheStore.
//
// The cache uses the pure-Go SQLite driver (modernc.org/sqlite) so the binary
// can be built with CGO_ENABLED=0. WAL mode and a generous busy timeout are
// enabled at open time so the cache survives concurrent use from many
// technique goroutines.
package cache

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	// modernc.org/sqlite registers itself as the "sqlite" database/sql
	// driver via init(); we never reference its API directly.
	_ "modernc.org/sqlite"
)

// Cache is the SQLite-backed result store. It is safe for concurrent use:
// reads are unsynchronized at the Go level and serialized by SQLite; writes
// are serialized by an internal mutex to avoid "database is locked" under
// burst write load that modernc's connection pool occasionally surfaces
// even with WAL + busy_timeout.
type Cache struct {
	db     *sql.DB
	path   string
	now    func() time.Time
	writeM sync.Mutex
}

// The compile-time assertion that *Cache satisfies techniques.CacheStore is
// kept in an external test package (cache_test) — see interface_test.go —
// to avoid a real import cycle once techniques.Run depends on cache.Key.

// Open opens or creates the cache at the given path. Pass "" for the default
// XDG path ($XDG_CACHE_HOME/unearth/cache.db, falling back to
// ~/.cache/unearth/cache.db). Parent directories are created as needed.
func Open(path string) (*Cache, error) {
	if path == "" {
		def, err := defaultPath()
		if err != nil {
			return nil, fmt.Errorf("cache: resolving default path: %w", err)
		}
		path = def
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("cache: creating parent directory: %w", err)
	}

	// _pragma URL args ensure these PRAGMAs run on every connection in the
	// pool, not just the first one.
	dsn := fmt.Sprintf(
		"file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)",
		path,
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("cache: opening %s: %w", path, err)
	}

	c := &Cache{db: db, path: path, now: time.Now}
	if err := c.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return c, nil
}

// Close closes the underlying database. It is safe to call once. Further
// operations on a closed Cache return errors.
func (c *Cache) Close() error {
	return c.db.Close()
}

// Path returns the on-disk path of the cache file, primarily for diagnostics.
func (c *Cache) Path() string {
	return c.path
}

func (c *Cache) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS cache (
    key        TEXT PRIMARY KEY,
    technique  TEXT NOT NULL,
    target     TEXT NOT NULL,
    payload    BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache(expires_at);
`
	if _, err := c.db.Exec(schema); err != nil {
		return fmt.Errorf("cache: creating schema: %w", err)
	}
	if err := c.migrateCalibration(); err != nil {
		return err
	}
	return nil
}

// Get returns the cached value for key. hit reports whether a live
// (unexpired) entry was found. A missing key is not an error. An expired
// entry is reported as hit=false and is deleted opportunistically.
func (c *Cache) Get(key string) ([]byte, bool, error) {
	var payload []byte
	var expires int64
	row := c.db.QueryRow(`SELECT payload, expires_at FROM cache WHERE key = ?`, key)
	switch err := row.Scan(&payload, &expires); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("cache: get %s: %w", key, err)
	}
	if c.now().Unix() >= expires {
		// Best-effort opportunistic delete; we ignore the error to keep Get
		// read-only from the caller's perspective.
		c.writeM.Lock()
		_, _ = c.db.Exec(`DELETE FROM cache WHERE key = ? AND expires_at <= ?`, key, c.now().Unix())
		c.writeM.Unlock()
		return nil, false, nil
	}
	return payload, true, nil
}

// Set upserts the value under key with the given time-to-live. A non-positive
// ttl is treated as an immediate expiry, which is occasionally useful in
// tests; production callers should always pass a positive duration.
func (c *Cache) Set(key string, value []byte, ttl time.Duration) error {
	now := c.now()
	expires := now.Add(ttl).Unix()
	technique, target := splitKey(key)

	c.writeM.Lock()
	defer c.writeM.Unlock()
	const q = `
INSERT INTO cache (key, technique, target, payload, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(key) DO UPDATE SET
    technique  = excluded.technique,
    target     = excluded.target,
    payload    = excluded.payload,
    created_at = excluded.created_at,
    expires_at = excluded.expires_at
`
	if _, err := c.db.Exec(q, key, technique, target, value, now.Unix(), expires); err != nil {
		return fmt.Errorf("cache: set %s: %w", key, err)
	}
	return nil
}

// Purge deletes all expired rows and returns the count removed.
func (c *Cache) Purge() (int, error) {
	c.writeM.Lock()
	defer c.writeM.Unlock()
	res, err := c.db.Exec(`DELETE FROM cache WHERE expires_at <= ?`, c.now().Unix())
	if err != nil {
		return 0, fmt.Errorf("cache: purge: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("cache: purge rows affected: %w", err)
	}
	return int(n), nil
}

// Stats reports total and expired row counts, intended for a future
// `unearth cache` subcommand and for tests.
func (c *Cache) Stats() (total, expired int, err error) {
	row := c.db.QueryRow(`SELECT COUNT(*), SUM(CASE WHEN expires_at <= ? THEN 1 ELSE 0 END) FROM cache`, c.now().Unix())
	var expiredN sql.NullInt64
	if scanErr := row.Scan(&total, &expiredN); scanErr != nil {
		return 0, 0, fmt.Errorf("cache: stats: %w", scanErr)
	}
	if expiredN.Valid {
		expired = int(expiredN.Int64)
	}
	return total, expired, nil
}

// Key builds a stable, deterministic cache key from a technique name, a
// target, and a set of parameters. The same inputs always produce the same
// key, regardless of map iteration order. The wire format is
// "<technique>|<target>|<hex-sha256-of-params>"; the prefix allows splitKey
// to populate the cache's technique and target columns.
func Key(technique, target string, params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(params[k]))
		h.Write([]byte{0})
	}
	return fmt.Sprintf("%s|%s|%s", technique, target, hex.EncodeToString(h.Sum(nil)))
}

// splitKey reverses the prefix part of Key for column population on insert.
// When the key was not produced by Key it stores the whole key in the
// technique column and leaves target empty — those columns are diagnostic
// only, never part of the lookup path.
func splitKey(key string) (technique, target string) {
	parts := strings.SplitN(key, "|", 3)
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	return key, ""
}

func defaultPath() (string, error) {
	if dir := os.Getenv("XDG_CACHE_HOME"); dir != "" {
		return filepath.Join(dir, "unearth", "cache.db"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cache", "unearth", "cache.db"), nil
}
