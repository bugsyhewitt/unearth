package cache

import (
	"fmt"
	"sort"
)

// Observation is one technique's contribution to one candidate IP in one
// discovery run. The engine records a batch of these after every run so the
// `unearth calibrate` command can estimate per-technique precision from the
// accumulated history.
//
// We have no external ground truth for "this IP really was the origin", so the
// proxy signal we record is corroboration: whether the candidate this
// technique surfaced was independently confirmed by at least one other
// technique in the same run. A technique whose candidates are consistently
// corroborated is contributing real origin signal; a technique that only ever
// produces lone, single-source candidates is the noisy one.
type Observation struct {
	// Technique is the contributing technique's stable name.
	Technique string
	// Corroborated is true when the candidate IP this technique found was also
	// found by at least one other technique in the same run.
	Corroborated bool
}

// TechniqueStat aggregates every recorded Observation for one technique into a
// precision estimate. Precision is the fraction of that technique's
// contributions that were corroborated by another technique.
type TechniqueStat struct {
	Technique    string
	Total        int
	Corroborated int
	// Precision is Corroborated/Total in [0,1]. Zero when Total is zero.
	Precision float64
}

// migrateCalibration creates the observations table. It is called from
// migrate() so an existing cache file is upgraded in place on next open.
func (c *Cache) migrateCalibration() error {
	const schema = `
CREATE TABLE IF NOT EXISTS observations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    technique    TEXT NOT NULL,
    corroborated INTEGER NOT NULL,
    observed_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_observations_technique ON observations(technique);
`
	if _, err := c.db.Exec(schema); err != nil {
		return fmt.Errorf("cache: creating observations schema: %w", err)
	}
	return nil
}

// RecordObservations appends a batch of observations from one discovery run.
// An empty slice is a no-op. The whole batch is written in a single
// transaction so a run's observations are all-or-nothing. Recording failures
// are non-fatal to discovery: the caller treats the cache as best-effort and
// degrades to no calibration data rather than failing the run.
func (c *Cache) RecordObservations(obs []Observation) error {
	if len(obs) == 0 {
		return nil
	}
	now := c.now().Unix()

	c.writeM.Lock()
	defer c.writeM.Unlock()

	tx, err := c.db.Begin()
	if err != nil {
		return fmt.Errorf("cache: begin observations tx: %w", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO observations (technique, corroborated, observed_at) VALUES (?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("cache: prepare observation insert: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, o := range obs {
		corr := 0
		if o.Corroborated {
			corr = 1
		}
		if _, err := stmt.Exec(o.Technique, corr, now); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("cache: insert observation for %q: %w", o.Technique, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cache: commit observations tx: %w", err)
	}
	return nil
}

// CalibrationStats aggregates all recorded observations into one
// TechniqueStat per technique, sorted by technique name. The returned slice is
// empty (not nil-checked specially) when no observations have been recorded.
func (c *Cache) CalibrationStats() ([]TechniqueStat, error) {
	rows, err := c.db.Query(`
SELECT technique,
       COUNT(*) AS total,
       SUM(corroborated) AS corroborated
FROM observations
GROUP BY technique`)
	if err != nil {
		return nil, fmt.Errorf("cache: calibration stats: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var stats []TechniqueStat
	for rows.Next() {
		var s TechniqueStat
		if err := rows.Scan(&s.Technique, &s.Total, &s.Corroborated); err != nil {
			return nil, fmt.Errorf("cache: scanning calibration row: %w", err)
		}
		if s.Total > 0 {
			s.Precision = float64(s.Corroborated) / float64(s.Total)
		}
		stats = append(stats, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cache: iterating calibration rows: %w", err)
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].Technique < stats[j].Technique })
	return stats, nil
}

// ResetObservations deletes all recorded observations and returns the count
// removed. Operators reset the history after a meaningful change to their
// target profile or after data-source coverage shifts (e.g. a CDN range
// refresh) so stale precision estimates do not bias future suggestions.
func (c *Cache) ResetObservations() (int, error) {
	c.writeM.Lock()
	defer c.writeM.Unlock()
	res, err := c.db.Exec(`DELETE FROM observations`)
	if err != nil {
		return 0, fmt.Errorf("cache: reset observations: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("cache: reset observations rows affected: %w", err)
	}
	return int(n), nil
}

// ObservationCount reports the total number of recorded observations. It is a
// cheap pre-check the calibrate command uses to print a friendly "no data yet"
// message rather than an empty report.
func (c *Cache) ObservationCount() (int, error) {
	var n int
	row := c.db.QueryRow(`SELECT COUNT(*) FROM observations`)
	if err := row.Scan(&n); err != nil {
		return 0, fmt.Errorf("cache: observation count: %w", err)
	}
	return n, nil
}
