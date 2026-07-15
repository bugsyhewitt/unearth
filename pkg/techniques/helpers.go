package techniques

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"time"
)

// rateWait is a small helper so each technique need not check for a nil
// RateLimiter at every call site.
func rateWait(ctx context.Context, r RateLimiter, key string) error {
	if r == nil {
		return nil
	}
	return r.Wait(ctx, key)
}

// cacheRead returns the cached payload for key if caching is enabled, the
// caller didn't ask to bypass the cache, and the entry exists. A cache
// error is silently ignored — the caller proceeds with a live call.
func cacheRead(c CacheStore, opts RunOptions, key string) ([]byte, bool) {
	if c == nil || opts.NoCache || opts.Refresh {
		return nil, false
	}
	v, hit, err := c.Get(key)
	if err != nil || !hit {
		return nil, false
	}
	return v, true
}

// cacheWrite persists payload under key unless caching is disabled. Errors
// are intentionally ignored — caching is best-effort, never load-bearing.
func cacheWrite(c CacheStore, opts RunOptions, key string, payload []byte, ttl time.Duration) {
	if c == nil || opts.NoCache || ttl <= 0 {
		return
	}
	_ = c.Set(key, payload, ttl)
}

// isPublicOriginAddr reports whether a is a globally-routable unicast address
// worth surfacing as an origin candidate. It rejects the unspecified address,
// loopback, link-local (v4 and v6), multicast, RFC1918 / unique-local private
// space, interface-local multicast, and the IPv4 broadcast address.
//
// This is the canonical package-level check; individual techniques should call
// this instead of rolling their own addr-filtering logic.
func isPublicOriginAddr(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsPrivate() || a.IsInterfaceLocalMulticast() {
		return false
	}
	if a.Is4() && a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	return true
}

// httpGetJSON is the common pattern used by API-backed techniques: rate-
// limit, build a request, decorate, fire, decode JSON.
//
// decorate is called after the request is built so callers can add auth
// headers; pass nil when no decoration is needed. dest must be a pointer.
func httpGetJSON(
	ctx context.Context,
	r RateLimiter, rateKey string,
	hc *http.Client,
	url string,
	decorate func(*http.Request),
	dest any,
) error {
	if err := rateWait(ctx, r, rateKey); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if decorate != nil {
		decorate(req)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(dest)
}
