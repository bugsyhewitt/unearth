// Package techniques defines the Technique interface that every origin-discovery
// method implements, the shared types techniques exchange with the
// orchestration engine, and the registry that tracks them.
package techniques

import (
	"context"
	"net/http"
	"net/netip"
	"time"
)

// Tier expresses how aggressive a technique is. The CLI gates techniques by
// tier so a user can control how much a run touches the target.
type Tier int

const (
	// TierPassive techniques never contact the target. They query third-party
	// services and public records only and are safe for any scope.
	TierPassive Tier = iota
	// TierActive techniques make direct requests to candidate IPs and grab
	// service banners. They touch the target but stay within most scopes.
	TierActive
	// TierAggressive techniques deliberately provoke origin leaks and may
	// violate strict scope rules.
	TierAggressive
)

// String returns the lowercase name of the tier.
func (t Tier) String() string {
	switch t {
	case TierPassive:
		return "passive"
	case TierActive:
		return "active"
	case TierAggressive:
		return "aggressive"
	default:
		return "unknown"
	}
}

// Candidate is a single origin-IP guess produced by a technique.
type Candidate struct {
	// IP is the candidate origin address, IPv4 or IPv6. The producing
	// technique is responsible for validating it.
	IP string
	// Evidence is human-readable proof of why this IP was surfaced,
	// e.g. "cert SHA256 abc123... via Censys".
	Evidence string
	// Metadata holds optional raw fragments from the underlying source.
	// It may be nil.
	Metadata map[string]any
}

// APIKeys holds optional third-party credentials. An empty field means the
// technique that depends on it is skipped rather than failed.
type APIKeys struct {
	// CensysPlatformPAT is the Personal Access Token for the Censys
	// Platform API (api.platform.censys.io). Required to run
	// censys_cert. Generated at https://platform.censys.io account
	// settings → Personal Access Tokens.
	CensysPlatformPAT string

	// CensysAPIID is the legacy Censys Search v1/v2 API id.
	//
	// Deprecated: superseded by CensysPlatformPAT. The legacy Search API
	// is disabled for Free accounts and is sunsetting in 2026. Kept here
	// only to avoid a breaking schema change; a later cleanup packet will
	// remove it.
	CensysAPIID string
	// CensysAPISecret is the legacy Censys Search v1/v2 API secret.
	//
	// Deprecated: superseded by CensysPlatformPAT — see CensysAPIID.
	CensysAPISecret string

	ShodanAPIKey      string
	SecurityTrailsKey string
	ViewDNSKey        string

	// FOFAEmail and FOFAKey are the credential pair for the FOFA
	// (fofa.info) search API. Both are required to run fofa_cert; either
	// one absent skips the technique. The pair is generated from a FOFA
	// account's Personal Center → API page.
	FOFAEmail string
	FOFAKey   string

	// NetlasAPIKey is the API key for the Netlas (netlas.io) search API.
	// Required to run netlas_cert; absent skips the technique. Generated
	// from a Netlas account's Profile → API key page. Netlas offers a free
	// tier with a daily request allowance.
	NetlasAPIKey string

	// CriminalIPKey is the API key for the Criminal IP (criminalip.io)
	// search API. Required to run criminalip_asset; absent skips the
	// technique. Generated from a Criminal IP account's My Information → API
	// Key page. Criminal IP offers a free tier with a monthly request
	// allowance.
	CriminalIPKey string
}

// BudgetCaps limits the number of paid-API calls a single invocation may make.
type BudgetCaps struct {
	Censys         int
	Shodan         int
	SecurityTrails int
}

// CacheStore is the contract the SQLite cache (Packet 2) satisfies. Techniques
// depend on this interface so the techniques package never imports the cache
// implementation.
type CacheStore interface {
	// Get returns the cached value for key. hit reports whether a live
	// (unexpired) entry was found.
	Get(key string) (value []byte, hit bool, err error)
	// Set stores value under key with the given time-to-live.
	Set(key string, value []byte, ttl time.Duration) error
}

// BudgetCharger is the contract the per-invocation paid-API budget
// (internal/ratelimit.Budget) satisfies. Techniques depend on this interface
// so this package never imports internal/ratelimit, which would form a
// cycle (ratelimit imports BudgetCaps from here).
type BudgetCharger interface {
	// Charge attempts to consume one call against the named service budget
	// ("censys", "shodan", "securitytrails"). It returns false when the
	// budget is exhausted; the caller is then expected to stop and return
	// ErrBudgetExhausted.
	Charge(service string) bool
	// Remaining reports calls left for a service. -1 means unlimited.
	Remaining(service string) int
}

// RateLimiter is the contract the rate limiter (Packet 2) satisfies.
type RateLimiter interface {
	// Wait blocks until a call keyed by key is permitted or ctx is done.
	Wait(ctx context.Context, key string) error
	// Allow reports whether a call keyed by key is permitted right now
	// without blocking.
	Allow(key string) bool
}

// TimeoutOverrider is an optional interface. A technique that needs longer
// than the engine's default PerTechniqueTimeout may implement it to declare
// a per-technique ceiling. The engine uses the larger of the override and
// the configured PerTechniqueTimeout — an override never shortens a
// technique's budget below the global default. The OverallTimeout still
// bounds the run: the per-technique budget is clamped to the remaining
// overall budget, so a slow technique cannot run past the global deadline.
type TimeoutOverrider interface {
	Technique
	TimeoutOverride() time.Duration
}

// CandidateConsumer is an optional interface a technique may satisfy to
// declare that it wants to run in a second phase, after the engine has
// pooled the candidate IPs that every other technique produced. The
// engine then sets RunOptions.SeedIPs to that pool before invoking
// the technique's Run.
//
// Techniques that do not implement this interface (every Packet 1–4
// technique) run in the first phase exactly as before, with SeedIPs
// left nil — the engine change is fully additive.
type CandidateConsumer interface {
	Technique
	// ConsumesCandidates reports whether the technique wants pooled
	// seed IPs from the first phase. A method (not a marker) so a
	// future technique can decide at runtime if it ever needs to.
	ConsumesCandidates() bool
}

// RunOptions carries everything a technique needs to execute a single run.
type RunOptions struct {
	// HTTPClient is the shared client techniques should use for HTTP work.
	HTTPClient *http.Client
	// APIKeys holds third-party credentials; fields may be empty.
	APIKeys APIKeys
	// Cache is the result cache. It may be nil when caching is disabled.
	Cache CacheStore
	// RateLimiter throttles outbound calls. It may be nil.
	RateLimiter RateLimiter
	// BudgetCaps limits paid-API usage for this invocation.
	BudgetCaps BudgetCaps
	// Budget is the live per-invocation paid-API budget. Techniques that
	// call paid services must Charge it before every request and return
	// ErrBudgetExhausted when Charge reports false. It may be nil only when
	// no paid techniques are selected for the run.
	Budget BudgetCharger
	// NoCache, when true, instructs techniques to bypass the cache entirely.
	NoCache bool
	// Refresh, when true, instructs techniques to ignore cached entries but
	// still write fresh results back to the cache.
	Refresh bool
	// SeedIPs is the de-duplicated pool of candidate IPs that first-phase
	// techniques produced during this run. The engine populates it only
	// when invoking a CandidateConsumer in phase 2; for every other
	// technique it is left nil.
	SeedIPs []netip.Addr
	// EmailFile is an optional path to an operator-supplied raw email
	// message (.eml). The email_header technique parses its Received:
	// header chain for CDN-bypassed relay IPs. Empty means the technique
	// is skipped.
	EmailFile string
}

// Technique is the extension point of unearth. Each technique is implemented
// in its own file in this package and registers itself in an init function.
type Technique interface {
	// Name is the stable, lowercase identifier of the technique, e.g. "crtsh".
	Name() string
	// Tier reports the technique's aggression level.
	Tier() Tier
	// RequiresAPIKey reports whether the technique needs credentials to run.
	// When true and the relevant key is absent, the engine skips it.
	RequiresAPIKey() bool
	// DefaultWeight is the technique's baseline reliability, in [0,1]. The
	// config layer may override this per technique; the engine resolves a
	// configured override first and falls back to this value.
	DefaultWeight() float64
	// Run executes the technique against a single target and returns the
	// candidate origin IPs it found.
	Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error)
}
