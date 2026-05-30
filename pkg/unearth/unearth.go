// Package unearth is the public library API for origin-IP discovery. It
// exposes the Discover entrypoint and the result types that the CLI and the
// MCP server consume.
package unearth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/unearth-tool/unearth/internal/httpclient"
	"github.com/unearth-tool/unearth/internal/ratelimit"
	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
	"github.com/unearth-tool/unearth/pkg/config"
	"github.com/unearth-tool/unearth/pkg/rank"
	"github.com/unearth-tool/unearth/pkg/techniques"
)

// Options configures a discovery run.
type Options struct {
	// Tier is the maximum technique aggression to run. Lower tiers are
	// always included: TierActive runs passive and active techniques.
	Tier techniques.Tier
	// APIKeys holds optional third-party credentials.
	APIKeys techniques.APIKeys
	// BudgetCaps limits paid-API usage for the run.
	BudgetCaps techniques.BudgetCaps
	// NoCache bypasses the result cache entirely.
	NoCache bool
	// Refresh ignores cached entries but writes fresh results back.
	Refresh bool
	// Concurrency is the number of techniques run in parallel.
	Concurrency int
	// PerTechniqueTimeout bounds how long a single technique may run.
	PerTechniqueTimeout time.Duration
	// OverallTimeout bounds the whole discovery run.
	OverallTimeout time.Duration
	// WeightsPath optionally points at a YAML file of technique-weight
	// overrides. Empty string preserves the default behavior of consulting
	// only the embedded defaults plus the XDG-default user file.
	WeightsPath string
	// EmailFile optionally points at a raw email message (.eml) whose
	// Received: header chain the email_header technique parses for
	// CDN-bypassed relay IPs. Empty string skips that technique.
	EmailFile string
}

// DefaultOptions returns Options with conservative defaults: passive tier only,
// ten concurrent techniques, a 30s per-technique timeout and a 5m overall
// timeout.
func DefaultOptions() Options {
	return Options{
		Tier:                techniques.TierPassive,
		Concurrency:         10,
		PerTechniqueTimeout: 30 * time.Second,
		OverallTimeout:      5 * time.Minute,
	}
}

// TechniqueHit records one technique's contribution to a candidate IP.
type TechniqueHit struct {
	Name     string  `json:"name"`
	Weight   float64 `json:"weight"`
	Evidence string  `json:"evidence"`
}

// ScoredIP is a single ranked candidate origin IP.
type ScoredIP struct {
	// IP is the candidate origin address.
	IP string `json:"candidate_ip"`
	// Score is the noisy-OR confidence in [0,1].
	Score float64 `json:"score"`
	// Corroboration is the number of distinct techniques that found this IP.
	Corroboration int `json:"corroboration"`
	// SingleSource is true when exactly one technique found this IP. It is a
	// deliberate, separate signal from Score: a lone weak hit and a lone
	// strong hit can both warrant caution that the numeric score alone hides.
	SingleSource bool `json:"single_source"`
	// Techniques lists every technique that contributed, with its weight.
	Techniques []TechniqueHit `json:"techniques"`
}

// TechniqueErr records a technique that failed or was skipped during a run.
type TechniqueErr struct {
	Technique string `json:"technique"`
	Err       string `json:"error"`
	// Reason is a short machine-readable cause, e.g. "missing_api_key",
	// "timeout" or "budget_exhausted". It may be empty.
	Reason string `json:"reason,omitempty"`
}

// Result is the full output of a discovery run.
type Result struct {
	Target      string         `json:"target"`
	CDNDetected string         `json:"cdn_detected,omitempty"`
	Candidates  []ScoredIP     `json:"candidates"`
	Timestamp   time.Time      `json:"timestamp"`
	Errors      []TechniqueErr `json:"errors,omitempty"`
	// Warnings is a list of non-fatal issues — config warnings from
	// LoadWeights, cache-open failures, CDN-detection errors. Surfaced so
	// the CLI and the MCP server can show them without inspecting Errors,
	// which is reserved for per-technique failures.
	Warnings []string `json:"warnings,omitempty"`
}

// Discover runs origin-IP discovery against a single target and returns
// ranked candidates. The returned error is non-nil only when the engine
// itself could not start the run (e.g. ctx was already cancelled);
// per-technique failures are recorded on Result.Errors.
func Discover(ctx context.Context, target string, opts Options) (*Result, error) {
	opts = withDefaults(opts)

	overallCtx, cancel := context.WithTimeout(ctx, opts.OverallTimeout)
	defer cancel()

	if err := overallCtx.Err(); err != nil {
		return nil, fmt.Errorf("unearth: context: %w", err)
	}

	result := &Result{Target: target}

	// Weights (and any unknown-technique warnings).
	weights, warns, err := config.LoadWeights(opts.WeightsPath)
	if err != nil {
		result.Warnings = append(result.Warnings, "config: "+err.Error())
	}
	result.Warnings = append(result.Warnings, warns...)

	// Cache (best-effort). We keep the concrete *cache.Cache handle (calCache)
	// as well as the technique-facing interface so that, at the end of the
	// run, we can record per-technique calibration observations. The handle is
	// nil when caching is disabled or the cache failed to open.
	var cstore techniques.CacheStore
	var calCache *cache.Cache
	if !opts.NoCache {
		c, err := cache.Open("")
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("cache: open failed (%s); running without cache", err))
		} else {
			cstore = c
			calCache = c
			defer func() { _ = c.Close() }()
		}
	}

	// HTTP client, rate limiter, budget.
	hc := httpclient.New(httpclient.Options{})
	limiter := ratelimit.NewLimiter(map[string]ratelimit.EndpointConfig{
		"crtsh": {RPS: 0.5, Burst: 2}, // crt.sh is a free community service
		"dns":   {RPS: 20, Burst: 20},
	})
	budget := ratelimit.NewBudget(opts.BudgetCaps)

	// CDN detection — non-fatal.
	if det, err := cdnDetect(overallCtx, target, hc); err == nil {
		result.CDNDetected = det.CDN
	} else {
		result.Warnings = append(result.Warnings, "cdn detect: "+err.Error())
		// det is still useful (may have matched some signals before error).
		result.CDNDetected = det.CDN
	}

	// Build the technique RunOptions once; it is read-only across goroutines.
	runOpts := techniques.RunOptions{
		HTTPClient:  hc,
		APIKeys:     opts.APIKeys,
		Cache:       cstore,
		RateLimiter: limiter,
		BudgetCaps:  opts.BudgetCaps,
		Budget:      budget,
		NoCache:     opts.NoCache,
		Refresh:     opts.Refresh,
		EmailFile:   opts.EmailFile,
	}

	// Select techniques, filter for missing keys, split into the
	// two execution phases described in Packet 5A §6: producers run
	// first in parallel; consumers (techniques that implement
	// techniques.CandidateConsumer and opt in) run second with the
	// pooled candidate IPs from phase 1 in RunOptions.SeedIPs.
	selected := techniqueSelector(opts.Tier)
	var phase1, phase2 []techniques.Technique
	for _, t := range selected {
		if t.RequiresAPIKey() && !hasKeyFor(t.Name(), opts.APIKeys) {
			result.Errors = append(result.Errors, TechniqueErr{
				Technique: t.Name(),
				Err:       techniques.ErrMissingAPIKey.Error(),
				Reason:    "missing_api_key",
			})
			continue
		}
		if cc, ok := t.(techniques.CandidateConsumer); ok && cc.ConsumesCandidates() {
			phase2 = append(phase2, t)
		} else {
			phase1 = append(phase1, t)
		}
	}

	groups := map[string]*ScoredIP{}
	foldResults := func(rs []techResult) {
		for _, r := range rs {
			if r.err != nil {
				result.Errors = append(result.Errors, TechniqueErr{
					Technique: r.t.Name(),
					Err:       r.err.Error(),
					Reason:    reasonForErr(r.err),
				})
				continue
			}
			w := resolveWeight(weights, r.t)
			for _, c := range r.candidates {
				g, ok := groups[c.IP]
				if !ok {
					g = &ScoredIP{IP: c.IP}
					groups[c.IP] = g
				}
				g.Techniques = append(g.Techniques, TechniqueHit{
					Name:     r.t.Name(),
					Weight:   w,
					Evidence: c.Evidence,
				})
			}
		}
	}

	// Phase 1: producers.
	phase1Results := runBatch(overallCtx, phase1, target, runOpts, opts)
	foldResults(phase1Results)

	// Phase 2: consumers, with the pooled phase-1 IPs as seeds.
	if len(phase2) > 0 {
		seeds := collectSeedIPs(groups)
		phase2Opts := runOpts
		phase2Opts.SeedIPs = seeds
		phase2Results := runBatch(overallCtx, phase2, target, phase2Opts, opts)
		foldResults(phase2Results)
	}

	// Score and finalize.
	for _, g := range groups {
		ws := make([]float64, len(g.Techniques))
		for i, h := range g.Techniques {
			ws[i] = h.Weight
		}
		g.Score = rank.Score(ws)
		g.Corroboration = len(g.Techniques)
		g.SingleSource = g.Corroboration == 1
		sort.Slice(g.Techniques, func(i, j int) bool { return g.Techniques[i].Name < g.Techniques[j].Name })
		result.Candidates = append(result.Candidates, *g)
	}
	sort.Slice(result.Candidates, func(i, j int) bool {
		if result.Candidates[i].Score != result.Candidates[j].Score {
			return result.Candidates[i].Score > result.Candidates[j].Score
		}
		return result.Candidates[i].IP < result.Candidates[j].IP
	})
	sort.Slice(result.Errors, func(i, j int) bool {
		return result.Errors[i].Technique < result.Errors[j].Technique
	})

	result.Timestamp = time.Now().UTC()

	// Record per-technique calibration observations (best-effort). For each
	// technique contribution to a candidate, the observation is "corroborated"
	// when that candidate was found by more than one technique in this run.
	// This corroboration history is what `unearth calibrate` later turns into
	// per-technique precision estimates and weight suggestions. A recording
	// failure is non-fatal — calibration is a convenience, not part of the
	// discovery contract.
	if calCache != nil {
		if obs := buildObservations(result.Candidates); len(obs) > 0 {
			if err := calCache.RecordObservations(obs); err != nil {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("calibration: recording observations failed: %s", err))
			}
		}
	}

	return result, nil
}

// buildObservations converts a run's scored candidates into per-technique
// calibration observations. Each (technique, candidate) contribution becomes
// one observation; it is marked corroborated when the candidate was found by
// more than one technique. The corroboration signal is the closest proxy for
// precision available without external ground truth.
func buildObservations(candidates []ScoredIP) []cache.Observation {
	var obs []cache.Observation
	for _, c := range candidates {
		corroborated := c.Corroboration > 1
		for _, h := range c.Techniques {
			obs = append(obs, cache.Observation{
				Technique:    h.Name,
				Corroborated: corroborated,
			})
		}
	}
	return obs
}

// techResult bundles one technique's outcome for engine-internal use.
type techResult struct {
	t          techniques.Technique
	candidates []techniques.Candidate
	err        error
}

// runBatch executes the techniques in techs in parallel (bounded by
// opts.Concurrency), each under a child context with opts.PerTechniqueTimeout.
// Used twice in Discover: once for phase-1 producers, once for phase-2
// consumers with seeded IPs.
func runBatch(
	ctx context.Context, techs []techniques.Technique, target string,
	runOpts techniques.RunOptions, opts Options,
) []techResult {
	results := make([]techResult, len(techs))
	if len(techs) == 0 {
		return results
	}
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	for i, t := range techs {
		wg.Add(1)
		i, t := i, t
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = techResult{t: t, err: ctx.Err()}
				return
			}
			defer func() { <-sem }()
			results[i] = runOne(ctx, t, target, runOpts, techniqueTimeout(t, opts.PerTechniqueTimeout))
		}()
	}
	wg.Wait()
	return results
}

// techniqueTimeout resolves the per-technique deadline budget for one
// technique. The default is the engine's global PerTechniqueTimeout; a
// technique that implements techniques.TimeoutOverrider widens the
// budget to max(global, override). The overall-run deadline still bounds
// the resulting child context — that clamp happens later in runOne
// because only there do we have the parent context's remaining budget.
func techniqueTimeout(t techniques.Technique, defaultTimeout time.Duration) time.Duration {
	if to, ok := t.(techniques.TimeoutOverrider); ok {
		if override := to.TimeoutOverride(); override > defaultTimeout {
			return override
		}
	}
	return defaultTimeout
}

// collectSeedIPs flattens the current candidate-IP map into a
// deterministically-ordered slice of netip.Addr values for phase 2.
// Order is not load-bearing, but a stable order keeps tests predictable.
func collectSeedIPs(groups map[string]*ScoredIP) []netip.Addr {
	seeds := make([]netip.Addr, 0, len(groups))
	for ipStr := range groups {
		a, err := netip.ParseAddr(ipStr)
		if err != nil {
			continue
		}
		seeds = append(seeds, a)
	}
	sort.Slice(seeds, func(i, j int) bool { return seeds[i].Less(seeds[j]) })
	return seeds
}

// runOne runs a single technique under a child context with the per-
// technique timeout, recovers from any panic the technique might throw, and
// returns a normalized techResult.
func runOne(
	ctx context.Context, t techniques.Technique, target string,
	opts techniques.RunOptions, timeout time.Duration,
) (out techResult) {
	out.t = t
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			out.candidates = nil
			out.err = fmt.Errorf("technique %s panicked: %v", t.Name(), r)
		}
	}()
	out.candidates, out.err = t.Run(tctx, target, opts)
	if out.err != nil && errors.Is(out.err, context.DeadlineExceeded) {
		out.err = context.DeadlineExceeded
	} else if out.err == nil && tctx.Err() != nil {
		out.err = tctx.Err()
	}
	return out
}

func withDefaults(opts Options) Options {
	d := DefaultOptions()
	if opts.Concurrency <= 0 {
		opts.Concurrency = d.Concurrency
	}
	if opts.PerTechniqueTimeout <= 0 {
		opts.PerTechniqueTimeout = d.PerTechniqueTimeout
	}
	if opts.OverallTimeout <= 0 {
		opts.OverallTimeout = d.OverallTimeout
	}
	return opts
}

func resolveWeight(w config.Weights, t techniques.Technique) float64 {
	if v, ok := w.Weight(t.Name()); ok {
		return v
	}
	return t.DefaultWeight()
}

func reasonForErr(err error) string {
	switch {
	case errors.Is(err, techniques.ErrMissingAPIKey):
		return "missing_api_key"
	case errors.Is(err, techniques.ErrBudgetExhausted):
		return "budget_exhausted"
	case errors.Is(err, techniques.ErrTierInsufficient):
		return "tier_insufficient"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return ""
	}
}

// techniqueSelector resolves the technique list for a given tier. The
// indirection lets tests inject fake techniques without polluting the
// global registry. Production code path is techniques.ByTier.
var techniqueSelector = techniques.ByTier

// cdnDetect is the indirection used by Discover to invoke CDN detection so
// tests can stub it offline without faking DNS and HTTP at the same time.
// Production code path is cdn.Detect.
var cdnDetect = cdn.Detect

// hasKeyFor reports whether opts.APIKeys carries credentials usable by the
// named technique. Used by the engine to skip key-required techniques
// before launching a goroutine.
func hasKeyFor(name string, k techniques.APIKeys) bool {
	switch name {
	case "censys_cert":
		return k.CensysPlatformPAT != ""
	case "censys_ipv6":
		return k.CensysPlatformPAT != ""
	case "dns_history":
		return k.SecurityTrailsKey != "" || k.ViewDNSKey != ""
	case "shodan_cert":
		return k.ShodanAPIKey != ""
	case "fofa_cert":
		return k.FOFAEmail != "" && k.FOFAKey != ""
	case "netlas_cert":
		return k.NetlasAPIKey != ""
	case "criminalip_asset":
		return k.CriminalIPKey != ""
	case "binaryedge_cert":
		return k.BinaryEdgeKey != ""
	case "leakix_cert":
		return k.LeakIXKey != ""
	case "onyphe_cert":
		return k.OnypheKey != ""
	case "fullhunt_asset":
		return k.FullHuntKey != ""
	case "zoomeye_asset":
		return k.ZoomEyeKey != ""
	case "chaos_asset":
		return k.ChaosKey != ""
	case "virustotal_passivedns":
		return k.VirusTotalKey != ""
	case "urlscan_asset":
		return k.URLScanKey != ""
	default:
		// Unknown technique that declares RequiresAPIKey()==true: the
		// conservative answer is "we don't know what key it needs, so we
		// don't have one." The technique still gets a chance to defend
		// itself if a caller bypasses the engine's pre-filter.
		return false
	}
}

// RunTechnique runs a single named technique and returns its raw candidates.
// It is the helper used by the MCP server's single-technique tool calls.
// The full Discover pipeline is not run — no CDN detection, no ranking.
//
// seedIPs provides the candidate IP pool for phase-2 consumer techniques
// (e.g. host_header). For phase-1 techniques, seedIPs is ignored.
// Each element must be a valid IP address string; invalid strings are silently
// dropped.
//
// If the named technique is not registered, RunTechnique returns an error.
// If the technique requires an API key that is absent from opts.APIKeys, it
// returns a descriptive error.
func RunTechnique(ctx context.Context, name string, target string, opts Options, seedIPs []string) ([]techniques.Candidate, error) {
	t, ok := techniques.Get(name)
	if !ok {
		return nil, fmt.Errorf("technique %q not registered", name)
	}

	opts = withDefaults(opts)

	if t.RequiresAPIKey() && !hasKeyFor(name, opts.APIKeys) {
		return nil, fmt.Errorf("technique %q requires an API key (missing_api_key)", name)
	}

	var cstore techniques.CacheStore
	if !opts.NoCache {
		if c, err := cache.Open(""); err == nil {
			cstore = c
			defer func() { _ = c.Close() }()
		}
	}
	hc := httpclient.New(httpclient.Options{})
	limiter := ratelimit.NewLimiter(map[string]ratelimit.EndpointConfig{
		"crtsh": {RPS: 0.5, Burst: 2},
		"dns":   {RPS: 20, Burst: 20},
	})

	var seedAddrs []netip.Addr
	for _, s := range seedIPs {
		if a, err := netip.ParseAddr(s); err == nil {
			seedAddrs = append(seedAddrs, a.Unmap())
		}
	}

	timeout := techniqueTimeout(t, opts.PerTechniqueTimeout)
	if opts.OverallTimeout > 0 && opts.OverallTimeout < timeout {
		timeout = opts.OverallTimeout
	}
	tCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	runOpts := techniques.RunOptions{
		Cache:       cstore,
		HTTPClient:  hc,
		RateLimiter: limiter,
		APIKeys:     opts.APIKeys,
		BudgetCaps:  opts.BudgetCaps,
		NoCache:     opts.NoCache,
		Refresh:     opts.Refresh,
		SeedIPs:     seedAddrs,
		EmailFile:   opts.EmailFile,
	}
	return t.Run(tCtx, target, runOpts)
}
