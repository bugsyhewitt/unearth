package unearth

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unearth-tool/unearth/pkg/cdn"
	"github.com/unearth-tool/unearth/pkg/rank"
	"github.com/unearth-tool/unearth/pkg/techniques"
)

func TestDefaultOptions(t *testing.T) {
	o := DefaultOptions()
	if o.Tier != techniques.TierPassive {
		t.Errorf("default Tier = %v, want passive", o.Tier)
	}
	if o.Concurrency != 10 {
		t.Errorf("default Concurrency = %d, want 10", o.Concurrency)
	}
	if o.PerTechniqueTimeout <= 0 {
		t.Error("default PerTechniqueTimeout must be positive")
	}
	if o.OverallTimeout <= 0 {
		t.Error("default OverallTimeout must be positive")
	}
}

// fakeTech is a minimal in-memory technique driven by the test.
type fakeTech struct {
	name       string
	weight     float64
	tier       techniques.Tier
	requiresK  bool
	candidates []techniques.Candidate
	err        error
	delay      time.Duration
	doPanic    bool
	ranOnce    atomic.Int32
}

func (f *fakeTech) Name() string           { return f.name }
func (f *fakeTech) Tier() techniques.Tier  { return f.tier }
func (f *fakeTech) RequiresAPIKey() bool   { return f.requiresK }
func (f *fakeTech) DefaultWeight() float64 { return f.weight }

func (f *fakeTech) Run(ctx context.Context, _ string, _ techniques.RunOptions) ([]techniques.Candidate, error) {
	f.ranOnce.Add(1)
	if f.doPanic {
		panic("kaboom")
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.candidates, nil
}

func withSelector(t *testing.T, techs ...techniques.Technique) {
	t.Helper()
	prev := techniqueSelector
	techniqueSelector = func(maxTier techniques.Tier) []techniques.Technique {
		var out []techniques.Technique
		for _, x := range techs {
			if x.Tier() <= maxTier {
				out = append(out, x)
			}
		}
		return out
	}
	// Also stub CDN detection so the test suite is fully offline.
	prevDet := cdnDetect
	cdnDetect = func(context.Context, string, *http.Client) (cdn.Detection, error) {
		return cdn.Detection{}, nil
	}
	t.Cleanup(func() {
		techniqueSelector = prev
		cdnDetect = prevDet
	})
}

func testOpts() Options {
	o := DefaultOptions()
	o.OverallTimeout = 5 * time.Second
	o.PerTechniqueTimeout = 500 * time.Millisecond
	o.NoCache = true
	return o
}

func TestDiscover_BasicGroupingAndScoring(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "a", weight: 0.5, candidates: []techniques.Candidate{
			{IP: "203.0.113.1", Evidence: "a-evidence"},
		}},
		&fakeTech{name: "b", weight: 0.5, candidates: []techniques.Candidate{
			{IP: "203.0.113.1", Evidence: "b-evidence"},
			{IP: "203.0.113.2", Evidence: "lone"},
		}},
	)
	res, err := Discover(context.Background(), "example.test", testOpts())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Candidates) != 2 {
		t.Fatalf("Candidates: want 2, got %d (%+v)", len(res.Candidates), res.Candidates)
	}
	top := res.Candidates[0]
	if top.IP != "203.0.113.1" {
		t.Errorf("top IP: want .1, got %s", top.IP)
	}
	if top.Corroboration != 2 {
		t.Errorf("Corroboration: want 2, got %d", top.Corroboration)
	}
	if top.SingleSource {
		t.Errorf("SingleSource should be false for 2-source hit")
	}
	wantScore := rank.Score([]float64{0.5, 0.5}) // 0.75
	if math.Abs(top.Score-wantScore) > 1e-9 {
		t.Errorf("Score: want %g, got %g", wantScore, top.Score)
	}
	lone := res.Candidates[1]
	if lone.IP != "203.0.113.2" {
		t.Errorf("lone IP: want .2, got %s", lone.IP)
	}
	if !lone.SingleSource || lone.Corroboration != 1 {
		t.Errorf("lone: SingleSource=%v Corroboration=%d", lone.SingleSource, lone.Corroboration)
	}
	if math.Abs(lone.Score-0.5) > 1e-9 {
		t.Errorf("lone Score: want 0.5, got %g", lone.Score)
	}
}

func TestDiscover_SortOrder(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "a", weight: 0.3, candidates: []techniques.Candidate{
			{IP: "203.0.113.10"}, {IP: "203.0.113.20"},
		}},
		&fakeTech{name: "b", weight: 0.9, candidates: []techniques.Candidate{
			{IP: "203.0.113.20"}, // gets the higher-scoring hit
		}},
	)
	res, _ := Discover(context.Background(), "x", testOpts())
	if res.Candidates[0].IP != "203.0.113.20" {
		t.Errorf("sort by score desc: want .20 first, got %s", res.Candidates[0].IP)
	}
	// Same-score tiebreak by IP asc — induce by giving both .30 and .40 only
	// from technique 'a' with weight 0.3.
	withSelector(t,
		&fakeTech{name: "a", weight: 0.3, candidates: []techniques.Candidate{
			{IP: "203.0.113.40"}, {IP: "203.0.113.30"},
		}},
	)
	res, _ = Discover(context.Background(), "x", testOpts())
	if res.Candidates[0].IP != "203.0.113.30" || res.Candidates[1].IP != "203.0.113.40" {
		t.Errorf("tiebreak by IP asc: got %v", []string{res.Candidates[0].IP, res.Candidates[1].IP})
	}
}

func TestDiscover_PerTechniqueTimeout(t *testing.T) {
	slow := &fakeTech{name: "slow", weight: 0.5, delay: 5 * time.Second}
	fast := &fakeTech{name: "fast", weight: 0.5, candidates: []techniques.Candidate{{IP: "203.0.113.5"}}}
	withSelector(t, slow, fast)
	opts := testOpts()
	opts.PerTechniqueTimeout = 50 * time.Millisecond
	start := time.Now()
	res, _ := Discover(context.Background(), "x", opts)
	if time.Since(start) > 2*time.Second {
		t.Errorf("per-tech timeout did not cut slow: %v", time.Since(start))
	}
	var foundSlow bool
	for _, e := range res.Errors {
		if e.Technique == "slow" {
			foundSlow = true
			if e.Reason != "timeout" {
				t.Errorf("slow reason: want timeout, got %q (err %q)", e.Reason, e.Err)
			}
		}
	}
	if !foundSlow {
		t.Error("slow technique should appear in Errors")
	}
	if len(res.Candidates) != 1 || res.Candidates[0].IP != "203.0.113.5" {
		t.Errorf("fast technique should still produce its candidate, got %+v", res.Candidates)
	}
}

func TestDiscover_MissingAPIKeySkipped(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "needs_key", weight: 0.9, requiresK: true},
		&fakeTech{name: "open", weight: 0.5, candidates: []techniques.Candidate{{IP: "203.0.113.7"}}},
	)
	res, _ := Discover(context.Background(), "x", testOpts())
	var skipped TechniqueErr
	for _, e := range res.Errors {
		if e.Technique == "needs_key" {
			skipped = e
		}
	}
	if skipped.Reason != "missing_api_key" {
		t.Errorf("needs_key reason: want missing_api_key, got %q", skipped.Reason)
	}
	if len(res.Candidates) != 1 {
		t.Errorf("open technique still produces results, got %d", len(res.Candidates))
	}
}

func TestDiscover_PanicContained(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "boom", weight: 0.5, doPanic: true},
		&fakeTech{name: "ok", weight: 0.5, candidates: []techniques.Candidate{{IP: "203.0.113.9"}}},
	)
	res, err := Discover(context.Background(), "x", testOpts())
	if err != nil {
		t.Fatalf("panic should not escape Discover: %v", err)
	}
	var boomErr TechniqueErr
	for _, e := range res.Errors {
		if e.Technique == "boom" {
			boomErr = e
		}
	}
	if boomErr.Err == "" {
		t.Error("panicking technique should produce a TechniqueErr")
	}
	if len(res.Candidates) != 1 {
		t.Errorf("non-panicking technique still works, got %d candidates", len(res.Candidates))
	}
}

func TestDiscover_BudgetExhaustedReason(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "broke", weight: 0.5, err: techniques.ErrBudgetExhausted},
	)
	res, _ := Discover(context.Background(), "x", testOpts())
	if len(res.Errors) != 1 || res.Errors[0].Reason != "budget_exhausted" {
		t.Errorf("want budget_exhausted reason, got %+v", res.Errors)
	}
}

func TestDiscover_ErrorsSortedByTechniqueName(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "zeta", weight: 0.5, err: errors.New("z")},
		&fakeTech{name: "alpha", weight: 0.5, err: errors.New("a")},
		&fakeTech{name: "mike", weight: 0.5, err: errors.New("m")},
	)
	res, _ := Discover(context.Background(), "x", testOpts())
	if len(res.Errors) != 3 {
		t.Fatalf("want 3 errors, got %d", len(res.Errors))
	}
	want := []string{"alpha", "mike", "zeta"}
	for i, w := range want {
		if res.Errors[i].Technique != w {
			t.Errorf("Errors[%d]: want %s, got %s", i, w, res.Errors[i].Technique)
		}
	}
}

func TestDiscover_ConcurrencyBoundRespected(t *testing.T) {
	var live, peak atomic.Int64
	makeTech := func(name string) *fakeTech {
		return &fakeTech{
			name:   name,
			weight: 0.5,
			delay:  40 * time.Millisecond,
		}
	}
	tech := func(name string) *fakeTech {
		f := makeTech(name)
		f.candidates = []techniques.Candidate{{IP: "203.0.113." + name}}
		return f
	}
	_ = tech
	// Use a wrapper that bumps live/peak around Run.
	wrap := func(name string) techniques.Technique {
		return &countingTech{fakeTech: fakeTech{name: name, weight: 0.5, delay: 40 * time.Millisecond}, live: &live, peak: &peak}
	}
	withSelector(t, wrap("a"), wrap("b"), wrap("c"), wrap("d"))
	opts := testOpts()
	opts.Concurrency = 2
	opts.PerTechniqueTimeout = 2 * time.Second
	_, _ = Discover(context.Background(), "x", opts)
	if peak.Load() > 2 {
		t.Errorf("concurrency bound violated: peak %d > 2", peak.Load())
	}
}

type countingTech struct {
	fakeTech
	live, peak *atomic.Int64
}

func (c *countingTech) Run(ctx context.Context, target string, opts techniques.RunOptions) ([]techniques.Candidate, error) {
	n := c.live.Add(1)
	defer c.live.Add(-1)
	for {
		p := c.peak.Load()
		if n <= p || c.peak.CompareAndSwap(p, n) {
			break
		}
	}
	return c.fakeTech.Run(ctx, target, opts)
}

func TestDiscover_ContextAlreadyCancelled(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "n", weight: 0.5, candidates: []techniques.Candidate{{IP: "203.0.113.5"}}},
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Discover(ctx, "x", testOpts())
	if err == nil {
		t.Error("expected engine error on pre-cancelled context")
	}
}

// TestDiscover_ExcludeTechnique_SkipsNamedTechnique verifies that a technique
// named in opts.ExcludeTechniques is never run and never appears in Errors.
func TestDiscover_ExcludeTechnique_SkipsNamedTechnique(t *testing.T) {
	excluded := &fakeTech{name: "skip_me", weight: 0.9,
		candidates: []techniques.Candidate{{IP: "203.0.113.99", Evidence: "should not appear"}}}
	kept := &fakeTech{name: "keep_me", weight: 0.7,
		candidates: []techniques.Candidate{{IP: "203.0.113.1", Evidence: "kept"}}}
	withSelector(t, excluded, kept)

	opts := testOpts()
	opts.ExcludeTechniques = []string{"skip_me"}
	res, err := Discover(context.Background(), "example.test", opts)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	// skip_me must not have run
	if excluded.ranOnce.Load() != 0 {
		t.Error("excluded technique was run but should have been skipped")
	}
	// keep_me must still produce its candidate
	if len(res.Candidates) != 1 || res.Candidates[0].IP != "203.0.113.1" {
		t.Errorf("kept technique candidates: want [203.0.113.1], got %+v", res.Candidates)
	}
	// skip_me must not appear in Errors either
	for _, e := range res.Errors {
		if e.Technique == "skip_me" {
			t.Errorf("excluded technique appeared in Errors: %+v", e)
		}
	}
}

// TestDiscover_ExcludeTechnique_MultipleExclusions verifies that all names in
// ExcludeTechniques are skipped, not just the first.
func TestDiscover_ExcludeTechnique_MultipleExclusions(t *testing.T) {
	a := &fakeTech{name: "a", weight: 0.5, candidates: []techniques.Candidate{{IP: "1.1.1.1"}}}
	b := &fakeTech{name: "b", weight: 0.5, candidates: []techniques.Candidate{{IP: "2.2.2.2"}}}
	c := &fakeTech{name: "c", weight: 0.5, candidates: []techniques.Candidate{{IP: "3.3.3.3"}}}
	withSelector(t, a, b, c)

	opts := testOpts()
	opts.ExcludeTechniques = []string{"a", "c"}
	res, err := Discover(context.Background(), "x", opts)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if a.ranOnce.Load() != 0 {
		t.Error("technique 'a' should have been excluded")
	}
	if c.ranOnce.Load() != 0 {
		t.Error("technique 'c' should have been excluded")
	}
	if b.ranOnce.Load() != 1 {
		t.Error("technique 'b' should still run")
	}
	if len(res.Candidates) != 1 || res.Candidates[0].IP != "2.2.2.2" {
		t.Errorf("candidates: want [2.2.2.2], got %+v", res.Candidates)
	}
}

// TestDiscover_ExcludeTechnique_UnknownNameWarns verifies that an unknown
// technique name in ExcludeTechniques results in a Warnings entry (not an
// error) and does not prevent normal discovery.
func TestDiscover_ExcludeTechnique_UnknownNameWarns(t *testing.T) {
	known := &fakeTech{name: "known", weight: 0.6,
		candidates: []techniques.Candidate{{IP: "203.0.113.1"}}}
	withSelector(t, known)

	opts := testOpts()
	opts.ExcludeTechniques = []string{"nonexistent_technique"}
	res, err := Discover(context.Background(), "x", opts)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	// The unknown name should produce a warning.
	var foundWarn bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "nonexistent_technique") {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Errorf("expected warning for unknown technique, got warnings: %v", res.Warnings)
	}
	// Discovery still runs normally.
	if len(res.Candidates) != 1 {
		t.Errorf("candidates: want 1, got %d", len(res.Candidates))
	}
}

// TestDiscover_ExcludeTechnique_EmptySliceIsNoop verifies that an empty
// ExcludeTechniques slice is equivalent to not setting the field.
func TestDiscover_ExcludeTechnique_EmptySliceIsNoop(t *testing.T) {
	tech := &fakeTech{name: "t", weight: 0.5, candidates: []techniques.Candidate{{IP: "203.0.113.1"}}}
	withSelector(t, tech)

	opts := testOpts()
	opts.ExcludeTechniques = []string{} // explicitly empty
	res, err := Discover(context.Background(), "x", opts)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if tech.ranOnce.Load() != 1 {
		t.Error("technique should run when ExcludeTechniques is empty")
	}
	if len(res.Candidates) != 1 {
		t.Errorf("candidates: want 1, got %d", len(res.Candidates))
	}
}

// TestHasKeyFor_FaviconHash is a regression test for the bug where
// favicon_hash was missing from the hasKeyFor switch and fell through to the
// default case (return false), silently dropping the technique even when
// SHODAN_API_KEY or CENSYS_PLATFORM_PAT was configured.
func TestHasKeyFor_FaviconHash(t *testing.T) {
	tests := []struct {
		name string
		keys techniques.APIKeys
		want bool
	}{
		{"shodan only", techniques.APIKeys{ShodanAPIKey: "s"}, true},
		{"censys only", techniques.APIKeys{CensysPlatformPAT: "c"}, true},
		{"both", techniques.APIKeys{ShodanAPIKey: "s", CensysPlatformPAT: "c"}, true},
		{"neither", techniques.APIKeys{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasKeyFor("favicon_hash", tc.keys); got != tc.want {
				t.Errorf("hasKeyFor(favicon_hash, %+v) = %v, want %v", tc.keys, got, tc.want)
			}
		})
	}
}

// TestHasKeyFor_AllKeyRequiringTechniquesCovered verifies that every
// registered technique declaring RequiresAPIKey()==true has an explicit case
// in hasKeyFor. The default case returns false, which would silently drop the
// technique even when its key is configured.
func TestHasKeyFor_AllKeyRequiringTechniquesCovered(t *testing.T) {
	// A fully-populated APIKeys struct that covers every backend credential.
	full := techniques.APIKeys{
		CensysPlatformPAT: "c",
		ShodanAPIKey:      "s",
		SecurityTrailsKey: "st",
		ViewDNSKey:        "vd",
		FOFAEmail:         "e",
		FOFAKey:           "k",
		NetlasAPIKey:      "n",
		CriminalIPKey:     "ci",
		BinaryEdgeKey:     "be",
		LeakIXKey:         "lx",
		OnypheKey:         "on",
		FullHuntKey:       "fh",
		ZoomEyeKey:        "ze",
		ChaosKey:          "ch",
		VirusTotalKey:     "vt",
		URLScanKey:        "us",
		GreyNoiseKey:      "gn",
	}
	for _, tech := range techniques.All() {
		if !tech.RequiresAPIKey() {
			continue
		}
		if !hasKeyFor(tech.Name(), full) {
			t.Errorf("technique %q declares RequiresAPIKey()==true but hasKeyFor returns false with all credentials populated; add a case for it in hasKeyFor()", tech.Name())
		}
	}
}
