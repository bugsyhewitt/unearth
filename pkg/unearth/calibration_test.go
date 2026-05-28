package unearth

import (
	"context"
	"testing"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/techniques"
)

// cacheOpts returns engine options with the cache enabled, pointed at an
// isolated XDG_CACHE_HOME so the run records calibration observations into a
// throwaway database.
func cacheOpts(t *testing.T) Options {
	t.Helper()
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	o := DefaultOptions()
	o.OverallTimeout = 5 * time.Second
	o.PerTechniqueTimeout = 500 * time.Millisecond
	o.NoCache = false
	return o
}

func TestDiscover_RecordsCalibrationObservations(t *testing.T) {
	withSelector(t,
		// Two techniques agree on .1 (corroborated); 'b' alone finds .2.
		&fakeTech{name: "a", weight: 0.5, candidates: []techniques.Candidate{
			{IP: "203.0.113.1", Evidence: "a"},
		}},
		&fakeTech{name: "b", weight: 0.5, candidates: []techniques.Candidate{
			{IP: "203.0.113.1", Evidence: "b"},
			{IP: "203.0.113.2", Evidence: "lone"},
		}},
	)

	opts := cacheOpts(t)
	res, err := Discover(context.Background(), "example.test", opts)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	for _, w := range res.Warnings {
		if containsCalibrationFailure(w) {
			t.Fatalf("unexpected calibration warning: %s", w)
		}
	}

	c, err := cache.Open("")
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	defer func() { _ = c.Close() }()

	stats, err := c.CalibrationStats()
	if err != nil {
		t.Fatalf("CalibrationStats: %v", err)
	}
	byName := map[string]cache.TechniqueStat{}
	for _, s := range stats {
		byName[s.Technique] = s
	}

	// 'a' contributed only to the corroborated .1 → 1 total, 1 corroborated.
	a := byName["a"]
	if a.Total != 1 || a.Corroborated != 1 {
		t.Fatalf("technique a stats: %+v, want total=1 corroborated=1", a)
	}
	// 'b' contributed to .1 (corroborated) and .2 (lone) → 2 total, 1 corroborated.
	b := byName["b"]
	if b.Total != 2 || b.Corroborated != 1 {
		t.Fatalf("technique b stats: %+v, want total=2 corroborated=1", b)
	}
}

func TestDiscover_NoCacheRecordsNothing(t *testing.T) {
	withSelector(t,
		&fakeTech{name: "a", weight: 0.5, candidates: []techniques.Candidate{
			{IP: "203.0.113.1"},
		}},
	)
	opts := cacheOpts(t)
	opts.NoCache = true // disable caching → no observations
	if _, err := Discover(context.Background(), "x", opts); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	c, err := cache.Open("")
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	defer func() { _ = c.Close() }()
	n, err := c.ObservationCount()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("NoCache run recorded %d observations, want 0", n)
	}
}

func containsCalibrationFailure(s string) bool {
	const marker = "calibration: recording observations failed"
	return len(s) >= len(marker) && s[:len(marker)] == marker
}
