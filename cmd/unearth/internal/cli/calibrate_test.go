package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/unearth-tool/unearth/pkg/cache"
)

// isolateCache points the default cache path at a temp dir for the test so the
// calibrate command operates on a fresh, controllable database. It returns the
// opened cache for seeding.
func isolateCache(t *testing.T) *cache.Cache {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", dir)
	// Also isolate the config dir so LoadWeights doesn't pick up a developer's
	// real ~/.config/unearth/weights.yaml.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	c, err := cache.Open("")
	if err != nil {
		t.Fatalf("open isolated cache: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestCalibrate_NoDataMessage(t *testing.T) {
	isolateCache(t)
	code, stdout, stderr := captured(t, "calibrate")
	if code != 0 {
		t.Fatalf("exit code %d, stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "no calibration data") {
		t.Fatalf("want no-data message, stderr=%q stdout=%q", stderr, stdout)
	}
}

func TestCalibrate_Table(t *testing.T) {
	c := isolateCache(t)
	// crtsh: highly corroborated, many samples — should suggest a higher
	// weight than its default and not be low-confidence.
	var obs []cache.Observation
	for i := 0; i < 40; i++ {
		obs = append(obs, cache.Observation{Technique: "crtsh", Corroborated: true})
	}
	if err := c.RecordObservations(obs); err != nil {
		t.Fatalf("seed: %v", err)
	}

	code, stdout, stderr := captured(t, "calibrate")
	if code != 0 {
		t.Fatalf("exit code %d, stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "crtsh") {
		t.Fatalf("table missing crtsh: %q", stdout)
	}
	if !strings.Contains(stdout, "technique") || !strings.Contains(stdout, "precision") {
		t.Fatalf("table missing header: %q", stdout)
	}
}

func TestCalibrate_YAMLOutput(t *testing.T) {
	c := isolateCache(t)
	// One well-sampled technique and one low-sampled technique.
	var obs []cache.Observation
	for i := 0; i < 40; i++ {
		obs = append(obs, cache.Observation{Technique: "crtsh", Corroborated: true})
	}
	obs = append(obs,
		cache.Observation{Technique: "host_header", Corroborated: false},
		cache.Observation{Technique: "host_header", Corroborated: false},
	)
	if err := c.RecordObservations(obs); err != nil {
		t.Fatalf("seed: %v", err)
	}

	code, stdout, stderr := captured(t, "calibrate", "--yaml")
	if code != 0 {
		t.Fatalf("exit code %d, stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "weights:") {
		t.Fatalf("yaml output missing weights key: %q", stdout)
	}
	// crtsh is well-sampled → an active suggestion line.
	if !strings.Contains(stdout, "crtsh:") {
		t.Fatalf("yaml missing crtsh suggestion: %q", stdout)
	}
	// host_header has only 2 samples → low-confidence, emitted commented-out.
	if !strings.Contains(stdout, "# host_header:") {
		t.Fatalf("low-confidence technique should be commented out: %q", stdout)
	}
}

func TestCalibrate_Reset(t *testing.T) {
	c := isolateCache(t)
	if err := c.RecordObservations([]cache.Observation{
		{Technique: "crtsh", Corroborated: true},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	code, stdout, stderr := captured(t, "calibrate", "reset", "--yes")
	if code != 0 {
		t.Fatalf("exit code %d, stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "reset 1 calibration observations") {
		t.Fatalf("unexpected reset output: %q", stdout)
	}
}
