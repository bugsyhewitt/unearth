package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/unearth-tool/unearth/pkg/techniques"
	"github.com/unearth-tool/unearth/pkg/unearth"
)

// withRunner swaps the package-level discoverRunner so CLI tests don't have
// to round-trip through the real engine (which would touch the network for
// CDN detection, open a cache, etc.).
func withRunner(t *testing.T, fn runner) {
	t.Helper()
	prev := discoverRunner
	discoverRunner = fn
	t.Cleanup(func() { discoverRunner = prev })
}

// captured invokes Run and returns its exit code plus captured streams.
func captured(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	// stdin: an empty Reader. isTTY returns false for it (not *os.File),
	// which would normally trigger stdin-target mode; pass an empty
	// *os.File-pointing-at-/dev/null instead so stdin is treated as a TTY.
	null, _ := os.Open(os.DevNull)
	defer func() { _ = null.Close() }()
	code := Run(args, null, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// fakeResult builds a synthetic Result the runner returns.
func fakeResult(target string, ips ...string) *unearth.Result {
	r := &unearth.Result{
		Target:      target,
		CDNDetected: "cloudflare",
		Timestamp:   time.Unix(1700000000, 0).UTC(),
	}
	for i, ip := range ips {
		r.Candidates = append(r.Candidates, unearth.ScoredIP{
			IP:            ip,
			Score:         0.9 - 0.1*float64(i),
			Corroboration: 1,
			SingleSource:  true,
			Techniques:    []unearth.TechniqueHit{{Name: "crtsh", Weight: 0.55, Evidence: "ev"}},
		})
	}
	return r
}

func TestRoot_NoInputIsUsageError(t *testing.T) {
	withRunner(t, func(context.Context, string, unearth.Options) (*unearth.Result, error) {
		t.Fatal("runner should not be called")
		return nil, nil
	})
	code, _, stderr := captured(t)
	if code != exitUsageError {
		t.Errorf("exit code: want %d, got %d", exitUsageError, code)
	}
	if !strings.Contains(stderr, "no targets") {
		t.Errorf("stderr: %q", stderr)
	}
}

func TestRoot_JSONLOutput_Default(t *testing.T) {
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return fakeResult(target, "203.0.113.1", "203.0.113.2"), nil
	})
	code, stdout, _ := captured(t, "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 jsonl lines, got %d: %q", len(lines), stdout)
	}
	var row struct {
		Target string `json:"target"`
		IP     string `json:"candidate_ip"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &row); err != nil {
		t.Fatalf("parse first line: %v", err)
	}
	if row.Target != "example.test" || row.IP != "203.0.113.1" {
		t.Errorf("first row: %+v", row)
	}
}

func TestRoot_JSONOutput_ArrayOfResults(t *testing.T) {
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return fakeResult(target, "203.0.113.10"), nil
	})
	code, stdout, _ := captured(t, "-o", "json", "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var got []unearth.Result
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("json parse: %v\nout: %s", err, stdout)
	}
	if len(got) != 1 || got[0].Target != "example.test" {
		t.Errorf("got %+v", got)
	}
}

func TestRoot_TableOutput(t *testing.T) {
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return fakeResult(target, "203.0.113.5"), nil
	})
	code, stdout, _ := captured(t, "-o", "table", "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"Target: example.test", "cloudflare", "203.0.113.5", "SCORE", "CORROB"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("table output missing %q\n---\n%s", want, stdout)
		}
	}
}

func TestRoot_InvalidOutput(t *testing.T) {
	code, _, stderr := captured(t, "-o", "yaml", "example.test")
	if code != exitUsageError {
		t.Errorf("exit code: want %d, got %d", exitUsageError, code)
	}
	if !strings.Contains(stderr, "invalid --output") {
		t.Errorf("stderr: %q", stderr)
	}
}

func TestRoot_SilentAndVerboseExclusive(t *testing.T) {
	code, _, stderr := captured(t, "--silent", "--verbose", "example.test")
	if code != exitUsageError {
		t.Errorf("exit code: want %d, got %d", exitUsageError, code)
	}
	if !strings.Contains(stderr, "mutually exclusive") {
		t.Errorf("stderr: %q", stderr)
	}
}

func TestRoot_TooManyPositional(t *testing.T) {
	code, _, stderr := captured(t, "a", "b")
	if code != exitUsageError {
		t.Errorf("exit code: want %d, got %d", exitUsageError, code)
	}
	if !strings.Contains(stderr, "only one target") {
		t.Errorf("stderr: %q", stderr)
	}
}

func TestRoot_ListFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(path, []byte("# comment\nfoo.test\n\nbar.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var got []string
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		got = append(got, target)
		return fakeResult(target), nil
	})
	code, _, _ := captured(t, "-l", path)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if len(got) != 2 || got[0] != "foo.test" || got[1] != "bar.test" {
		t.Errorf("targets: %v", got)
	}
}

func TestRoot_AllTargetsFailedIsExecError(t *testing.T) {
	withRunner(t, func(context.Context, string, unearth.Options) (*unearth.Result, error) {
		return nil, errUsageNot{"boom"}
	})
	code, _, _ := captured(t, "example.test")
	if code != exitExecError {
		t.Errorf("want exec error %d, got %d", exitExecError, code)
	}
}

type errUsageNot struct{ s string }

func (e errUsageNot) Error() string { return e.s }

func TestRoot_ZeroCandidatesIsStillSuccess(t *testing.T) {
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return &unearth.Result{Target: target}, nil
	})
	code, stdout, _ := captured(t, "example.test")
	if code != 0 {
		t.Errorf("zero candidates should exit 0, got %d", code)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("expected empty stdout, got %q", stdout)
	}
}

func TestRoot_TopCapped(t *testing.T) {
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return fakeResult(target, "1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"), nil
	})
	code, stdout, _ := captured(t, "--top", "2", "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 {
		t.Errorf("--top 2 should yield 2 lines, got %d", len(lines))
	}
}

func TestRoot_OptionsThreaded(t *testing.T) {
	var seenOpts unearth.Options
	withRunner(t, func(_ context.Context, target string, opts unearth.Options) (*unearth.Result, error) {
		seenOpts = opts
		return fakeResult(target), nil
	})
	args := []string{
		"--active", "--max-censys", "5", "--max-shodan", "7", "--max-st", "9",
		"--no-cache", "--refresh", "--concurrency", "3", "--timeout", "1s",
		"--weights", "/tmp/w.yaml",
		"example.test",
	}
	code, _, _ := captured(t, args...)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if seenOpts.Tier != techniques.TierActive {
		t.Errorf("tier: %v", seenOpts.Tier)
	}
	if seenOpts.BudgetCaps.Censys != 5 || seenOpts.BudgetCaps.Shodan != 7 || seenOpts.BudgetCaps.SecurityTrails != 9 {
		t.Errorf("budget caps: %+v", seenOpts.BudgetCaps)
	}
	if !seenOpts.NoCache || !seenOpts.Refresh {
		t.Errorf("cache flags: NoCache=%v Refresh=%v", seenOpts.NoCache, seenOpts.Refresh)
	}
	if seenOpts.Concurrency != 3 {
		t.Errorf("concurrency: %d", seenOpts.Concurrency)
	}
	if seenOpts.OverallTimeout != time.Second {
		t.Errorf("timeout: %v", seenOpts.OverallTimeout)
	}
	if seenOpts.WeightsPath != "/tmp/w.yaml" {
		t.Errorf("weights: %q", seenOpts.WeightsPath)
	}
}

func TestRoot_AggressiveImpliesAggressiveTier(t *testing.T) {
	var seenTier techniques.Tier
	withRunner(t, func(_ context.Context, target string, opts unearth.Options) (*unearth.Result, error) {
		seenTier = opts.Tier
		return fakeResult(target), nil
	})
	_, _, _ = captured(t, "--aggressive", "example.test")
	if seenTier != techniques.TierAggressive {
		t.Errorf("tier: %v", seenTier)
	}
}

func TestRoot_PipelineBatchInvalid(t *testing.T) {
	code, _, stderr := captured(t, "--pipeline-batch", "0", "example.test")
	if code != exitUsageError {
		t.Errorf("exit code: want %d, got %d", exitUsageError, code)
	}
	if !strings.Contains(stderr, "pipeline-batch") {
		t.Errorf("stderr: %q", stderr)
	}
}

// TestRoot_PipelineBatchOrderedOutput verifies that concurrent discovery
// (pipeline-batch > 1) still emits results in input order, even when later
// targets finish first. The fake runner sleeps an amount inversely
// proportional to input order so the last target completes first.
func TestRoot_PipelineBatchOrderedOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(path, []byte("a.test\nb.test\nc.test\nd.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	order := map[string]time.Duration{
		"a.test": 40 * time.Millisecond,
		"b.test": 30 * time.Millisecond,
		"c.test": 20 * time.Millisecond,
		"d.test": 10 * time.Millisecond,
	}
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		time.Sleep(order[target])
		return fakeResult(target, "203.0.113.9"), nil
	})
	code, stdout, _ := captured(t, "-l", path, "--pipeline-batch", "4")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 4 {
		t.Fatalf("want 4 jsonl lines, got %d: %q", len(lines), stdout)
	}
	want := []string{"a.test", "b.test", "c.test", "d.test"}
	for i, line := range lines {
		var row struct {
			Target string `json:"target"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("parse line %d: %v", i, err)
		}
		if row.Target != want[i] {
			t.Errorf("line %d: want target %q, got %q", i, want[i], row.Target)
		}
	}
}

// TestRoot_PipelineBatchRunsAllTargets confirms every target is dispatched
// exactly once under the concurrent pool and that mixed success/failure is
// handled — failures go to stderr, successes to stdout, exit stays 0.
func TestRoot_PipelineBatchRunsAllTargets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(path, []byte("ok1.test\nbad.test\nok2.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	seen := map[string]int{}
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		mu.Lock()
		seen[target]++
		mu.Unlock()
		if target == "bad.test" {
			return nil, errUsageNot{"boom"}
		}
		return fakeResult(target, "203.0.113.7"), nil
	})
	code, stdout, stderr := captured(t, "-l", path, "--pipeline-batch", "3")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, target := range []string{"ok1.test", "bad.test", "ok2.test"} {
		if seen[target] != 1 {
			t.Errorf("target %q dispatched %d times, want 1", target, seen[target])
		}
	}
	if !strings.Contains(stdout, "ok1.test") || !strings.Contains(stdout, "ok2.test") {
		t.Errorf("stdout missing successful targets: %q", stdout)
	}
	if strings.Contains(stdout, "bad.test") {
		t.Errorf("failed target should not appear in stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "bad.test") {
		t.Errorf("failed target should be reported to stderr: %q", stderr)
	}
}

// TestRoot_PipelineBatchClampsToTargetCount ensures a batch larger than the
// target count does not deadlock or drop work.
func TestRoot_PipelineBatchClampsToTargetCount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(path, []byte("only.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return fakeResult(target, "203.0.113.1"), nil
	})
	code, stdout, _ := captured(t, "-l", path, "--pipeline-batch", "16")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout, "only.test") {
		t.Errorf("stdout: %q", stdout)
	}
}

func TestVersionCmd(t *testing.T) {
	code, stdout, _ := captured(t, "version")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout, "unearth ") {
		t.Errorf("version output should start with 'unearth ': %q", stdout)
	}
}

func TestCacheStats_PrintsPath(t *testing.T) {
	// Redirect XDG_CACHE_HOME so we don't touch the user's real cache.
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	code, stdout, _ := captured(t, "cache", "stats")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout, "path:") || !strings.Contains(stdout, "total:") {
		t.Errorf("stats output: %q", stdout)
	}
}

func TestCachePurge_OK(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	code, stdout, _ := captured(t, "cache", "purge")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout, "purged") {
		t.Errorf("purge output: %q", stdout)
	}
}

func TestCacheClear_WithYes(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	// Create the cache file by opening + closing it via the stats path.
	_, _, _ = captured(t, "cache", "stats")
	code, stdout, _ := captured(t, "cache", "clear", "--yes")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout, "removed") {
		t.Errorf("clear output: %q", stdout)
	}
}

func TestResolveTargets_PrecedenceListWinsOverArg(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.txt")
	_ = os.WriteFile(path, []byte("from-file.test\n"), 0o644)
	null, _ := os.Open(os.DevNull)
	defer func() { _ = null.Close() }()
	targets, notice, err := resolveTargets(path, []string{"from-arg.test"}, null)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0] != "from-file.test" {
		t.Errorf("targets: %v", targets)
	}
	if !strings.Contains(notice, "positional target") {
		t.Errorf("notice should mention ignored source, got %q", notice)
	}
}

func TestTierFromFlags(t *testing.T) {
	if tierFromFlags(false, false) != techniques.TierPassive {
		t.Error("default should be passive")
	}
	if tierFromFlags(true, false) != techniques.TierActive {
		t.Error("--active → active")
	}
	if tierFromFlags(false, true) != techniques.TierAggressive {
		t.Error("--aggressive → aggressive")
	}
	if tierFromFlags(true, true) != techniques.TierAggressive {
		t.Error("--aggressive wins over --active")
	}
}

// --- SARIF output tests ---------------------------------------------------

// sarifDoc is a minimal struct for unmarshalling SARIF output in tests. It
// does not need to cover every SARIF field — only what the tests assert on.
type sarifDoc struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Rules   []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				LogicalLocations []struct {
					FullyQualifiedName string `json:"fullyQualifiedName"`
					Kind               string `json:"kind"`
				} `json:"logicalLocations"`
			} `json:"locations"`
			Properties struct {
				Score         float64 `json:"score"`
				Corroboration int     `json:"corroboration"`
				SingleSource  bool    `json:"single_source"`
				CDNDetected   string  `json:"cdn_detected"`
			} `json:"properties"`
		} `json:"results"`
	} `json:"runs"`
}

func TestRoot_SARIFOutput_Schema(t *testing.T) {
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return fakeResult(target, "203.0.113.1", "203.0.113.2"), nil
	})
	code, stdout, _ := captured(t, "-o", "sarif", "example.test")
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s", code, stdout)
	}

	var doc sarifDoc
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("sarif parse error: %v\n---\n%s", err, stdout)
	}

	// SARIF schema and version.
	if doc.Schema == "" {
		t.Error("$schema must be set")
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version: want 2.1.0, got %q", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs: want 1, got %d", len(doc.Runs))
	}

	// Driver metadata.
	driver := doc.Runs[0].Tool.Driver
	if driver.Name != "unearth" {
		t.Errorf("driver.name: want unearth, got %q", driver.Name)
	}
	if driver.Version == "" {
		t.Error("driver.version must be set")
	}
	if len(driver.Rules) < 1 || driver.Rules[0].ID != "UNEARTH001" {
		t.Errorf("rules: want UNEARTH001, got %v", driver.Rules)
	}

	// Two candidates → two results.
	results := doc.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("results: want 2, got %d", len(results))
	}
}

func TestRoot_SARIFOutput_ResultFields(t *testing.T) {
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return fakeResult(target, "203.0.113.5"), nil
	})
	code, stdout, _ := captured(t, "-o", "sarif", "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}

	var doc sarifDoc
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("sarif parse: %v", err)
	}
	if len(doc.Runs[0].Results) != 1 {
		t.Fatalf("want 1 result, got %d", len(doc.Runs[0].Results))
	}
	r := doc.Runs[0].Results[0]

	if r.RuleID != "UNEARTH001" {
		t.Errorf("ruleId: want UNEARTH001, got %q", r.RuleID)
	}
	if r.Message.Text == "" {
		t.Error("message.text must not be empty")
	}
	if !strings.Contains(r.Message.Text, "203.0.113.5") {
		t.Errorf("message should contain candidate IP, got %q", r.Message.Text)
	}
	if !strings.Contains(r.Message.Text, "example.test") {
		t.Errorf("message should contain target, got %q", r.Message.Text)
	}

	// logical location carries the target domain.
	if len(r.Locations) == 0 || len(r.Locations[0].LogicalLocations) == 0 {
		t.Fatal("location must be set")
	}
	loc := r.Locations[0].LogicalLocations[0]
	if loc.FullyQualifiedName != "example.test" {
		t.Errorf("logicalLocation.fullyQualifiedName: want example.test, got %q", loc.FullyQualifiedName)
	}
	if loc.Kind != "namespace" {
		t.Errorf("logicalLocation.kind: want namespace, got %q", loc.Kind)
	}

	// Properties: score and cdn_detected.
	if r.Properties.Score <= 0 {
		t.Errorf("properties.score must be > 0, got %f", r.Properties.Score)
	}
	if r.Properties.CDNDetected != "cloudflare" {
		t.Errorf("properties.cdn_detected: want cloudflare, got %q", r.Properties.CDNDetected)
	}
}

func TestRoot_SARIFOutput_Level(t *testing.T) {
	// fakeResult gives score 0.9 for first IP → "error"
	// and 0.8 for second → also "error" boundary; test with three IPs.
	// Override score via a custom runner.
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return &unearth.Result{
			Target:      target,
			CDNDetected: "cloudflare",
			Candidates: []unearth.ScoredIP{
				{IP: "1.1.1.1", Score: 0.9, Corroboration: 2, Techniques: []unearth.TechniqueHit{{Name: "crtsh", Weight: 0.55}}},
				{IP: "2.2.2.2", Score: 0.6, Corroboration: 1, Techniques: []unearth.TechniqueHit{{Name: "spf_mx", Weight: 0.50}}},
				{IP: "3.3.3.3", Score: 0.3, Corroboration: 1, Techniques: []unearth.TechniqueHit{{Name: "subdomain_enum", Weight: 0.35}}},
			},
		}, nil
	})
	code, stdout, _ := captured(t, "-o", "sarif", "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}

	var doc sarifDoc
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("sarif parse: %v", err)
	}
	results := doc.Runs[0].Results
	if len(results) != 3 {
		t.Fatalf("want 3 results, got %d", len(results))
	}

	cases := []struct{ ip, wantLevel string }{
		{"1.1.1.1", "error"},
		{"2.2.2.2", "warning"},
		{"3.3.3.3", "note"},
	}
	for i, tc := range cases {
		r := results[i]
		if r.Level != tc.wantLevel {
			t.Errorf("result[%d] (%s): level want %q, got %q", i, tc.ip, tc.wantLevel, r.Level)
		}
		if !strings.Contains(r.Message.Text, tc.ip) {
			t.Errorf("result[%d]: message should contain %s, got %q", i, tc.ip, r.Message.Text)
		}
	}
}

func TestRoot_SARIFOutput_ZeroCandidates(t *testing.T) {
	// When there are no candidates, SARIF should still be a valid document
	// with an empty results array (not null).
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return &unearth.Result{Target: target}, nil
	})
	code, stdout, _ := captured(t, "-o", "sarif", "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}

	var doc sarifDoc
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("sarif parse: %v", err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(doc.Runs))
	}
	results := doc.Runs[0].Results
	// results must be an array (possibly empty), not null — verified by
	// the successful JSON unmarshal into []struct above.
	if results == nil {
		t.Error("results must be a non-null empty array, not null")
	}
	if len(results) != 0 {
		t.Errorf("want 0 results, got %d", len(results))
	}
}

func TestRoot_SARIFOutput_TopCapped(t *testing.T) {
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return fakeResult(target, "1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"), nil
	})
	code, stdout, _ := captured(t, "-o", "sarif", "--top", "2", "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var doc sarifDoc
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("sarif parse: %v", err)
	}
	if len(doc.Runs[0].Results) != 2 {
		t.Errorf("--top 2 should cap to 2 SARIF results, got %d", len(doc.Runs[0].Results))
	}
}

func TestRoot_SARIFOutput_MultiTarget(t *testing.T) {
	// Two targets → results from both appear in the single run.
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(path, []byte("alpha.test\nbeta.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return fakeResult(target, "203.0.113."+target[:1]), nil
	})
	code, stdout, _ := captured(t, "-o", "sarif", "-l", path)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var doc sarifDoc
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("sarif parse: %v", err)
	}
	// Each target has 1 candidate → 2 results total.
	if len(doc.Runs[0].Results) != 2 {
		t.Errorf("want 2 results (1 per target), got %d", len(doc.Runs[0].Results))
	}
	// Both targets should appear in logical locations.
	targets := map[string]bool{}
	for _, r := range doc.Runs[0].Results {
		if len(r.Locations) > 0 && len(r.Locations[0].LogicalLocations) > 0 {
			targets[r.Locations[0].LogicalLocations[0].FullyQualifiedName] = true
		}
	}
	for _, want := range []string{"alpha.test", "beta.test"} {
		if !targets[want] {
			t.Errorf("expected target %q in SARIF results, got %v", want, targets)
		}
	}
}

// --- --min-confidence tests -----------------------------------------------

// fakeResultWithScores builds a Result whose candidate scores are explicit.
func fakeResultWithScores(target string, scores ...float64) *unearth.Result {
	r := &unearth.Result{
		Target:      target,
		CDNDetected: "cloudflare",
	}
	for i, sc := range scores {
		r.Candidates = append(r.Candidates, unearth.ScoredIP{
			IP:           fmt.Sprintf("10.0.0.%d", i+1),
			Score:        sc,
			Corroboration: 1,
			SingleSource:  true,
			Techniques:   []unearth.TechniqueHit{{Name: "crtsh", Weight: 0.55}},
		})
	}
	return r
}

func TestRoot_MinConfidence_InvalidBelowZero(t *testing.T) {
	code, _, stderr := captured(t, "--min-confidence", "-0.1", "example.test")
	if code != exitUsageError {
		t.Errorf("exit code: want %d, got %d", exitUsageError, code)
	}
	if !strings.Contains(stderr, "min-confidence") {
		t.Errorf("stderr should mention min-confidence: %q", stderr)
	}
}

func TestRoot_MinConfidence_InvalidAboveOne(t *testing.T) {
	code, _, stderr := captured(t, "--min-confidence", "1.1", "example.test")
	if code != exitUsageError {
		t.Errorf("exit code: want %d, got %d", exitUsageError, code)
	}
	if !strings.Contains(stderr, "min-confidence") {
		t.Errorf("stderr should mention min-confidence: %q", stderr)
	}
}

func TestRoot_MinConfidence_ZeroShowsAll(t *testing.T) {
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return fakeResultWithScores(target, 0.9, 0.5, 0.1), nil
	})
	code, stdout, _ := captured(t, "--min-confidence", "0", "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 3 {
		t.Errorf("--min-confidence 0 should show all 3 candidates, got %d lines: %q", len(lines), stdout)
	}
}

func TestRoot_MinConfidence_FiltersJSONL(t *testing.T) {
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		// Three candidates: 0.9, 0.5, 0.3. Threshold 0.5 keeps first two.
		return fakeResultWithScores(target, 0.9, 0.5, 0.3), nil
	})
	code, stdout, _ := captured(t, "--min-confidence", "0.5", "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 {
		t.Errorf("--min-confidence 0.5 should keep 2 candidates (>=0.5), got %d lines: %q", len(lines), stdout)
	}
	// Verify the surviving candidates carry scores >= 0.5.
	for _, line := range lines {
		var row struct {
			Score float64 `json:"score"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("json parse: %v", err)
		}
		if row.Score < 0.5 {
			t.Errorf("candidate with score %.2f should have been filtered out", row.Score)
		}
	}
}

func TestRoot_MinConfidence_ThresholdIsInclusive(t *testing.T) {
	// A candidate whose score exactly equals the threshold must be kept.
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return fakeResultWithScores(target, 0.75, 0.74), nil
	})
	code, stdout, _ := captured(t, "--min-confidence", "0.75", "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 1 {
		t.Errorf("only the candidate at exactly 0.75 should survive, got %d lines: %q", len(lines), stdout)
	}
}

func TestRoot_MinConfidence_FiltersJSON(t *testing.T) {
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return fakeResultWithScores(target, 0.9, 0.4), nil
	})
	code, stdout, _ := captured(t, "-o", "json", "--min-confidence", "0.5", "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var got []unearth.Result
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("json parse: %v\nout: %s", err, stdout)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 result, got %d", len(got))
	}
	if len(got[0].Candidates) != 1 {
		t.Errorf("--min-confidence 0.5 should leave 1 candidate in json output, got %d", len(got[0].Candidates))
	}
	if got[0].Candidates[0].Score < 0.5 {
		t.Errorf("surviving candidate score %.2f is below threshold", got[0].Candidates[0].Score)
	}
}

func TestRoot_MinConfidence_FiltersSARIF(t *testing.T) {
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return fakeResultWithScores(target, 0.9, 0.4, 0.2), nil
	})
	code, stdout, _ := captured(t, "-o", "sarif", "--min-confidence", "0.8", "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var doc sarifDoc
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("sarif parse: %v\nout: %s", err, stdout)
	}
	if len(doc.Runs[0].Results) != 1 {
		t.Errorf("--min-confidence 0.8 should leave 1 SARIF result, got %d", len(doc.Runs[0].Results))
	}
}

func TestRoot_MinConfidence_FiltersTable(t *testing.T) {
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return fakeResultWithScores(target, 0.9, 0.3), nil
	})
	code, stdout, _ := captured(t, "-o", "table", "--min-confidence", "0.5", "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	// 0.9 passes, 0.3 is filtered. Only one IP should appear.
	if strings.Contains(stdout, "10.0.0.2") {
		t.Errorf("10.0.0.2 (score 0.3) should have been filtered out:\n%s", stdout)
	}
	if !strings.Contains(stdout, "10.0.0.1") {
		t.Errorf("10.0.0.1 (score 0.9) should appear in table output:\n%s", stdout)
	}
}

func TestRoot_MinConfidence_AllFilteredIsEmptyOutput(t *testing.T) {
	// When every candidate is below the threshold, output should be empty (not an error).
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return fakeResultWithScores(target, 0.3, 0.2), nil
	})
	code, stdout, _ := captured(t, "--min-confidence", "0.9", "example.test")
	if code != 0 {
		t.Errorf("all-filtered should still exit 0, got %d", code)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("no candidates above threshold; stdout should be empty, got %q", stdout)
	}
}

// --- SARIF level tests -----------------------------------------------

// TestSarifLevel_Boundaries verifies the score→level mapping at boundary values.
func TestSarifLevel_Boundaries(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{1.00, "error"},
		{0.80, "error"},
		{0.799, "warning"},
		{0.50, "warning"},
		{0.499, "note"},
		{0.00, "note"},
	}
	for _, tc := range cases {
		got := sarifLevel(tc.score)
		if got != tc.want {
			t.Errorf("sarifLevel(%.3f): want %q, got %q", tc.score, tc.want, got)
		}
	}
}
