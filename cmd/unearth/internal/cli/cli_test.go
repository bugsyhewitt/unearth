package cli

import (
	"bytes"
	"context"
	"encoding/json"
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
