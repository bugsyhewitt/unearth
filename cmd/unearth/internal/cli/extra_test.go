package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/unearth-tool/unearth/pkg/techniques"
	"github.com/unearth-tool/unearth/pkg/unearth"
)

func TestTableSink_Colorized(t *testing.T) {
	// Drive the table sink directly with color enabled and verify ANSI
	// sequences are present at each band.
	s := &tableSink{top: 0, color: true}
	res := &unearth.Result{
		Target: "x",
		Candidates: []unearth.ScoredIP{
			{IP: "1.1.1.1", Score: 0.95, Corroboration: 3, Techniques: []unearth.TechniqueHit{{Name: "a"}}},
			{IP: "2.2.2.2", Score: 0.60, Corroboration: 1, Techniques: []unearth.TechniqueHit{{Name: "b"}}},
			{IP: "3.3.3.3", Score: 0.20, Corroboration: 1, Techniques: []unearth.TechniqueHit{{Name: "c"}}},
		},
		Errors:   []unearth.TechniqueErr{{Technique: "x", Err: "boom"}},
		Warnings: []string{"warn-x"},
	}
	var out bytes.Buffer
	if err := s.write(&out, nil, res, &rootFlags{}); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{ansiGreen, ansiYellow, ansiRed, "warn-x", "boom"} {
		if !strings.Contains(got, want) {
			t.Errorf("table output missing %q\n---\n%s", want, got)
		}
	}
}

func TestVerbose_AnnouncesCredentialStatus(t *testing.T) {
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		return fakeResult(target), nil
	})
	code, _, stderr := captured(t, "--verbose", "--active", "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stderr, "censys") || !strings.Contains(stderr, "shodan") {
		t.Errorf("credential status not announced under --verbose:\n%s", stderr)
	}
}

func TestVerbose_EmitsResultMetaOnStderrForJSONL(t *testing.T) {
	withRunner(t, func(_ context.Context, target string, _ unearth.Options) (*unearth.Result, error) {
		r := fakeResult(target, "203.0.113.1")
		r.Warnings = []string{"w1"}
		r.Errors = []unearth.TechniqueErr{{Technique: "t", Err: "e", Reason: "missing_api_key"}}
		return r, nil
	})
	code, stdout, stderr := captured(t, "--verbose", "example.test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	// stdout should have the candidate jsonl, NOT the metadata.
	if !strings.Contains(stdout, "203.0.113.1") {
		t.Errorf("stdout missing candidate: %q", stdout)
	}
	if strings.Contains(stdout, "warn:") || strings.Contains(stdout, "CDN:") {
		t.Errorf("stdout should not carry result metadata: %q", stdout)
	}
	// stderr should mention CDN, warning, and error reason.
	for _, want := range []string{"CDN: cloudflare", "warn:", "missing_api_key"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
}

func TestUsageError_HasStableErrorString(t *testing.T) {
	e := errUsage("nope").(*usageError)
	if e.Error() != "nope" || e.code != exitUsageError {
		t.Errorf("usageError: %+v", e)
	}
}

func TestNewSink_InvalidFormatRejected(t *testing.T) {
	if _, err := newSink("xml", false, 0, 0); err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestCapN(t *testing.T) {
	if capN(0, 5) != 5 {
		t.Error("top<=0 means uncapped")
	}
	if capN(10, 3) != 3 {
		t.Error("top>=have means uncapped")
	}
	if capN(2, 5) != 2 {
		t.Error("top<have should clamp")
	}
}

func TestColorScore_BandsAndReset(t *testing.T) {
	s := &tableSink{color: true}
	if s.colorScore(0.9) != ansiGreen {
		t.Errorf("high band: %q", s.colorScore(0.9))
	}
	if s.colorScore(0.6) != ansiYellow {
		t.Errorf("mid band: %q", s.colorScore(0.6))
	}
	if s.colorScore(0.1) != ansiRed {
		t.Errorf("low band: %q", s.colorScore(0.1))
	}
}

func TestFilterByConfidence(t *testing.T) {
	candidates := []unearth.ScoredIP{
		{IP: "1.1.1.1", Score: 0.9},
		{IP: "2.2.2.2", Score: 0.5},
		{IP: "3.3.3.3", Score: 0.2},
	}
	cases := []struct {
		threshold float64
		wantLen   int
		desc      string
	}{
		{0, 3, "zero means no filter"},
		{0.5, 2, ">=0.5 keeps first two"},
		{0.9, 1, ">=0.9 keeps only first"},
		{1.0, 0, ">=1.0 keeps nothing"},
		{0.2, 3, ">=0.2 keeps all three (inclusive)"},
	}
	for _, tc := range cases {
		got := filterByConfidence(candidates, tc.threshold)
		if len(got) != tc.wantLen {
			t.Errorf("threshold=%.1f (%s): want %d, got %d", tc.threshold, tc.desc, tc.wantLen, len(got))
		}
		// Verify original slice is not modified.
		if len(candidates) != 3 {
			t.Errorf("filterByConfidence must not modify input slice")
		}
	}
}

func TestEmitResultMeta_HandlesEmptyResult(t *testing.T) {
	var w bytes.Buffer
	emitResultMeta(&w, &unearth.Result{Target: "x"})
	if w.Len() != 0 {
		t.Errorf("empty result should produce no output, got %q", w.String())
	}
}

func TestTierNotice_QuietWhenPassive(t *testing.T) {
	var w bytes.Buffer
	announceTierNotice(&w, techniques.TierPassive)
	if w.Len() != 0 {
		t.Errorf("passive tier should not announce: %q", w.String())
	}
}
