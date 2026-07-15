package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/unearth-tool/unearth/internal/httpclient"
	"github.com/unearth-tool/unearth/pkg/unearth"
)

// sink is the output strategy. Four implementations: jsonl (stream per
// candidate), json (one big array at the end), table (human-readable per
// target), sarif (SARIF 2.1.0 for GitHub Code Scanning). All four honor
// the --top cap.
type sink interface {
	// write emits whatever the format prints per result. For streaming
	// formats (jsonl, table) that's per-target; for accumulating formats
	// (json, sarif) it just buffers.
	write(stdout, stderr io.Writer, res *unearth.Result, f *rootFlags) error
	// flush is called once after every target has been processed; the
	// json and sarif sinks use it to emit the full document, the others no-op.
	flush(stdout io.Writer, all []*unearth.Result) error
}

func newSink(format string, useColor bool, top int, minConfidence float64) (sink, error) {
	switch format {
	case "jsonl":
		return &jsonlSink{top: top, minConfidence: minConfidence}, nil
	case "json":
		return &jsonSink{top: top, minConfidence: minConfidence}, nil
	case "table":
		return &tableSink{top: top, color: useColor, minConfidence: minConfidence}, nil
	case "sarif":
		return &sarifSink{top: top, minConfidence: minConfidence}, nil
	default:
		return nil, errUsage("invalid --output: " + format)
	}
}

// filterByConfidence returns the candidates whose Score >= minConfidence.
// When minConfidence is 0, all candidates are returned unchanged (no-op).
// The input slice is not modified.
func filterByConfidence(candidates []unearth.ScoredIP, minConfidence float64) []unearth.ScoredIP {
	if minConfidence <= 0 {
		return candidates
	}
	out := make([]unearth.ScoredIP, 0, len(candidates))
	for _, c := range candidates {
		if c.Score >= minConfidence {
			out = append(out, c)
		}
	}
	return out
}

// --- jsonl -----------------------------------------------------------

type jsonlSink struct {
	top           int
	minConfidence float64
}

// jsonlRow is one line of JSONL: an augmented ScoredIP carrying the
// target it belongs to.
type jsonlRow struct {
	Target string `json:"target"`
	unearth.ScoredIP
}

func (s *jsonlSink) write(stdout, stderr io.Writer, res *unearth.Result, f *rootFlags) error {
	enc := json.NewEncoder(stdout)
	candidates := filterByConfidence(res.Candidates, s.minConfidence)
	limit := capN(s.top, len(candidates))
	for _, c := range candidates[:limit] {
		if err := enc.Encode(jsonlRow{Target: res.Target, ScoredIP: c}); err != nil {
			return err
		}
	}
	// Per §C.6, Result-level info (CDN, errors, warnings) goes to stderr
	// under --verbose, never into the stdout JSONL stream.
	if f.verbose {
		emitResultMeta(stderr, res)
	}
	return nil
}

func (*jsonlSink) flush(io.Writer, []*unearth.Result) error { return nil }

// --- json ------------------------------------------------------------

type jsonSink struct {
	top           int
	minConfidence float64
}

func (*jsonSink) write(io.Writer, io.Writer, *unearth.Result, *rootFlags) error { return nil }

func (s *jsonSink) flush(stdout io.Writer, all []*unearth.Result) error {
	capped := make([]*unearth.Result, len(all))
	for i, r := range all {
		// Make a shallow copy so we can filter and truncate Candidates
		// without mutating the caller's slice.
		cp := *r
		filtered := filterByConfidence(cp.Candidates, s.minConfidence)
		n := capN(s.top, len(filtered))
		cp.Candidates = filtered[:n]
		capped[i] = &cp
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(capped)
}

// --- table -----------------------------------------------------------

type tableSink struct {
	top           int
	color         bool
	minConfidence float64
}

const (
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
	ansiReset  = "\x1b[0m"
)

func (s *tableSink) write(stdout, _ io.Writer, res *unearth.Result, _ *rootFlags) error {
	header := fmt.Sprintf("Target: %s", res.Target)
	if res.CDNDetected != "" {
		header += fmt.Sprintf("  (CDN: %s)", res.CDNDetected)
	}
	if _, err := fmt.Fprintln(stdout, header); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "  IP\tSCORE\tCORROB\tTECHNIQUES"); err != nil {
		return err
	}
	candidates := filterByConfidence(res.Candidates, s.minConfidence)
	limit := capN(s.top, len(candidates))
	for _, c := range candidates[:limit] {
		score := fmt.Sprintf("%.3f", c.Score)
		if s.color {
			score = s.colorScore(c.Score) + score + ansiReset
		}
		if _, err := fmt.Fprintf(tw, "  %s\t%s\t%d\t%s\n",
			c.IP, score, c.Corroboration, strings.Join(techHitNames(c.Techniques), ",")); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(res.Errors) > 0 || len(res.Warnings) > 0 {
		if _, err := fmt.Fprintln(stdout, ""); err != nil {
			return err
		}
		for _, e := range res.Errors {
			if _, err := fmt.Fprintf(stdout, "  ! %s: %s\n", e.Technique, e.Err); err != nil {
				return err
			}
		}
		for _, w := range res.Warnings {
			if _, err := fmt.Fprintf(stdout, "  ~ %s\n", w); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintln(stdout, "")
	return err
}

func (*tableSink) flush(io.Writer, []*unearth.Result) error { return nil }

func (s *tableSink) colorScore(score float64) string {
	switch {
	case score >= 0.8:
		return ansiGreen
	case score >= 0.5:
		return ansiYellow
	default:
		return ansiRed
	}
}

// --- sarif -----------------------------------------------------------

// sarifSink emits a SARIF 2.1.0 document on flush. SARIF is used by GitHub
// Code Scanning, Semgrep, CodeQL, and other security-toolchain consumers.
// Results are accumulated per write() call and emitted as a single document.
//
// Spec reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
type sarifSink struct {
	top           int
	minConfidence float64
}

func (*sarifSink) write(io.Writer, io.Writer, *unearth.Result, *rootFlags) error { return nil }

func (s *sarifSink) flush(stdout io.Writer, all []*unearth.Result) error {
	doc := s.buildDocument(all)
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// sarifDocument is the top-level SARIF 2.1.0 document.
type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	FullDescription  sarifMessage    `json:"fullDescription"`
	HelpURI          string          `json:"helpUri"`
	Properties       sarifRuleProps  `json:"properties"`
}

type sarifRuleProps struct {
	Tags []string `json:"tags"`
}

type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   sarifMessage     `json:"message"`
	Locations []sarifLocation  `json:"locations"`
	// Properties carries unearth-specific data for consumers that can read
	// SARIF property bags (e.g. GitHub Advanced Security UI extensions).
	Properties sarifResultProps `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifLogicalLocation struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

type sarifResultProps struct {
	Score        float64            `json:"score"`
	Corroboration int               `json:"corroboration"`
	SingleSource  bool              `json:"single_source"`
	CDNDetected   string            `json:"cdn_detected,omitempty"`
	Techniques    []unearth.TechniqueHit `json:"techniques"`
}

// sarifLevel maps a confidence score to a SARIF level.
//   ≥ 0.80 → "error"   (high confidence — very likely a real origin)
//   ≥ 0.50 → "warning" (medium confidence — worth investigating)
//   < 0.50 → "note"    (low confidence — possible but uncertain)
func sarifLevel(score float64) string {
	switch {
	case score >= 0.80:
		return "error"
	case score >= 0.50:
		return "warning"
	default:
		return "note"
	}
}

func (s *sarifSink) buildDocument(all []*unearth.Result) sarifDocument {
	results := s.buildResults(all)
	return sarifDocument{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "unearth",
						Version:        httpclient.Version,
						InformationURI: "https://github.com/unearth-tool/unearth",
						Rules: []sarifRule{
							{
								ID:               "UNEARTH001",
								Name:             "OriginIPCandidate",
								ShortDescription: sarifMessage{Text: "Candidate origin IP behind CDN"},
								FullDescription: sarifMessage{
									Text: "unearth identified an IP address as a potential origin server hidden behind " +
										"a CDN or WAF. The confidence score reflects how many independent techniques " +
										"corroborated the finding. Verify with a direct HTTP request using the Host " +
										"header set to the target domain before treating this as confirmed.",
								},
								HelpURI:    "https://github.com/unearth-tool/unearth/blob/main/docs/techniques.md",
								Properties: sarifRuleProps{Tags: []string{"security", "cdn-bypass", "origin-ip"}},
							},
						},
					},
				},
				Results: results,
			},
		},
	}
}

func (s *sarifSink) buildResults(all []*unearth.Result) []sarifResult {
	var out []sarifResult
	for _, r := range all {
		candidates := filterByConfidence(r.Candidates, s.minConfidence)
		limit := capN(s.top, len(candidates))
		for _, c := range candidates[:limit] {
			msgText := fmt.Sprintf(
				"Origin IP candidate for %s: %s (score=%.2f, corroboration=%d, techniques=%s)",
				r.Target, c.IP, c.Score, c.Corroboration, strings.Join(techHitNames(c.Techniques), ","),
			)
			if r.CDNDetected != "" {
				msgText += fmt.Sprintf(", cdn=%s", r.CDNDetected)
			}
			out = append(out, sarifResult{
				RuleID:  "UNEARTH001",
				Level:   sarifLevel(c.Score),
				Message: sarifMessage{Text: msgText},
				Locations: []sarifLocation{
					{
						LogicalLocations: []sarifLogicalLocation{
							{
								FullyQualifiedName: r.Target,
								Kind:               "namespace",
							},
						},
					},
				},
				Properties: sarifResultProps{
					Score:         c.Score,
					Corroboration: c.Corroboration,
					SingleSource:  c.SingleSource,
					CDNDetected:   r.CDNDetected,
					Techniques:    c.Techniques,
				},
			})
		}
	}
	// An empty results array is valid SARIF (means no findings).
	if out == nil {
		out = []sarifResult{}
	}
	return out
}

// --- helpers ---------------------------------------------------------

// techHitNames extracts the Name field from each TechniqueHit in order.
func techHitNames(hits []unearth.TechniqueHit) []string {
	names := make([]string, len(hits))
	for i, h := range hits {
		names[i] = h.Name
	}
	return names
}

func capN(top, have int) int {
	if top <= 0 || top >= have {
		return have
	}
	return top
}

func emitResultMeta(w io.Writer, res *unearth.Result) {
	if res.CDNDetected != "" {
		_, _ = fmt.Fprintf(w, "unearth: %s — CDN: %s\n", res.Target, res.CDNDetected)
	}
	for _, e := range res.Errors {
		_, _ = fmt.Fprintf(w, "unearth: %s — err[%s] reason=%q: %s\n",
			res.Target, e.Technique, e.Reason, e.Err)
	}
	for _, ww := range res.Warnings {
		_, _ = fmt.Fprintf(w, "unearth: %s — warn: %s\n", res.Target, ww)
	}
}
