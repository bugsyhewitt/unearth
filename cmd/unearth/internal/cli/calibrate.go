package cli

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/config"
	"github.com/unearth-tool/unearth/pkg/rank"
	"github.com/unearth-tool/unearth/pkg/techniques"
)

// newCalibrateCmd builds the `unearth calibrate` subcommand and its `reset`
// child. Calibration surfaces per-technique precision estimates accumulated in
// the local cache across discovery runs and suggests weight overrides.
func newCalibrateCmd(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	var (
		weightsPath string
		emitYAML    bool
	)
	cmd := &cobra.Command{
		Use:   "calibrate",
		Short: "Suggest technique-weight overrides from accumulated run history",
		Long: "calibrate reads the per-technique corroboration history recorded in the\n" +
			"local cache after each discovery run and estimates how precise each\n" +
			"technique has been. It prints a report and, with --yaml, a weights.yaml\n" +
			"block you can drop into ~/.config/unearth/weights.yaml or pass via --weights.\n\n" +
			"The precision proxy is corroboration: how often a technique's candidate\n" +
			"was independently confirmed by another technique in the same run. There\n" +
			"is no external ground truth, so treat low-sample suggestions cautiously.",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runCalibrate(weightsPath, emitYAML, stdout, stderr)
		},
	}
	cmd.Flags().StringVar(&weightsPath, "weights", "", "Path to a custom weights YAML to use as the calibration baseline")
	cmd.Flags().BoolVar(&emitYAML, "yaml", false, "Emit a weights.yaml block of suggested overrides instead of the table")
	cmd.AddCommand(newCalibrateResetCmd(stdin, stdout, stderr))
	return cmd
}

func runCalibrate(weightsPath string, emitYAML bool, stdout, stderr io.Writer) error {
	c, err := cache.Open("")
	if err != nil {
		return fmt.Errorf("opening cache: %w", err)
	}
	defer func() { _ = c.Close() }()

	count, err := c.ObservationCount()
	if err != nil {
		return err
	}
	if count == 0 {
		_, _ = fmt.Fprintln(stderr,
			"unearth: no calibration data yet — run some discoveries first (each run records observations).")
		return nil
	}

	stats, err := c.CalibrationStats()
	if err != nil {
		return err
	}

	// Resolve the baseline weight for each technique: a configured override if
	// present, else the technique's DefaultWeight(). Config warnings are
	// surfaced to stderr but do not abort calibration.
	weights, warns, werr := config.LoadWeights(weightsPath)
	if werr != nil {
		_, _ = fmt.Fprintf(stderr, "unearth: %v\n", werr)
	}
	for _, w := range warns {
		_, _ = fmt.Fprintf(stderr, "unearth: %s\n", w)
	}

	samples := make([]rank.Sample, 0, len(stats))
	for _, s := range stats {
		samples = append(samples, rank.Sample{
			Technique:    s.Technique,
			Total:        s.Total,
			Corroborated: s.Corroborated,
			Default:      baselineWeight(weights, s.Technique),
		})
	}
	suggestions := rank.Calibrate(samples)

	if emitYAML {
		writeYAMLSuggestions(stdout, suggestions)
		return nil
	}
	writeCalibrationTable(stdout, suggestions)
	return nil
}

// baselineWeight resolves the weight currently in effect for a technique: a
// configured override wins, otherwise the registered technique's default. An
// unregistered technique name (e.g. recorded by an older binary) falls back to
// 0.5, a neutral prior.
func baselineWeight(w config.Weights, name string) float64 {
	if v, ok := w.Weight(name); ok {
		return v
	}
	if t, ok := techniques.Get(name); ok {
		return t.DefaultWeight()
	}
	return 0.5
}

func writeCalibrationTable(out io.Writer, suggestions []rank.Suggestion) {
	if len(suggestions) == 0 {
		_, _ = fmt.Fprintln(out, "no per-technique observations to calibrate")
		return
	}
	_, _ = fmt.Fprintf(out, "%-18s %8s %8s %10s %8s %s\n",
		"technique", "current", "suggest", "precision", "samples", "note")
	for _, s := range suggestions {
		note := ""
		if s.LowConfidence {
			note = "low-confidence"
		}
		_, _ = fmt.Fprintf(out, "%-18s %8.2f %8.2f %10.2f %8d %s\n",
			s.Technique, s.Current, s.Suggested, s.Precision, s.Samples, note)
	}
}

// writeYAMLSuggestions emits a weights.yaml-compatible block of the suggested
// overrides. Low-confidence techniques are emitted as commented-out lines so
// operators opt in deliberately rather than adopting noise.
func writeYAMLSuggestions(out io.Writer, suggestions []rank.Suggestion) {
	sorted := append([]rank.Suggestion(nil), suggestions...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Technique < sorted[j].Technique })

	_, _ = fmt.Fprintln(out, "# unearth calibrate — suggested technique weights")
	_, _ = fmt.Fprintln(out, "# Generated from corroboration history; review before adopting.")
	_, _ = fmt.Fprintln(out, "# Commented-out lines are low-confidence (insufficient samples).")
	_, _ = fmt.Fprintln(out, "weights:")
	for _, s := range sorted {
		line := fmt.Sprintf("  %s: %.2f", s.Technique, s.Suggested)
		if s.LowConfidence {
			line = "  # " + strings.TrimSpace(line) + fmt.Sprintf("  # %d samples", s.Samples)
		}
		_, _ = fmt.Fprintln(out, line)
	}
}

func newCalibrateResetCmd(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Delete all recorded calibration observations",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := cache.Open("")
			if err != nil {
				return fmt.Errorf("opening cache: %w", err)
			}
			defer func() { _ = c.Close() }()
			if !yes {
				_, _ = fmt.Fprint(stderr, "About to delete all calibration observations. Type 'yes' to confirm: ")
				answer, _ := bufio.NewReader(stdin).ReadString('\n')
				if strings.TrimSpace(strings.ToLower(answer)) != "yes" {
					return errUsage("calibrate reset cancelled")
				}
			}
			n, err := c.ResetObservations()
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(stdout, "reset %d calibration observations\n", n)
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip the confirmation prompt")
	return cmd
}
