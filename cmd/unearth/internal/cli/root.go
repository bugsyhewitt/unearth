package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/unearth-tool/unearth/pkg/config"
	"github.com/unearth-tool/unearth/pkg/techniques"
	"github.com/unearth-tool/unearth/pkg/unearth"
)

// rootFlags captures every flag the root command accepts. Keeping them in
// one struct keeps the command definition uncluttered and gives tests one
// place to inspect resolved values.
type rootFlags struct {
	list          string
	active        bool
	aggressive    bool
	maxCensys     int
	maxShodan     int
	maxST         int
	noCache       bool
	refresh       bool
	output        string
	top           int
	concurrent    int
	timeout       time.Duration
	verbose       bool
	silent        bool
	weights       string
	emailFile     string
	pipelineBatch int
}

// runner is the indirection through which the root command invokes
// discovery, so tests can swap it for a deterministic fake.
type runner func(ctx context.Context, target string, opts unearth.Options) (*unearth.Result, error)

var discoverRunner runner = unearth.Discover

func newRootCmd(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	f := &rootFlags{}
	cmd := &cobra.Command{
		Use:   "unearth [flags] [target]",
		Short: "Discover the origin server behind a CDN",
		Long: "unearth discovers the real origin IP hidden behind a CDN by running\n" +
			"multiple recon techniques in parallel and ranking candidate IPs by\n" +
			"how many techniques independently agree.",
		Args:          cobra.ArbitraryArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRoot(cmd.Context(), f, args, stdin, stdout, stderr)
		},
	}

	// Input.
	cmd.Flags().StringVarP(&f.list, "list", "l", "", "File of targets (one per line, # comments OK)")

	// Tier.
	cmd.Flags().BoolVar(&f.active, "active", false, "Include active-tier techniques")
	cmd.Flags().BoolVar(&f.aggressive, "aggressive", false, "Include aggressive-tier techniques (implies --active)")

	// Budget.
	cmd.Flags().IntVar(&f.maxCensys, "max-censys", 10, "Censys query cap per target")
	cmd.Flags().IntVar(&f.maxShodan, "max-shodan", 10, "Shodan query cap per target")
	cmd.Flags().IntVar(&f.maxST, "max-st", 20, "SecurityTrails query cap per target")

	// Cache.
	cmd.Flags().BoolVar(&f.noCache, "no-cache", false, "Bypass the cache entirely")
	cmd.Flags().BoolVar(&f.refresh, "refresh", false, "Ignore cached entries but write fresh results")

	// Output.
	cmd.Flags().StringVarP(&f.output, "output", "o", "jsonl", "Output format: jsonl | json | table")
	cmd.Flags().IntVar(&f.top, "top", 50, "Max candidates shown per target")

	// Execution.
	cmd.Flags().IntVar(&f.concurrent, "concurrency", 10, "Parallel techniques per target")
	cmd.Flags().DurationVar(&f.timeout, "timeout", 5*time.Minute, "Overall timeout per target")

	// General.
	cmd.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "Verbose progress/logging to stderr")
	cmd.Flags().BoolVar(&f.silent, "silent", false, "Suppress all non-result output")
	cmd.Flags().StringVar(&f.weights, "weights", "", "Path to a custom weights YAML")
	cmd.Flags().StringVar(&f.emailFile, "email-file", "", "Path to a raw email (.eml) whose Received: headers are mined for origin IPs")
	cmd.Flags().IntVar(&f.pipelineBatch, "pipeline-batch", 1, "Number of targets to discover concurrently (1 = sequential; output stays in input order)")

	cmd.AddCommand(newVersionCmd(stdout))
	cmd.AddCommand(newCacheCmd(stdin, stdout, stderr))
	cmd.AddCommand(newCalibrateCmd(stdin, stdout, stderr))
	return cmd
}

func runRoot(ctx context.Context, f *rootFlags, posArgs []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if f.silent && f.verbose {
		return errUsage("--silent and --verbose are mutually exclusive")
	}
	switch f.output {
	case "jsonl", "json", "table":
	default:
		return errUsage("invalid --output: must be jsonl, json, or table")
	}
	if f.pipelineBatch < 1 {
		return errUsage("--pipeline-batch must be >= 1")
	}

	targets, sourceNotice, err := resolveTargets(f.list, posArgs, stdin)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errUsage("no targets supplied (pass a target, -l <file>, or pipe via stdin)")
	}
	if f.verbose && sourceNotice != "" {
		_, _ = fmt.Fprintln(stderr, sourceNotice)
	}

	opts := unearth.Options{
		Tier: tierFromFlags(f.active, f.aggressive),
		BudgetCaps: techniques.BudgetCaps{
			Censys:         f.maxCensys,
			Shodan:         f.maxShodan,
			SecurityTrails: f.maxST,
		},
		NoCache:             f.noCache,
		Refresh:             f.refresh,
		Concurrency:         f.concurrent,
		OverallTimeout:      f.timeout,
		PerTechniqueTimeout: 30 * time.Second,
		WeightsPath:         f.weights,
		EmailFile:           f.emailFile,
		APIKeys:             config.LoadAPIKeys(),
	}

	if f.verbose {
		announceCredentialStatus(stderr, opts.APIKeys)
		announceTierNotice(stderr, opts.Tier)
	}

	sink, err := newSink(f.output, isTTY(stdout), f.top)
	if err != nil {
		return err
	}

	results, failures, err := processTargets(ctx, targets, opts, f, sink, stdout, stderr)
	if err != nil {
		return err
	}
	if err := sink.flush(stdout, results); err != nil {
		return err
	}

	if failures > 0 && len(results) == 0 {
		return errors.New("every target failed to run")
	}
	return nil
}

// targetOutcome carries the result (or error) for one target alongside its
// position in the input list, so concurrent workers can report back and the
// writer can emit them in deterministic input order.
type targetOutcome struct {
	index int
	res   *unearth.Result
	err   error
}

// processTargets runs discovery over every target and streams each result
// through the sink. When f.pipelineBatch > 1, discovery runs concurrently
// across a bounded worker pool, but results are always written in input
// order so the streaming output contract (jsonl/table per target) is
// preserved deterministically regardless of which target finishes first.
func processTargets(
	ctx context.Context,
	targets []string,
	opts unearth.Options,
	f *rootFlags,
	sink sink,
	stdout, stderr io.Writer,
) (results []*unearth.Result, failures int, err error) {
	results = make([]*unearth.Result, 0, len(targets))

	emit := func(o targetOutcome) error {
		if o.err != nil {
			failures++
			if !f.silent {
				_, _ = fmt.Fprintf(stderr, "unearth: %s: %v\n", targets[o.index], o.err)
			}
			return nil
		}
		results = append(results, o.res)
		return sink.write(stdout, stderr, o.res, f)
	}

	if f.pipelineBatch <= 1 {
		for i, target := range targets {
			if ctx.Err() != nil {
				break
			}
			if f.verbose {
				_, _ = fmt.Fprintf(stderr, "unearth: discovering %s\n", target)
			}
			res, runErr := discoverRunner(ctx, target, opts)
			if werr := emit(targetOutcome{index: i, res: res, err: runErr}); werr != nil {
				return results, failures, werr
			}
		}
		return results, failures, nil
	}

	// Concurrent pipeline mode: a fixed pool of workers pulls target
	// indices off a channel and pushes outcomes into a slot array. A single
	// writer goroutine drains slots in input order so output stays
	// deterministic and sink.write is never called concurrently.
	outcomes := runPipeline(ctx, targets, opts, f, stderr)
	for _, o := range outcomes {
		if werr := emit(o); werr != nil {
			return results, failures, werr
		}
	}
	return results, failures, nil
}

// runPipeline discovers targets concurrently with a worker pool of size
// f.pipelineBatch and returns the outcomes ordered by input index. It does
// not touch the sink — ordering and writing are the caller's job — so all
// stdout writes remain single-threaded.
func runPipeline(
	ctx context.Context,
	targets []string,
	opts unearth.Options,
	f *rootFlags,
	stderr io.Writer,
) []targetOutcome {
	workers := f.pipelineBatch
	if workers > len(targets) {
		workers = len(targets)
	}

	outcomes := make([]targetOutcome, len(targets))
	jobs := make(chan int)
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() != nil {
					outcomes[i] = targetOutcome{index: i, err: ctx.Err()}
					continue
				}
				if f.verbose {
					_, _ = fmt.Fprintf(stderr, "unearth: discovering %s\n", targets[i])
				}
				res, runErr := discoverRunner(ctx, targets[i], opts)
				outcomes[i] = targetOutcome{index: i, res: res, err: runErr}
			}
		}()
	}

	for i := range targets {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	return outcomes
}

// resolveTargets implements the precedence in §C.3.
func resolveTargets(list string, posArgs []string, stdin io.Reader) ([]string, string, error) {
	var ignored []string
	switch {
	case list != "":
		if len(posArgs) > 0 {
			ignored = append(ignored, "positional target")
		}
		if !isTTY(stdin) {
			ignored = append(ignored, "stdin")
		}
		ts, err := readTargetsFile(list)
		if err != nil {
			return nil, "", err
		}
		return ts, ignoredNotice(ignored), nil
	case len(posArgs) > 0:
		if !isTTY(stdin) {
			ignored = append(ignored, "stdin")
		}
		if len(posArgs) > 1 {
			return nil, "", errUsage("only one target argument may be passed (use -l for a list file)")
		}
		return []string{posArgs[0]}, ignoredNotice(ignored), nil
	case !isTTY(stdin):
		ts, err := readTargets(stdin)
		if err != nil {
			return nil, "", err
		}
		return ts, "", nil
	default:
		return nil, "", nil
	}
}

func ignoredNotice(ignored []string) string {
	if len(ignored) == 0 {
		return ""
	}
	return "unearth: ignoring additional target source(s): " + strings.Join(ignored, ", ")
}

func readTargetsFile(path string) ([]string, error) {
	f, err := os.Open(path) // #nosec G304 — user-supplied path is the point
	if err != nil {
		return nil, errUsage(fmt.Sprintf("reading -l file: %v", err))
	}
	defer func() { _ = f.Close() }()
	return readTargets(f)
}

func readTargets(r io.Reader) ([]string, error) {
	var out []string
	scn := bufio.NewScanner(r)
	for scn.Scan() {
		line := strings.TrimSpace(scn.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := scn.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func tierFromFlags(active, aggressive bool) techniques.Tier {
	switch {
	case aggressive:
		return techniques.TierAggressive
	case active:
		return techniques.TierActive
	default:
		return techniques.TierPassive
	}
}

func announceCredentialStatus(stderr io.Writer, k techniques.APIKeys) {
	status := config.CredentialStatus(k)
	keys := []string{"censys", "shodan", "securitytrails", "viewdns", "fofa", "netlas"}
	for _, name := range keys {
		mark := "skipped (no key)"
		if status[name] {
			mark = "unlocked"
		}
		_, _ = fmt.Fprintf(stderr, "unearth: %-15s %s\n", name+":", mark)
	}
}

func announceTierNotice(stderr io.Writer, tier techniques.Tier) {
	if tier == techniques.TierPassive {
		return
	}
	want := tier
	for _, tt := range techniques.All() {
		if tt.Tier() == want {
			return
		}
	}
	_, _ = fmt.Fprintf(stderr,
		"unearth: note: %s tier selected but no techniques of that tier are registered yet\n",
		tier)
}
