# unearth — Phase 2 improvement: --min-confidence confidence-threshold filter

## What was done

Added `--min-confidence <float>` to the `unearth` CLI. The flag hides candidates
whose noisy-OR score falls below the supplied threshold, across all four output
formats (jsonl, json, table, sarif). With `--min-confidence 0` (the default),
all candidates are shown and behaviour is unchanged.

## The problem

`unearth` can surface dozens of candidates per target when many passive techniques
agree on several IPs. Operators reviewing output in a pipeline (e.g. piping JSONL
into `httpx` or uploading SARIF to GitHub Code Scanning) often only care about
high-confidence hits and want to filter the noise at the source rather than
post-processing with `jq '.score >= 0.8'`.

## Implementation

### New flag

`--min-confidence float` — range `[0.0, 1.0]`, default `0` (show all).
Validated at parse time; values outside the range return a usage error.

### Changed files

**`cmd/unearth/internal/cli/root.go`**
- Added `minConfidence float64` to `rootFlags` struct.
- Registered `--min-confidence` flag with cobra.
- Validation: `if f.minConfidence < 0 || f.minConfidence > 1 { return errUsage(...) }`.
- Passes `f.minConfidence` to `newSink`.

**`cmd/unearth/internal/cli/output.go`**
- Added `minConfidence float64` field to `jsonlSink`, `jsonSink`, `tableSink`,
  `sarifSink`.
- Updated `newSink` signature to accept `minConfidence float64` and thread it
  into each sink struct.
- Added `filterByConfidence(candidates []unearth.ScoredIP, minConfidence float64)
  []unearth.ScoredIP` helper. The filter is a no-op when `minConfidence <= 0`.
  The input slice is never modified (a new slice is allocated).
- Applied the filter before the existing `capN(top, ...)` cap in every
  sink's `write` / `buildResults`:
  - `jsonlSink.write`: `candidates := filterByConfidence(res.Candidates, s.minConfidence)`
  - `jsonSink.flush`: filter each result's candidates before truncating
  - `tableSink.write`: filter before the tabwriter loop
  - `sarifSink.buildResults`: filter before the top cap

**`cmd/unearth/internal/cli/extra_test.go`**
- Updated existing `TestNewSink_InvalidFormatRejected` call to use the new
  4-argument `newSink` signature.
- Added `TestFilterByConfidence` — unit test for the helper directly,
  covering: zero threshold (no-op), `>= threshold` semantics (inclusive),
  and that the input slice is not mutated.

**`cmd/unearth/internal/cli/cli_test.go`**
- Added `fakeResultWithScores` helper that builds a result with explicit scores.
- Added 8 new tests:
  - `TestRoot_MinConfidence_InvalidBelowZero`
  - `TestRoot_MinConfidence_InvalidAboveOne`
  - `TestRoot_MinConfidence_ZeroShowsAll`
  - `TestRoot_MinConfidence_FiltersJSONL`
  - `TestRoot_MinConfidence_ThresholdIsInclusive`
  - `TestRoot_MinConfidence_FiltersJSON`
  - `TestRoot_MinConfidence_FiltersSARIF`
  - `TestRoot_MinConfidence_FiltersTable`
  - `TestRoot_MinConfidence_AllFilteredIsEmptyOutput`

**`README.md`**
- Updated CLI reference to add `--min-confidence` with description.
- Corrected `--top` default (50, not 0) and `--concurrency` name.
- Added a quick-start example: `unearth --min-confidence 0.8 example.com`.

## Test results

All 10 packages pass under `go test ./... -count=1 -race`. See `test-output.txt`.
