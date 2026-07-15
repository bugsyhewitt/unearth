# unearth — Phase 2 improvement: --exclude-technique flag

## What was done

Added `--exclude-technique <name>[,<name>...]` to the `unearth` CLI and the
`unearth.Options` library API. The flag lets operators skip one or more
techniques by name for a single run, without changing any global configuration.

## The problem

`unearth` runs all tier-appropriate techniques for every target. Operators
sometimes need to suppress specific techniques:

- A backend is rate-limiting today (`crtsh`, `shodan_cert`)
- A technique is irrelevant for the target (e.g. no MX record, `spf_mx` will
  always miss)
- Troubleshooting: narrow down which technique is producing noisy results
- Reproducing a result without a specific technique to isolate signal

Previously the only options were tier flags (`--active`, `--passive`) or
weights YAML to zero out a technique's weight — neither is ergonomic for
ad-hoc exclusions and the weights file persists across runs.

## Implementation

### New library field

`unearth.Options.ExcludeTechniques []string` — names to skip. Empty means no
exclusions (the default; existing callers are unaffected). Unknown names produce
a `Warnings` entry rather than an error, so a mistyped name is visible but never
breaks a run.

### New CLI flag

`--exclude-technique string` — registered as a `StringSlice` flag, which
accepts both comma-separated values and repeated flags:

```sh
# Comma-separated
unearth --exclude-technique crtsh,shodan_cert example.com

# Repeated flag (same result)
unearth --exclude-technique crtsh --exclude-technique spf_mx example.com
```

### Changed files

**`pkg/unearth/unearth.go`**
- Added `ExcludeTechniques []string` field to `Options` with doc comment.
- In `Discover`: built a `map[string]bool` exclusion set from
  `opts.ExcludeTechniques`, warned on unknown names via `techniques.Get`, then
  checked `excludeSet[t.Name()]` before the existing API-key pre-filter in the
  technique selection loop.

**`cmd/unearth/internal/cli/root.go`**
- Added `excludeTechniques []string` to `rootFlags`.
- Registered `--exclude-technique` with `cmd.Flags().StringSliceVar`.
- Wired `f.excludeTechniques` into `opts.ExcludeTechniques` in `runRoot`.

**`pkg/unearth/unearth_test.go`**
- Added `"strings"` import.
- Added 4 engine-level tests:
  - `TestDiscover_ExcludeTechnique_SkipsNamedTechnique` — excluded technique
    never runs, no candidates, not in Errors
  - `TestDiscover_ExcludeTechnique_MultipleExclusions` — all names in the slice
    are excluded; non-excluded technique still runs
  - `TestDiscover_ExcludeTechnique_UnknownNameWarns` — unknown name becomes a
    Warning, discovery proceeds normally
  - `TestDiscover_ExcludeTechnique_EmptySliceIsNoop` — empty
    ExcludeTechniques is identical to not setting the field

**`cmd/unearth/internal/cli/cli_test.go`**
- Added 3 CLI-level tests:
  - `TestRoot_ExcludeTechnique_ThreadedIntoOpts` — comma-separated form is
    parsed and delivered to opts.ExcludeTechniques
  - `TestRoot_ExcludeTechnique_RepeatedFlag` — repeated flag collects all values
  - `TestRoot_ExcludeTechnique_NotSetMeansEmptySlice` — absent flag leaves
    ExcludeTechniques empty

**`README.md`**
- Added `--exclude-technique` to the CLI reference flag table.
- Added "Excluding techniques" section with usage examples.

## Test results

All 10 packages pass under `go test ./... -count=1 -race`. See `test-output.txt`.
