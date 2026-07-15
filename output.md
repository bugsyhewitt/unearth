# unearth — Phase 2 improvement: complete post-v1.0 technique configuration

## What was done

Seven techniques shipped after v1.0 were never added to the weight configuration system, and one of them had a concrete bug that prevented it from ever running.

### Bug fixed: `favicon_hash` silently dropped with valid keys

`favicon_hash` declares `RequiresAPIKey() == true` and accepts either `SHODAN_API_KEY` or `CENSYS_PLATFORM_PAT`. However, it was missing from the `hasKeyFor()` switch statement in `pkg/unearth/unearth.go`. The `default` case returns `false`, so the engine's pre-filter (`if t.RequiresAPIKey() && !hasKeyFor(...)`) was unconditionally skipping `favicon_hash` — even when the operator had `SHODAN_API_KEY` or `CENSYS_PLATFORM_PAT` set.

**Fix:** added `case "favicon_hash": return k.ShodanAPIKey != "" || k.CensysPlatformPAT != ""` to `hasKeyFor`.

### Config system gap patched for 7 post-v1.0 techniques

The `knownTechniques` map in `pkg/config/config.go` and both `default-weights.yaml` files (the embedded `pkg/config/default-weights.yaml` and the canonical `configs/default-weights.yaml`) were missing entries for:

| Technique | Tier | Key required | Weight |
|---|---|---|---|
| `split_dns` | Passive | No | 0.80 |
| `email_header` | Passive | No | 0.85 |
| `jarm_fingerprint` | Active | No | 0.80 |
| `asn_sweep` | Active | No | 0.70 |
| `shodan_cve` | Passive | Yes (Shodan) | 0.78 |
| `favicon_hash` | Active | Yes (Shodan or Censys) | 0.75 |
| `dns_txt_leak` | Passive | No | 0.55 |

Without these entries, any user who tried to override one of these weights in a `weights.yaml` file received an "unknown technique" warning and the override was silently dropped. The `unearth calibrate --yaml` command also could not surface suggestions for them.

All seven are now in `knownTechniques` and both YAML files.

### `dns_txt_leak` documented in README

The `dns_txt_leak` technique (`pkg/techniques/txtleak.go`) was fully implemented and running but not documented anywhere in the README. It is now listed in the techniques table with its tier, weight, and description.

### Vercel and Netlify CDN providers documented in README

`buildVercel()` and `buildNetlify()` were fully implemented in `pkg/cdn/cdn.go` with embedded range data and header/DNS detection signals, but were absent from the README's CDN coverage section. Both are now documented.

### Regression guards added (3 new tests)

- `TestKnownTechniquesMatchesRegistry` (pkg/config) — iterates `techniques.All()` and fails if any registered technique is absent from `knownTechniques`; prevents a recurrence of the 7-technique gap.
- `TestHasKeyFor_FaviconHash` (pkg/unearth) — verifies each of the two sufficient keys for `favicon_hash` individually and that neither key present returns false.
- `TestHasKeyFor_AllKeyRequiringTechniquesCovered` (pkg/unearth) — iterates `techniques.All()`, finds every technique with `RequiresAPIKey()==true`, and confirms `hasKeyFor` returns true with a fully-populated `APIKeys`; prevents the `favicon_hash` class of bug from recurring.

## Files changed

- `pkg/unearth/unearth.go` — add `favicon_hash` case to `hasKeyFor`
- `pkg/config/config.go` — add 7 techniques to `knownTechniques`
- `pkg/config/default-weights.yaml` — add 7 technique weights
- `configs/default-weights.yaml` — add same 7 technique weights (byte-identical copy)
- `pkg/config/config_test.go` — add `TestKnownTechniquesMatchesRegistry`
- `pkg/unearth/unearth_test.go` — add `TestHasKeyFor_FaviconHash` and `TestHasKeyFor_AllKeyRequiringTechniquesCovered`
- `README.md` — add `dns_txt_leak` to techniques table; add Vercel and Netlify to CDN coverage section
- `CHANGELOG.md` — document all changes

## Test results

All 10 test packages pass under `go test ./... -count=1 -race`. See `test-output.txt`.
