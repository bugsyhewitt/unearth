# unearth v1.1.0 release — Worker output

## Summary

Shipped a **v1.1.0** release for `unearth`, capturing 45 post-v1.0.0 commits that
had accumulated on `main` since the initial `v1.0.0` tag (2026-05-17, commit `bef8eaf`).

## Key finding: v1.0.0 already existed

The Team Lead task was written assuming v1.0.0 had not been cut. In fact:
- Tag `v1.0.0` already exists at `bef8eaf` (the initial release, 2026-05-17)
- 45 subsequent commits added 20 new techniques, 10 CDN providers, SARIF output, new
  CLI flags, MCP utility tools, and several bug fixes
- The in-code version sentinel (`internal/httpclient/httpclient.go`) was never bumped
  from `"0.1.0-dev"` after the initial release — that's why the roster showed "v0.1"

## Changes made

### `internal/httpclient/httpclient.go`
- Bumped `var Version` from `"0.1.0-dev"` to `"1.1.0"`

### `CHANGELOG.md`
- Promoted `## [Unreleased]` to `## [1.1.0] — 2026-07-15`
- Added `[1.1.0]: https://github.com/bugsyhewitt/unearth/compare/v1.0.0...v1.1.0`
  to the footer link list

## Tests

All 10 test packages pass with `-race`:

```
ok  github.com/unearth-tool/unearth/cmd/unearth/internal/cli   1.244s
ok  github.com/unearth-tool/unearth/cmd/unearth-mcp            1.053s
ok  github.com/unearth-tool/unearth/internal/httpclient        1.020s
ok  github.com/unearth-tool/unearth/internal/ratelimit         1.029s
ok  github.com/unearth-tool/unearth/pkg/cache                  10.862s
ok  github.com/unearth-tool/unearth/pkg/cdn                    1.454s
ok  github.com/unearth-tool/unearth/pkg/config                 1.074s
ok  github.com/unearth-tool/unearth/pkg/rank                   1.015s
ok  github.com/unearth-tool/unearth/pkg/techniques             4.595s
ok  github.com/unearth-tool/unearth/pkg/unearth                1.556s
```

## Artifacts

- Branch: `worker-unearth-lap-20260715T120000Z`
- PR: https://github.com/bugsyhewitt/unearth/pull/44 (title: "v1.1.0 release")
- Tag: `v1.1.0` pushed to origin
- Test results: `test-output.txt`

## What's in v1.1.0

**20 new discovery techniques** (total: 32 across all tiers)
- Passive no-key: `split_dns`, `email_header`, `dns_txt_leak`, `otx_passivedns`
- Passive keyed: `greynoise_asset`, `urlscan_asset`, `virustotal_passivedns`,
  `chaos_asset`, `zoomeye_asset`, `fullhunt_asset`, `onyphe_cert`, `leakix_cert`,
  `binaryedge_cert`, `criminalip_asset`, `netlas_cert`, `fofa_cert`, `shodan_cve`,
  `censys_ipv6`
- Active: `jarm_fingerprint`, `asn_sweep`

**10 new CDN providers** (total: 18)
- StackPath/Highwinds, BunnyCDN, CDN77, Edgio, KeyCDN, Gcore, Google Cloud CDN,
  Azure Front Door, Imperva (Incapsula), CacheFly, Vercel Edge Network, Netlify CDN

**CLI additions**
- `--min-confidence` threshold filter
- `--exclude-technique` per-run technique skip
- `--pipeline-batch` for concurrent bulk-target runs
- `-o sarif` SARIF 2.1.0 output format
- `unearth calibrate` weight auto-calibration subcommand

**MCP server additions**
- `unearth_check_cdn`, `unearth_is_cdn_ip`, `unearth_list_techniques` (8 tools total)

**Bug fixes**
- Credential env var names now match documented names (unprefixed names work)
- `favicon_hash` pre-filter corrected (was silently skipped even with keys set)
- Config system registration back-filled for 7 post-v1.0 techniques
- MurmurHash3 replaced with pointer-safe pure-Go implementation (race detector fix)
- Imperva prefix overlap with StackPath removed; `TestNoDuplicatePrefixAcrossProviders` added
