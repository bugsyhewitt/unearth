# unearth — Phase 2 improvement: fix credential test environment isolation gap

## What was done

Five credential sets were absent from `allCredentialEnvVars` in
`pkg/config/config_test.go`, and nine of the nineteen key-bearing backends
were absent from the canonical-name test. Additionally, the README's technique
count was out of date.

### Root problem: `allCredentialEnvVars` missing five credential sets

`clearCredentialEnv` calls `t.Setenv(name, "")` for every variable in
`allCredentialEnvVars` to prevent real-environment keys from leaking into
tests that intend to start from a clean state. Five sets were missing:

| Missing from `allCredentialEnvVars` | Env vars |
|---|---|
| ZoomEye | `ZOOMEYE_API_KEY`, `UNEARTH_ZOOMEYE_API_KEY` |
| Chaos/PDCP | `PDCP_API_KEY`, `CHAOS_API_KEY`, `UNEARTH_PDCP_API_KEY` |
| VirusTotal | `VIRUSTOTAL_API_KEY`, `VT_API_KEY`, `UNEARTH_VIRUSTOTAL_API_KEY` |
| URLScan | `URLSCAN_API_KEY`, `UNEARTH_URLSCAN_API_KEY` |
| GreyNoise | `GREYNOISE_API_KEY`, `UNEARTH_GREYNOISE_API_KEY` |

Impact: any CI runner (or developer) with these API keys set in the shell
environment would see non-empty values bleed into tests. For example,
`TestLoadAPIKeys_EmptyEnv` intended to verify a zero-key state but
`clearCredentialEnv` did not clear `GREYNOISE_API_KEY`, so
`k.GreyNoiseKey` could be non-empty while the test passed. Tests that then
asserted specific CredentialStatus map values could silently produce the
wrong result.

**Fix:** added all five missing sets (10 canonical vars + aliases) to
`allCredentialEnvVars`, with inline comments explaining why each was absent.

### `TestLoadAPIKeys_CanonicalNames` only covered 10 of 19 key-bearing backends

The test verified that the unprefixed canonical env-var name (the one the
README tells users to export) is read by `LoadAPIKeys`. It covered:
Censys, Shodan, SecurityTrails, ViewDNS, FOFA, Netlas, CriminalIP. Missing:
BinaryEdge, LeakIX, Onyphe, FullHunt, ZoomEye, Chaos, VirusTotal, URLScan,
GreyNoise, OTX.

**Fix:** extended the test to assert all 20 struct fields map to their
canonical env-var values; restructured as a slice of `{field, got, want}`
entries so a new backend needs only one line to add.

### Missing `CredentialStatus` test coverage for nine backends

`TestCredentialStatus_CriminalIP` and `TestCredentialStatus_OTX` existed but
no dedicated tests covered: BinaryEdge, LeakIX, Onyphe, FullHunt, ZoomEye,
Chaos, VirusTotal, URLScan, GreyNoise.

**Fix:** added three new tests:

- `TestCredentialStatus_NewBackends` — table-driven, one sub-test per
  backend; each sub-test verifies false with no key, true with canonical
  name, and true with the UNEARTH_-prefixed legacy alias.
- `TestCredentialStatus_VTAliases` — verifies the `VT_API_KEY` alias for
  VirusTotal (three accepted names).
- `TestCredentialStatus_ChaosAliases` — verifies the `CHAOS_API_KEY` alias
  for Chaos/PDCP (three accepted names).

### README technique count corrected

The introduction said "seventeen recon techniques" but the tool now ships 32.
Updated to "thirty-two" and expanded the brief technique list to include
JARM fingerprinting and ASN-range sweeps (which were absent from the summary
even though they shipped months ago).

## Files changed

- `pkg/config/config_test.go` — fix `allCredentialEnvVars` (5 missing sets);
  extend `TestLoadAPIKeys_CanonicalNames` to all 20 fields; add
  `TestCredentialStatus_NewBackends`, `TestCredentialStatus_VTAliases`,
  `TestCredentialStatus_ChaosAliases`
- `README.md` — update technique count from "seventeen" to "thirty-two";
  expand technique list in introduction

## Test results

All 10 test packages pass under `go test ./... -count=1 -race`. See `test-output.txt`.
