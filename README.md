# unearth

[![CI](https://github.com/bugsyhewitt/unearth/actions/workflows/ci.yml/badge.svg)](https://github.com/bugsyhewitt/unearth/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/bugsyhewitt/unearth)](https://github.com/bugsyhewitt/unearth/releases/latest)
[![Go version](https://img.shields.io/badge/go-1.23+-00ADD8)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Unearth the real origin server hiding behind a CDN.**

`unearth` discovers origin IPs by running thirteen recon techniques in parallel — certificate transparency pivots, DNS history, SPF/MX analysis, subdomain enumeration, and more — then ranks candidate IPs by how many techniques independently agree. The result is a scored list of origin candidates, from most to least confident.

---

## Install

```sh
go install github.com/unearth-tool/unearth/cmd/unearth@latest
go install github.com/unearth-tool/unearth/cmd/unearth-mcp@latest
```

Pre-built release binaries (linux/darwin × amd64/arm64) are available on the [Releases](https://github.com/bugsyhewitt/unearth/releases) page.

---

## Quick start

```sh
# Passive run — zero API keys needed
unearth example.com

# Include active techniques (direct connections to candidate IPs)
unearth --active example.com

# Table output for terminal review
unearth -o table example.com

# Pipeline: enumerate targets with subfinder, discover origins, probe with httpx
subfinder -d target.com -silent | unearth -l - | jq -r '.candidates[].candidate_ip' | httpx
```

---

## How it works

`unearth` runs techniques in three tiers:

| Tier | What it does | Example techniques |
|---|---|---|
| **Passive** | No contact with the target | Certificate transparency, DNS history, SPF/MX pivot |
| **Active** | Direct connections to *candidate IPs*, not the target | Host-header bypass, banner grab, Shodan |
| **Aggressive** | Probes that touch the target directly | Error-page leak, IPv6 probe |

The default (`passive`) never touches the target. `--active` and `--aggressive` opt in to progressively louder techniques.

**Ranking:** each technique declares a reliability weight. When two or more techniques surface the same IP independently, their weights combine with a [noisy-OR](docs/ranking.md) rule — independent corroboration raises confidence without one weak signal dominating. The `corroboration` field counts how many techniques agreed; `single_source: true` flags lone hits. See [docs/ranking.md](docs/ranking.md).

---

## Techniques

| Name | Tier | API key | Weight | What it does |
|---|---|---|---|---|
| `ct_fingerprint` | Passive | No | 0.70 | Keyless cert-fingerprint pivot via kaeferjaeger SNI-IP datasets and Cert Spotter CT logs |
| `crtsh` | Passive | No | 0.55 | Certificate Transparency enumeration via crt.sh (with retry and Cert Spotter fallback) |
| `spf_mx` | Passive | No | 0.50 | SPF and MX record analysis — mail infrastructure often reveals origin IPs |
| `subdomain_enum` | Passive | No | 0.35 | Wordlist subdomain brute-force to find exposing subdomains |
| `split_dns` | Passive | No | 0.80 | Split-DNS / partial-proxy detection — flags non-CDN apex or mail/admin siblings when the www front door is CDN-fronted |
| `censys_cert` | Passive | Yes — `CENSYS_PLATFORM_PAT` | 0.90 | Censys Platform certificate-fingerprint search |
| `dns_history` | Passive | Yes — `SECURITYTRAILS_API_KEY` or `VIEWDNS_API_KEY` | 0.65 | Historical DNS A/AAAA records |
| `host_header` | Active | No | 0.85 | HTTP host-header bypass: connects to candidate IPs with `Host: target` |
| `banner_grab` | Active | No | 0.45 | SSH and HTTP banner fingerprinting of candidate IPs |
| `shodan_cert` | Active | Yes — `SHODAN_API_KEY` | 0.85 | Shodan certificate-fingerprint search |
| `favicon_hash` | Active | Yes — `SHODAN_API_KEY` or `CENSYS_PLATFORM_PAT` | 0.75 | Favicon MurmurHash3 pivot — fetches `/favicon.ico`, queries Shodan/Censys for hosts sharing the same favicon |
| `asn_sweep` | Active | No | 0.70 | BGPView ASN-range sweep — resolves target DNS to find its ASN, then probes live IPs across all ASN prefixes with host-header injection to find the real origin |
| `jarm_fingerprint` | Active | No | 0.70 | JARM TLS active fingerprinting — sends 10 crafted ClientHellos to candidate IPs, hashes the handshake response into a 62-char fingerprint, and flags candidates whose JARM matches the target's (rejecting known CDN-edge signatures) |
| `error_page` | Aggressive | No | 0.60 | Error-page leak detection on the live target |
| `ipv6_probe` | Aggressive | No | 0.70 | IPv6 exposure probe — resolves AAAA and checks for CDN bypass |

See [docs/techniques.md](docs/techniques.md) for detailed descriptions of each technique.

---

## API keys

`unearth` is fully usable with zero API keys. The keyless passive techniques (`ct_fingerprint`, `crtsh`, `spf_mx`, `subdomain_enum`, `split_dns`) plus keyless active techniques (`host_header`, `asn_sweep`, `jarm_fingerprint`) cover the common case. API keys extend coverage with higher-confidence keyed sources.

Set keys in your environment before running:

```sh
export CENSYS_PLATFORM_PAT="your-key"
export SECURITYTRAILS_API_KEY="your-key"
export VIEWDNS_API_KEY="your-key"
export SHODAN_API_KEY="your-key"
```

The tool announces which keys are loaded (or absent) on every run. Key-required techniques are silently skipped when the key is missing.

> **Censys note:** `censys_cert` uses the Censys Platform API (PAT-based). The Censys Legacy API is not supported. Free-tier Platform accounts may return `403 Tier Insufficient` for some queries — the technique degrades gracefully.

---

## Output formats

**`jsonl` (default)** — one JSON object per line, suitable for piping:

```json
{"target":"example.com","cdn_detected":"cloudflare","candidates":[{"candidate_ip":"93.184.216.34","score":0.82,"corroboration":3,"single_source":false,"techniques":[...]}],"timestamp":"2026-05-17T10:00:00Z"}
```

**`json`** — a single pretty-printed JSON object:

```sh
unearth -o json example.com | jq '.candidates[0]'
```

**`table`** — human-readable terminal table:

```sh
unearth -o table example.com
```

```
TARGET         CDN          IP              SCORE  CORR  TECHNIQUES
example.com    cloudflare   93.184.216.34   0.82   3     ct_fingerprint, crtsh, spf_mx
example.com    cloudflare   1.2.3.4         0.35   1     subdomain_enum
```

---

## CLI reference

```
unearth [flags] [target]

Flags:
  -l, --list string         File of targets (one per line, # comments OK)
      --active              Include active-tier techniques
      --aggressive          Include aggressive-tier techniques (implies --active)
  -o, --output string       Output format: jsonl | json | table (default "jsonl")
      --top int             Limit output to top N candidates (default 0 = all)
  -c, --concurrent int      Parallel technique slots (default 10)
      --timeout duration    Overall run timeout (default 5m0s)
      --no-cache            Bypass the cache
      --refresh             Ignore cache; write fresh results
      --max-censys int      Censys query cap per target (default 10)
      --max-shodan int      Shodan query cap per target (default 10)
      --max-st int          SecurityTrails query cap per target (default 20)
      --weights string      Path to technique-weight overrides YAML
      --verbose             Print per-technique results to stderr
      --silent              Suppress all stderr output

Subcommands:
  unearth version           Print version, commit, and build date
  unearth cache stats       Show cache row counts and on-disk path
  unearth cache purge       Delete expired cache entries
  unearth cache clear       Delete all cache entries (prompts for confirmation)
```

---

## MCP server

`unearth-mcp` exposes `unearth`'s capabilities as Model Context Protocol tools over a stdio transport. An AI agent (Claude Desktop, or a custom MCP client) can call origin discovery directly without shelling out to the CLI.

See [docs/mcp.md](docs/mcp.md) for tool parameters, result shapes, and client configuration.

**Sample Claude Desktop configuration:**

```json
{
  "mcpServers": {
    "unearth": {
      "command": "unearth-mcp",
      "env": {
        "CENSYS_PLATFORM_PAT": "your-key"
      }
    }
  }
}
```

---

## Library use

`unearth` is importable as a Go package for embedding in larger tools:

```go
import "github.com/unearth-tool/unearth/pkg/unearth"

result, err := unearth.Discover(ctx, "example.com", unearth.DefaultOptions())
if err != nil {
    log.Fatal(err)
}
for _, c := range result.Candidates {
    fmt.Printf("%s  score=%.2f  corroboration=%d\n", c.IP, c.Score, c.Corroboration)
}
```

---

## CDN coverage

The following CDNs are detected (IP-range matching + header and DNS signals):

- **Cloudflare** — first-party IP ranges, `server: cloudflare`, `cf-ray` header, CNAME signals
- **CloudFront (AWS)** — first-party `ip-ranges.json` (`CLOUDFRONT` service), `x-amz-cf-id` header
- **Fastly** — first-party `public-ip-list` API, `x-fastly-request-id` header
- **Sucuri** — published WAF CIDR ranges, `x-sucuri-cache` header

Ranges are embedded at build time (snapshot date 2026-05-17) and can be refreshed via `pkg/cdn.Refresh()`. Akamai is deferred to v1.1 — no authoritative machine-readable range list is available.

---

## Limitations

- **Origin discovery is probabilistic.** A high-confidence score is evidence, not proof. Verify with the host-header technique or manual curl.
- **Active and aggressive techniques touch the target or its infrastructure.** Passive-only mode (`--passive`, which is the default) is safe for recon; the other tiers make network connections to the target itself.
- **Kaeferjaeger coverage is cloud-provider-only.** The `ct_fingerprint` Backend A scans AWS, Azure, GCP, DigitalOcean, and Oracle ranges. A bare-metal or niche-VPS origin will not appear in that dataset (though Backend B via Cert Spotter has broader reach).
- **API key sources are rate-limited.** Censys, Shodan, SecurityTrails, and ViewDNS all have per-day or per-second limits. The tool respects those limits but cannot run more queries than the account allows.

---

## Contributing

Techniques follow a [registry pattern](pkg/techniques/registry.go). To add one:

1. Create `pkg/techniques/yourtechnique.go` implementing the `Technique` interface.
2. Register it via `init()` — `func init() { Register(yourTechnique{}) }`.
3. Add a weight entry to both `configs/default-weights.yaml` and `pkg/config/default-weights.yaml`.
4. Write tests following the offline-stub pattern in existing `*_test.go` files.
5. Check `go vet ./...` and `gofmt -l .` are clean.

To run the test suite:

```sh
go test ./...
go test -race ./...
```

E2e tests (live internet required) are tagged `//go:build e2e` and excluded from default runs:

```sh
go test -tags e2e ./pkg/unearth/... -v
```

---

## License

MIT — see [LICENSE](LICENSE).
