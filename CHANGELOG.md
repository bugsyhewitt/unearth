# Changelog

All notable changes to `unearth` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `split_dns` discovery technique (passive tier, weight 0.80). Detects partial-proxy / split-DNS misconfigurations: resolves the apex and `www` to determine whether a CDN-fronted front door exists, then flags non-CDN IPs on the apex or on commonly un-proxied siblings (`mail`, `smtp`, `ftp`, `direct`, `origin`, `backend`, `cpanel`, `webmail`) as high-confidence origin candidates. Purely DNS-based — no target contact, no API key. Yields no signal when no CDN front door is present.
- `favicon_hash` discovery technique (active tier, weight 0.75). Fetches the target's `/favicon.ico` (HTTPS with HTTP fallback), computes its MurmurHash3 using Shodan's convention — `mmh3(base64.encodebytes(favicon_bytes))` as a signed int32 — and queries Shodan (`http.favicon.hash`) and/or Censys (`services.http.response.favicons.hashes`) for hosts sharing that favicon. Either API key alone is sufficient; with neither configured the technique skips gracefully. Favicon hashes survive cert rotations and IP moves, complementing the cert-pivot techniques.

## [1.0.0] — 2026-05-17

### Added

**Twelve discovery techniques across three aggression tiers:**

*Passive* (never contacts the target):
- `crtsh` — Certificate Transparency log search via crt.sh with retry, backoff, and Cert Spotter fallback
- `ct_fingerprint` — Keyless cert-fingerprint pivot using kaeferjaeger SNI-IP datasets and Cert Spotter CT search
- `dns_history` — Historical DNS A/AAAA records via SecurityTrails and ViewDNS
- `spf_mx` — SPF and MX record pivot to resolve mail infrastructure IPs
- `subdomain_enum` — Wordlist-based subdomain resolution to find exposing subdomains
- `censys_cert` — Censys Platform certificate-search (API key required)

*Active* (direct connections to candidate IPs, not the target):
- `host_header` — HTTP host-header bypass validation against candidate IPs
- `banner_grab` — SSH and HTTP banner fingerprinting against candidate IPs
- `shodan_cert` — Shodan certificate-fingerprint pivot (API key required)

*Aggressive* (probes that may touch the target):
- `error_page` — Error-page leak detection on the target
- `ipv6_probe` — IPv6 exposure probe on the target

**Two-phase orchestration engine:**
- Phase 1: passive and active producers run in parallel
- Phase 2: consumer techniques (`host_header`, `banner_grab`) receive the pooled candidate IPs
- Per-technique timeout overrides via `TimeoutOverrider` interface

**Noisy-OR ranking engine:**
- Confidence scores in [0, 1] via independent technique agreement
- Corroboration count and `single_source` flag per candidate
- Configurable technique weights via YAML (`~/.config/unearth/weights.yaml`)

**CLI (`unearth`):**
- Target from positional argument or `--list` file (one per line)
- Tier selection: `--active`, `--aggressive`
- Output formats: `jsonl` (default), `json`, `table`
- Budget caps: `--max-censys`, `--max-shodan`, `--max-st`
- Cache management: `--no-cache`, `--refresh`
- `unearth version` — reports version, commit, and build date
- `unearth cache stats` / `purge` / `clear` — cache management subcommands
- Pipeline support: reads targets from stdin when piped; emits structured JSONL for tools like `jq`, `httpx`

**MCP server (`unearth-mcp`):**
- Five MCP tools over stdio transport: `unearth_discover`, `unearth_cert_fingerprint`, `unearth_dns_history`, `unearth_subdomain_enum`, `unearth_host_header_probe`
- Built with `mark3labs/mcp-go` v0.48.0 (MCP spec 2025-03-26)
- No API keys required to start; keyless techniques run automatically

**CDN detection (`pkg/cdn`):**
- IP range matching: Cloudflare, CloudFront (AWS), Fastly, Sucuri
- DNS CNAME/NS signals, HTTP response header signals
- Embedded snapshot with 24h disk-cached refresh from first-party sources
- `Refresh()` fetches fresh ranges from Cloudflare, AWS, and Fastly APIs

**Infrastructure:**
- SQLite result cache with configurable TTL per technique
- Per-endpoint rate limiting (configurable RPS and burst)
- XDG-compliant cache directories
- `CGO_ENABLED=0` builds: pure-Go binary, no system libraries required
- Cross-platform: linux/darwin × amd64/arm64 release artifacts
- GoReleaser release pipeline with version stamping via ldflags

[1.0.0]: https://github.com/bugsyhewitt/unearth/releases/tag/v1.0.0
