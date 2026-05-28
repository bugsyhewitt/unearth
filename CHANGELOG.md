# Changelog

All notable changes to `unearth` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Azure Front Door CDN/WAF detection. Azure Front Door is now a recognized provider in the CDN registry, so its anycast edge IPs are filtered from origin candidates instead of polluting results. Detection uses embedded service-tag ranges (Microsoft `AzureFrontDoor` service tag), the `azurefd.net` / `azureedge.net` / `t-msedge.net` / `trafficmanager.net` CNAME suffixes, the proprietary `X-Azure-Ref` response header, and an `X-Cache` value mentioning the `FrontDoor` cache node. No API key and no new dependency — pure embedded data plus header/DNS classification, mirroring the existing Akamai and Imperva providers.
- Imperva (Incapsula) CDN/WAF detection. Imperva is now a recognized provider in the CDN registry, so its edge IPs are filtered from origin candidates instead of polluting results. Detection uses embedded edge IP ranges (primary ASN AS19551), the `incapdns.net` / `incapdns.com` / `incapsula.com` CNAME suffixes, the proprietary `X-Iinfo` response header, `X-CDN: Incapsula`, and the `incap_ses` / `visid_incap` session cookies Incapsula sets on every fronted response. No API key and no new dependency — pure embedded data plus header/DNS classification, mirroring the existing Akamai provider.
- `unearth calibrate` subcommand for data-driven weight tuning. After every discovery run, unearth now records a lightweight per-technique observation in its local cache: whether the candidate that technique surfaced was independently corroborated by another technique in the same run. `unearth calibrate` aggregates that history into per-technique precision estimates and suggested weight overrides; `--yaml` emits a ready-to-use `weights.yaml` block (low-confidence techniques commented out) for use with `--weights`, and `calibrate reset` clears the history. The suggested weight is a Beta-prior shrinkage estimate (observed corroboration rate blended toward the technique's current weight by a pseudo-count of 20), so techniques with few observations keep their defaults rather than swinging on noise; suggestions backed by fewer than 20 observations are flagged `low-confidence`. There is no external ground truth for origin correctness, so corroboration is used as the precision proxy. Recording is best-effort and never affects discovery results; `--no-cache` runs record nothing.
- `--pipeline-batch <n>` flag for bulk-target runs. When reading targets from `-l <file>` or stdin, up to `n` targets are now discovered concurrently instead of one at a time, addressing the slow sequential processing of large subdomain lists (`subfinder | unearth -l -`). A bounded worker pool runs discovery in parallel while a single writer emits outcomes in input order, so `jsonl` / `table` streaming and the accumulated `json` array stay deterministic regardless of completion order. Default `1` preserves the original strictly-sequential behavior; the existing per-target `--concurrency` (technique-level parallelism) is independent and composes with it.
- `email_header` discovery technique (passive tier, weight 0.85). Parses an operator-supplied raw email (`.eml`) with the standard-library `net/mail` package, walks the `Received:` header chain, and surfaces every public, non-CDN IP literal as an origin candidate. Email infrastructure is rarely fronted by the website's CDN, so relay IPs in the hop chain frequently expose the origin. Filters RFC1918 / unique-local, loopback, link-local, and multicast addresses plus any known CDN IP. Supplied via the new `--email-file <path>` CLI flag (and `RunOptions.EmailFile`); skips silently when no file is given. The active send-a-probe variant remains deferred (needs operator SMTP infrastructure).
- `split_dns` discovery technique (passive tier, weight 0.80). Detects partial-proxy / split-DNS misconfigurations: resolves the apex and `www` to determine whether a CDN-fronted front door exists, then flags non-CDN IPs on the apex or on commonly un-proxied siblings (`mail`, `smtp`, `ftp`, `direct`, `origin`, `backend`, `cpanel`, `webmail`) as high-confidence origin candidates. Purely DNS-based — no target contact, no API key. Yields no signal when no CDN front door is present.
- `favicon_hash` discovery technique (active tier, weight 0.75). Fetches the target's `/favicon.ico` (HTTPS with HTTP fallback), computes its MurmurHash3 using Shodan's convention — `mmh3(base64.encodebytes(favicon_bytes))` as a signed int32 — and queries Shodan (`http.favicon.hash`) and/or Censys (`services.http.response.favicons.hashes`) for hosts sharing that favicon. Either API key alone is sufficient; with neither configured the technique skips gracefully. Favicon hashes survive cert rotations and IP moves, complementing the cert-pivot techniques.
- `jarm_fingerprint` discovery technique (active tier, weight 0.70). A self-contained pure-Go port of the Salesforce JARM active TLS fingerprinting method: sends ten crafted ClientHello probes to each phase-1 candidate IP, folds the handshake responses into a 62-character fingerprint, and flags candidates whose JARM matches the target's reference JARM as likely origins. Rejects candidates matching an embedded table of known CDN-edge JARM signatures (Cloudflare, CloudFront, Fastly, Akamai) and skips CDN-range seed IPs before probing. Phase-2 candidate consumer like `host_header`; no API key and no external module dependency. Makes only TLS handshakes — no application-layer request — so it leaves no entry in the target's HTTP access logs.

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
