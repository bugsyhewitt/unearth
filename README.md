# unearth

[![CI](https://github.com/bugsyhewitt/unearth/actions/workflows/ci.yml/badge.svg)](https://github.com/bugsyhewitt/unearth/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/bugsyhewitt/unearth)](https://github.com/bugsyhewitt/unearth/releases/latest)
[![Go version](https://img.shields.io/badge/go-1.23+-00ADD8)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Unearth the real origin server hiding behind a CDN.**

`unearth` discovers origin IPs by running seventeen recon techniques in parallel — certificate transparency pivots, DNS history, SPF/MX analysis, subdomain enumeration, email `Received:`-header mining, and more — then ranks candidate IPs by how many techniques independently agree. The result is a scored list of origin candidates, from most to least confident.

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

# Large target list: discover up to 8 targets concurrently (output stays in input order)
subfinder -d target.com -silent | unearth -l - --pipeline-batch 8 | jq -r '.candidate_ip' | httpx
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
| `censys_ipv6` | Passive | Yes — `CENSYS_PLATFORM_PAT` | 0.78 | Censys Platform IPv6 asset-discovery — pivots on the target apex via `host.dns.names` and emits only non-CDN IPv6 hits, catching dual-stack AAAA-leak origins that never reused the front-door certificate and so escape `censys_cert` |
| `dns_history` | Passive | Yes — `SECURITYTRAILS_API_KEY` or `VIEWDNS_API_KEY` | 0.65 | Historical DNS A/AAAA records |
| `host_header` | Active | No | 0.85 | HTTP host-header bypass: connects to candidate IPs with `Host: target` |
| `banner_grab` | Active | No | 0.45 | SSH and HTTP banner fingerprinting of candidate IPs |
| `shodan_cert` | Active | Yes — `SHODAN_API_KEY` | 0.85 | Shodan certificate-fingerprint search |
| `fofa_cert` | Passive | Yes — `FOFA_EMAIL` + `FOFA_KEY` | 0.80 | FOFA certificate-fingerprint search — pivots the target's TLS leaf-cert SHA-256 against FOFA's 4B+ asset index for broader APAC coverage than Shodan/Censys |
| `netlas_cert` | Passive | Yes — `NETLAS_API_KEY` | 0.75 | Netlas certificate-fingerprint search — pivots the target's TLS leaf-cert SHA-256 against Netlas's response index; indexes domains alongside IPs and has a free tier with a daily allowance |
| `criminalip_asset` | Passive | Yes — `CRIMINALIP_API_KEY` | 0.70 | Criminal IP certificate-fingerprint search — pivots the target's TLS leaf-cert SHA-256 against Criminal IP's 4.2B+ asset index; its own AI-scored scan corpus surfaces origins absent from the other engines, and a free tier with a monthly allowance keeps it reachable |
| `binaryedge_cert` | Passive | Yes — `BINARYEDGE_API_KEY` | 0.72 | BinaryEdge certificate-fingerprint search — pivots the target's TLS leaf-cert SHA-1 against BinaryEdge's continuous scan grid; its independent corpus surfaces origins absent from the other engines, and a free tier with a monthly allowance keeps it reachable |
| `leakix_cert` | Passive | Yes — `LEAKIX_API_KEY` | 0.71 | LeakIX certificate-fingerprint search — pivots the target's TLS leaf-cert SHA-1 against LeakIX's continuous scan/exposure index; its independent corpus surfaces origins absent from the other engines, and a free tier with a daily allowance keeps it reachable |
| `onyphe_cert` | Passive | Yes — `ONYPHE_API_KEY` | 0.69 | Onyphe certificate-fingerprint search — pivots the target's TLS leaf-cert SHA-256 against Onyphe's datascan corpus; its independent, meaningfully European-weighted scan footprint surfaces origins absent from the US-centric Censys/Shodan and APAC-weighted FOFA/ZoomEye engines, and a free tier keeps it reachable |
| `fullhunt_asset` | Passive | Yes — `FULLHUNT_API_KEY` | 0.70 | FullHunt attack-surface host enumeration — not a cert pivot; queries FullHunt's domain-details API for every host it has crawled under the target domain and emits the non-CDN IPs it observed, surfacing origins (e.g. `origin.`/`direct.` records) that never reused the front-door certificate and so escape the cert engines; free tier with a monthly allowance |
| `zoomeye_asset` | Passive | Yes — `ZOOMEYE_API_KEY` | 0.68 | ZoomEye domain host enumeration — not a cert pivot; queries ZoomEye's domain-search API for every host it has crawled under the target domain and emits the non-CDN IPs it observed; ZoomEye scans a markedly APAC/China-weighted slice of the internet, so it surfaces origins the US-centric Censys/Shodan engines miss; free tier with a monthly allowance |
| `chaos_asset` | Passive | Yes — `PDCP_API_KEY` | 0.66 | ProjectDiscovery Chaos subdomain enumeration — not a cert pivot; queries Chaos's dataset API for every subdomain it has catalogued under the target apex, resolves each one, and emits the non-CDN IPs behind them; Chaos's corpus is aggregated independently (bug-bounty programs, CT, community), so it surfaces forgotten origin records (`origin.`/`direct.`/`dev.`) the cert and active-scan engines miss; free tier (PDCP API key) |
| `virustotal_passivedns` | Passive | Yes — `VIRUSTOTAL_API_KEY` | 0.67 | VirusTotal v3 passive-DNS — not a cert pivot; queries `/api/v3/domains/{domain}/resolutions` for every historical hostname→IP observation VirusTotal has accumulated for the target apex and emits the non-CDN IPs; the corpus is *temporal* (years of observations from URL scans, file submissions, partner DNS feeds), so it surfaces forgotten origin records the cert engines and asset crawlers miss, with their last-observed date; free public tier (~500 req/day, 4 req/min) |
| `urlscan_asset` | Passive | Yes — `URLSCAN_API_KEY` | 0.66 | URLScan.io search — not a cert pivot; queries `/api/v1/search/?q=domain:<target>` for every public browser-rendered scan recorded against the target apex and emits the non-CDN page-serving IPs; the corpus is *community-submitted browser scans* (PhishTank, SOC playbook automation, manual lookups), so a misconfigured origin that briefly leaked from behind a CDN — during a deploy cutover, a CDN outage, or a targeted scan against a `direct.example.com` shortcut — can be preserved here even though the cert engines, scan grids, and passive-DNS feeds never recorded it; free tier with a generous monthly allowance |
| `otx_passivedns` | Passive | **No** (optional `OTX_API_KEY` lifts rate limit) | 0.64 | AlienVault OTX passive-DNS — not a cert pivot; queries `/api/v1/indicators/domain/<target>/passive_dns` for every historical hostname→IP observation OTX has accumulated for the target apex and emits the non-CDN IPs; the corpus is *threat-intelligence telemetry* (community analyst "pulses", OTX's own honeypot/sensor network, partner DNS feeds), a different lineage than every other backend — an IP invisible to every scanner-driven engine can still appear here because a defender posted a pulse mentioning it or an OTX honeypot logged a callback. **The only OSINT backend that runs without credentials** — passive-DNS reads are anonymous-accessible, so this technique lifts every run's floor coverage even on a key-less deployment; supplying `OTX_API_KEY` only lifts the per-IP anonymous rate limit |
| `favicon_hash` | Active | Yes — `SHODAN_API_KEY` or `CENSYS_PLATFORM_PAT` | 0.75 | Favicon MurmurHash3 pivot — fetches `/favicon.ico`, queries Shodan/Censys for hosts sharing the same favicon |
| `asn_sweep` | Active | No | 0.70 | BGPView ASN-range sweep — resolves target DNS to find its ASN, then probes live IPs across all ASN prefixes with host-header injection to find the real origin |
| `jarm_fingerprint` | Active | No | 0.70 | JARM TLS active fingerprinting — sends 10 crafted ClientHellos to candidate IPs, hashes the handshake response into a 62-char fingerprint, and flags candidates whose JARM matches the target's (rejecting known CDN-edge signatures) |
| `email_header` | Passive | No | 0.85 | Email `Received:`-header mining — parses an operator-supplied `.eml` file (`--email-file`) and surfaces non-CDN relay IPs from the mail hop chain |
| `error_page` | Aggressive | No | 0.60 | Error-page leak detection on the live target |
| `ipv6_probe` | Aggressive | No | 0.70 | IPv6 exposure probe — resolves AAAA and checks for CDN bypass |

See [docs/techniques.md](docs/techniques.md) for detailed descriptions of each technique.

---

## API keys

`unearth` is fully usable with zero API keys. The keyless passive techniques (`ct_fingerprint`, `crtsh`, `spf_mx`, `subdomain_enum`, `split_dns`, `email_header`, `otx_passivedns`) plus keyless active techniques (`host_header`, `asn_sweep`, `jarm_fingerprint`) cover the common case. API keys extend coverage with higher-confidence keyed sources.

Set keys in your environment before running:

```sh
export CENSYS_PLATFORM_PAT="your-key"
export SECURITYTRAILS_API_KEY="your-key"
export VIEWDNS_API_KEY="your-key"
export SHODAN_API_KEY="your-key"
export FOFA_EMAIL="you@example.com"
export FOFA_KEY="your-fofa-key"
export NETLAS_API_KEY="your-netlas-key"
export CRIMINALIP_API_KEY="your-criminalip-key"
export BINARYEDGE_API_KEY="your-binaryedge-key"
export LEAKIX_API_KEY="your-leakix-key"
export ONYPHE_API_KEY="your-onyphe-key"
export FULLHUNT_API_KEY="your-fullhunt-key"
export ZOOMEYE_API_KEY="your-zoomeye-key"
export PDCP_API_KEY="your-projectdiscovery-key"
export VIRUSTOTAL_API_KEY="your-virustotal-key"
export URLSCAN_API_KEY="your-urlscan-key"
export OTX_API_KEY="your-alienvault-otx-key"   # optional; otx_passivedns runs anonymously without it
```

The tool announces which keys are loaded (or absent) on every run. Key-required techniques are silently skipped when the key is missing.

> **Variable names:** each credential above is also accepted under an `UNEARTH_`-prefixed alias (e.g. `UNEARTH_SHODAN_API_KEY`, `UNEARTH_CENSYS_PAT`) for backward compatibility. When both a name and its alias are set, the unprefixed name shown above wins.

> **Censys note:** `censys_cert` uses the Censys Platform API (PAT-based). The Censys Legacy API is not supported. Free-tier Platform accounts may return `403 Tier Insufficient` for some queries — the technique degrades gracefully.

> **Censys IPv6 note:** `censys_ipv6` shares the same `CENSYS_PLATFORM_PAT` credential as `censys_cert` and hits the same `POST /v3/global/search/query` endpoint, but pivots on a completely different signal: the target's DNS apex via the `host.dns.names` CenQL field, restricted to IPv6 hits whose addresses fall outside the embedded CDN ranges. **It is not a cert-fingerprint pivot** — and that is exactly the point. `censys_cert` requires a host to *reuse the front-door certificate*, which a forgotten dual-stack IPv6 listener typically does not (a common misconfiguration: the IPv4 frontend was migrated behind a CDN, the IPv6 listener was left bound to a stale or internal cert, and the AAAA record was never withdrawn). `censys_ipv6` catches those hosts by matching the apex literally and via wildcard subdomain expansion, then filtering Censys's response down to v6-only, non-CDN addresses; IPv4-mapped v6 addresses (`::ffff:1.2.3.4`) are deliberately dropped so the technique stays orthogonal to `censys_cert`. The Platform's same tier-insufficient ladder applies (401/403/429 → clean tier-insufficient skip), so the technique degrades the same way as `censys_cert` when the Free-tier account lacks the host-search capability. Coverage diversity is the value — when both techniques surface the same IPv6 the noisy-OR ranking combines their weights; when only `censys_ipv6` fires it is reporting a genuine v6 origin leak the cert engines cannot see.

> **FOFA note:** `fofa_cert` needs **both** `FOFA_EMAIL` and `FOFA_KEY` (generated from your FOFA account's Personal Center → API page); with only one set the technique is skipped. FOFA's free tier exposes the certificate search; when an account is out of query quota FOFA answers `HTTP 200` with an `error` flag, which the technique treats as a clean tier-insufficient skip rather than a failure. FOFA's heavier APAC scan coverage complements the US-centric Shodan/Censys indexes — its value is reach, not redundancy.

> **Netlas note:** `netlas_cert` needs `NETLAS_API_KEY` (generated from your Netlas account's Profile → API key page); without it the technique is skipped. Netlas offers a free tier with a daily request allowance — when that allowance is exhausted the API answers `HTTP 429` (or a quota message), which the technique treats as a clean tier-insufficient skip rather than a failure. Netlas indexes domain names alongside IPs and maintains its own scan corpus, so it surfaces origins that may be absent from Shodan, Censys, and FOFA — coverage diversity, not redundancy.

> **Criminal IP note:** `criminalip_asset` needs `CRIMINALIP_API_KEY` (generated from your Criminal IP account's My Information → API Key page); without it the technique is skipped. Criminal IP offers a free tier with a monthly request allowance — when that allowance is exhausted, or the plan lacks the banner-search capability, the API answers with a quota/permission message (often `HTTP 200` carrying a non-200 `status` field), which the technique treats as a clean tier-insufficient skip rather than a failure. Criminal IP runs its own AI-scored scan corpus over 4.2B+ IPs, so it surfaces origins that may be absent from Shodan, Censys, FOFA, and Netlas — coverage diversity, not redundancy.

> **BinaryEdge note:** `binaryedge_cert` needs `BINARYEDGE_API_KEY` (generated from your BinaryEdge account's Account → API Access page); without it the technique is skipped. BinaryEdge offers a free tier with a monthly request allowance — when that allowance is exhausted, or the plan lacks the search capability, the API answers `HTTP 429`/`403` (or a quota/permission message), which the technique treats as a clean tier-insufficient skip rather than a failure. Unlike the other certificate-pivot engines, BinaryEdge indexes the leaf cert's **SHA-1** fingerprint (the same flavor Shodan uses), and it runs an independent continuous scan grid, so it surfaces origins that may be absent from Shodan, Censys, FOFA, Netlas, and Criminal IP — coverage diversity, not redundancy.

> **LeakIX note:** `leakix_cert` needs `LEAKIX_API_KEY` (generated from your LeakIX account's Settings → API key page); without it the technique is skipped. LeakIX offers a free tier with a daily request allowance — when that allowance is exhausted, or the plan lacks the search capability, the API answers `HTTP 429`/`403` (or a quota/permission message, sometimes `HTTP 200` carrying an `error`/`message` field), which the technique treats as a clean tier-insufficient skip rather than a failure. Like Shodan and BinaryEdge, LeakIX indexes the leaf cert's **SHA-1** fingerprint, and it runs an independent continuous scan/exposure index, so it surfaces origins that may be absent from Shodan, Censys, FOFA, Netlas, Criminal IP, and BinaryEdge — coverage diversity, not redundancy.

> **Onyphe note:** `onyphe_cert` needs `ONYPHE_API_KEY` (generated from your Onyphe account's API page at `https://www.onyphe.io/auth/api`); without it the technique is skipped. Onyphe offers a free tier with a request allowance — when that allowance is exhausted, or the plan lacks the datascan endpoint, the API answers `HTTP 429`/`403` (or a quota/permission message, typically `HTTP 200` carrying a non-zero `error` field with a `text` description), which the technique treats as a clean tier-insufficient skip rather than a failure. Onyphe indexes the leaf cert's **SHA-256** fingerprint under `tls.fingerprint.sha256` in its datascan corpus — the same flavor Censys/FOFA/Netlas/Criminal IP use, so the techniques corroborate. Onyphe is French-based and its continuous internet-wide datascan footprint is meaningfully European-weighted, so it surfaces origins that may be absent from the US-centric Shodan/Censys, the APAC-weighted FOFA/ZoomEye, and the other independent scan engines (Netlas, Criminal IP, BinaryEdge, LeakIX) — coverage diversity, not redundancy.

> **FullHunt note:** `fullhunt_asset` needs `FULLHUNT_API_KEY` (generated from your FullHunt account's API key page); without it the technique is skipped. FullHunt offers a free tier with a monthly request allowance — when that allowance is exhausted, or the plan lacks the endpoint, the API answers `HTTP 429`/`403` (or a quota/permission message, sometimes `HTTP 200` carrying a `message`/`error` field), which the technique treats as a clean tier-insufficient skip rather than a failure. **Unlike the seven certificate-fingerprint engines, FullHunt is not a cert pivot** — its public API has no cert-fingerprint search. It is an attack-surface enumerator: given the target apex domain, FullHunt's `/domain/{domain}/details` endpoint returns the host inventory it has crawled, each host carrying the IP(s) FullHunt observed. The technique emits the non-CDN IPs from that inventory. Its value is a different kind of corpus: a misconfigured origin that never reused the front-door certificate (e.g. an `origin.example.com` or `direct.example.com` record pointing straight at the backend) escapes the cert engines but can still appear in FullHunt's crawl — coverage diversity, not redundancy.

> **ZoomEye note:** `zoomeye_asset` needs `ZOOMEYE_API_KEY` (generated from your ZoomEye account's Profile → API Key page); without it the technique is skipped. ZoomEye offers a free tier with a monthly request allowance — when that allowance is exhausted, or the plan lacks the endpoint, the API answers `HTTP 429`/`403` (or a quota/permission message, sometimes `HTTP 200` carrying a `message`/`error` field), which the technique treats as a clean tier-insufficient skip rather than a failure. **Like FullHunt, and unlike the seven certificate-fingerprint engines, ZoomEye is not a cert pivot** — it is a domain host enumerator: given the target apex domain, ZoomEye's `/domain/search` endpoint returns the associated hosts it has crawled, each carrying the IP(s) ZoomEye resolved. The technique emits the non-CDN IPs from that list. Its value is coverage diversity: ZoomEye (a Chinese cyberspace search engine, like FOFA) scans a markedly APAC/China-weighted slice of the internet, so an origin hosted in that space — one the US-centric Censys and Shodan engines never indexed and that FullHunt never crawled — can still surface in ZoomEye's inventory.

> **OTX note:** `otx_passivedns` is the only OSINT backend in the suite that does **not** require an API key — AlienVault OTX's `/api/v1/indicators/domain/<target>/passive_dns` endpoint is publicly accessible to anonymous callers. Supplying `OTX_API_KEY` (generated from your OTX account's Settings → API Integration page; the `ALIENVAULT_OTX_API_KEY` and `UNEARTH_OTX_API_KEY` aliases are also accepted) only lifts the anonymous per-IP rate limit and identifies the caller for OTX's plan-level allowance. When the rate limit is hit, or a supplied key is rejected, the API answers `HTTP 429`/`403` (or a 4xx carrying a `detail` envelope mentioning `throttle`/`rate limit`/`upgrade`), which the technique treats as a clean tier-insufficient skip rather than a failure; a supplied bad key (`HTTP 401`, or a `detail` envelope mentioning `Invalid API key`/`unauthorized`) degrades to a clean missing-key skip; an `HTTP 404` means OTX has no passive-DNS data for the apex (a clean empty success, not an error). **Like FullHunt, ZoomEye, Chaos, VirusTotal, and URLScan — and unlike the eight certificate-fingerprint engines — this technique is not a cert pivot.** It is a passive-DNS pivot on a corpus distinct from VirusTotal's: OTX's `passive_dns` array is aggregated from the community-submitted "pulse" indicator feeds (analyst-curated IoC bundles describing real-world campaigns), OTX's own honeypot/sensor network, and partner DNS telemetry. The technique emits the non-CDN, deduplicated IPs (filtering non-A/AAAA records) as origin candidates, with the last-observed date folded into each candidate's evidence string — and like `virustotal_passivedns` and `urlscan_asset`, OTX returns the IP directly under `address`, so there is no second-stage DNS fan-out. Its value is both **corpus diversity** (threat-intel telemetry surfaces IPs no scanner ever indexed) and **deployment friction** — a key-free deployment still gets passive-DNS coverage out of the box.
>
> **URLScan note:** `urlscan_asset` needs `URLSCAN_API_KEY` (generated from your URLScan.io account's User Profile → API page; the `UNEARTH_URLSCAN_API_KEY` alias is also accepted); without it the technique is skipped. URLScan offers a free tier with a generous monthly request allowance — when that allowance is exhausted, or the plan lacks the search capability, the API answers `HTTP 429`/`403` (or a 4xx carrying a `message`/`description` envelope mentioning `rate limit`/`quota`/`upgrade`), which the technique treats as a clean tier-insufficient skip rather than a failure; a missing/invalid key (`HTTP 401`, or a `message`/`description` envelope mentioning `Invalid API key`/`unauthorized`/`API-Key` required) degrades to a clean missing-key skip. **Like FullHunt, ZoomEye, Chaos, and VirusTotal — and unlike the eight certificate-fingerprint engines — this technique is not a cert pivot.** It is a browser-scan pivot: URLScan.io's `/api/v1/search/?q=domain:<target>` endpoint returns every public scan submission ever rendered against the target apex (PhishTank automation, SOC playbook submissions, community lookups, URLScan's own crawler), each record carrying the page-serving IP, the resolved hostname, the ASN, and the scan timestamp. The technique emits the non-CDN, deduplicated IPs as origin candidates — and like `virustotal_passivedns`, URLScan returns the IP directly under `page.ip`, so there is no second-stage DNS fan-out. Its value is yet another orthogonal axis: a misconfigured origin that *briefly* leaked from behind a CDN (a five-minute deploy cutover, a CDN outage, a quietly-shipped `direct.example.com` shortcut someone submitted to URLScan) is preserved in URLScan's index even though the cert engines, scan grids, and passive-DNS feeds never recorded it.
>
> **VirusTotal note:** `virustotal_passivedns` needs `VIRUSTOTAL_API_KEY` (generated from your VirusTotal account's API key page at `https://www.virustotal.com/gui/my-apikey`; the `VT_API_KEY` and `UNEARTH_VIRUSTOTAL_API_KEY` aliases are also accepted); without it the technique is skipped. VirusTotal's free public tier has a strict allowance (currently ~500 requests/day and 4 requests/minute) — when the per-minute or daily quota is exhausted, or the account lacks the v3 endpoint, the API answers `HTTP 429`/`403` (or a 4xx carrying an `error.code` of `QuotaExceededError`/`TooManyRequestsError`/`UserNotActiveError`), which the technique treats as a clean tier-insufficient skip rather than a failure; a missing/invalid key (`HTTP 401`, `AuthenticationRequiredError`, `WrongCredentialsError`) degrades to a clean missing-key skip; an `HTTP 404` means VirusTotal has no passive-DNS data for the apex (a clean empty success, not an error). **Like FullHunt, ZoomEye, and Chaos, and unlike the eight certificate-fingerprint engines, this technique is not a cert pivot.** It is a passive-DNS pivot: VirusTotal's `/api/v3/domains/{domain}/resolutions` endpoint returns historical hostname→IP observations harvested from URL scans, file submissions, and partner DNS feeds, going back years; each record carries the IP, the hostname under which it was observed, and the last-observed date. The technique emits the non-CDN, deduplicated IPs as origin candidates — and unlike `chaos_asset` (which returns subdomain *names* and resolves them itself), VirusTotal returns the IP directly, so there is no second-stage DNS fan-out. Its value is a temporal axis the other backends lack: a forgotten `origin.example.com` record from three years ago — one no cert engine ever touched and no asset crawler recorded — can still surface here with its observation date.
>
> **Chaos note:** `chaos_asset` needs `PDCP_API_KEY` (generated from your [ProjectDiscovery Cloud Platform](https://cloud.projectdiscovery.io) account's API-key page; the legacy `CHAOS_API_KEY` and `UNEARTH_PDCP_API_KEY` aliases are also accepted); without it the technique is skipped. ProjectDiscovery offers a free tier — when the request allowance is exhausted, or the plan lacks the endpoint, the API answers `HTTP 429`/`403` (or a quota/permission message, sometimes `HTTP 200` carrying a `message`/`error` field), which the technique treats as a clean tier-insufficient skip rather than a failure. **Like FullHunt and ZoomEye, and unlike the seven certificate-fingerprint engines, Chaos is not a cert pivot.** It also differs from FullHunt and ZoomEye in shape: Chaos returns only the *subdomain names* it has catalogued under the target apex (the same dataset that powers `subfinder`), not host→IP records, so the technique resolves each returned subdomain itself (via the shared resolver) and emits the non-CDN IPs behind it. Its value is corpus diversity: Chaos is aggregated from public bug-bounty programs, certificate transparency, and community contributions — a different lineage than the active internet-wide scans behind Censys/Shodan. A forgotten origin record (`origin.example.com`, `direct.example.com`, a stale `dev.`/`mail.` host) that never reused the front-door certificate, so the cert pivots miss it, can still appear in Chaos's dataset and resolve to the backend. To keep the DNS fan-out bounded, the technique resolves at most the first 256 subdomains (sorted) per run.

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
      --email-file string   Path to a raw email (.eml); its Received: headers are mined for origin IPs
      --pipeline-batch int  Targets to discover concurrently in list/stdin mode (default 1 = sequential)
      --verbose             Print per-technique results to stderr
      --silent              Suppress all stderr output

Subcommands:
  unearth version           Print version, commit, and build date
  unearth cache stats       Show cache row counts and on-disk path
  unearth cache purge       Delete expired cache entries
  unearth cache clear       Delete all cache entries (prompts for confirmation)
  unearth calibrate         Suggest technique-weight overrides from run history
  unearth calibrate --yaml  Emit a weights.yaml block of suggested overrides
  unearth calibrate reset   Delete all recorded calibration observations
```

### Weight calibration

The default technique weights are hand-tuned. As data sources shift over time (CDN range growth, search-engine index changes) those defaults can drift away from how each technique actually performs against *your* target profile. `unearth calibrate` gives you data to tune them.

After every discovery run, unearth records a lightweight observation per technique contribution in its local cache: whether the candidate that technique surfaced was independently **corroborated** by at least one other technique in the same run. There is no external ground truth for "this IP really was the origin", so corroboration is the precision proxy — a technique whose candidates are consistently confirmed by other techniques is contributing real signal; a technique that only ever produces lone hits is the noisy one.

Once you've accumulated some runs, `unearth calibrate` reports each technique's observed precision and a suggested weight:

```sh
unearth calibrate
# technique          current  suggest  precision  samples note
# crtsh                 0.55     0.71       0.78        64
# host_header           0.70     0.69       0.20         3 low-confidence
```

The suggested weight is a shrinkage estimate: the observed corroboration rate blended toward the technique's existing weight by a pseudo-count, so a technique with only a handful of observations keeps its default rather than swinging on noise. Suggestions backed by fewer than 20 observations are flagged `low-confidence`.

Emit a ready-to-use overrides file and adopt it via `--weights`:

```sh
unearth calibrate --yaml > my-weights.yaml   # low-confidence lines are commented out
unearth --weights my-weights.yaml target.com
```

Reset the history (e.g. after a CDN data refresh changes coverage) with `unearth calibrate reset`. Calibration recording is best-effort and never affects discovery results; `--no-cache` runs record nothing.

### Bulk targets and pipeline batching

When you feed `unearth` a list of targets (via `-l <file>` or stdin), it processes them one at a time by default. For large programs with hundreds of subdomains this is slow, even though each individual run is already concurrent at the technique level.

`--pipeline-batch <n>` lifts that concurrency to the target level: up to `n` targets are discovered at the same time. Results are still emitted **in input order**, so streaming output (`jsonl`, `table`) and the accumulated `json` array remain deterministic regardless of which target finishes first:

```sh
# Discover up to 8 targets concurrently; output order matches input order
unearth -l subdomains.txt --pipeline-batch 8 -o jsonl
```

`--pipeline-batch 1` (the default) preserves the original strictly-sequential behavior. The per-target `--concurrency` flag (technique-level parallelism) is independent and composes with `--pipeline-batch`.

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
- **Akamai** — published ASN ranges (AS20940 et al.), `edgesuite.net`/`edgekey.net`/`akamaized.net` CNAME signals, `x-check-cacheable`/`x-akamai-transformed` headers
- **Imperva (Incapsula)** — published edge ranges (AS19551), `incapdns.net`/`incapsula.com` CNAME signals, `x-iinfo` header, `x-cdn: incapsula`, and `incap_ses`/`visid_incap` session cookies
- **Azure Front Door** — published service-tag anycast ranges (`AzureFrontDoor`), `azurefd.net`/`azureedge.net`/`t-msedge.net`/`trafficmanager.net` CNAME signals, `x-azure-ref` header, and `x-cache: ... from FrontDoor`
- **Google Cloud CDN** — published `goog`/`cloud.json` ranges plus the GFE load-balancer blocks (`130.211.0.0/22`, `35.191.0.0/16`), `googlehosted.com`/`googleusercontent.com`/`storage.googleapis.com` CNAME signals, `server: Google Frontend`, `via: 1.1 google`, and `x-goog-*` headers
- **StackPath / Highwinds** — published Highwinds edge ranges (AS20446 / AS33438, the former NetDNA / MaxCDN network), `stackpathcdn.com`/`stackpathdns.com`/`hwcdn.net`/`netdna-cdn.com`/`netdna-ssl.com` CNAME signals, the `x-hw` Highwinds edge header, `server: NetDNA-cache`, and `x-cdn: stackpath`
- **BunnyCDN (bunny.net)** — published edge ranges (AS200325, BunnyWay d.o.o.), `b-cdn.net`/`bunnycdn.com`/`bunny.net` CNAME signals, the `server: BunnyCDN-<pop>` edge marker, and the `cdn-pullzone`/`cdn-requestcountrycode` pull-zone headers
- **CDN77 (DataCamp)** — published edge ranges (AS60068, DataCamp Limited / CDN77 s.r.o.), `cdn77.org`/`cdn77-ssl.net`/`cdn77.net`/`cdn77.com` CNAME signals, the proprietary `x-77-*` edge headers (`x-77-cache`/`x-77-nzt`/`x-77-pop`), the `server: CDN77` marker, and an `x-cdn: cdn77` value
- **Edgio (Limelight / Edgecast)** — published edge ranges from the two operating ASNs (AS22822 Limelight Networks Global and AS15133 Edgecast / Verizon Media, now Edgio), `llnwd.net`/`llnw.com`/`lldns.net`/`edgecastcdn.net`/`systemcdn.net`/`edgio.net` CNAME signals, the Edgecast `server: ECS`/`server: ECAcc` and Limelight `server: LimeLight` edge markers, the `x-llid` request-tracking header, the `x-ec-*` Edgecast header family, and an `x-cdn: edgio` value
- **KeyCDN (proinity GmbH)** — published edge ranges (AS199653, proinity GmbH, Switzerland), `kxcdn.com`/`keycdn.com` CNAME signals, the `server: keycdn-engine` edge marker, the `x-edge-location` serving-POP header and `x-pull` pull-zone header, and an `x-cdn: keycdn` value
- **Gcore (G-Core Labs)** — published edge ranges (AS199524, G-Core Labs S.A., Luxembourg), `gcdn.co`/`gcorelabs.com`/`gcore.com` CNAME signals, the `server: gcore` edge marker, the proprietary `x-gcore-*` header family (e.g. `x-gcore-pop` serving POP), and an `x-cdn: gcore` value
- **CacheFly (CacheNetworks)** — published edge ranges (AS30081, CacheNetworks, LLC), `cachefly.net` CNAME signals, the `server: CacheFly` edge marker, the proprietary `x-cf1`/`x-cf2` request-tracking headers, and an `x-cdn: cachefly` value

Ranges are embedded at build time and can be refreshed via `pkg/cdn.Refresh()`.

---

## Limitations

- **Origin discovery is probabilistic.** A high-confidence score is evidence, not proof. Verify with the host-header technique or manual curl.
- **Active and aggressive techniques touch the target or its infrastructure.** Passive-only mode (`--passive`, which is the default) is safe for recon; the other tiers make network connections to the target itself.
- **Kaeferjaeger coverage is cloud-provider-only.** The `ct_fingerprint` Backend A scans AWS, Azure, GCP, DigitalOcean, and Oracle ranges. A bare-metal or niche-VPS origin will not appear in that dataset (though Backend B via Cert Spotter has broader reach).
- **API key sources are rate-limited.** Censys, Shodan, SecurityTrails, ViewDNS, FOFA, Netlas, Criminal IP, and ProjectDiscovery Chaos all have per-day or per-second limits. The tool respects those limits but cannot run more queries than the account allows.

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
