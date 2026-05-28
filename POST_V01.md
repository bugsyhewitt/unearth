# unearth — Post-v1.0 Directions

Research lap completed: 2026-05-26. Covers CDN bypass / origin-discovery landscape
from late 2024 through mid-2026. Items are ranked by estimated signal-to-effort ratio.

---

## Ranking legend

| Priority | Meaning |
|---|---|
| P1 | High value, clear implementation path, fits existing architecture |
| P2 | High value, moderate implementation complexity |
| P3 | Useful extension, lower urgency or narrower use case |
| P4 | Exploratory / dependent on third-party access |

---

## P1 — Favicon hash technique (`favicon_hash`) — ✅ IMPLEMENTED (Phase 2, 2026-05-26)

> Shipped in `pkg/techniques/faviconhash.go`. Active tier, weight 0.75, queries
> Shodan (`http.favicon.hash`) and/or Censys
> (`services.http.response.favicons.hashes`); either key alone is sufficient and
> it skips gracefully with neither. Hash uses `mmh3(base64.encodebytes(favicon))`
> as a signed int32 per Shodan convention. MurmurHash3 via
> `github.com/spaolacci/murmur3`.

**What:** Fetch the target's `/favicon.ico`, compute its MurmurHash3 (the same
hash used by Shodan, Censys, FOFA, and ZoomEye), and query at least Shodan
(`http.favicon.hash:<hash>`) for hosts presenting that hash. Non-CDN IPs from
those results are origin candidates.

**Why P1:**
- Passive technique (no contact with the target — reads favicon via a single
  HTTP GET, then queries a search-engine API).
- The hash is stable and uniquely identifies application-level fingerprints that
  transcend IP changes. A company's favicon rarely changes between moves.
- Complements existing cert-based techniques: cert pivots miss hosts that rotate
  certificates; favicon pivots catch them.
- Shodan already supports `http.favicon.hash` filtering; Censys supports
  `services.http.response.favicons.hashes`. Both have existing API integrations
  in the codebase.
- Low false-positive rate when combined with the existing CDN filter: CDN edge
  nodes rarely serve the same favicon as an origin that has been moved behind a
  CDN.

**Implementation notes:**
- Add `pkg/techniques/faviconhash.go` implementing `Technique` interface.
- Tier: **Active** (one outbound GET to `/favicon.ico` on the target domain,
  then passive Shodan/Censys API queries).
- Weight: **0.75** — reliable when the hash is unique; modest false-positive
  risk when a common framework favicon is used.
- MurmurHash3 Go package: `github.com/spaolacci/murmur3` (already widely used
  in the Go ecosystem; check go.mod before adding).
- Two sub-techniques sharing a single registration: one Shodan query path
  (requires `SHODAN_API_KEY`) and one Censys query path (requires
  `CENSYS_PLATFORM_PAT`). Either path alone is sufficient.
- Skip gracefully if no API key is present for either backend, same pattern as
  existing `shodan_cert` and `censys_cert`.
- Hash method: `mmh3(base64(favicon_bytes))` per Shodan convention.

**References:**
- https://www.blackhatethicalhacking.com/articles/using-favicon-for-osint/
- https://medium.com/@amirseyedian/de-anonymize-identify-fingerprint-back-end-infrastructure-using-favicon-and-header-hashing-a-c08b09b9011d
- https://osintme.com/index.php/2025/01/20/the-importance-of-favicons-in-website-osint-research/

---

## P1 — ASN-range sweep technique (`asn_sweep`)

**What:** Resolve the target's current DNS records to find its ASN. Use a BGP
lookup service (Team Cymru WHOIS or BGPView REST API) to retrieve the full
prefix list for that ASN. Make passive HTTP/S probes (host-header injection)
against live IPs in those ranges — same verification logic as `host_header` —
filtering out known CDN ranges.

**Why P1:**
- Directly targets the discovery gap that `ct_fingerprint` misses: origins on
  bare-metal or niche VPS providers outside the cloud-provider ranges scanned by
  kaeferjaeger.
- ASN enumeration is standard practice in red-team recon (2025 community
  consensus per multiple sources). Mature tooling (`asnrecon`, `nitefood/asn`,
  BGPView) confirms reliable free-tier APIs exist.
- Unearth already does host-header verification (`host_header` technique). The
  sweep layer reuses that verification logic with a different candidate source.
- Covers the BreakingWAF misconfiguration class (Dec 2024, Zafran research):
  40% of Fortune 100 companies had origins reachable via ASN-range scanning
  with host-header injection despite WAF protection.

**Implementation notes:**
- Add `pkg/techniques/asnrange.go`.
- Tier: **Active** (resolves target DNS passively, then makes HTTP probes to
  candidate IPs in ASN prefix ranges — same footprint as `host_header`).
- Weight: **0.70**.
- Free API path: BGPView `https://api.bgpview.io/ip/<ip>` for ASN lookup;
  `https://api.bgpview.io/asn/<asn>/prefixes` for prefix list.
- Rate-limit: BGPView free tier is generous but should be respected with a
  shared `ratelimit.Limiter` (existing internal package).
- Concurrency: scan prefix ranges in parallel using existing `--concurrent` cap.
- Scope guard: skip RFC1918, loopback, and multicast prefixes. Warn if ASN
  prefix count exceeds a configurable ceiling (default 65536 IPs) to avoid
  runaway scans.
- No API key required. Document BGPView as the default backend; allow override
  to Netlas or Hurricane Electric BGP (`bgp.he.net`) via config.

**References:**
- https://medium.com/@0xbrut/from-zero-to-recon-your-first-asn-based-scanning-workflow-b08c88709410
- https://www.zafran.io/resources/breaking-waf
- https://www.akamai.com/blog/security-research/what-you-should-know-about-breakingwaf
- https://github.com/nitefood/asn

---

## P1 — Akamai CDN detection (CDN coverage gap) — ✅ IMPLEMENTED (Phase 2)

> Shipped in `pkg/cdn/cdn.go` (`buildAkamai`) with embedded
> `pkg/cdn/data/akamai-v4.txt` / `akamai-v6.txt` snapshots, `edgesuite.net` /
> `edgekey.net` / `akamaized.net` / `akamaitechnologies.com` / `akamai.net`
> CNAME hints, and `X-Check-Cacheable` / `X-Akamai-Transformed` header
> classification.

**What:** Add Akamai to the CDN provider registry (`pkg/cdn/cdn.go`). Currently
the codebase covers Cloudflare, CloudFront, Fastly, and Sucuri. Akamai is the
largest CDN by market share and its absence causes false positives: Akamai IPs
are returned as origin candidates instead of being filtered.

**Why P1:**
- The README explicitly lists Akamai as "deferred to v1.1." It is now the most
  obvious gap in CDN coverage.
- Without Akamai filtering, techniques like `crtsh` and `subdomain_enum` surface
  Akamai edge IPs as origin candidates, artificially inflating the candidate
  list and reducing result quality.
- Akamai publishes machine-readable range data via their open-source `akamai-
  edgesuite.net` CNAME pattern and several third-party aggregators (e.g.,
  ipinfo.io ASN data for AS20940, AS16625, AS17334, AS18680, AS22207, AS23454,
  AS24319, AS35994, AS43639, AS55164, AS200005).

**Implementation notes:**
- Add `pkg/cdn/data/akamai-v4.txt` and `pkg/cdn/data/akamai-v6.txt` sourced
  from ipinfo.io bulk ASN export for Akamai's known ASNs.
- Add DNS hint: `edgesuite.net`, `edgekey.net`, `akamaized.net`,
  `akamaitechnologies.com`, `akamai.net` CNAME suffixes.
- Add HTTP header hint: `X-Check-Cacheable` and `X-Akamai-Transformed`.
- Follow existing `buildCloudflare()` pattern for the new provider.
- Update `SnapshotDate` constant after embedding new data.
- Add a `Refresh()` sub-path for Akamai that fetches the ASN prefix list from
  BGPView for AS20940 (primary Akamai ASN) as a live update mechanism.

**References:**
- https://www.aecyberpro.com/blog/general/2024-07-11-Finding-CDN-Origin-Hosts/
- https://www.akamai.com/blog/security-research/what-you-should-know-about-breakingwaf

---

## P1 — Imperva (Incapsula) CDN detection (CDN coverage gap) — ✅ IMPLEMENTED (Phase 2, 2026-05-28)

> Shipped in `pkg/cdn/cdn.go` (`buildImperva`, `isImpervaHeaders`) with embedded
> `pkg/cdn/data/imperva-v4.txt` / `imperva-v6.txt` snapshots sourced from
> Imperva's published edge ranges (primary ASN AS19551). Detection signals:
> `incapdns.net` / `incapdns.com` / `incapsula.com` CNAME suffixes; the
> proprietary `X-Iinfo` response header; `X-CDN: Incapsula`; and the
> `incap_ses` / `visid_incap` session cookies Incapsula sets on every fronted
> response. Mirrors the `buildAkamai()` pattern exactly — registered in `init()`
> and wired into `classifyHeaders` / `collectHeaderSignals`.

**What:** Add Imperva/Incapsula to the CDN provider registry. Imperva is a
top-tier enterprise WAF/CDN; before this change its edge IPs were surfaced as
origin candidates by certificate- and subdomain-based techniques, polluting the
candidate list for any Imperva-fronted target.

**Why P1:**
- Imperva (Incapsula) is one of the most common enterprise WAF/CDN front-ends.
  Its absence from the CDN filter caused false-positive origin candidates —
  the same quality issue Akamai coverage fixed.
- Incapsula leaves an unusually distinctive footprint (`X-Iinfo` header,
  `incap_ses` cookies, `*.incapdns.net` CNAMEs), so detection is high-confidence
  and low-false-positive.
- Self-contained: no API key, no new dependency, pure data + classification.

**References:**
- https://www.imperva.com/ (published edge IP integration endpoint)
- https://docs.imperva.com/ (Incapsula DNS / header signatures)

---

## P2 — FOFA / Netlas / Criminal IP technique integration

**What:** Add optional passive technique backends for FOFA and/or Netlas,
paralleling the existing Censys and Shodan integrations. Both support
certificate-fingerprint queries and favicon hash queries via REST APIs.

**Why P2:**
- FOFA has 4B+ indexed assets; Netlas indexes domain names in addition to IPs
  (broader hit rate for targets not in Shodan/Censys).
- Coverage diversity matters: Shodan and Censys are both US-centric in scanning
  focus; FOFA and ZoomEye provide significantly better coverage of Asian IP
  space (67-72% of FOFA/ZoomEye scan IPs are China-origin) which is important
  for targets hosted in APAC.
- Criminal IP (4.2B+ IPs, AI-powered scoring) provides a free-tier API that
  complements Censys.
- The technique registry pattern makes adding backends straightforward.

**Implementation notes:**
- Add `pkg/techniques/fofacert.go` (FOFA certificate search, API key:
  `FOFA_EMAIL` + `FOFA_KEY`).
- Add `pkg/techniques/netlascert.go` (Netlas certificate search, API key:
  `NETLAS_API_KEY`).
- Criminal IP: add as a third backend inside a single `pkg/techniques/cipasset.go`
  (API key: `CRIMINAL_IP_API_KEY`).
- All three: tier **Passive**, weights **0.80** (FOFA), **0.75** (Netlas),
  **0.70** (Criminal IP). These are tentative; calibrate against real targets.
- Skip gracefully when API key is absent, same pattern as `censys_cert`.
- Document key acquisition in README API keys section.

**References:**
- https://www.securityvision.ru/en/blog/sravnitelnyy-obzor-shodan-zoomeye-netlas-censys-fofa-i-criminal-ip-chast-1/
- https://en.fofa.info/api_tools
- https://netlas.io/features/discovery/
- https://blog.criminalip.io/2024/12/24/criminal-ip-vs-shodan/

---

## P2 — JARM active server fingerprinting technique (`jarm_fingerprint`)

**What:** For each candidate IP, probe port 443 with JARM's 10-probe TLS
handshake sequence. Compute the JARM hash. Compare against the target's JARM
hash (obtained by probing the CDN-fronted target). If the candidate's JARM
matches the target's JARM hash, it is strong evidence that the candidate is the
origin (since CDN edge nodes have very different TLS stacks from origin servers).

**Why P2:**
- JARM is active but makes no application-layer requests to the target — only
  TLS handshakes to candidate IPs. Lower detectability than `host_header`.
- The signal is highly specific: CDN edge servers (Cloudflare, Akamai) use
  hardened, proprietary TLS stacks with distinctive JARM hashes. An origin
  running Nginx/Apache/Caddy will produce a completely different JARM.
- Shodan indexes JARM hashes; cross-referencing candidate JARM against Shodan's
  `ssl.jarm` field could enable a passive variant as well.
- Complements `host_header` by providing corroborating evidence without
  triggering application-level WAF rules.

**Implementation notes:**
- Add `pkg/techniques/jarmfp.go`.
- Tier: **Active** (probes candidate IPs, not the target's public hostname).
- Weight: **0.80** for a match; technique returns no results on mismatch (binary
  signal).
- JARM implementation: pure Go port of the Salesforce JARM algorithm is
  available as `github.com/RumbleDiscovery/jarm-go`. Evaluate license
  compatibility (Apache 2.0 — compatible with unearth's MIT license).
- Also probe the CDN-fronted target to obtain a reference JARM; CDN edge JARM
  hashes are well-known and can be embedded as constants for Cloudflare, Akamai,
  CloudFront, Fastly, and Sucuri.
- Phase-2 consumer: receives candidate IPs from phase-1 techniques, same as
  `host_header`.

**References:**
- https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a/
- https://kc7cyber.com/blog/jarm-fingerprinting
- https://github.com/RumbleDiscovery/jarm-go

---

## P2 — Apex vs. www split-DNS detection technique (`split_dns`)

**What:** Resolve both the apex (`example.com`) and `www.example.com` to their
A/AAAA records. Many organizations proxy only the `www` subdomain through a CDN
but leave the apex in DNS-only mode pointing directly at the origin. If the apex
resolves to a non-CDN IP and `www` resolves to a CDN IP, the apex IP is
flagged as a strong origin candidate.

**Why P2:**
- Documented in multiple 2025 bug-bounty write-ups as one of the most
  consistently productive passive techniques against large organizations.
- Zero API key dependency. Purely DNS-based; no external service calls.
- Extends naturally to a list of common split-DNS patterns: `mail.`, `smtp.`,
  `ftp.`, `direct.`, `origin.`, `backend.` (overlap with `subdomain_enum` but
  with targeted split-resolution comparison logic).
- Lightweight: adds one DNS lookup pair per target.

**Implementation notes:**
- Add `pkg/techniques/splitdns.go`.
- Tier: **Passive**.
- Weight: **0.80** for apex/www mismatch hitting a non-CDN IP. Rationale: when
  this fires, it is almost always the real origin.
- Extend to resolve a short list of mail/admin subdomains and compare against
  current A record to catch partial-proxy configurations.
- Dedup with `subdomain_enum` results at the engine level (existing merge logic
  handles this).

**References:**
- https://herish.me/blog/cloudflare-origin-ip-bypass-misconfiguration/
- https://medium.com/@smitgharat0001/cloudflare-bypass-origin-server-deserves-some-love-too-e8bd2182cfea
- https://maddevs.io/writeups/finding-servers-origin-ip/

---

## P2 — Email header leak technique (`email_header`) — ✅ IMPLEMENTED (passive variant, Phase 2, 2026-05-28)

> Shipped in `pkg/techniques/emailheader.go`. Passive tier, weight 0.85. Parses
> an operator-supplied raw email (`.eml`) via the standard-library `net/mail`
> package, walks the `Received:` header chain, and surfaces every public,
> non-CDN IP literal as an origin candidate. Filters RFC1918 / unique-local,
> loopback, link-local, and multicast addresses, plus any IP in a known CDN
> range. Wired into the CLI as `--email-file <path>` and into the engine via
> `RunOptions.EmailFile`; the technique skips gracefully (no candidates) when no
> file is supplied. The **active** send-a-probe variant is deferred — it needs an
> operator-supplied SMTP relay (`UNEARTH_SMTP_RELAY`) and a canary inbox, which
> is operator infrastructure out of scope for this packet.

**What:** A new aggressive-tier technique that, given a target domain with an
MX record, can optionally send a test email (to a canary inbox controlled by the
operator) or parse a previously received email from that domain's mail
infrastructure. The raw `Received:` headers in email messages often contain
internal IP addresses and mail relay hostnames that bypass CDN fronting.

**Why P2:**
- Email infrastructure is almost never routed through CDN, yet often shares the
  same datacenter or even the same server as the web origin.
- The `Received:` header chain from a real inbound email exposes internal relay
  IPs with very high confidence.
- Passive variant: read `.eml` file from stdin / file flag; parse `Received:`
  headers; return non-RFC1918 IPs as candidates. This passive variant has no
  footprint on the target at all.
- Active variant: send a probe message to a catch-all address at the domain and
  await the bounce or delivery receipt. Higher footprint; document clearly.

**Implementation notes:**
- Add `pkg/techniques/emailheader.go`.
- Tier: **Aggressive** for the active variant (sends mail to the target domain);
  add a `--email-file` flag path for the passive variant (tier: Passive, reads
  an operator-supplied .eml file).
- Weight: **0.85** when a non-RFC1918, non-CDN IP is found in a `Received:`
  chain.
- Passive `.eml` parsing requires no external dependencies: parse via
  `net/mail` standard library.
- The active send variant requires SMTP configuration; defer to an operator-
  supplied SMTP relay via environment variable `UNEARTH_SMTP_RELAY`.

**References:**
- https://www.intigriti.com/researchers/blog/hacking-tools/identifying-servers-origin-ip
- https://undercodetesting.com/bug-bounty-techniques-discovering-origin-ip-to-bypass-waf-protections/

---

## P3 — FOFA / ZoomEye MCP tool expansion

**What:** Expose FOFA and Netlas queries as additional MCP tools in
`unearth-mcp`, alongside the existing `discover`, `check_cdn`, `is_cdn_ip`,
`cache_stats`, and `list_techniques` tools. An AI agent could then directly
query FOFA or Netlas for a target without running a full discovery sweep.

**Why P3:**
- Useful for AI-driven recon workflows; lower urgency than technique-level work.
- Depends on P2 FOFA/Netlas technique integration being done first.

---

## P3 — Bulk target parallelism improvements (pipeline mode)

**What:** When reading from `-l -` (stdin pipeline mode), process targets in a
sliding window rather than one-at-a-time. Allow `--pipeline-batch <n>` to
control the number of concurrent target runs. Current pipeline reads one target,
runs all techniques, outputs, then reads next target.

**Why P3:**
- Unearth is already used in `subfinder | unearth -l -` pipelines per README.
- For large programs with 100s of subdomains, sequential processing is slow.
- The engine is already concurrent at the technique level; lifting the same
  concurrency to the target level is the natural extension.

**References:**
- README pipeline example: `subfinder -d target.com -silent | unearth -l - | jq ...`

---

## P3 — Weight auto-calibration from historical results — ✅ IMPLEMENTED (Phase 2, 2026-05-28)

> Shipped across `pkg/cache/calibration.go` (an `observations` table plus
> `RecordObservations`, `CalibrationStats`, `ResetObservations`,
> `ObservationCount`), `pkg/rank/calibrate.go` (the pure shrinkage estimator
> `Calibrate`), an engine hook in `pkg/unearth/unearth.go` (`buildObservations`
> records one observation per technique contribution after each run, marked
> corroborated when the candidate was found by >1 technique), and the
> `unearth calibrate` CLI subcommand (`cmd/unearth/internal/cli/calibrate.go`)
> with `--yaml` output and a `calibrate reset` child. Because there is no
> external ground truth, the precision proxy is corroboration: how often a
> technique's candidate was independently confirmed by another technique in the
> same run. The suggested weight is a Beta-prior posterior mean (observed rate
> shrunk toward the technique's current weight by a pseudo-count of 20), so
> small samples keep their defaults and are flagged `low-confidence`.
> Recording is best-effort and never affects discovery; `--no-cache` runs
> record nothing.

**What:** Track technique hit rates (true positives vs. total candidates
returned) in the local SQLite cache. After N runs, surface per-technique
precision estimates as suggestions for weight overrides.

**Why P3:**
- The current weights are hand-tuned and may drift as data sources change (e.g.,
  kaeferjaeger coverage growth, Censys index changes).
- Auto-calibration provides operators with data to tune weights for their
  specific target profile (e.g., targets on bare-metal benefit from different
  weights than cloud-hosted targets).

---

## P4 — SSRF-assisted origin discovery integration

**What:** Add an aggressive-tier technique that, given known SSRF gadgets in the
target application (WordPress XML-RPC pingback, common SSRF parameters), can
trigger an outbound connection from the target to a canary server controlled by
the operator. The canary server logs the source IP, which is the real origin.

**Why P4:**
- Very high signal confidence when the canary ping fires — the origin IP reveals
  itself without any inference.
- Requires operator infrastructure (a canary listener). Cannot be self-contained
  without operator setup.
- WordPress pingback is the most automatable variant; add a `--pingback-canary
  <url>` flag that triggers the XML-RPC call and then polls the operator's canary
  for the inbound connection log.
- Out of scope for near-term work without canary infrastructure.

**References:**
- https://infosecwriteups.com/finding-the-origin-ip-behind-cdns-37cd18d5275

---

## P4 — JA4 / HTTP/2 fingerprint matching

**What:** Use JA4 (successor to JA3) to fingerprint the origin server's TLS
stack via probes to candidate IPs, then cross-reference JA4 hashes against
Censys/Shodan's indexed JA4 data to find other hosts presenting the same stack.
Extend to HTTP/2 SETTINGS frame fingerprinting (Akamai-style detection).

**Why P4:**
- JA4 is now industry-standard (adopted by Cloudflare, AWS, Censys, Shodan).
- Implementation requires a stable Go JA4 library; current open-source options
  (`FoxIO-LLC/ja4`) are evolving rapidly. Revisit in 6-12 months when the Go
  ecosystem stabilizes.
- HTTP/2 fingerprinting adds complexity without a clear Go library precedent.

**References:**
- https://www.fastly.com/blog/the-state-of-tls-fingerprinting-whats-working-what-isnt-and-whats-next
- https://medium.com/@ggabrielhd/all-you-need-to-know-about-ja3-ja4-fingerprints-and-how-to-collect-them-8f189085b61f

---

## Landscape summary

The CDN origin-discovery space in mid-2026:

1. **Favicon hash pivoting** has emerged as a high-value technique not yet in
   unearth. Multiple tools (FavHash, CloudFlare-IP, Favihash) target exactly
   this; adding it as a native technique closes the gap.

2. **BreakingWAF** (Dec 2024, Zafran) demonstrated that ASN-range sweeping with
   host-header injection defeats origin protection on ~40% of Fortune 100
   companies. The ASN sweep technique directly operationalizes this finding.

3. **Akamai**, **Imperva (Incapsula)**, and **Azure Front Door** were the
   critical CDN detection gaps in unearth's filter — all now closed. The CDN
   registry covers Cloudflare, CloudFront, Fastly, Sucuri, Akamai, Imperva, and
   Azure Front Door. The remaining notable enterprise front-ends not yet modeled
   are Google Cloud CDN and StackPath/Highwinds — candidate follow-ups for the
   next coverage pass.

   > Azure Front Door shipped Phase 2, 2026-05-28 in `pkg/cdn/cdn.go`
   > (`buildAzureFrontDoor`, `isAzureFrontDoorHeaders`) with embedded
   > `pkg/cdn/data/azurefd-v4.txt` / `azurefd-v6.txt` snapshots sourced from the
   > Microsoft `AzureFrontDoor` service tag. Detection signals:
   > `azurefd.net` / `azureedge.net` / `t-msedge.net` / `trafficmanager.net`
   > CNAME suffixes; the proprietary `X-Azure-Ref` response header; and an
   > `X-Cache` value mentioning the `FrontDoor` cache node. Self-contained: no
   > API key, no new dependency, pure data + classification. Mirrors the
   > `buildAkamai()` / `buildImperva()` pattern exactly.

4. **FOFA, Netlas, Criminal IP** are growing alternatives to Shodan/Censys with
   better APAC coverage and free-tier access. Worth integrating as optional
   backends.

5. **JARM** provides a low-noise active corroboration signal (TLS server
   fingerprint) that complements the existing HTTP host-header bypass.

6. **Split-DNS detection** is underrated: simple, keyless, and consistently
   productive in bug-bounty reports. Low implementation cost.

7. **JA4/HTTP2 fingerprinting** is promising but Go library ecosystem is not
   stable enough to ship in 2026. Revisit H1 2027.
