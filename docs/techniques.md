# Techniques Reference

Each technique is a self-contained recon method that discovers candidate origin IPs for a target. All techniques implement the `techniques.Technique` interface and register themselves via `init()` in `pkg/techniques/`.

This document describes what each technique does, what it queries, and where it falls short.

---

## Passive Techniques

Passive techniques make no connections to the target. They are safe to run in any context.

---

### `ct_fingerprint`

**Tier:** Passive | **Weight:** 0.70 | **API key:** None

**What it does:** Pivots from a target's TLS certificate to candidate origin IPs using two keyless backends:

- **Backend A — kaeferjaeger SNI-IP dataset.** `kaeferjaeger.gay` publishes daily scans of major cloud-provider IPv4 ranges (AWS, Azure, GCP, DigitalOcean, Oracle). Each line maps an IP:port to the certificate SANs observed on that port. The technique downloads and stream-scans these files (total ~640 MB) for lines whose SAN list names the target domain (exact match or wildcard). Datasets are disk-cached under `$XDG_CACHE_HOME/unearth/datasets/` with a 24h staleness check.

- **Backend B — Cert Spotter CT search.** Queries `https://api.certspotter.com/v1/issuances` (keyless tier, ~75 req/hour) for all certificates issued to the target domain. IP-literal SANs are emitted directly; non-wildcard hostname SANs are resolved via DNS and non-CDN IPs are emitted.

Both backends run in parallel. If one fails, the technique returns the other's results. Only both failing returns an error.

**Limitations:**
- Backend A only covers cloud-provider ranges. An origin on a bare-metal server or niche VPS will not appear.
- Backend B can find a certificate but CT logs record issuances, not serving hosts. Hostnames in SANs resolve to whatever they currently point to — which may be the CDN, not the origin.

---

### `crtsh`

**Tier:** Passive | **Weight:** 0.55 | **API key:** None

**What it does:** Queries crt.sh for CT log entries matching `%.target` (all subdomains), extracts hostnames from `common_name` and `name_value` fields, and resolves them via DNS. Non-CDN IPs are returned as candidates.

**Hardening (Packet 5B):**
- Dedicated 90s per-technique timeout (crt.sh latency can exceed 30s under load)
- Retry with exponential backoff + jitter (3 attempts)
- Cert Spotter fallback if crt.sh fails all attempts

**Data source:** `https://crt.sh/?q=%.target&output=json`

**Limitations:** crt.sh is a free community service with variable latency. The technique retries and falls back, but under sustained crt.sh outages may return no results.

---

### `spf_mx`

**Tier:** Passive | **Weight:** 0.50 | **API key:** None

**What it does:** Looks up the target's SPF record (from its TXT records) and MX records, resolves the IP mechanisms and mail server hostnames, and returns non-CDN IPs as origin candidates. The hypothesis: mail infrastructure often shares the same physical host or network as the web origin.

**Limitations:** Only effective when the domain's mail infrastructure overlaps its web infrastructure. SaaS-hosted mail (G Suite, Office 365) produces many false leads that the CDN filter drops, but the technique may still produce misleading candidates.

---

### `subdomain_enum`

**Tier:** Passive | **Weight:** 0.35 | **API key:** None

**What it does:** Resolves a built-in wordlist of common subdomain prefixes (e.g. `origin`, `direct`, `backend`, `api`, `staging`) against the target domain. Subdomains that resolve to non-CDN IPs are returned as origin candidates.

**Limitations:** Coverage is limited to the built-in wordlist. Does not crawl or enumerate; purely dictionary-based. Low weight because many subdomain hits resolve to CDN IPs.

---

### `split_dns`

**Tier:** Passive | **Weight:** 0.80 | **API key:** None

**What it does:** Detects partial-proxy ("split-DNS") misconfigurations. Many organizations route only `www` through a CDN while leaving the apex — or a mail/admin subdomain — in DNS-only mode pointing straight at the origin. The technique resolves the apex and `www` to establish whether a CDN-fronted "front door" exists, then compares it against the apex and a short list of commonly un-proxied siblings (`mail`, `smtp`, `ftp`, `direct`, `origin`, `backend`, `cpanel`, `webmail`). When the front door is CDN-fronted but a sibling resolves to a non-CDN IP, that IP is surfaced as a high-confidence origin candidate. It is purely DNS-based: no contact with the target, no API key, at most one lookup per probed label.

**Why the high weight:** When this signal fires it is almost always the real origin — a non-CDN IP sitting next to a CDN-fronted front door is rarely a coincidence. It is consistently one of the most productive keyless techniques in bug-bounty reports.

**Limitations:** Produces nothing when no CDN front door is present (a fully direct or fully fronted domain yields no signal). Limited to the apex plus the built-in sibling list; it does not perform general subdomain enumeration (`subdomain_enum` covers that, and the engine de-duplicates overlapping candidates).

---

### `email_header`

**Tier:** Passive | **Weight:** 0.85 | **API key:** None

**What it does:** Mines the `Received:` header chain of an operator-supplied raw email message for CDN-bypassed origin IPs. Email infrastructure is almost never routed through the CDN that fronts a website, yet it often shares the same datacenter — or even the same host — as the web origin. Each mail transfer agent stamps a `Received:` header recording the relay hop it accepted the message from, so the chain exposes internal relay IPs with high confidence. Supply a message with `--email-file <path>` (any `.eml` you already possess — a newsletter, a password-reset mail, a bounce). The technique parses it with the standard-library `net/mail` package, extracts every IPv4/IPv6 literal from the `Received:` headers, discards RFC1918 / unique-local, loopback, link-local, multicast and known-CDN addresses, and surfaces the remaining public IPs as origin candidates.

**Why the high weight:** A public, non-CDN IP appearing in a real inbound `Received:` chain is direct evidence of the sender's mail relay — frequently co-located with, or identical to, the web origin. False positives are low because the private/CDN filter removes the common noise.

**Limitations:** Requires the operator to supply an email; it cannot fetch one on its own. Only the passive `.eml` variant is implemented — the active "send a probe and read the bounce" variant needs an operator SMTP relay and a canary inbox and is deferred. The signal is only as good as the supplied message: a forwarded or heavily-relayed mail may bury the origin behind intermediate hops. When no `--email-file` is given the technique skips silently and contributes nothing.

---

### `censys_cert`

**Tier:** Passive | **Weight:** 0.90 | **API key:** `CENSYS_PLATFORM_PAT`

**What it does:** Searches the Censys Platform certificate index for hosts that present a certificate naming the target domain. Returns non-CDN IPs that serve such a certificate.

**Data source:** Censys Platform API (`https://search.censys.io/api/v2/certificates/search`)

**Key requirement:** A Censys Platform personal access token. Free-tier Platform accounts may receive `403 Tier Insufficient` responses — the technique skips those responses rather than failing the run.

**Limitations:** Requires a paid Censys Platform account for full coverage. Free tier is rate-limited and may not return all results.

---

### `fofa_cert`

**Tier:** Passive | **Weight:** 0.80 | **API key:** `FOFA_EMAIL` + `FOFA_KEY`

**What it does:** Fingerprints the target's current TLS leaf certificate (SHA-256), then queries FOFA (`fofa.info`) for every host that serves a certificate containing that fingerprint. Non-CDN hits are surfaced as origin candidates — the same cert-pivot idea as `censys_cert` / `shodan_cert`, against a different index.

**Data source:** FOFA search API (`https://fofa.info/api/v1/search/all`). The query (`cert="<sha256>"`) is base64-encoded into the `qbase64` parameter; the email + key pair authenticate as query parameters. The request asks for the single `ip` field, so each result row is one host address (a trailing `:port` is stripped before parsing).

**Why it complements Censys/Shodan:** Shodan and Censys are both US-centric in scanning focus. FOFA indexes 4B+ assets with substantially heavier APAC coverage, so a meaningful fraction of targets hosted in Asia appear in FOFA but not in Shodan/Censys. The value is reach, not redundancy — and a FOFA hit corroborating a Censys/Shodan hit on the same fingerprint raises confidence under the noisy-OR ranking.

**Key requirement:** Both `FOFA_EMAIL` and `FOFA_KEY` must be present; with either missing the technique skips gracefully (exactly like `censys_cert` / `shodan_cert`). When a FOFA account is out of query quota the API answers `HTTP 200` with an `error` flag and a quota message — the technique treats that as a clean tier-insufficient skip, not a run failure.

**Limitations:** FOFA's certificate match is a substring match against the indexed certificate text rather than a structured fingerprint field, so a hit means the fingerprint hex appears in the cert FOFA indexed for that host. Free-tier accounts are quota-limited and may not return all pages; this technique fetches a single page of up to 100 results to stay within free-tier budgets.

### `netlas_cert`

**Tier:** Passive | **Weight:** 0.75 | **API key:** `NETLAS_API_KEY`

**What it does:** Fingerprints the target's current TLS leaf certificate (SHA-256), then queries Netlas (`netlas.io`) for every indexed response whose certificate carries that fingerprint. Non-CDN hits are surfaced as origin candidates — the same cert-pivot idea as `censys_cert` / `shodan_cert` / `fofa_cert`, against a fourth independent index.

**Data source:** Netlas responses search API (`https://app.netlas.io/api/responses/`). The query (`certificate.fingerprints.sha256:<sha256>`) is passed in the `q` parameter and the key authenticates via the `X-API-Key` header. Each result item carries a `data.ip` field, which is parsed into a candidate (CDN edge IPs are filtered).

**Why it complements Censys/Shodan/FOFA:** Netlas indexes domain names alongside IPs and maintains its own internet-wide scan corpus that overlaps only partially with the other three. A misconfigured origin that leaks its real certificate may surface in Netlas when it is absent from Shodan, Censys, and FOFA — and a Netlas hit corroborating another source on the same fingerprint raises confidence under the noisy-OR ranking. The value is coverage diversity, not redundancy.

**Key requirement:** `NETLAS_API_KEY` must be present; without it the technique skips gracefully (exactly like the other keyed cert pivots). Netlas offers a free tier with a daily request allowance — when that allowance is exhausted the API answers `HTTP 429` (or a quota message in a `200` envelope), which the technique treats as a clean tier-insufficient skip rather than a run failure. An invalid key degrades to a clean missing-key skip.

**Limitations:** This technique fetches a single page of up to 100 results to stay within free-tier budgets, so targets with very large certificate-sharing sets may be truncated. Netlas's free tier covers the response search used here; some advanced query operators are reserved for paid plans and are not relied upon.

### `criminalip_asset`

**Tier:** Passive | **Weight:** 0.70 | **API key:** `CRIMINALIP_API_KEY`

**What it does:** Fingerprints the target's current TLS leaf certificate (SHA-256), then queries Criminal IP (`criminalip.io`) for every indexed asset whose banner carries that certificate fingerprint. Non-CDN hits are surfaced as origin candidates — the same cert-pivot idea as `censys_cert` / `shodan_cert` / `fofa_cert` / `netlas_cert`, against a fifth independent index.

**Data source:** Criminal IP banner search API (`https://api.criminalip.io/v1/banner/search`). The query (`certificate: <sha256>`) is passed in the `query` parameter and the key authenticates via the `x-api-key` header. Each result carries a `data.result[].ip_address` field, which is parsed into a candidate (CDN edge IPs are filtered).

**Why it complements the other engines:** Criminal IP runs its own AI-scored internet-wide scan corpus over 4.2B+ IPs, overlapping only partially with Shodan, Censys, FOFA, and Netlas. A misconfigured origin that leaks its real certificate may surface in Criminal IP when it is absent from the others — and a Criminal IP hit corroborating another source on the same fingerprint raises confidence under the noisy-OR ranking. The value is coverage diversity, not redundancy.

**Key requirement:** `CRIMINALIP_API_KEY` must be present; without it the technique skips gracefully (exactly like the other keyed cert pivots). Criminal IP offers a free tier with a monthly request allowance — when that allowance is exhausted, or the plan lacks the banner-search capability, the API answers with a quota/permission message (frequently `HTTP 200` carrying a non-200 `status` field), which the technique treats as a clean tier-insufficient skip rather than a run failure. An invalid key degrades to a clean missing-key skip.

**Limitations:** This technique fetches a single page of results to stay within free-tier budgets, so targets with very large certificate-sharing sets may be truncated. Criminal IP's free tier covers the banner search used here; some advanced search operators are reserved for paid plans and are not relied upon.

---

### `binaryedge_cert`

**Tier:** Passive | **Weight:** 0.72 | **API key:** `BINARYEDGE_API_KEY`

**What it does:** Fingerprints the target's current TLS leaf certificate (SHA-1), then queries BinaryEdge (`binaryedge.io`) for every scanned service whose certificate carries that fingerprint. Non-CDN hits are surfaced as origin candidates — the same cert-pivot idea as `censys_cert` / `shodan_cert` / `fofa_cert` / `netlas_cert` / `criminalip_asset`, against a sixth independent index.

**Data source:** BinaryEdge host search API (`https://api.binaryedge.io/v2/query/search`). The query (`ssl.cert.as_dict.fingerprint.sha1:<sha1>`) is passed in the `query` parameter and the key authenticates via the `X-Key` header. Each result carries an `events[].target.ip` field, which is parsed into a candidate (CDN edge IPs are filtered). Results are paginated by the `page` parameter until the reported `total` is covered.

**Why it complements the other engines:** BinaryEdge runs its own continuous internet-wide scan grid, overlapping only partially with Shodan, Censys, FOFA, Netlas, and Criminal IP. Notably, BinaryEdge indexes the leaf cert's **SHA-1** fingerprint (the same flavor Shodan uses) rather than the SHA-256 the Censys/FOFA/Netlas/Criminal IP pivots rely on, so it both broadens reach and corroborates the SHA-1 pivot from a second source. A misconfigured origin that leaks its real certificate may surface in BinaryEdge when it is absent from the others — the value is coverage diversity, not redundancy.

**Key requirement:** `BINARYEDGE_API_KEY` must be present; without it the technique skips gracefully (exactly like the other keyed cert pivots). BinaryEdge offers a free tier with a monthly request allowance — when that allowance is exhausted, or the plan lacks the search capability, the API answers `HTTP 429`/`403` (or a quota/permission message), which the technique treats as a clean tier-insufficient skip rather than a run failure. An invalid key/token degrades to a clean missing-key skip.

**Limitations:** BinaryEdge's free tier covers the host search used here; some operators and result depth are reserved for paid plans. Pagination follows the API's reported `total`, so extremely large certificate-sharing sets consume more of the monthly allowance.

---

### `leakix_cert`

**Tier:** Passive | **Weight:** 0.71 | **API key:** `LEAKIX_API_KEY`

**What it does:** Fingerprints the target's current TLS leaf certificate (SHA-1), then queries LeakIX (`leakix.net`) for every scanned service whose certificate carries that fingerprint. Non-CDN hits are surfaced as origin candidates — the same cert-pivot idea as `censys_cert` / `shodan_cert` / `fofa_cert` / `netlas_cert` / `criminalip_asset` / `binaryedge_cert`, against a seventh independent index.

**Data source:** LeakIX search API (`https://leakix.net/search`). The query (`ssl.certificate.fingerprint:"<sha1>"`) is passed in the `q` parameter, the service scope is selected with `scope=service`, and the key authenticates via the `api-key` header. The success response is a bare JSON array of service events; each event's `ip` field (with a fallback to `host`) is parsed into a candidate (CDN edge IPs are filtered). Results are paged via the `page` parameter; paging stops on the first short page since LeakIX reports no total count.

**Why it complements the other engines:** LeakIX runs its own continuous internet-wide scan and exposure index, overlapping only partially with Shodan, Censys, FOFA, Netlas, Criminal IP, and BinaryEdge. Like Shodan and BinaryEdge, LeakIX indexes the leaf cert's **SHA-1** fingerprint rather than the SHA-256 the Censys/FOFA/Netlas/Criminal IP pivots rely on, so it both broadens reach and corroborates the SHA-1 pivot from a third source. A misconfigured origin that leaks its real certificate may surface in LeakIX when it is absent from the others — the value is coverage diversity, not redundancy.

**Key requirement:** `LEAKIX_API_KEY` must be present; without it the technique skips gracefully (exactly like the other keyed cert pivots). LeakIX offers a free tier with a daily request allowance — when that allowance is exhausted, or the plan lacks the search capability, the API answers `HTTP 429`/`403` (or a quota/permission message, sometimes `HTTP 200` carrying an `error`/`message` field), which the technique treats as a clean tier-insufficient skip rather than a run failure. An invalid key/token degrades to a clean missing-key skip.

**Limitations:** LeakIX's free tier covers the search used here; deeper result pages and some plugins are reserved for paid plans. Because LeakIX reports no total-result count, pagination relies on a page-fill heuristic and a hard page ceiling, so extremely large certificate-sharing sets may be truncated.

---

### `fullhunt_asset`

**Tier:** Passive | **Weight:** 0.70 | **API key:** `FULLHUNT_API_KEY`

**What it does:** Queries FullHunt (`fullhunt.io`) for the host inventory it has crawled under the target apex domain and surfaces the non-CDN IPs FullHunt observed for those hosts as origin candidates. **This is not a certificate-fingerprint pivot.** Unlike the seven cert engines (`censys_cert` / `shodan_cert` / `fofa_cert` / `netlas_cert` / `criminalip_asset` / `binaryedge_cert` / `leakix_cert`), FullHunt's public API has no cert-fingerprint search; it is an attack-surface enumerator that maps a domain to the hosts and IPs it has discovered.

**Data source:** FullHunt domain-details API (`https://fullhunt.io/api/v1/domain/{domain}/details`). The target domain is the path parameter and the key authenticates via the `X-API-KEY` header. The response is a single object envelope carrying a `hosts[]` array; each host's `ip_address` field (a JSON array of strings, with a defensive single-string fallback) is parsed into candidates (CDN edge IPs are filtered, IPs deduped). The full inventory arrives in one response, so no pagination is needed.

**Why it complements the cert engines:** FullHunt's corpus is a different kind, not a redundant one. The cert engines find hosts presenting the *same leaf certificate* the live target serves; FullHunt finds every host *under the same domain* it has crawled and the IPs behind them. A misconfigured origin that never reused the front-door certificate — so the cert pivots miss it — can still appear in FullHunt's historical inventory (e.g. an `origin.example.com` or `direct.example.com` record pointing straight at the backend). The non-CDN IPs FullHunt recorded for those hosts become origin candidates.

**Key requirement:** `FULLHUNT_API_KEY` must be present; without it the technique skips gracefully. FullHunt offers a free tier with a monthly request allowance — when that allowance is exhausted, or the plan lacks the endpoint, the API answers `HTTP 429`/`403` (or a quota/permission message, sometimes `HTTP 200` carrying a `message`/`error` field), which the technique treats as a clean tier-insufficient skip rather than a run failure. An invalid key degrades to a clean missing-key skip.

**Limitations:** FullHunt's free tier covers the domain-details endpoint used here; deeper subdomain and host-detail data are reserved for paid plans. The inventory is only as current as FullHunt's last crawl of the domain, and only hosts FullHunt has discovered are returned — a brand-new or obscure origin record may not yet be indexed.

---

### `chaos_asset`

**Tier:** Passive | **Weight:** 0.66 | **API key:** `PDCP_API_KEY`

**What it does:** Queries ProjectDiscovery's Chaos dataset (`chaos.projectdiscovery.io` — the same corpus that powers `subfinder`) for the subdomains it has catalogued under the target apex, resolves each one, and surfaces the non-CDN IPs behind them as origin candidates. **This is not a certificate-fingerprint pivot.** Like `fullhunt_asset` and `zoomeye_asset`, it is an asset enumerator, not a cert engine.

**Data source:** Chaos dataset DNS API (`https://dns.projectdiscovery.io/dns/{domain}/subdomains`). The target domain is the path parameter and the key authenticates via the `Authorization` header. The response is a single envelope carrying a `subdomains[]` array of bare, apex-relative labels (e.g. `origin` for `origin.example.com`). The whole list arrives in one response, so no pagination is needed.

**How it differs from the other asset backends:** `fullhunt_asset` and `zoomeye_asset` return host→IP records directly; Chaos returns only subdomain *names*. The technique therefore reassembles each label into a fully qualified hostname under the apex and resolves it with the shared resolver (the same one the other passive DNS techniques use). The non-CDN IPs the resolver returns become candidates. To keep the DNS fan-out bounded, at most the first 256 subdomains (sorted for determinism) are resolved per run.

**Why it complements the other engines:** Chaos's corpus is a different lineage, not a redundant one. It is aggregated from public bug-bounty programs, certificate transparency, and community contributions rather than from active internet-wide scanning. A forgotten origin record — `origin.example.com`, `direct.example.com`, a stale `dev.`/`mail.` host — that never reused the front-door certificate (so the cert pivots miss it) but that ProjectDiscovery has catalogued will surface here, resolved to its backend IP.

**Key requirement:** `PDCP_API_KEY` must be present (the legacy `CHAOS_API_KEY` and `UNEARTH_PDCP_API_KEY` aliases are also accepted); without it the technique skips gracefully. ProjectDiscovery offers a free tier — when the request allowance is exhausted, or the plan lacks the endpoint, the API answers `HTTP 429`/`403` (or a quota/permission message, sometimes `HTTP 200` carrying a `message`/`error` field), which the technique treats as a clean tier-insufficient skip rather than a run failure. An invalid key degrades to a clean missing-key skip.

**Limitations:** Chaos returns names, not addresses, so a subdomain whose record has since been deleted or repointed resolves to nothing (or to the current, possibly CDN-fronted, address) and contributes no useful candidate. The dataset is only as fresh as ProjectDiscovery's last ingestion, and only subdomains it has catalogued are returned. The 256-subdomain resolve cap means very large apex domains are sampled rather than exhaustively resolved.

---

### `virustotal_passivedns`

**Tier:** Passive | **Weight:** 0.67 | **API key:** `VIRUSTOTAL_API_KEY`

**What it does:** Queries VirusTotal's v3 passive-DNS endpoint for every historical hostname→IP observation VirusTotal has accumulated for the target apex domain and surfaces the non-CDN IPs as origin candidates. **This is not a certificate-fingerprint pivot.** Like `fullhunt_asset`, `zoomeye_asset`, and `chaos_asset`, it is an asset enumerator, not a cert engine — but unlike all three, it operates on a *temporal* corpus: each observation carries the date it was last seen, so origins that have since rotated out of DNS can still surface.

**Data source:** VirusTotal v3 API (`https://www.virustotal.com/api/v3/domains/{domain}/resolutions`). The target apex is the path parameter and the key authenticates via the `x-apikey` header. The response envelope is `{"data":[{"attributes":{"ip_address","host_name","date"}},…],"meta":{"cursor"},"links":{"next"}}`. Pagination is cursor-based (`?cursor=…`), and the technique walks pages up to a hard 25-page ceiling.

**How it differs from the other asset backends:** Unlike `chaos_asset` (which returns subdomain *names* and must resolve each one itself), VirusTotal returns the IP directly under `attributes.ip_address`. The technique therefore makes no DNS lookups at all — the target is never contacted, only VirusTotal's API is — which keeps results deterministic for caching and the footprint on the target at zero.

**Why it complements the other engines:** the eight certificate-fingerprint engines pivot on the target's *current* leaf certificate, so they miss any origin that rotated its certificate, never reused the front-door cert, or was decommissioned. The three other asset enumerators pivot on host inventories indexed at the time of their last crawl. VirusTotal's passive-DNS corpus is *temporal*: it preserves hostname→IP observations going back years, harvested from URL scans, file submissions, and integrated DNS feeds. A forgotten `origin.example.com` record from three years ago — one no cert engine ever touched and no asset crawler recorded — can still surface here with its last-observed date. Coverage diversity along an axis the other backends don't reach.

**Key requirement:** `VIRUSTOTAL_API_KEY` must be present (the `VT_API_KEY` and `UNEARTH_VIRUSTOTAL_API_KEY` aliases are also accepted); without it the technique skips gracefully. VirusTotal's free public tier has a strict allowance (currently ~500 requests/day and 4 requests/minute) — when the per-minute or daily quota is exhausted, or the account lacks the v3 endpoint, the API answers `HTTP 429`/`403` (or a 4xx body carrying an `error.code` of `QuotaExceededError`/`TooManyRequestsError`/`UserNotActiveError`), which the technique treats as a clean tier-insufficient skip rather than a run failure. A missing/invalid key (`HTTP 401`, `AuthenticationRequiredError`, `WrongCredentialsError`) degrades to a clean missing-key skip; an `HTTP 404` (no resolutions known for the apex) is a clean empty success, not an error.

**Why VirusTotal over Hunter.io:** Hunter.io was the alternative considered for this slot. Hunter's API is an email-address finder — it returns people and email addresses associated with a domain, a different axis than asset discovery (and a less useful one for origin-IP hunting, since email infrastructure is already covered by the `email_header` and `spf_mx` techniques and the path from `person@domain` to origin-server-IP is indirect at best). VirusTotal's passive-DNS endpoint, by contrast, adds the one coverage axis the existing eleven asset/cert backends lack: temporal history.

**Limitations:** VirusTotal's corpus is observation-based — it only contains IPs that VirusTotal's scanners or partners actually saw resolve for the apex. A target that has always been CDN-fronted, with no historical DNS leak, will return only CDN edge IPs (all filtered) and contribute no candidates. The free-tier rate limit (4 req/min) makes high-fan-out pipeline runs slow; for large target lists, consider running this technique in a separate pass or with a paid tier. Cursor pagination is capped at 25 pages to prevent runaway pulls; for apex domains with deep history this means VirusTotal's first ~1000 most-recent observations, not the entire dataset.

---

### `urlscan_asset`

**Tier:** Passive | **Weight:** 0.66 | **API key:** `URLSCAN_API_KEY`

**What it does:** Queries URLScan.io's search API for every public browser-rendered scan submission ever recorded against the target apex domain and surfaces the non-CDN page-serving IPs as origin candidates. **This is not a certificate-fingerprint pivot.** Like `fullhunt_asset`, `zoomeye_asset`, `chaos_asset`, and `virustotal_passivedns`, it is an asset enumerator, not a cert engine — but unlike all four, it operates on a *user-submitted browser-scan* corpus: every scan record carries the IP the page actually served from at the moment a real browser rendered it.

**Data source:** URLScan.io API (`https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100`). The key authenticates via the `API-Key` header. The response envelope is `{"results":[{"page":{"ip","domain","url","asnname"},"task":{"time"},"sort":[…]},…],"total","has_more"}`. Pagination is deep-cursor-based (`?search_after=`, derived from the last result's `sort` array), and the technique walks pages until URLScan flags `has_more:false` or a hard 10-page ceiling (1000 results max) is reached.

**How it differs from the other asset backends:** Unlike `chaos_asset` (which returns subdomain *names* and must resolve each one itself), URLScan returns the page-serving IP directly under `page.ip`. The technique therefore makes no DNS lookups at all — the target is never contacted, only URLScan's API is — which keeps results deterministic for caching and the footprint on the target at zero. Unlike `virustotal_passivedns` (which records every passive-DNS resolution VirusTotal's partners ever saw), URLScan only records IPs that were *actually rendered* by a real browser at scan time, so its hits are higher-confidence at a smaller corpus size.

**Why it complements the other engines:** the eight certificate-fingerprint engines pivot on the target's *current* leaf certificate, so they miss any origin that rotated its certificate, never reused the front-door cert, or was decommissioned. The three host-inventory enumerators pivot on what active scan grids observed at crawl time. VirusTotal's passive-DNS corpus records resolutions observed in network telemetry. URLScan's corpus records *what a browser actually rendered* — community-submitted PhishTank entries, SOC playbook automation, manual lookups, URLScan's own crawler. A misconfigured origin that *briefly* leaked from behind a CDN — a five-minute deploy cutover, a CDN outage, a quietly-shipped `direct.example.com` shortcut someone submitted to URLScan once — is preserved here even though the cert engines, scan grids, and passive-DNS feeds never recorded it. Coverage diversity along yet another orthogonal axis.

**Key requirement:** `URLSCAN_API_KEY` must be present (the `UNEARTH_URLSCAN_API_KEY` alias is also accepted); without it the technique skips gracefully. URLScan offers a free tier with a generous monthly request allowance — when that allowance is exhausted, or the plan lacks the search capability, the API answers `HTTP 429`/`403` (or a 4xx body carrying a `message`/`description` envelope mentioning `rate limit`/`quota`/`upgrade`/`forbidden`), which the technique treats as a clean tier-insufficient skip rather than a run failure. A missing/invalid key (`HTTP 401`, or a `message`/`description` envelope mentioning `Invalid API key`/`unauthorized`/`API-Key required`) degrades to a clean missing-key skip.

**Why URLScan over Shodan Monitor:** Shodan Monitor was the alternative considered for this slot. Monitor is Shodan's *alerting* product — it watches netblocks the operator has pre-registered and notifies on changes. It is not an asset-discovery surface for an unknown origin, in the same way Hunter.io is not (Hunter is an email-address axis). For unearth's job — "given a CDN-fronted domain, find the origin IP behind it" — Monitor adds nothing that the existing `shodan_cert` backend doesn't already cover, because the operator has to know the netblock in advance to register an alert. URLScan.io's search endpoint, by contrast, adds the one corpus the existing twelve cert / asset / passive-DNS backends lack: the *moment-in-time browser-rendered scan record*.

**Limitations:** URLScan's corpus is submission-based — it only contains IPs from scans that were actually submitted (manually or programmatically). A target that has always been CDN-fronted, with no historical browser scan capturing an origin leak, will return only CDN edge IPs (all filtered) and contribute no candidates. The free-tier monthly allowance makes high-fan-out pipeline runs feasible but not unlimited; for large target lists, monitor your URLScan dashboard. Deep paging is capped at 10 pages to prevent runaway pulls; for very popular apex domains this means URLScan's first ~1000 most-recent scans, not the entire dataset.

---

### `otx_passivedns`

**Tier:** Passive | **Weight:** 0.64 | **API key:** **none required** (optional `OTX_API_KEY` lifts the anonymous rate limit)

**What it does:** Queries AlienVault OTX's passive-DNS endpoint for every historical hostname → IP observation OTX has accumulated for the target apex domain and surfaces the non-CDN IPs as origin candidates. **This is not a certificate-fingerprint pivot.** Like `fullhunt_asset`, `zoomeye_asset`, `chaos_asset`, `virustotal_passivedns`, and `urlscan_asset`, it is an asset enumerator, not a cert engine — and like `virustotal_passivedns` it is a *passive-DNS* enumerator specifically, but operating on a corpus distinct from VirusTotal's.

**Data source:** AlienVault OTX API (`https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns`). The endpoint is anonymous-accessible; when `OTX_API_KEY` is supplied it is sent as the `X-OTX-API-KEY` header. The response envelope is `{"passive_dns":[{"address","hostname","record_type","first","last","asn"},…],"count"}`. Records whose `record_type` is anything other than `A` or `AAAA` (e.g. CNAME, NS, MX) are filtered out so only routable origin IPs surface; the technique makes a single request per target — no pagination.

**How it differs from the other asset backends:** Two distinct axes set OTX apart. First, **corpus lineage.** Every other backend pivots on infrastructure data harvested by scanners (Censys/Shodan/FOFA/Netlas/Criminal IP/BinaryEdge/LeakIX/Onyphe internet-wide scans), crawl inventories (FullHunt/ZoomEye/Chaos), URL/file submissions (VirusTotal, URLScan). OTX's passive-DNS corpus is *threat-intelligence telemetry*: the aggregate of OTX's own honeypot/sensor network, community-submitted analyst "pulse" indicator feeds (curated IoC bundles describing real-world campaigns), and partner DNS telemetry. An IP invisible to every scanner-driven backend can appear in OTX because a defender posted a pulse mentioning it, or an OTX honeypot logged a callback to it. Second, **anonymous access.** OTX is the only backend in the suite that runs without credentials — the public passive-DNS endpoint is rate-limited per source IP rather than gated on an API key. That makes `otx_passivedns` the floor-coverage backend every key-less deployment gets for free.

**Why it complements the other engines:** the eight certificate-fingerprint engines pivot on the target's *current* leaf certificate, so they miss any origin that rotated its certificate, never reused the front-door cert, or was decommissioned. The four host-inventory/browser-scan enumerators pivot on what active scan grids and community submissions observed at crawl time. VirusTotal's passive-DNS corpus records resolutions observed in network telemetry from scanner submissions and partner feeds. OTX's corpus records resolutions observed in *defensive* telemetry — honeypot callbacks, analyst-curated campaign IoCs, partner DNS feeds OTX has separately negotiated. A C2 origin briefly flagged by a defender's pulse, an attacker-staged "throwaway" origin observed in an OTX honeypot, an old hostname referenced in a years-old campaign report — all can surface here even though no scanner ever indexed them. Like `virustotal_passivedns`, OTX returns the IP directly under `address`, so there is no second-stage DNS fan-out; the target is never contacted, only `otx.alienvault.com` is.

**Why OTX over FOFA / Netlas (the R32 packet's original suggestion):** the codebase audit at R32 start showed FOFA (`fofa_cert`) and Netlas (`netlas_cert`) were already shipped in earlier packets — the post-v0.1 directions file (`POST_V01.md`) was stale on this point. Criminal IP (`criminalip_asset`), BinaryEdge (`binaryedge_cert`), LeakIX (`leakix_cert`), Onyphe (`onyphe_cert`), FullHunt (`fullhunt_asset`), ZoomEye (`zoomeye_asset`), Chaos (`chaos_asset`), VirusTotal (`virustotal_passivedns`), and URLScan (`urlscan_asset`) were also all already shipped. SecurityTrails passive DNS is covered via the existing `dns_history` technique. OTX was selected as the next-best unshipped backend on two grounds the others cannot match: a distinct threat-intel corpus that no scanner-driven engine indexes, and zero-credential operation that lifts every key-less deployment's floor coverage.

**Key requirement:** **none.** The technique runs anonymously by default. If `OTX_API_KEY` (also accepted as `ALIENVAULT_OTX_API_KEY` and `UNEARTH_OTX_API_KEY`) is supplied, the request is authenticated, lifting the per-IP anonymous rate limit and identifying the caller for OTX's plan-level allowance. A missing key is **never** an error; a supplied bad key degrades to a clean missing-key skip (`HTTP 401`, or a `detail` envelope mentioning `Invalid API key`/`unauthorized`/`credentials`). Rate-limit/quota responses (`HTTP 429`/`403`, or a 4xx carrying a `detail`/`error`/`message` envelope mentioning `throttle`/`rate limit`/`upgrade`/`forbidden`) degrade to a clean tier-insufficient skip; `HTTP 404` (OTX has no record for this apex) is a clean empty success.

**Limitations:** OTX's corpus is telemetry-based — coverage is uneven, weighted toward apex domains that have appeared in security incidents, malware campaigns, or analyst pulses. A purely-benign target that has never appeared in any threat-intel context may have a sparse or empty OTX record (the technique then contributes no candidates, which is the correct behavior). The anonymous rate limit is per-source-IP and modest; high-fan-out pipeline runs from a single host benefit from supplying a key. Non-A/AAAA records in the `passive_dns` array (CNAME/NS/MX) are intentionally skipped — they would not yield routable origin IPs.

---

### `dns_history`

**Tier:** Passive | **Weight:** 0.65 | **API key:** `SECURITYTRAILS_API_KEY` or `VIEWDNS_API_KEY`

**What it does:** Queries historical DNS A and AAAA records for the target domain. Before a domain moved to a CDN, its A record pointed directly at the origin IP. Historical records expose that IP.

**Data sources:**
- SecurityTrails API (preferred; returns more history)
- ViewDNS.info API (fallback)

**Limitations:** Only finds IPs that the domain pointed to before the CDN was added. If the origin IP has changed since the CDN was deployed, this technique won't find it. Both data sources are rate-limited and require an API key.

---

## Active Techniques

Active techniques make direct TCP/HTTP connections to *candidate IPs*, not to the target's public hostname. They never appear in the target's access logs under normal operation. Enabled with `--active`.

---

### `host_header`

**Tier:** Active | **Weight:** 0.85 | **API key:** None

**What it does:** For each candidate IP (from phase-1 techniques), makes an HTTP GET request with `Host: target` to port 443 (TLS, skip-verify). A response that mirrors the target's content and lacks CDN-identifying headers is strong evidence that the IP is the real origin.

**Phase-2 consumer:** This is a phase-2 technique — it receives the pool of candidate IPs from phase-1 producers, not from the network. An empty phase-1 result means it has nothing to probe.

**Limitations:** Requires at least one phase-1 candidate IP. Origins running on non-standard ports or requiring specific SNI for TLS may not respond. Very aggressive rate limiting on the origin may cause false negatives.

---

### `banner_grab`

**Tier:** Active | **Weight:** 0.45 | **API key:** None

**What it does:** For each candidate IP, attempts SSH banner grab (port 22) and HTTP/S banner grab (port 80/443). Returns the candidate if the banner uniquely identifies the origin application and does not match CDN patterns.

**Phase-2 consumer:** Same as `host_header` — uses phase-1 candidate pool.

**Limitations:** Low weight because banners are not a reliable origin signal — many CDNs pass through application banners. More useful as corroborating evidence than a primary signal.

---

### `shodan_cert`

**Tier:** Active | **Weight:** 0.85 | **API key:** `SHODAN_API_KEY`

**What it does:** Searches Shodan's certificate index for hosts whose TLS certificate names the target domain. Returns non-CDN IPs.

**Data source:** Shodan API (`https://api.shodan.io/shodan/host/search`)

**Limitations:** Shodan's scan coverage depends on their crawl frequency and target selection. Some ranges are crawled less frequently. Free Shodan accounts may not have access to the `ssl.cert.subject.cn` filter — the technique degrades gracefully with a `tier_insufficient` skip reason.

---

### `favicon_hash`

**Tier:** Active | **Weight:** 0.75 | **API key:** `SHODAN_API_KEY` or `CENSYS_PLATFORM_PAT` (either is sufficient)

**What it does:** Fetches the target's `/favicon.ico` (HTTPS, with an HTTP fallback) and computes its MurmurHash3 using Shodan's convention — `mmh3` over the standard-base64 encoding of the raw favicon bytes, line-wrapped at 76 columns with a trailing newline, taken as a signed 32-bit integer. It then queries Shodan (`http.favicon.hash:<hash>`) and/or Censys (`services.http.response.favicons.hashes`) for every other host presenting the same favicon. Non-CDN hits are origin candidates.

**Why it complements cert pivots:** A favicon hash is stable across IP moves and TLS-certificate rotations. A host that rotated its certificate is invisible to `shodan_cert` / `censys_cert` but is still caught here, because its application favicon rarely changes between moves.

**Data source:** the target's own `/favicon.ico`, plus the Shodan host-search and Censys Platform global-search APIs.

**Limitations:** False positives rise when the target uses a stock framework favicon (e.g. a default admin-panel icon) shared by many unrelated hosts — the existing CDN filter removes edge nodes but not unrelated origins. Targets without a favicon produce no candidates (a graceful no-op, not an error). Requires at least one of the two API keys; with neither configured the technique skips gracefully, exactly like `shodan_cert` and `censys_cert`.

---

### `jarm_fingerprint`

**Tier:** Active | **Weight:** 0.70 | **API key:** None

**What it does:** JARM is the Salesforce active TLS server-fingerprinting method. The technique sends ten hand-crafted TLS ClientHello packets — each varying the protocol version, cipher ordering (forward, reverse, top/bottom half, middle-out), extension ordering, GREASE values, and ALPN set — and folds the server's ten handshake responses into a single 62-character fingerprint. Because the fingerprint is derived purely from *how* a server negotiates TLS, two hosts running the same server software and configuration produce the same JARM even when their certificates and IPs differ.

For origin discovery the technique first probes the target hostname to obtain a reference JARM, then probes each phase-1 candidate IP. A candidate whose JARM equals the reference is surfaced as a likely origin. A CDN edge node (Cloudflare, CloudFront, Fastly, Akamai) presents a distinctive, hardened JARM that differs from a stock Nginx/Apache/Caddy origin, so the match is a low-noise corroborating signal.

**Phase-2 consumer:** Like `host_header`, this is a phase-2 technique — it draws its candidate pool from the phase-1 producers (`RunOptions.SeedIPs`) rather than discovering its own. An empty phase-1 result means it has nothing to validate.

**CDN-signature guard:** unearth ships an embedded table of well-known CDN-edge JARM signatures. Any candidate whose JARM matches a CDN signature is rejected outright (it is another edge node, not the origin), and CDN-range seed IPs are skipped before a handshake is ever opened.

**Data source:** direct TLS handshakes to candidate IPs and one reference handshake to the target — no application-layer request is made, so the technique never appears in the target's HTTP access logs. Self-contained, with no third-party API and no external module dependency.

**Limitations:** Requires at least one phase-1 candidate IP and a target that completes a TLS handshake on port 443 (a plain-HTTP or closed-443 target yields no reference and therefore no candidates). Two unrelated hosts running identically configured TLS stacks can collide on the same JARM, so the signal is strongest as corroboration alongside `host_header` rather than as a lone hit — hence the conservative 0.70 weight.

---

## Aggressive Techniques

Aggressive techniques touch the target directly. They may appear in the target's logs or trigger security monitoring. Enabled with `--aggressive` (implies `--active`).

---

### `error_page`

**Tier:** Aggressive | **Weight:** 0.60 | **API key:** None

**What it does:** Sends deliberately malformed or misconfigured HTTP requests to the target to provoke error pages that leak origin server information — stack traces, server headers, or IP addresses that CDN error pages do not intercept.

**Limitations:** Requires the target to serve an error page without full CDN interception. Many modern CDN configurations intercept all 4xx/5xx responses. Moderate weight because the signal (when it fires) is reliable, but it doesn't fire often.

---

### `ipv6_probe`

**Tier:** Aggressive | **Weight:** 0.70 | **API key:** None

**What it does:** Resolves the target's AAAA (IPv6) records. Some CDNs front only the IPv4 address of a dual-stack origin, leaving the IPv6 address exposed. Returns non-CDN IPv6 addresses as origin candidates.

**Limitations:** Only effective for dual-stack origins. Most modern CDN deployments also front IPv6. The signal is reliable when it fires — a non-CDN IPv6 address almost certainly is the origin — but it fires infrequently.

---

## Weight Overrides

Default weights are in `configs/default-weights.yaml` and embedded in the binary. To override for a specific run:

```sh
# Create an override file
cat > my-weights.yaml <<EOF
censys_cert: 0.95
crtsh: 0.40
EOF

unearth --weights my-weights.yaml example.com
```

The user-level override file at `$XDG_CONFIG_HOME/unearth/weights.yaml` (or `~/.config/unearth/weights.yaml`) is loaded automatically if it exists.
