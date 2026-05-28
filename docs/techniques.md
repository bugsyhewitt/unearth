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

### `censys_cert`

**Tier:** Passive | **Weight:** 0.90 | **API key:** `CENSYS_PLATFORM_PAT`

**What it does:** Searches the Censys Platform certificate index for hosts that present a certificate naming the target domain. Returns non-CDN IPs that serve such a certificate.

**Data source:** Censys Platform API (`https://search.censys.io/api/v2/certificates/search`)

**Key requirement:** A Censys Platform personal access token. Free-tier Platform accounts may receive `403 Tier Insufficient` responses — the technique skips those responses rather than failing the run.

**Limitations:** Requires a paid Censys Platform account for full coverage. Free tier is rate-limited and may not return all results.

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
