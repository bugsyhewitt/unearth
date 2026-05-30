package techniques

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(otxPassiveDNSTechnique{}) }

// otxPassiveDNSTechnique queries AlienVault OTX's passive-DNS endpoint
// (GET /api/v1/indicators/domain/{domain}/passive_dns) for every
// hostname→IP observation OTX has accumulated for the target apex domain and
// emits the non-CDN, deduplicated IPs as origin candidates.
//
// Why AlienVault OTX in addition to the existing thirteen backends: a
// genuinely different axis of coverage, on two distinct dimensions.
//
// First, the corpus axis. The eight certificate-fingerprint engines
// (censys_cert, shodan_cert, fofa_cert, netlas_cert, criminalip_asset,
// binaryedge_cert, leakix_cert, onyphe_cert) all pivot on the target's
// *current* TLS leaf certificate — they miss any origin that rotated its
// certificate, never reused the front-door cert, or was decommissioned. The
// three host-inventory enumerators (fullhunt_asset, zoomeye_asset, chaos_asset)
// pivot on what active scan grids and bug-bounty/CT aggregation observed at
// crawl time. virustotal_passivedns replays historical hostname → IP
// resolutions harvested from VT's URL/file scanner submissions and partner DNS
// feeds. urlscan_asset replays community-submitted browser-rendered scans.
// OTX's passive-DNS corpus is a different lineage again: it is the aggregate
// of OTX's own honeypot/sensor network, the community-submitted "pulse"
// indicator feeds (analyst-curated IoC bundles describing real-world
// campaigns), and OTX's partner DNS telemetry. The same IP can be invisible
// to every scanner-driven backend yet present in OTX because a defender
// posted an analyst pulse mentioning it, or an OTX honeypot logged a callback
// to it. The corpus is also long-tailed: OTX retains observations going back
// years.
//
// Second, the cost axis. OTX's passive-DNS endpoint is publicly accessible
// **without an API key**, with a per-IP rate limit. This is the first
// technique in the suite to require zero credentials and zero on-target
// footprint — a deployment-friendly baseline backend that lifts every run's
// floor coverage. When OTX_API_KEY is supplied the request is authenticated
// (lifting the per-IP limit and identifying the caller for OTX's plan
// allowance) but the technique never fails closed on the key: a missing key
// degrades to the public anonymous path, not to ErrMissingAPIKey.
//
// OTX returns the IP directly in each passive_dns record (under `address`),
// so this technique — like virustotal_passivedns and urlscan_asset, and
// unlike chaos_asset — needs no second-stage DNS resolution to convert
// names to addresses. That keeps its DNS footprint at zero (the target is
// never contacted; only otx.alienvault.com is) and its results deterministic
// for caching.
//
// OTX API endpoint — isolated in a single constant per the codebase's
// "one URL constant per provider" discipline. The passive_dns endpoint
// authenticates optionally via the `X-OTX-API-KEY` header. The success
// envelope is
//
//	{"passive_dns": [ {"address":"1.2.3.4","hostname":"...",
//	    "record_type":"A","first":"2024-01-02T03:04:05",
//	    "last":"2025-06-07T08:09:10","asn":"..."} , ... ],
//	 "count": N}
//
// and a logical error envelope (anonymous-rate-limit, bad key, unknown
// indicator) typically returns a 4xx status with a JSON envelope carrying
// `detail` / `error` / `message` fields.
const (
	otxPassiveDNSURL  = "https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns"
	otxPassiveDNSTTL  = 1 * time.Hour
	otxPassiveDNSTName = "otx_passivedns"
)

type otxPassiveDNSTechnique struct{}

func (otxPassiveDNSTechnique) Name() string         { return otxPassiveDNSTName }
func (otxPassiveDNSTechnique) Tier() Tier           { return TierPassive }
// RequiresAPIKey reports false: the OTX passive-DNS endpoint is publicly
// accessible without credentials. A key is honored when present (lifting the
// per-IP rate limit) but never required.
func (otxPassiveDNSTechnique) RequiresAPIKey() bool   { return false }
func (otxPassiveDNSTechnique) DefaultWeight() float64 { return 0.64 }

// otxPassiveDNSResponse is the subset of the passive_dns envelope we read.
// On success: `passive_dns` is the array of observations. On a logical
// error OTX returns either a `detail` string (DRF convention) or an
// `error`/`message` field carrying a human-readable reason.
type otxPassiveDNSResponse struct {
	PassiveDNS []otxPassiveDNSRecord `json:"passive_dns"`
	Count      int                   `json:"count,omitempty"`

	// Error envelopes OTX returns on auth/quota/lookup issues. OTX is a
	// Django REST Framework service, so `detail` is the canonical error
	// field; `error` / `message` are also observed in the wild for some
	// failure modes.
	Detail  string `json:"detail,omitempty"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}

// otxPassiveDNSRecord is one passive-DNS observation. OTX records the
// resolved IP under `address`, the hostname under which it was observed
// under `hostname`, the DNS record type under `record_type`, and the
// first/last observation times under `first`/`last` (ISO 8601 strings).
type otxPassiveDNSRecord struct {
	Address    string `json:"address"`
	Hostname   string `json:"hostname"`
	RecordType string `json:"record_type"`
	First      string `json:"first"`
	Last       string `json:"last"`
}

func (otxPassiveDNSTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	apex := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(target), "."))
	if apex == "" {
		return nil, errors.New("otx_passivedns: empty target")
	}

	// Cache key is keyed on the apex only — the response is identical with
	// or without an API key (auth only changes rate-limit accounting, not
	// the corpus returned).
	key := cache.Key(otxPassiveDNSTName, apex, nil)
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		var cached otxPassiveDNSResponse
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return otxCandidates(cached, apex), nil
		}
	}

	if err := rateWait(ctx, opts.RateLimiter, "otx"); err != nil {
		return nil, err
	}
	doc, err := otxFetch(ctx, opts, apex)
	if err != nil {
		return nil, err
	}

	if payload, err := json.Marshal(doc); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, otxPassiveDNSTTL)
	}
	return otxCandidates(doc, apex), nil
}

func otxFetch(ctx context.Context, opts RunOptions, apex string) (otxPassiveDNSResponse, error) {
	var doc otxPassiveDNSResponse

	u := fmt.Sprintf(otxPassiveDNSURL, url.PathEscape(apex))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return doc, err
	}
	if opts.APIKeys.OTXKey != "" {
		req.Header.Set("X-OTX-API-KEY", opts.APIKeys.OTXKey)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("otx_passivedns: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 401 = bad key supplied (anonymous access does not produce 401 here).
	//        With no key on the request OTX never returns 401 — public
	//        passive-DNS is anonymous-readable — so any 401 implies the
	//        operator supplied a rejected key; degrade to a clean
	//        ErrMissingAPIKey skip.
	// 403 = key valid but plan disallows the endpoint, or anonymous rate
	//        limit hit.
	// 429 = per-IP or per-key rate limit hit.
	// 404 = OTX has no record for this indicator → empty success, not error.
	// 403/429 both surface as ErrTierInsufficient (a clean skip, not a hard
	// error) so a rate-capped anonymous run degrades gracefully.
	if resp.StatusCode == http.StatusUnauthorized {
		return doc, fmt.Errorf("otx_passivedns: status 401: %w", ErrMissingAPIKey)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return doc, fmt.Errorf("otx_passivedns: status %d: %w", resp.StatusCode, ErrTierInsufficient)
	}
	if resp.StatusCode == http.StatusNotFound {
		// No passive-DNS data on file for this apex — return an empty
		// success so callers see "no candidates" rather than an error.
		return otxPassiveDNSResponse{}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Try to decode an error envelope for richer classification before
		// falling back to a generic status error.
		if err := json.NewDecoder(resp.Body).Decode(&doc); err == nil && (doc.Detail != "" || doc.Error != "" || doc.Message != "") {
			pretty := firstNonEmpty(doc.Detail, doc.Error, doc.Message)
			combined := doc.Detail + " " + doc.Error + " " + doc.Message
			if isOTXTierError(combined) {
				return doc, fmt.Errorf("otx_passivedns: %s: %w", pretty, ErrTierInsufficient)
			}
			if isOTXKeyError(combined) {
				return doc, fmt.Errorf("otx_passivedns: %s: %w", pretty, ErrMissingAPIKey)
			}
			return doc, errors.New("otx_passivedns: " + pretty)
		}
		return doc, fmt.Errorf("otx_passivedns: status %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("otx_passivedns decode: %w", err)
	}

	// OTX occasionally answers 200 with a non-empty `detail`/`error`/
	// `message` envelope and an empty list for plan/quota problems;
	// classify those rather than returning an empty (and misleadingly
	// "successful") result.
	if msg := firstNonEmpty(doc.Detail, doc.Error, doc.Message); msg != "" && len(doc.PassiveDNS) == 0 {
		combined := doc.Detail + " " + doc.Error + " " + doc.Message
		if isOTXTierError(combined) {
			return doc, fmt.Errorf("otx_passivedns: %s: %w", msg, ErrTierInsufficient)
		}
		if isOTXKeyError(combined) {
			return doc, fmt.Errorf("otx_passivedns: %s: %w", msg, ErrMissingAPIKey)
		}
		return doc, errors.New("otx_passivedns: " + msg)
	}

	return doc, nil
}

// isOTXTierError matches OTX's documented quota / rate-limit / plan-gating
// messages. OTX reports these in human-readable text under `detail` /
// `error` / `message`, so we classify on substring.
func isOTXTierError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "quota") ||
		strings.Contains(low, "rate limit") ||
		strings.Contains(low, "ratelimit") ||
		strings.Contains(low, "limit reached") ||
		strings.Contains(low, "limit exceeded") ||
		strings.Contains(low, "throttled") ||
		strings.Contains(low, "throttle") ||
		strings.Contains(low, "too many requests") ||
		strings.Contains(low, "toomanyrequests") ||
		strings.Contains(low, "upgrade") ||
		strings.Contains(low, "subscription") ||
		strings.Contains(low, "premium") ||
		strings.Contains(low, "forbidden") ||
		strings.Contains(low, "not allowed") ||
		strings.Contains(low, "insufficient")
}

// isOTXKeyError matches OTX's credential-rejection messages so a supplied
// bad key degrades to ErrMissingAPIKey (a clean skip) rather than a generic
// failure. Anonymous (no-key) access never produces these messages because
// the public passive-DNS endpoint accepts unauthenticated requests.
func isOTXKeyError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "invalid api key") ||
		strings.Contains(low, "invalid api-key") ||
		strings.Contains(low, "invalid apikey") ||
		strings.Contains(low, "invalid token") ||
		strings.Contains(low, "invalid key") ||
		strings.Contains(low, "unauthorized") ||
		strings.Contains(low, "authentication") ||
		strings.Contains(low, "credentials")
}

// otxCandidates walks the passive_dns array and emits one Candidate per
// unique non-CDN IP. The IP is read from `address`; the hostname under
// which it was observed and the last-observed date are folded into the
// Evidence string. CDN edge IPs are filtered using the shared CDN registry.
// Duplicates (same IP observed across multiple hostnames or dates) collapse
// to a single candidate; the Evidence string then names the first
// observation seen for that IP. Non-A/AAAA record types (CNAME, etc.) are
// skipped — only address records carry routable origin IPs.
func otxCandidates(doc otxPassiveDNSResponse, apex string) []Candidate {
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, r := range doc.PassiveDNS {
		// Skip non-address record types. OTX's passive_dns array can
		// occasionally include CNAME / NS / MX records whose `address`
		// field is a hostname rather than an IP literal; those would
		// fail ParseAddr below anyway, but filtering by record_type
		// keeps the intent explicit and the parse-error path quiet.
		rt := strings.ToUpper(strings.TrimSpace(r.RecordType))
		if rt != "" && rt != "A" && rt != "AAAA" {
			continue
		}
		raw := strings.TrimSpace(r.Address)
		if raw == "" {
			continue
		}
		a, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		a = a.Unmap()
		if seen[a] || cdn.IsCDNIP(a) {
			continue
		}
		seen[a] = true
		host := strings.ToLower(strings.TrimSpace(r.Hostname))
		if host == "" {
			host = apex
		}
		when := strings.TrimSpace(r.Last)
		if when == "" {
			when = strings.TrimSpace(r.First)
		}
		if when == "" {
			when = "unknown date"
		}
		out = append(out, Candidate{
			IP: a.String(),
			Evidence: fmt.Sprintf(
				"AlienVault OTX passive-DNS: %s historically resolved to %s under apex %s (last observed %s)",
				host, a, apex, when),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}
