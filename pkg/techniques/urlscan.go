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

func init() { Register(urlscanAssetTechnique{}) }

// urlscanAssetTechnique queries URLScan.io's search API for every public scan
// recorded against the target domain and emits the non-CDN page-serving IPs as
// origin candidates.
//
// Why URLScan.io complements the existing twelve OSINT backends: a genuinely
// different axis of coverage. The eight certificate-fingerprint engines
// (censys_cert, shodan_cert, fofa_cert, netlas_cert, criminalip_asset,
// binaryedge_cert, leakix_cert, onyphe_cert) all pivot on the target's *current*
// TLS leaf certificate — they miss any origin that rotated its certificate,
// never reused the front-door cert, or was decommissioned. The asset
// enumerators (fullhunt_asset, zoomeye_asset, chaos_asset) pivot on host
// inventories captured by active scan grids and bug-bounty/CT aggregation.
// The passive-DNS pivot (virustotal_passivedns) replays historical
// hostname → IP resolutions. URLScan.io's corpus is *user-submitted browser
// scans*: every time someone (or an automated submission, e.g. PhishTank,
// urlscan's public crawler, SOC playbook automation) renders a URL under the
// target domain, URLScan records the page-serving IP, the resolved hostname,
// the ASN, and a screenshot. A misconfigured origin that briefly leaked from
// behind a CDN — for example during a deploy cutover, a CDN outage, or a
// targeted scan submission against a `direct.example.com` shortcut — can be
// preserved in URLScan's index even though the cert engines, scan grids, and
// passive-DNS feeds never recorded it. The corpus is also long-tailed and
// independent (community submissions, not its own internet-wide scan grid),
// so it overlaps only partially with every other backend.
//
// URLScan.io also returns the IP directly in each result record (under
// `page.ip`), so this technique — like virustotal_passivedns and unlike
// chaos_asset — needs no second-stage DNS resolution to convert names to
// addresses. That keeps its DNS footprint at zero (the target is never
// contacted; only urlscan.io's API is) and its results deterministic for
// caching.
//
// URLSCAN API endpoint — isolated in a single constant per the codebase's
// "one URL constant per provider" discipline. The /api/v1/search/ endpoint
// authenticates via the `API-Key` header and supports the ElasticSearch-DSL
// query language; the `domain:` field matches the page or any subdomain at
// crawl time. The success envelope is
//
//	{"results": [ {"page":{"ip":"1.2.3.4","domain":"...","url":"...",
//	    "asnname":"..."}, "task":{"time":"2025-..."} }, ... ],
//	 "total": N, "has_more": false}
//
// and a quota / permission failure typically returns a 4xx with either an
// empty body or a JSON envelope carrying `message` / `description` fields.
const (
	urlscanSearchURL  = "https://urlscan.io/api/v1/search/"
	urlscanPageSize   = 100 // URLScan's documented default; maximum 10000 with deep paging
	urlscanMaxPages   = 10  // hard guard against runaway pagination (1000 results max)
	urlscanAssetTTL   = 1 * time.Hour
	urlscanAssetTName = "urlscan_asset"
)

type urlscanAssetTechnique struct{}

func (urlscanAssetTechnique) Name() string           { return urlscanAssetTName }
func (urlscanAssetTechnique) Tier() Tier             { return TierPassive }
func (urlscanAssetTechnique) RequiresAPIKey() bool   { return true }
func (urlscanAssetTechnique) DefaultWeight() float64 { return 0.66 }

// urlscanSearchResponse models the subset of /api/v1/search/ we read.
type urlscanSearchResponse struct {
	Results []urlscanResult `json:"results"`
	Total   int             `json:"total,omitempty"`
	HasMore bool            `json:"has_more,omitempty"`
	// Error envelopes URLScan returns on quota / auth issues.
	Message     string `json:"message,omitempty"`
	Description string `json:"description,omitempty"`
	Status      int    `json:"status,omitempty"`
}

// urlscanResult is one scan record. Page carries the resolved IP and
// hostname; Task carries the submission timestamp (folded into Evidence so
// an operator can see when the scan was recorded). Sort is the deep-paging
// cursor URLScan emits for follow-up requests.
type urlscanResult struct {
	Page urlscanPage `json:"page"`
	Task urlscanTask `json:"task"`
	Sort []any       `json:"sort,omitempty"`
}

type urlscanPage struct {
	IP      string `json:"ip"`
	Domain  string `json:"domain"`
	URL     string `json:"url"`
	ASNName string `json:"asnname"`
}

type urlscanTask struct {
	Time string `json:"time"`
}

func (urlscanAssetTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if opts.APIKeys.URLScanKey == "" {
		return nil, ErrMissingAPIKey
	}

	apex := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(target), "."))
	if apex == "" {
		return nil, errors.New("urlscan_asset: empty target")
	}

	key := cache.Key(urlscanAssetTName, apex, nil)
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		var cached urlscanSearchResponse
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return urlscanCandidates(cached, apex), nil
		}
	}

	var merged urlscanSearchResponse
	var searchAfter string
	for page := 0; page < urlscanMaxPages; page++ {
		if err := rateWait(ctx, opts.RateLimiter, "urlscan"); err != nil {
			return nil, err
		}
		got, err := urlscanFetchPage(ctx, opts, apex, searchAfter)
		if err != nil {
			return nil, err
		}
		merged.Results = append(merged.Results, got.Results...)

		// Stop conditions: URLScan flagged the result list complete, or we
		// got a short page (fewer than urlscanPageSize results means no
		// further pages exist), or there's no cursor to advance.
		if !got.HasMore || len(got.Results) < urlscanPageSize {
			break
		}
		cursor := urlscanCursor(got.Results[len(got.Results)-1].Sort)
		if cursor == "" {
			break
		}
		searchAfter = cursor
	}

	if payload, err := json.Marshal(merged); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, urlscanAssetTTL)
	}
	return urlscanCandidates(merged, apex), nil
}

// urlscanCursor renders the deep-paging `sort` field from a result into the
// URL-query form `search_after=` expects: comma-joined string values. URLScan
// emits sort as a heterogeneous JSON array (typically [timestamp_int, scan_id_string]);
// rendering each element through fmt %v keeps numbers and strings round-tripping
// correctly.
func urlscanCursor(sort []any) string {
	if len(sort) == 0 {
		return ""
	}
	parts := make([]string, 0, len(sort))
	for _, v := range sort {
		parts = append(parts, fmt.Sprintf("%v", v))
	}
	return strings.Join(parts, ",")
}

func urlscanFetchPage(ctx context.Context, opts RunOptions, apex, searchAfter string) (urlscanSearchResponse, error) {
	var doc urlscanSearchResponse

	q := url.Values{}
	q.Set("q", "domain:"+apex)
	q.Set("size", fmt.Sprintf("%d", urlscanPageSize))
	if searchAfter != "" {
		q.Set("search_after", searchAfter)
	}
	u := urlscanSearchURL + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return doc, err
	}
	req.Header.Set("API-Key", opts.APIKeys.URLScanKey)
	req.Header.Set("Accept", "application/json")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("urlscan_asset: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 401 = bad / missing key → clean missing-key skip.
	// 403 = key valid but plan disallows the endpoint (e.g. private-scan-only key).
	// 429 = per-minute or daily quota exhausted.
	// 400 with `description` carrying a quota / rate / auth message is also
	// observed in the wild; classified below from the JSON envelope.
	// 403 / 429 surface as ErrTierInsufficient (a clean skip, not a hard
	// error) so a quota-capped free account degrades gracefully.
	if resp.StatusCode == http.StatusUnauthorized {
		return doc, fmt.Errorf("urlscan_asset: status 401: %w", ErrMissingAPIKey)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return doc, fmt.Errorf("urlscan_asset: status %d: %w", resp.StatusCode, ErrTierInsufficient)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Try to decode an error envelope for richer classification before
		// falling back to a generic status error.
		if err := json.NewDecoder(resp.Body).Decode(&doc); err == nil && (doc.Message != "" || doc.Description != "") {
			// Inspect both fields together for classification — URLScan
			// sometimes puts the key-error keywords in `message` and the
			// human description in `description` (or vice-versa).
			combined := doc.Message + " " + doc.Description
			pretty := firstNonEmpty(doc.Description, doc.Message)
			if isURLScanTierError(combined) {
				return doc, fmt.Errorf("urlscan_asset: %s: %w", pretty, ErrTierInsufficient)
			}
			if isURLScanKeyError(combined) {
				return doc, fmt.Errorf("urlscan_asset: %s: %w", pretty, ErrMissingAPIKey)
			}
			return doc, errors.New("urlscan_asset: " + pretty)
		}
		return doc, fmt.Errorf("urlscan_asset: status %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("urlscan_asset decode: %w", err)
	}

	// URLScan occasionally answers 200 with a non-empty `message` /
	// `description` envelope and an empty results list for plan / quota
	// problems; classify those rather than returning an empty (and
	// misleadingly "successful") result.
	if msg := firstNonEmpty(doc.Description, doc.Message); msg != "" && len(doc.Results) == 0 {
		combined := doc.Message + " " + doc.Description
		if isURLScanTierError(combined) {
			return doc, fmt.Errorf("urlscan_asset: %s: %w", msg, ErrTierInsufficient)
		}
		if isURLScanKeyError(combined) {
			return doc, fmt.Errorf("urlscan_asset: %s: %w", msg, ErrMissingAPIKey)
		}
		return doc, errors.New("urlscan_asset: " + msg)
	}

	return doc, nil
}

// isURLScanTierError matches URLScan's documented quota / plan-gating
// messages. URLScan reports these in human-readable text under `message`
// or `description`, so we classify on substring.
func isURLScanTierError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "quota") ||
		strings.Contains(low, "rate limit") ||
		strings.Contains(low, "ratelimit") ||
		strings.Contains(low, "limit reached") ||
		strings.Contains(low, "limit exceeded") ||
		strings.Contains(low, "too many requests") ||
		strings.Contains(low, "toomanyrequests") ||
		strings.Contains(low, "upgrade") ||
		strings.Contains(low, "subscription") ||
		strings.Contains(low, "premium") ||
		strings.Contains(low, "forbidden") ||
		strings.Contains(low, "not allowed") ||
		strings.Contains(low, "insufficient")
}

// isURLScanKeyError matches URLScan's credential-rejection messages so a bad
// or absent key degrades to ErrMissingAPIKey (a clean skip) rather than a
// generic failure.
func isURLScanKeyError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "invalid api key") ||
		strings.Contains(low, "invalid api-key") ||
		strings.Contains(low, "invalid apikey") ||
		strings.Contains(low, "invalid token") ||
		strings.Contains(low, "invalid key") ||
		strings.Contains(low, "unauthorized") ||
		strings.Contains(low, "authentication") ||
		strings.Contains(low, "missing api key") ||
		strings.Contains(low, "missing api-key") ||
		strings.Contains(low, "missing apikey") ||
		(strings.Contains(low, "api key") && strings.Contains(low, "required"))
}

// urlscanCandidates walks the results array and emits one Candidate per
// unique non-CDN IP. The IP is read from `page.ip`; the hostname observed
// and the scan submission time are folded into the Evidence string. CDN
// edge IPs are filtered using the shared CDN registry. Duplicates (same IP
// observed across multiple scans) collapse to a single candidate; the
// Evidence string then names the first scan observed for that IP.
func urlscanCandidates(doc urlscanSearchResponse, apex string) []Candidate {
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, r := range doc.Results {
		raw := strings.TrimSpace(r.Page.IP)
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
		host := strings.ToLower(strings.TrimSpace(r.Page.Domain))
		if host == "" {
			host = apex
		}
		when := strings.TrimSpace(r.Task.Time)
		if when == "" {
			when = "unknown date"
		}
		out = append(out, Candidate{
			IP: a.String(),
			Evidence: fmt.Sprintf(
				"URLScan.io: %s scan of %s under apex %s resolved to %s",
				when, host, apex, a),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}
