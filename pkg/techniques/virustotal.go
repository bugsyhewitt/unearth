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

func init() { Register(virusTotalPassiveDNSTechnique{}) }

// virusTotalPassiveDNSTechnique queries VirusTotal's v3 passive-DNS endpoint
// (GET /api/v3/domains/{domain}/resolutions) for every hostname→IP observation
// VirusTotal has accumulated for the target apex domain, and emits the
// non-CDN, deduplicated IPs as origin candidates.
//
// Why VirusTotal passive-DNS in addition to the existing eleven backends: a
// genuinely different axis of coverage. The seven certificate-fingerprint
// engines (censys_cert, shodan_cert, fofa_cert, netlas_cert, criminalip_asset,
// binaryedge_cert, leakix_cert, onyphe_cert) all pivot on the target's
// *current* TLS leaf certificate — they miss any origin that rotated its
// certificate, never reused the front-door cert, or was decommissioned. The
// three asset enumerators (fullhunt_asset, zoomeye_asset, chaos_asset) pivot
// on host inventories indexed at the time of their last crawl. VirusTotal's
// passive-DNS corpus is *temporal*: it preserves historical hostname→IP
// observations going back years, harvested from URL scans, file submissions,
// and integrated DNS feeds. A forgotten `origin.example.com` record from
// three years ago — one no cert engine ever touched and no asset crawler
// recorded — can still surface here with its observation date. The corpus is
// also long-tailed and independent (gVisor, MISP, and partner feeds, not its
// own internet-wide scan grid), so it overlaps only partially with every
// other backend.
//
// VirusTotal also returns the IP directly in each `resolutions` record (under
// `attributes.ip_address`), so this technique — unlike chaos_asset — needs
// no second-stage DNS resolution to convert names to addresses. That keeps
// its DNS footprint at zero (the target is never contacted; only VT's API
// is) and its results deterministic for caching.
//
// VIRUSTOTAL API endpoint — isolated in a single constant per the codebase's
// "one URL constant per provider" discipline. The v3 resolutions endpoint
// authenticates via the `x-apikey` header and supports cursor-based
// pagination via the `cursor` query parameter. The standard envelope is
//
//	{"data": [ {"id":"...","type":"resolution","attributes":{
//	    "ip_address":"1.2.3.4","host_name":"...","date":1234567890} }, ... ],
//	 "meta": {"cursor":"..."},
//	 "links": {"next":"https://..."} }
//
// and a logical error envelope is
//
//	{"error":{"code":"AuthenticationRequiredError","message":"..."}}.
const (
	virusTotalResolutionsURL  = "https://www.virustotal.com/api/v3/domains/%s/resolutions"
	virusTotalPageSize        = 40 // VT's documented default; passed via `limit`
	virusTotalMaxPages        = 25 // hard guard against runaway pagination
	virusTotalPassiveDNSTTL   = 1 * time.Hour
	virusTotalPassiveDNSTName = "virustotal_passivedns"
)

type virusTotalPassiveDNSTechnique struct{}

func (virusTotalPassiveDNSTechnique) Name() string           { return virusTotalPassiveDNSTName }
func (virusTotalPassiveDNSTechnique) Tier() Tier             { return TierPassive }
func (virusTotalPassiveDNSTechnique) RequiresAPIKey() bool   { return true }
func (virusTotalPassiveDNSTechnique) DefaultWeight() float64 { return 0.67 }

// virusTotalResolution is the subset of a single resolutions record we read.
// VirusTotal stamps the resolved IP under `attributes.ip_address` and the
// hostname observed under `attributes.host_name`; the integer `date` is a
// Unix-epoch seconds timestamp of when the resolution was last observed.
type virusTotalResolution struct {
	Attributes virusTotalResolutionAttrs `json:"attributes"`
}

type virusTotalResolutionAttrs struct {
	IPAddress string `json:"ip_address"`
	HostName  string `json:"host_name"`
	Date      int64  `json:"date"`
}

// virusTotalResolutionsResponse is the subset of VT's documented success and
// error envelopes we read. On success: `data` is the array of resolutions
// and `meta.cursor`/`links.next` carry the next-page cursor when more pages
// exist. On a logical error (e.g. quota exhausted, key rejected) VT returns
// a 4xx status with an `error` envelope describing the problem.
type virusTotalResolutionsResponse struct {
	Data  []virusTotalResolution `json:"data"`
	Meta  virusTotalMeta         `json:"meta,omitempty"`
	Links virusTotalLinks        `json:"links,omitempty"`
	Error *virusTotalError       `json:"error,omitempty"`
}

type virusTotalMeta struct {
	Cursor string `json:"cursor,omitempty"`
}

type virusTotalLinks struct {
	Next string `json:"next,omitempty"`
}

type virusTotalError struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

func (virusTotalPassiveDNSTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if opts.APIKeys.VirusTotalKey == "" {
		return nil, ErrMissingAPIKey
	}

	apex := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(target), "."))
	if apex == "" {
		return nil, errors.New("virustotal_passivedns: empty target")
	}

	key := cache.Key(virusTotalPassiveDNSTName, apex, nil)
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		var cached virusTotalResolutionsResponse
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return virusTotalCandidates(cached, apex), nil
		}
	}

	var merged virusTotalResolutionsResponse
	cursor := ""
	for page := 0; page < virusTotalMaxPages; page++ {
		if err := rateWait(ctx, opts.RateLimiter, "virustotal"); err != nil {
			return nil, err
		}
		got, err := virusTotalFetchPage(ctx, opts, apex, cursor)
		if err != nil {
			return nil, err
		}
		merged.Data = append(merged.Data, got.Data...)

		// Stop conditions: no next cursor, or the page came back short of the
		// page-size ceiling (end of result set).
		cursor = got.Meta.Cursor
		if cursor == "" {
			break
		}
		if len(got.Data) < virusTotalPageSize {
			break
		}
	}

	if payload, err := json.Marshal(merged); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, virusTotalPassiveDNSTTL)
	}
	return virusTotalCandidates(merged, apex), nil
}

func virusTotalFetchPage(ctx context.Context, opts RunOptions, apex, cursor string) (virusTotalResolutionsResponse, error) {
	var doc virusTotalResolutionsResponse

	q := url.Values{}
	q.Set("limit", fmt.Sprintf("%d", virusTotalPageSize))
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	u := fmt.Sprintf(virusTotalResolutionsURL, url.PathEscape(apex)) + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return doc, err
	}
	req.Header.Set("x-apikey", opts.APIKeys.VirusTotalKey)
	req.Header.Set("Accept", "application/json")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("virustotal_passivedns: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 401 = bad/missing key → clean missing-key skip.
	// 403 = key valid but plan disallows the endpoint.
	// 429 = per-minute or daily quota exhausted.
	// 404 = no resolutions known for this domain → empty success, not an error.
	// 403/429 both surface as ErrTierInsufficient (a clean skip, not a hard
	// error) so a quota-capped free account degrades gracefully.
	if resp.StatusCode == http.StatusUnauthorized {
		return doc, fmt.Errorf("virustotal_passivedns: status 401: %w", ErrMissingAPIKey)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return doc, fmt.Errorf("virustotal_passivedns: status %d: %w", resp.StatusCode, ErrTierInsufficient)
	}
	if resp.StatusCode == http.StatusNotFound {
		// No resolutions on file for this apex — return an empty success so
		// callers see "no candidates" rather than an error.
		return virusTotalResolutionsResponse{}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Try to decode an error envelope for richer classification before
		// falling back to a generic status error.
		if err := json.NewDecoder(resp.Body).Decode(&doc); err == nil && doc.Error != nil {
			msg := firstNonEmpty(doc.Error.Message, doc.Error.Code)
			if isVirusTotalTierError(doc.Error.Code, msg) {
				return doc, fmt.Errorf("virustotal_passivedns: %s: %w", msg, ErrTierInsufficient)
			}
			if isVirusTotalKeyError(doc.Error.Code, msg) {
				return doc, fmt.Errorf("virustotal_passivedns: %s: %w", msg, ErrMissingAPIKey)
			}
			return doc, errors.New("virustotal_passivedns: " + msg)
		}
		return doc, fmt.Errorf("virustotal_passivedns: status %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("virustotal_passivedns decode: %w", err)
	}

	// VirusTotal sometimes answers 200 with an `error` envelope (rare, but
	// observed for malformed cursors and feature-gated lookups). Classify
	// those rather than returning an empty (and misleadingly "successful")
	// result.
	if doc.Error != nil {
		msg := firstNonEmpty(doc.Error.Message, doc.Error.Code)
		if isVirusTotalTierError(doc.Error.Code, msg) {
			return doc, fmt.Errorf("virustotal_passivedns: %s: %w", msg, ErrTierInsufficient)
		}
		if isVirusTotalKeyError(doc.Error.Code, msg) {
			return doc, fmt.Errorf("virustotal_passivedns: %s: %w", msg, ErrMissingAPIKey)
		}
		return doc, errors.New("virustotal_passivedns: " + msg)
	}

	return doc, nil
}

// isVirusTotalTierError matches VT's documented quota / plan-gating error
// codes and messages. VT uses code strings like QuotaExceededError,
// TooManyRequestsError, and UserNotActiveError in its `error.code`
// field, plus free-form messages.
func isVirusTotalTierError(code, msg string) bool {
	low := strings.ToLower(code + " " + msg)
	return strings.Contains(low, "quota") ||
		strings.Contains(low, "rate limit") ||
		strings.Contains(low, "ratelimit") ||
		strings.Contains(low, "limit reached") ||
		strings.Contains(low, "too many requests") ||
		strings.Contains(low, "toomanyrequests") ||
		strings.Contains(low, "upgrade") ||
		strings.Contains(low, "subscription") ||
		strings.Contains(low, "premium") ||
		strings.Contains(low, "forbidden") ||
		strings.Contains(low, "user not active") ||
		strings.Contains(low, "usernotactive")
}

// isVirusTotalKeyError matches VT's credential-rejection codes/messages so a
// bad or absent key degrades to ErrMissingAPIKey (a clean skip) rather than
// a generic failure.
func isVirusTotalKeyError(code, msg string) bool {
	low := strings.ToLower(code + " " + msg)
	return strings.Contains(low, "authenticationrequired") ||
		strings.Contains(low, "authentication required") ||
		strings.Contains(low, "wrongcredentials") ||
		strings.Contains(low, "wrong credentials") ||
		strings.Contains(low, "invalid api key") ||
		strings.Contains(low, "invalid apikey") ||
		strings.Contains(low, "invalid key") ||
		strings.Contains(low, "unauthorized")
}

// virusTotalCandidates walks the resolutions array and emits one Candidate
// per unique non-CDN IP. The IP is read from `attributes.ip_address`; the
// hostname under which it was observed is folded into the Evidence string
// so an operator can see which historical hostname surfaced the address.
// CDN edge IPs are filtered using the shared CDN registry. Duplicates
// (same IP observed under multiple hostnames) collapse to a single
// candidate; the Evidence string then names the first hostname observed
// for that IP.
func virusTotalCandidates(doc virusTotalResolutionsResponse, apex string) []Candidate {
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, r := range doc.Data {
		raw := strings.TrimSpace(r.Attributes.IPAddress)
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
		host := strings.ToLower(strings.TrimSpace(r.Attributes.HostName))
		if host == "" {
			host = apex
		}
		out = append(out, Candidate{
			IP: a.String(),
			Evidence: fmt.Sprintf(
				"VirusTotal passive-DNS: %s historically resolved to %s under apex %s",
				host, a, apex),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}
