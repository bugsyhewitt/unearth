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

func init() { Register(onypheCertTechnique{}) }

// onypheCertTechnique mirrors censys_cert, shodan_cert, fofa_cert,
// netlas_cert, criminalip_asset, binaryedge_cert, and leakix_cert but
// queries Onyphe (onyphe.io), a French internet-scanning search engine
// that markets itself as a "cyber defense search engine" and indexes its
// own datascan corpus. It takes the target's current TLS leaf-certificate
// SHA-256 fingerprint, asks Onyphe for every scanned service that presents
// the same fingerprint, and emits the non-CDN hits as origin candidates.
//
// Why Onyphe in addition to the existing seven engines: Onyphe runs its own
// continuous internet-wide datascan ingestion pipeline that overlaps only
// partially with Shodan, Censys, FOFA, Netlas, Criminal IP, BinaryEdge, and
// LeakIX. Its scan footprint is meaningfully European-weighted (Onyphe is
// based in France) compared with the US-centric Shodan/Censys and the
// APAC-weighted FOFA/ZoomEye, so a misconfigured European-hosted origin
// that leaks its real certificate may surface in Onyphe when it is absent
// from the others — coverage diversity, not redundancy. Onyphe offers a
// free tier with a request allowance and a paid API tier, so it is
// reachable without a paid plan.
//
// ONYPHE API endpoint — isolated in a single constant per the codebase's
// "one URL constant per provider" discipline. The datascan search endpoint
// (GET /api/v2/search/datascan) authenticates via the `Authorization:
// bearer <key>` header and takes the query in the `q` parameter using
// Onyphe's OQL (Onyphe Query Language) filter syntax. The
// `tls.fingerprint.sha256` field matches the indexed leaf certificate's
// SHA-256 fingerprint — the same lowercase-hex SHA-256 that censys_cert,
// fofa_cert, netlas_cert, and criminalip_asset pivot on, so the techniques
// corroborate.
const (
	onypheSearchURL = "https://www.onyphe.io/api/v2/search/datascan"
	onypheCertField = "tls.fingerprint.sha256"
	onyphePageSize  = 100 // Onyphe's documented per-page result ceiling
	onypheMaxPages  = 20  // hard guard against runaway pagination
	onypheCertTTL   = 1 * time.Hour
)

type onypheCertTechnique struct{}

func (onypheCertTechnique) Name() string           { return "onyphe_cert" }
func (onypheCertTechnique) Tier() Tier             { return TierPassive }
func (onypheCertTechnique) RequiresAPIKey() bool   { return true }
func (onypheCertTechnique) DefaultWeight() float64 { return 0.69 }

// onypheResult is the subset of a single Onyphe datascan result we read.
// Onyphe reports the scanned host in the top-level `ip` field; some
// payloads also echo it under `host` (an array of resolved hostnames or
// IPs), so we fall back to the first element of that when `ip` is empty.
// The `host` field tolerates both array and single-string shapes.
type onypheResult struct {
	IP   string         `json:"ip"`
	Host onypheHostList `json:"host"`
}

// onypheHostList tolerates Onyphe's documented array-of-strings shape for
// `host` plus the single-string form some payloads emit.
type onypheHostList []string

func (h *onypheHostList) UnmarshalJSON(data []byte) error {
	data = trimJSON(data)
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	switch data[0] {
	case '[':
		var arr []string
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*h = arr
	case '"':
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*h = []string{s}
	default:
		return fmt.Errorf("unexpected host shape: %s", string(data[:1]))
	}
	return nil
}

// onypheSearchResponse is the subset of Onyphe's documented success
// envelope we read. Onyphe's standard envelope carries:
//   - `error`: integer status (0 = success, non-zero = logical error)
//   - `status`: short text ("ok" / "nok")
//   - `text`: human-readable error message when `error` != 0
//   - `results`: array of matched records
//   - `total`: total matched records across pages
//   - `page` / `max_page`: pagination cursor and ceiling
//
// Onyphe sometimes also stamps `message` instead of `text` (older error
// envelopes); we read both. The `error` field is the canonical signal —
// when non-zero, `text`/`message` carries the description.
type onypheSearchResponse struct {
	Error   int            `json:"error"`
	Status  string         `json:"status,omitempty"`
	Text    string         `json:"text,omitempty"`
	Message string         `json:"message,omitempty"`
	Results []onypheResult `json:"results,omitempty"`
	Total   int            `json:"total,omitempty"`
	Page    int            `json:"page,omitempty"`
	MaxPage int            `json:"max_page,omitempty"`
}

func (onypheCertTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if opts.APIKeys.OnypheKey == "" {
		return nil, ErrMissingAPIKey
	}

	// Onyphe indexes the SHA-256 leaf-cert fingerprint (Censys's flavor).
	fp, err := tlsFingerprint(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("onyphe_cert fingerprint: %w", err)
	}

	key := cache.Key("onyphe_cert", target, map[string]string{"fp": fp})
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		var cached onypheSearchResponse
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return onypheCandidates(cached, target, fp), nil
		}
	}

	var merged onypheSearchResponse
	for page := 1; page <= onypheMaxPages; page++ {
		if err := rateWait(ctx, opts.RateLimiter, "onyphe"); err != nil {
			return nil, err
		}
		got, err := onypheSearchPage(ctx, opts, fp, page)
		if err != nil {
			return nil, err
		}
		merged.Results = append(merged.Results, got.Results...)
		// Stop conditions: the API reports max_page (so respect it), or the
		// page came back short of the page-size ceiling (end of result set).
		if got.MaxPage > 0 && page >= got.MaxPage {
			break
		}
		if len(got.Results) < onyphePageSize {
			break
		}
	}

	if payload, err := json.Marshal(merged); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, onypheCertTTL)
	}
	return onypheCandidates(merged, target, fp), nil
}

func onypheSearchPage(ctx context.Context, opts RunOptions, fp string, page int) (onypheSearchResponse, error) {
	var doc onypheSearchResponse

	q := url.Values{}
	// Onyphe's OQL filter syntax: `category:datascan tls.fingerprint.sha256:<value>`.
	// The category gate restricts the search to the datascan corpus (the one
	// holding TLS handshake records), reducing wasted page reads.
	q.Set("q", fmt.Sprintf("category:datascan %s:%s", onypheCertField, fp))
	if page > 1 {
		q.Set("page", fmt.Sprintf("%d", page))
	}
	u := onypheSearchURL + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return doc, err
	}
	req.Header.Set("Authorization", "bearer "+opts.APIKeys.OnypheKey)
	req.Header.Set("Accept", "application/json")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("onyphe_cert: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 401 = bad/missing key → clean missing-key skip.
	// 403 = key valid but plan disallows the endpoint.
	// 429 = monthly request allowance exhausted.
	// 403/429 both surface as ErrTierInsufficient (a clean skip, not a hard
	// error) so a quota-capped free account degrades gracefully.
	if resp.StatusCode == http.StatusUnauthorized {
		return doc, fmt.Errorf("onyphe_cert: status 401: %w", ErrMissingAPIKey)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return doc, fmt.Errorf("onyphe_cert: status %d: %w", resp.StatusCode, ErrTierInsufficient)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return doc, fmt.Errorf("onyphe_cert: %s status %d", onypheSearchURL, resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("onyphe_cert decode: %w", err)
	}

	// Onyphe often answers 200 with a non-zero `error` envelope for quota or
	// permission problems; classify those rather than returning an empty
	// (and misleadingly "successful") result. Onyphe's standard envelope
	// reports `error:0` on success; any non-zero value is a logical failure.
	if doc.Error != 0 {
		msg := firstNonEmpty(doc.Text, doc.Message, fmt.Sprintf("error %d", doc.Error))
		if isOnypheTierError(msg) {
			return doc, fmt.Errorf("onyphe_cert: %s: %w", msg, ErrTierInsufficient)
		}
		if isOnypheKeyError(msg) {
			return doc, fmt.Errorf("onyphe_cert: %s: %w", msg, ErrMissingAPIKey)
		}
		return doc, errors.New("onyphe_cert: " + msg)
	}
	return doc, nil
}

// isOnypheTierError matches Onyphe's plan-gated / quota error messages.
// Onyphe reports quota exhaustion and feature-gating with human-readable
// text in the `text` (or `message`) envelope field, so we classify on the
// message.
func isOnypheTierError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "quota") ||
		strings.Contains(low, "rate limit") ||
		strings.Contains(low, "limit reached") ||
		strings.Contains(low, "too many requests") ||
		strings.Contains(low, "upgrade") ||
		strings.Contains(low, "subscription") ||
		strings.Contains(low, "plan") ||
		strings.Contains(low, "permission") ||
		strings.Contains(low, "not allowed") ||
		strings.Contains(low, "forbidden")
}

// isOnypheKeyError matches Onyphe's credential-rejection messages so a bad
// key degrades to ErrMissingAPIKey (a clean skip) rather than a generic
// failure.
func isOnypheKeyError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "invalid api key") ||
		strings.Contains(low, "invalid apikey") ||
		strings.Contains(low, "invalid token") ||
		strings.Contains(low, "invalid key") ||
		strings.Contains(low, "unauthorized") ||
		(strings.Contains(low, "api key") && strings.Contains(low, "not found")) ||
		(strings.Contains(low, "apikey") && strings.Contains(low, "not found")) ||
		(strings.Contains(low, "missing") && strings.Contains(low, "key"))
}

func onypheCandidates(doc onypheSearchResponse, target, fp string) []Candidate {
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, r := range doc.Results {
		raw := strings.TrimSpace(r.IP)
		if raw == "" {
			// Fall back to the first usable host entry. Onyphe's `host`
			// field may carry hostnames *or* IPs depending on the record;
			// we only emit when it parses as an IP, leaving DNS resolution
			// to the engine layer.
			for _, h := range r.Host {
				if h = strings.TrimSpace(h); h != "" {
					raw = h
					break
				}
			}
		}
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
		out = append(out, Candidate{
			IP: a.String(),
			Evidence: fmt.Sprintf(
				"Onyphe: host %s presents cert sha256:%s also served by %s",
				a, fp, target),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// trimJSON removes leading/trailing JSON whitespace bytes (space, tab,
// newline, carriage return) without pulling in the bytes package — keeps
// the file's import set minimal and matches the discipline used by the
// sibling techniques. It is permissive: it never errors, it just returns
// an empty slice when the input is whitespace-only.
func trimJSON(data []byte) []byte {
	for len(data) > 0 {
		switch data[0] {
		case ' ', '\t', '\n', '\r':
			data = data[1:]
		default:
			goto trailing
		}
	}
trailing:
	for len(data) > 0 {
		switch data[len(data)-1] {
		case ' ', '\t', '\n', '\r':
			data = data[:len(data)-1]
		default:
			return data
		}
	}
	return data
}
