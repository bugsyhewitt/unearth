package techniques

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(leakIXCertTechnique{}) }

// leakIXCertTechnique mirrors censys_cert, shodan_cert, fofa_cert,
// netlas_cert, criminalip_asset, and binaryedge_cert but queries LeakIX
// (leakix.net), an internet-scanning search engine and exposure database. It
// takes the target's current TLS leaf-certificate SHA-1 fingerprint, asks
// LeakIX for every scanned service that presents the same fingerprint, and
// emits the non-CDN hits as origin candidates.
//
// Why LeakIX in addition to the existing six engines: LeakIX runs its own
// continuous internet-wide scan and indexes the leaf certificate it observed
// per service, keyed under `ssl.certificate.fingerprint`. Its corpus overlaps
// only partially with Shodan, Censys, FOFA, Netlas, Criminal IP, and
// BinaryEdge — a misconfigured origin that leaks its real certificate may
// surface in LeakIX when it is absent from the others. Coverage diversity is
// the value, not redundancy. LeakIX offers a free tier with a daily request
// allowance, so it is reachable without a paid plan.
//
// LEAKIX API endpoint — isolated in a single constant per the codebase's
// "one URL constant per provider" discipline. The host-search endpoint
// (GET /search) authenticates via the `api-key` header, takes the query in
// the `q` parameter using LeakIX's Lucene-style filter syntax, and selects
// the service scope with `scope=service`. The `ssl.certificate.fingerprint`
// field matches the indexed leaf certificate's SHA-1 fingerprint — the same
// lowercase-hex SHA-1 that shodan_cert and binaryedge_cert pivot on (LeakIX,
// like Shodan and BinaryEdge, indexes the SHA-1 form), so the techniques
// corroborate.
const (
	leakIXSearchURL = "https://leakix.net/search"
	leakIXCertField = "ssl.certificate.fingerprint"
	leakIXPageSize  = 100 // LeakIX's per-page event ceiling
	leakIXMaxPages  = 20  // hard guard against runaway pagination
	leakIXCertTTL   = 1 * time.Hour
)

type leakIXCertTechnique struct{}

func (leakIXCertTechnique) Name() string           { return "leakix_cert" }
func (leakIXCertTechnique) Tier() Tier             { return TierPassive }
func (leakIXCertTechnique) RequiresAPIKey() bool   { return true }
func (leakIXCertTechnique) DefaultWeight() float64 { return 0.71 }

// leakIXEvent is the subset of a single LeakIX service result we read. LeakIX
// reports the scanned host in the top-level `ip` field; some payloads also
// echo it under `host`, so we fall back to that when `ip` is empty.
type leakIXEvent struct {
	IP   string `json:"ip"`
	Host string `json:"host"`
}

// leakIXSearchResponse models both shapes LeakIX may return for /search.
// The documented success shape is a bare JSON array of events; some error
// and quota conditions answer 2xx with an object envelope carrying an
// `error`/`message` field instead. unmarshalLeakIXResponse normalizes both.
type leakIXSearchResponse struct {
	Events  []leakIXEvent
	Error   string
	Message string
}

// leakIXEnvelope is the object form LeakIX uses for error/quota replies.
type leakIXEnvelope struct {
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}

func (leakIXCertTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if opts.APIKeys.LeakIXKey == "" {
		return nil, ErrMissingAPIKey
	}

	// LeakIX indexes the SHA-1 leaf-cert fingerprint (Shodan's flavor).
	fp, err := tlsFingerprintSHA1(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("leakix_cert fingerprint: %w", err)
	}

	key := cache.Key("leakix_cert", target, map[string]string{"fp": fp})
	var cached leakIXSearchResponse
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		if jerr := json.Unmarshal(data, &cached.Events); jerr == nil {
			return leakIXCandidates(cached, target, fp), nil
		}
	}

	var merged leakIXSearchResponse
	for page := 0; page < leakIXMaxPages; page++ {
		if err := rateWait(ctx, opts.RateLimiter, "leakix"); err != nil {
			return nil, err
		}
		got, err := leakIXSearchPage(ctx, opts, fp, page)
		if err != nil {
			return nil, err
		}
		merged.Events = append(merged.Events, got.Events...)
		// A short (or empty) page means we've reached the end of the result
		// set; LeakIX has no total-count field, so the page-fill heuristic is
		// the stop condition.
		if len(got.Events) < leakIXPageSize {
			break
		}
	}

	if payload, err := json.Marshal(merged.Events); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, leakIXCertTTL)
	}
	return leakIXCandidates(merged, target, fp), nil
}

func leakIXSearchPage(ctx context.Context, opts RunOptions, fp string, page int) (leakIXSearchResponse, error) {
	var doc leakIXSearchResponse

	q := url.Values{}
	q.Set("scope", "service")
	q.Set("q", fmt.Sprintf("%s:%q", leakIXCertField, fp))
	if page > 0 {
		q.Set("page", fmt.Sprintf("%d", page))
	}
	u := leakIXSearchURL + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return doc, err
	}
	req.Header.Set("api-key", opts.APIKeys.LeakIXKey)
	req.Header.Set("Accept", "application/json")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("leakix_cert: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 401 = bad/missing key → clean missing-key skip.
	// 403 = key valid but plan disallows the search capability.
	// 429 = daily request allowance exhausted.
	// 403/429 both surface as ErrTierInsufficient (a clean skip, not a hard
	// error) so a quota-capped free account degrades gracefully.
	if resp.StatusCode == http.StatusUnauthorized {
		return doc, fmt.Errorf("leakix_cert: status 401: %w", ErrMissingAPIKey)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return doc, fmt.Errorf("leakix_cert: status %d: %w", resp.StatusCode, ErrTierInsufficient)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return doc, fmt.Errorf("leakix_cert: %s status %d", leakIXSearchURL, resp.StatusCode)
	}

	parsed, err := unmarshalLeakIXResponse(resp.Body)
	if err != nil {
		return doc, fmt.Errorf("leakix_cert decode: %w", err)
	}
	doc = parsed

	// LeakIX occasionally answers 200 with an error/message envelope for quota
	// or permission problems; classify those rather than returning an empty
	// (and misleadingly "successful") result.
	if msg := firstNonEmpty(doc.Error, doc.Message); msg != "" && len(doc.Events) == 0 {
		if isLeakIXTierError(msg) {
			return doc, fmt.Errorf("leakix_cert: %s: %w", msg, ErrTierInsufficient)
		}
		if isLeakIXKeyError(msg) {
			return doc, fmt.Errorf("leakix_cert: %s: %w", msg, ErrMissingAPIKey)
		}
		return doc, errors.New("leakix_cert: " + msg)
	}
	return doc, nil
}

// unmarshalLeakIXResponse normalizes LeakIX's two reply shapes: a bare JSON
// array of events on success, or an object envelope on error/quota. A null
// body (LeakIX answers `null` for a zero-hit search) is treated as an empty
// result.
func unmarshalLeakIXResponse(r io.Reader) (leakIXSearchResponse, error) {
	var doc leakIXSearchResponse
	raw, err := io.ReadAll(r)
	if err != nil {
		return doc, err
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return doc, nil
	}
	switch raw[0] {
	case '[':
		if err := json.Unmarshal(raw, &doc.Events); err != nil {
			return doc, err
		}
	case '{':
		var env leakIXEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return doc, err
		}
		doc.Error = env.Error
		doc.Message = env.Message
	default:
		return doc, fmt.Errorf("unexpected response shape: %q", string(raw[:1]))
	}
	return doc, nil
}

// isLeakIXTierError matches LeakIX's plan-gated / quota error messages. LeakIX
// reports quota exhaustion and feature-gating with human-readable text, so we
// classify on the message.
func isLeakIXTierError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "quota") ||
		strings.Contains(low, "rate limit") ||
		strings.Contains(low, "limit reached") ||
		strings.Contains(low, "too many requests") ||
		strings.Contains(low, "upgrade") ||
		strings.Contains(low, "subscription") ||
		strings.Contains(low, "plan") ||
		strings.Contains(low, "permission") ||
		strings.Contains(low, "not allowed")
}

// isLeakIXKeyError matches LeakIX's credential-rejection messages so a bad key
// degrades to ErrMissingAPIKey (a clean skip) rather than a generic failure.
func isLeakIXKeyError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "invalid api key") ||
		strings.Contains(low, "invalid token") ||
		strings.Contains(low, "invalid key") ||
		strings.Contains(low, "unauthorized") ||
		(strings.Contains(low, "api key") && strings.Contains(low, "not found")) ||
		(strings.Contains(low, "missing") && strings.Contains(low, "key"))
}

func leakIXCandidates(doc leakIXSearchResponse, target, fp string) []Candidate {
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, ev := range doc.Events {
		raw := strings.TrimSpace(ev.IP)
		if raw == "" {
			raw = strings.TrimSpace(ev.Host)
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
				"LeakIX: host %s presents cert sha1:%s also served by %s",
				a, fp, target),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}
