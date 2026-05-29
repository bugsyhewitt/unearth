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

func init() { Register(netlasCertTechnique{}) }

// netlasCertTechnique mirrors censys_cert, shodan_cert, and fofa_cert but
// queries Netlas (netlas.io), an attack-surface-discovery search engine. It
// takes the target's current TLS leaf-certificate SHA-256 fingerprint, asks
// Netlas for every response that presents the same fingerprint, and emits the
// non-CDN hits as origin candidates.
//
// Why Netlas in addition to Censys/Shodan/FOFA: Netlas indexes domain names
// alongside IPs and maintains its own internet-wide scan corpus that overlaps
// only partially with Shodan, Censys, and FOFA. Coverage diversity is the
// value — a misconfigured origin that leaks its real cert may surface in
// Netlas when it is absent from the other three. Netlas also offers a free
// tier with a daily request allowance, so it is reachable without a paid plan.
//
// NETLAS API endpoint — isolated in a single constant per the codebase's
// "one URL constant per provider" discipline. The responses search endpoint
// takes the query in the `q` parameter and authenticates via the `X-API-Key`
// header. The `certificate.fingerprints.sha256` field matches against the
// indexed leaf-certificate fingerprint — the same lowercase-hex SHA-256 that
// censys_cert and fofa_cert pivot on, so the techniques corroborate.
const (
	netlasSearchURL = "https://app.netlas.io/api/responses/"
	netlasCertField = "certificate.fingerprints.sha256"
	netlasPageSize  = 100
	netlasCertTTL   = 1 * time.Hour
)

type netlasCertTechnique struct{}

func (netlasCertTechnique) Name() string           { return "netlas_cert" }
func (netlasCertTechnique) Tier() Tier             { return TierPassive }
func (netlasCertTechnique) RequiresAPIKey() bool   { return true }
func (netlasCertTechnique) DefaultWeight() float64 { return 0.75 }

// netlasSearchResponse is the subset of the responses-search payload we read.
// On success the envelope is {"items": [{"data": {"ip": "...", ...}}, ...]}.
// On a logical failure Netlas returns a 2xx with an "error" / "message" field;
// we classify those alongside the HTTP-status checks.
type netlasSearchResponse struct {
	Items []struct {
		Data struct {
			IP string `json:"ip"`
		} `json:"data"`
	} `json:"items"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}

func (netlasCertTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if opts.APIKeys.NetlasAPIKey == "" {
		return nil, ErrMissingAPIKey
	}

	fp, err := tlsFingerprint(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("netlas_cert fingerprint: %w", err)
	}

	key := cache.Key("netlas_cert", target, map[string]string{"fp": fp})
	var cached netlasSearchResponse
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return netlasCandidates(cached, target, fp), nil
		}
	}

	doc, err := netlasSearchPage(ctx, opts, fp)
	if err != nil {
		return nil, err
	}
	if payload, merr := json.Marshal(doc); merr == nil {
		cacheWrite(opts.Cache, opts, key, payload, netlasCertTTL)
	}
	return netlasCandidates(doc, target, fp), nil
}

func netlasSearchPage(ctx context.Context, opts RunOptions, fp string) (netlasSearchResponse, error) {
	var doc netlasSearchResponse

	q := url.Values{}
	q.Set("q", fmt.Sprintf(`%s:%s`, netlasCertField, fp))
	q.Set("size", fmt.Sprintf("%d", netlasPageSize))
	u := netlasSearchURL + "?" + q.Encode()

	if err := rateWait(ctx, opts.RateLimiter, "netlas"); err != nil {
		return doc, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return doc, err
	}
	req.Header.Set("X-API-Key", opts.APIKeys.NetlasAPIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("netlas_cert: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 401 = bad/missing key → clean missing-key skip.
	// 403 = key valid but plan/quota disallows; 429 = daily allowance hit.
	// Both surface as ErrTierInsufficient (a clean skip, not a hard error).
	if resp.StatusCode == http.StatusUnauthorized {
		return doc, fmt.Errorf("netlas_cert: status 401: %w", ErrMissingAPIKey)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return doc, fmt.Errorf("netlas_cert: status %d: %w", resp.StatusCode, ErrTierInsufficient)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return doc, fmt.Errorf("netlas_cert: %s status %d", netlasSearchURL, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("netlas_cert decode: %w", err)
	}
	// Netlas occasionally answers 200 with an error/message envelope for
	// quota or permission problems; classify those rather than returning an
	// empty (and misleadingly "successful") result.
	if msg := firstNonEmpty(doc.Error, doc.Message); msg != "" {
		if isNetlasTierError(msg) {
			return doc, fmt.Errorf("netlas_cert: %s: %w", msg, ErrTierInsufficient)
		}
		if isNetlasKeyError(msg) {
			return doc, fmt.Errorf("netlas_cert: %s: %w", msg, ErrMissingAPIKey)
		}
		return doc, errors.New("netlas_cert: " + msg)
	}
	return doc, nil
}

// firstNonEmpty returns the first non-empty string of its arguments.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// isNetlasTierError matches Netlas's plan-gated / quota error messages. Netlas
// reports quota exhaustion and feature-gating with human-readable text, so we
// classify on the message.
func isNetlasTierError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "quota") ||
		strings.Contains(low, "limit") ||
		strings.Contains(low, "upgrade") ||
		strings.Contains(low, "subscription") ||
		strings.Contains(low, "permission") ||
		strings.Contains(low, "not allowed")
}

// isNetlasKeyError matches Netlas's credential-rejection messages so a bad key
// degrades to ErrMissingAPIKey (a clean skip) rather than a generic failure.
func isNetlasKeyError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "invalid api key") ||
		strings.Contains(low, "invalid token") ||
		(strings.Contains(low, "api key") && strings.Contains(low, "not found")) ||
		strings.Contains(low, "unauthorized")
}

func netlasCandidates(doc netlasSearchResponse, target, fp string) []Candidate {
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, item := range doc.Items {
		raw := strings.TrimSpace(item.Data.IP)
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
				"Netlas: host %s presents cert sha256:%s also served by %s",
				a, fp, target),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}
