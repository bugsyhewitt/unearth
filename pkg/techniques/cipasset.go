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

func init() { Register(criminalIPAssetTechnique{}) }

// criminalIPAssetTechnique mirrors censys_cert, shodan_cert, fofa_cert, and
// netlas_cert but queries Criminal IP (criminalip.io), an attack-surface
// search engine indexing 4.2B+ IPs. It takes the target's current TLS
// leaf-certificate SHA-256 fingerprint, asks Criminal IP's banner search for
// every asset that presents the same fingerprint, and emits the non-CDN hits
// as origin candidates.
//
// Why Criminal IP in addition to Censys/Shodan/FOFA/Netlas: Criminal IP runs
// its own internet-wide scan corpus with AI-driven asset scoring, and its
// coverage overlaps only partially with the other engines. Coverage diversity
// is the value — a misconfigured origin that leaks its real cert may surface in
// Criminal IP when it is absent elsewhere. Criminal IP offers a free tier with
// a monthly request allowance, so it is reachable without a paid plan.
//
// CRIMINAL IP API endpoint — isolated in a single constant per the codebase's
// "one URL constant per provider" discipline. The banner search endpoint takes
// the query in the `query` parameter and authenticates via the `x-api-key`
// header. The `certificate` field matches against the indexed leaf-certificate
// fingerprint — the same lowercase-hex SHA-256 that the other cert techniques
// pivot on, so the techniques corroborate one another.
const (
	criminalIPSearchURL = "https://api.criminalip.io/v1/banner/search"
	criminalIPCertField = "certificate"
	criminalIPCertTTL   = 1 * time.Hour
)

type criminalIPAssetTechnique struct{}

func (criminalIPAssetTechnique) Name() string           { return "criminalip_asset" }
func (criminalIPAssetTechnique) Tier() Tier             { return TierPassive }
func (criminalIPAssetTechnique) RequiresAPIKey() bool   { return true }
func (criminalIPAssetTechnique) DefaultWeight() float64 { return 0.70 }

// criminalIPSearchResponse is the subset of the banner-search payload we read.
// On success the envelope is
// {"status": 200, "data": {"result": [{"ip_address": "..."}, ...]}}.
// Criminal IP reports logical failures with a non-200 `status` field and a
// human-readable `message`, frequently still under an HTTP 200; we classify
// those alongside the HTTP-status checks.
type criminalIPSearchResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message,omitempty"`
	Data    struct {
		Result []struct {
			IPAddress string `json:"ip_address"`
		} `json:"result"`
	} `json:"data"`
}

func (criminalIPAssetTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if opts.APIKeys.CriminalIPKey == "" {
		return nil, ErrMissingAPIKey
	}

	fp, err := tlsFingerprint(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("criminalip_asset fingerprint: %w", err)
	}

	key := cache.Key("criminalip_asset", target, map[string]string{"fp": fp})
	var cached criminalIPSearchResponse
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return criminalIPCandidates(cached, target, fp), nil
		}
	}

	doc, err := criminalIPSearchPage(ctx, opts, fp)
	if err != nil {
		return nil, err
	}
	if payload, merr := json.Marshal(doc); merr == nil {
		cacheWrite(opts.Cache, opts, key, payload, criminalIPCertTTL)
	}
	return criminalIPCandidates(doc, target, fp), nil
}

func criminalIPSearchPage(ctx context.Context, opts RunOptions, fp string) (criminalIPSearchResponse, error) {
	var doc criminalIPSearchResponse

	q := url.Values{}
	q.Set("query", fmt.Sprintf(`%s: %s`, criminalIPCertField, fp))
	u := criminalIPSearchURL + "?" + q.Encode()

	if err := rateWait(ctx, opts.RateLimiter, "criminalip"); err != nil {
		return doc, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return doc, err
	}
	req.Header.Set("x-api-key", opts.APIKeys.CriminalIPKey)
	req.Header.Set("Accept", "application/json")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("criminalip_asset: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 401 = bad/missing key → clean missing-key skip.
	// 403 = key valid but plan/quota disallows; 429 = allowance hit.
	// Both surface as ErrTierInsufficient (a clean skip, not a hard error).
	if resp.StatusCode == http.StatusUnauthorized {
		return doc, fmt.Errorf("criminalip_asset: status 401: %w", ErrMissingAPIKey)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return doc, fmt.Errorf("criminalip_asset: status %d: %w", resp.StatusCode, ErrTierInsufficient)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return doc, fmt.Errorf("criminalip_asset: %s status %d", criminalIPSearchURL, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("criminalip_asset decode: %w", err)
	}
	// Criminal IP often answers HTTP 200 with a non-200 `status` field and a
	// message for quota or permission problems; classify those rather than
	// returning an empty (and misleadingly "successful") result.
	if doc.Status != 0 && doc.Status != http.StatusOK {
		msg := doc.Message
		if msg == "" {
			msg = fmt.Sprintf("status %d", doc.Status)
		}
		switch doc.Status {
		case http.StatusUnauthorized:
			return doc, fmt.Errorf("criminalip_asset: %s: %w", msg, ErrMissingAPIKey)
		case http.StatusForbidden, http.StatusTooManyRequests:
			return doc, fmt.Errorf("criminalip_asset: %s: %w", msg, ErrTierInsufficient)
		}
		if isCriminalIPTierError(msg) {
			return doc, fmt.Errorf("criminalip_asset: %s: %w", msg, ErrTierInsufficient)
		}
		if isCriminalIPKeyError(msg) {
			return doc, fmt.Errorf("criminalip_asset: %s: %w", msg, ErrMissingAPIKey)
		}
		return doc, errors.New("criminalip_asset: " + msg)
	}
	return doc, nil
}

// isCriminalIPTierError matches Criminal IP's plan-gated / quota error
// messages. Criminal IP reports quota exhaustion and feature-gating with
// human-readable text, so we classify on the message.
func isCriminalIPTierError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "quota") ||
		strings.Contains(low, "limit") ||
		strings.Contains(low, "upgrade") ||
		strings.Contains(low, "subscription") ||
		strings.Contains(low, "plan") ||
		strings.Contains(low, "permission") ||
		strings.Contains(low, "not allowed")
}

// isCriminalIPKeyError matches Criminal IP's credential-rejection messages so a
// bad key degrades to ErrMissingAPIKey (a clean skip) rather than a generic
// failure.
func isCriminalIPKeyError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "invalid api key") ||
		strings.Contains(low, "invalid api_key") ||
		strings.Contains(low, "invalid token") ||
		(strings.Contains(low, "api key") && strings.Contains(low, "not found")) ||
		strings.Contains(low, "unauthorized")
}

func criminalIPCandidates(doc criminalIPSearchResponse, target, fp string) []Candidate {
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, item := range doc.Data.Result {
		raw := strings.TrimSpace(item.IPAddress)
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
				"Criminal IP: host %s presents cert sha256:%s also served by %s",
				a, fp, target),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}
