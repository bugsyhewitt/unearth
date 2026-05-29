package techniques

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(zoomEyeTechnique{}) }

// zoomEyeTechnique queries ZoomEye (zoomeye.org), a cyberspace search engine
// in the same family as Censys, Shodan, FOFA, Netlas and Criminal IP. Unlike
// the seven certificate-fingerprint engines (censys_cert, shodan_cert,
// fofa_cert, netlas_cert, criminalip_asset, binaryedge_cert, leakix_cert),
// ZoomEye here is NOT a cert-fingerprint pivot — it is a domain → host-asset
// enumerator, the same shape as fullhunt_asset: given the target apex domain
// it asks ZoomEye for every host it has crawled under that domain and the IPs
// behind them.
//
// Why ZoomEye complements the existing backends: coverage diversity. Censys
// and Shodan are US-centric in their scanning focus. ZoomEye (a Chinese search
// engine, like FOFA) scans a markedly different slice of the internet — a
// large majority of its indexed assets sit in APAC / China-origin IP space.
// For a target whose origin is hosted in that space, an origin that never
// reused the front-door certificate (so the cert pivots miss it) and that was
// never crawled by FullHunt can still appear in ZoomEye's host inventory. The
// non-CDN IPs ZoomEye observed for those hosts are origin candidates. ZoomEye
// offers a free tier with a monthly request allowance, so it is reachable
// without a paid plan.
//
// ZOOMEYE API endpoint — isolated in a single constant per the codebase's
// "one URL constant per provider" discipline. The domain-search endpoint
// (GET /domain/search?q={domain}&type=1) authenticates via the `API-KEY`
// header and returns an associated-domain list, each entry carrying the IP(s)
// ZoomEye resolved the host to. type=1 selects associated (sub)domains rather
// than reverse-WHOIS results.
const (
	zoomEyeSearchURL = "https://api.zoomeye.org/domain/search?q=%s&type=1"
	zoomEyeTTL       = 1 * time.Hour
)

type zoomEyeTechnique struct{}

func (zoomEyeTechnique) Name() string           { return "zoomeye_asset" }
func (zoomEyeTechnique) Tier() Tier             { return TierPassive }
func (zoomEyeTechnique) RequiresAPIKey() bool   { return true }
func (zoomEyeTechnique) DefaultWeight() float64 { return 0.68 }

// zoomEyeSearchResponse models the subset of the domain-search payload we read.
// On success the envelope is
// {"status":200,"total":N,"list":[{"name":"host.example.com","ip":["1.2.3.4", ...]}, ...]}.
// On a quota/permission/auth problem ZoomEye answers either a non-2xx status
// or a 2xx body whose "message"/"error" field is set and whose list is empty;
// we classify those alongside the HTTP-status checks. ZoomEye's "ip" field is
// documented as an array, but to be defensive against single-string responses
// zoomEyeHost decodes it through a flexible type.
type zoomEyeSearchResponse struct {
	Status  int           `json:"status,omitempty"`
	Total   int           `json:"total,omitempty"`
	List    []zoomEyeHost `json:"list"`
	Message string        `json:"message,omitempty"`
	Error   string        `json:"error,omitempty"`
}

// zoomEyeHost is one entry in the associated-domain list. ip may arrive as a
// JSON array of strings or, defensively, as a bare string; zoomEyeIPs
// normalizes both.
type zoomEyeHost struct {
	Name string     `json:"name"`
	IP   zoomEyeIPs `json:"ip"`
}

// zoomEyeIPs unmarshals ZoomEye's ip field whether it arrives as a JSON array
// of strings or a single string.
type zoomEyeIPs []string

func (z *zoomEyeIPs) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		*z = nil
		return nil
	}
	switch trimmed[0] {
	case '[':
		var arr []string
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*z = arr
	case '"':
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*z = []string{s}
	default:
		return fmt.Errorf("unexpected ip shape: %q", trimmed[:1])
	}
	return nil
}

func (zoomEyeTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if opts.APIKeys.ZoomEyeKey == "" {
		return nil, ErrMissingAPIKey
	}

	key := cache.Key("zoomeye_asset", target, nil)
	var cached zoomEyeSearchResponse
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return zoomEyeCandidates(cached, target), nil
		}
	}

	if err := rateWait(ctx, opts.RateLimiter, "zoomeye"); err != nil {
		return nil, err
	}
	doc, err := zoomEyeFetch(ctx, opts, target)
	if err != nil {
		return nil, err
	}

	if payload, err := json.Marshal(doc); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, zoomEyeTTL)
	}
	return zoomEyeCandidates(doc, target), nil
}

func zoomEyeFetch(ctx context.Context, opts RunOptions, target string) (zoomEyeSearchResponse, error) {
	var doc zoomEyeSearchResponse

	u := fmt.Sprintf(zoomEyeSearchURL, target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return doc, err
	}
	req.Header.Set("API-KEY", opts.APIKeys.ZoomEyeKey)
	req.Header.Set("Accept", "application/json")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("zoomeye_asset: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 401 = bad/missing key → clean missing-key skip.
	// 403 = key valid but plan disallows the endpoint.
	// 429 = monthly request allowance exhausted.
	// 403/429 both surface as ErrTierInsufficient (a clean skip, not a hard
	// error) so a quota-capped free account degrades gracefully.
	if resp.StatusCode == http.StatusUnauthorized {
		return doc, fmt.Errorf("zoomeye_asset: status 401: %w", ErrMissingAPIKey)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return doc, fmt.Errorf("zoomeye_asset: status %d: %w", resp.StatusCode, ErrTierInsufficient)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return doc, fmt.Errorf("zoomeye_asset: %s status %d",
			fmt.Sprintf(zoomEyeSearchURL, target), resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("zoomeye_asset decode: %w", err)
	}

	// ZoomEye occasionally answers 200 with a {"message"|"error"} envelope and
	// an empty list for quota or permission problems; classify those rather
	// than returning an empty (and misleadingly "successful") result.
	if msg := firstNonEmpty(doc.Error, doc.Message); msg != "" && len(doc.List) == 0 {
		if isZoomEyeTierError(msg) {
			return doc, fmt.Errorf("zoomeye_asset: %s: %w", msg, ErrTierInsufficient)
		}
		if isZoomEyeKeyError(msg) {
			return doc, fmt.Errorf("zoomeye_asset: %s: %w", msg, ErrMissingAPIKey)
		}
		return doc, errors.New("zoomeye_asset: " + msg)
	}
	return doc, nil
}

// isZoomEyeTierError matches ZoomEye's plan-gated / quota error messages.
// The API reports quota exhaustion and feature-gating with human-readable
// text, so we classify on the message.
func isZoomEyeTierError(msg string) bool {
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
		strings.Contains(low, "insufficient")
}

// isZoomEyeKeyError matches ZoomEye's credential-rejection messages so a bad
// key degrades to ErrMissingAPIKey (a clean skip) rather than a generic
// failure.
func isZoomEyeKeyError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "invalid api key") ||
		strings.Contains(low, "invalid token") ||
		strings.Contains(low, "invalid key") ||
		strings.Contains(low, "unauthorized") ||
		strings.Contains(low, "wrong key") ||
		(strings.Contains(low, "api key") && strings.Contains(low, "not found")) ||
		(strings.Contains(low, "missing") && strings.Contains(low, "key"))
}

func zoomEyeCandidates(doc zoomEyeSearchResponse, target string) []Candidate {
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, h := range doc.List {
		host := strings.TrimSpace(h.Name)
		for _, rawIP := range h.IP {
			raw := strings.TrimSpace(rawIP)
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
			label := host
			if label == "" {
				label = target
			}
			out = append(out, Candidate{
				IP: a.String(),
				Evidence: fmt.Sprintf(
					"ZoomEye: host %s under %s observed at %s",
					label, target, a),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}
