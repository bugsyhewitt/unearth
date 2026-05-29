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

func init() { Register(fullHuntTechnique{}) }

// fullHuntTechnique queries FullHunt (fullhunt.io), an attack-surface
// management platform that continuously crawls the internet and maps every
// host it has observed under a domain to the IP addresses it resolved them
// to. Unlike the seven certificate-fingerprint engines (censys_cert,
// shodan_cert, fofa_cert, netlas_cert, criminalip_asset, binaryedge_cert,
// leakix_cert), FullHunt is NOT a cert-fingerprint pivot — its public API has
// no certificate-fingerprint search. Instead it is a domain → host-asset
// enumerator: given the target apex domain it returns FullHunt's recorded
// host inventory, each host carrying the IP(s) FullHunt observed it on.
//
// Why FullHunt complements the cert engines: FullHunt's value is a different
// kind of corpus, not a redundant one. The cert engines find hosts that
// present the *same leaf certificate* the live target serves; FullHunt finds
// every host *under the same domain* it has ever crawled and the IPs behind
// them. A misconfigured origin that never reused the front-door certificate —
// so the cert pivots miss it — can still appear in FullHunt's historical host
// inventory (e.g. an `origin.example.com` or `direct.example.com` record
// pointing straight at the backend). The non-CDN IPs FullHunt observed for
// those hosts are origin candidates. FullHunt offers a free tier with a
// monthly request allowance, so it is reachable without a paid plan.
//
// FULLHUNT API endpoint — isolated in a single constant per the codebase's
// "one URL constant per provider" discipline. The domain-details endpoint
// (GET /api/v1/domain/{domain}/details) authenticates via the `X-API-KEY`
// header and returns a single object envelope, so no pagination is required:
// the full host inventory for the domain arrives in one response.
const (
	fullHuntDetailsURL = "https://fullhunt.io/api/v1/domain/%s/details"
	fullHuntTTL        = 1 * time.Hour
)

type fullHuntTechnique struct{}

func (fullHuntTechnique) Name() string           { return "fullhunt_asset" }
func (fullHuntTechnique) Tier() Tier             { return TierPassive }
func (fullHuntTechnique) RequiresAPIKey() bool   { return true }
func (fullHuntTechnique) DefaultWeight() float64 { return 0.70 }

// fullHuntDetailsResponse models the subset of the domain-details payload we
// read. On success the envelope is
// {"domain":"...","hosts":[{"host":"...","ip_address":["1.2.3.4", ...]}, ...]}.
// On a quota/permission/auth problem FullHunt may answer 2xx with a
// "message"/"error" envelope and no hosts; we classify those alongside the
// HTTP-status checks. FullHunt's ip_address field is documented as an array,
// but to be defensive against single-string responses fullHuntHost decodes
// it through a flexible type.
type fullHuntDetailsResponse struct {
	Domain  string         `json:"domain"`
	Hosts   []fullHuntHost `json:"hosts"`
	Message string         `json:"message,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// fullHuntHost is one entry in the hosts inventory. ip_address may arrive as
// a JSON array of strings or, defensively, as a bare string; fullHuntIPs
// normalizes both.
type fullHuntHost struct {
	Host      string      `json:"host"`
	IPAddress fullHuntIPs `json:"ip_address"`
}

// fullHuntIPs unmarshals FullHunt's ip_address field whether it arrives as a
// JSON array of strings or a single string.
type fullHuntIPs []string

func (f *fullHuntIPs) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		*f = nil
		return nil
	}
	switch trimmed[0] {
	case '[':
		var arr []string
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*f = arr
	case '"':
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*f = []string{s}
	default:
		return fmt.Errorf("unexpected ip_address shape: %q", trimmed[:1])
	}
	return nil
}

func (fullHuntTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if opts.APIKeys.FullHuntKey == "" {
		return nil, ErrMissingAPIKey
	}

	key := cache.Key("fullhunt_asset", target, nil)
	var cached fullHuntDetailsResponse
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return fullHuntCandidates(cached, target), nil
		}
	}

	if err := rateWait(ctx, opts.RateLimiter, "fullhunt"); err != nil {
		return nil, err
	}
	doc, err := fullHuntFetch(ctx, opts, target)
	if err != nil {
		return nil, err
	}

	if payload, err := json.Marshal(doc); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, fullHuntTTL)
	}
	return fullHuntCandidates(doc, target), nil
}

func fullHuntFetch(ctx context.Context, opts RunOptions, target string) (fullHuntDetailsResponse, error) {
	var doc fullHuntDetailsResponse

	u := fmt.Sprintf(fullHuntDetailsURL, target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return doc, err
	}
	req.Header.Set("X-API-KEY", opts.APIKeys.FullHuntKey)
	req.Header.Set("Accept", "application/json")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("fullhunt_asset: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 401 = bad/missing key → clean missing-key skip.
	// 403 = key valid but plan disallows the endpoint.
	// 429 = monthly request allowance exhausted.
	// 403/429 both surface as ErrTierInsufficient (a clean skip, not a hard
	// error) so a quota-capped free account degrades gracefully.
	if resp.StatusCode == http.StatusUnauthorized {
		return doc, fmt.Errorf("fullhunt_asset: status 401: %w", ErrMissingAPIKey)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return doc, fmt.Errorf("fullhunt_asset: status %d: %w", resp.StatusCode, ErrTierInsufficient)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return doc, fmt.Errorf("fullhunt_asset: %s status %d",
			fmt.Sprintf(fullHuntDetailsURL, target), resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("fullhunt_asset decode: %w", err)
	}

	// FullHunt occasionally answers 200 with a {"message"|"error"} envelope and
	// no hosts for quota or permission problems; classify those rather than
	// returning an empty (and misleadingly "successful") result.
	if msg := firstNonEmpty(doc.Error, doc.Message); msg != "" && len(doc.Hosts) == 0 {
		if isFullHuntTierError(msg) {
			return doc, fmt.Errorf("fullhunt_asset: %s: %w", msg, ErrTierInsufficient)
		}
		if isFullHuntKeyError(msg) {
			return doc, fmt.Errorf("fullhunt_asset: %s: %w", msg, ErrMissingAPIKey)
		}
		return doc, errors.New("fullhunt_asset: " + msg)
	}
	return doc, nil
}

// isFullHuntTierError matches FullHunt's plan-gated / quota error messages.
// The API reports quota exhaustion and feature-gating with human-readable
// text, so we classify on the message.
func isFullHuntTierError(msg string) bool {
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

// isFullHuntKeyError matches FullHunt's credential-rejection messages so a bad
// key degrades to ErrMissingAPIKey (a clean skip) rather than a generic
// failure.
func isFullHuntKeyError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "invalid api key") ||
		strings.Contains(low, "invalid token") ||
		strings.Contains(low, "invalid key") ||
		strings.Contains(low, "unauthorized") ||
		(strings.Contains(low, "api key") && strings.Contains(low, "not found")) ||
		(strings.Contains(low, "missing") && strings.Contains(low, "key"))
}

func fullHuntCandidates(doc fullHuntDetailsResponse, target string) []Candidate {
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, h := range doc.Hosts {
		host := strings.TrimSpace(h.Host)
		for _, rawIP := range h.IPAddress {
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
					"FullHunt: host %s under %s observed at %s",
					label, target, a),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}
