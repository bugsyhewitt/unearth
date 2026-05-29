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

func init() { Register(chaosTechnique{}) }

// chaosTechnique queries ProjectDiscovery's Chaos dataset
// (chaos.projectdiscovery.io), the free subdomain corpus that powers
// `subfinder`. Like fullhunt_asset and zoomeye_asset — and unlike the seven
// certificate-fingerprint engines (censys_cert, shodan_cert, fofa_cert,
// netlas_cert, criminalip_asset, binaryedge_cert, leakix_cert) — Chaos is NOT
// a cert pivot. It is a domain → subdomain enumerator.
//
// Chaos differs from fullhunt_asset and zoomeye_asset in one important way:
// those backends return host→IP records directly, while Chaos returns only the
// subdomain names it has observed under the target apex. Chaos therefore needs
// a second step: each returned subdomain is resolved (via the shared resolver
// the other passive techniques use) and the non-CDN IPs behind it become
// origin candidates. A misconfigured origin record — `origin.example.com`,
// `direct.example.com`, a forgotten `mail.`/`dev.` host — that never reused the
// front-door certificate (so the cert pivots miss it) but that ProjectDiscovery
// has catalogued in its dataset will surface here, with its resolved address.
//
// Why Chaos complements the existing backends: coverage diversity from a
// genuinely independent corpus. Chaos is assembled by ProjectDiscovery from
// public bug-bounty programs, certificate transparency, and community
// contributions — a different aggregation than the active internet-wide scans
// behind Censys/Shodan or the APAC-weighted ZoomEye index. Its free tier (a
// PDCP API key, no payment) keeps it reachable.
//
// CHAOS API endpoint — isolated in a single constant per the codebase's
// "one URL constant per provider" discipline. The dataset DNS endpoint
// (GET /dns/{domain}/subdomains) authenticates via the `Authorization` header
// and returns the subdomain labels (without the apex) Chaos has recorded.
const (
	chaosSubdomainsURL = "https://dns.projectdiscovery.io/dns/%s/subdomains"
	chaosTTL           = 1 * time.Hour
	// chaosMaxResolve caps the number of subdomains the technique will resolve
	// in a single run. Chaos can return very large subdomain lists for popular
	// apex domains; resolving every one would dwarf the cost of a single API
	// call and risks a runaway DNS fan-out. The cap keeps the technique's
	// footprint bounded and predictable.
	chaosMaxResolve = 256
)

type chaosTechnique struct{}

func (chaosTechnique) Name() string           { return "chaos_asset" }
func (chaosTechnique) Tier() Tier             { return TierPassive }
func (chaosTechnique) RequiresAPIKey() bool   { return true }
func (chaosTechnique) DefaultWeight() float64 { return 0.66 }

// chaosResponse models the subset of the subdomains payload we read. On success
// the envelope is {"domain":"example.com","subdomains":["origin","www", ...],
// "count":N}. The subdomains are bare labels relative to the apex (Chaos omits
// the apex suffix); chaosHosts reassembles full hostnames. On a quota,
// permission, or auth problem Chaos answers either a non-2xx status or a 2xx
// body whose "message"/"error" field is set and whose list is empty; both are
// classified below.
type chaosResponse struct {
	Domain     string   `json:"domain,omitempty"`
	Subdomains []string `json:"subdomains"`
	Count      int      `json:"count,omitempty"`
	Message    string   `json:"message,omitempty"`
	Error      string   `json:"error,omitempty"`
}

func (chaosTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if opts.APIKeys.ChaosKey == "" {
		return nil, ErrMissingAPIKey
	}

	key := cache.Key("chaos_asset", target, nil)
	var cached chaosResponse
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return chaosCandidates(ctx, cached, target), nil
		}
	}

	if err := rateWait(ctx, opts.RateLimiter, "chaos"); err != nil {
		return nil, err
	}
	doc, err := chaosFetch(ctx, opts, target)
	if err != nil {
		return nil, err
	}

	if payload, err := json.Marshal(doc); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, chaosTTL)
	}
	return chaosCandidates(ctx, doc, target), nil
}

func chaosFetch(ctx context.Context, opts RunOptions, target string) (chaosResponse, error) {
	var doc chaosResponse

	u := fmt.Sprintf(chaosSubdomainsURL, target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return doc, err
	}
	req.Header.Set("Authorization", opts.APIKeys.ChaosKey)
	req.Header.Set("Accept", "application/json")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("chaos_asset: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 401 = bad/missing key → clean missing-key skip.
	// 403 = key valid but plan disallows the endpoint.
	// 429 = request allowance exhausted.
	// 403/429 both surface as ErrTierInsufficient (a clean skip, not a hard
	// error) so a quota-capped free account degrades gracefully.
	if resp.StatusCode == http.StatusUnauthorized {
		return doc, fmt.Errorf("chaos_asset: status 401: %w", ErrMissingAPIKey)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return doc, fmt.Errorf("chaos_asset: status %d: %w", resp.StatusCode, ErrTierInsufficient)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return doc, fmt.Errorf("chaos_asset: %s status %d",
			fmt.Sprintf(chaosSubdomainsURL, target), resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("chaos_asset decode: %w", err)
	}

	// Chaos occasionally answers 200 with a {"message"|"error"} envelope and an
	// empty subdomain list for quota or permission problems; classify those
	// rather than returning an empty (and misleadingly "successful") result.
	if msg := firstNonEmpty(doc.Error, doc.Message); msg != "" && len(doc.Subdomains) == 0 {
		if isChaosTierError(msg) {
			return doc, fmt.Errorf("chaos_asset: %s: %w", msg, ErrTierInsufficient)
		}
		if isChaosKeyError(msg) {
			return doc, fmt.Errorf("chaos_asset: %s: %w", msg, ErrMissingAPIKey)
		}
		return doc, errors.New("chaos_asset: " + msg)
	}
	return doc, nil
}

// isChaosTierError matches Chaos's plan-gated / quota error messages. The API
// reports quota exhaustion and feature-gating with human-readable text, so we
// classify on the message.
func isChaosTierError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "quota") ||
		strings.Contains(low, "rate limit") ||
		strings.Contains(low, "limit reached") ||
		strings.Contains(low, "limit exceeded") ||
		strings.Contains(low, "too many requests") ||
		strings.Contains(low, "upgrade") ||
		strings.Contains(low, "subscription") ||
		strings.Contains(low, "plan") ||
		strings.Contains(low, "permission") ||
		strings.Contains(low, "not allowed") ||
		strings.Contains(low, "insufficient")
}

// isChaosKeyError matches Chaos's credential-rejection messages so a bad key
// degrades to ErrMissingAPIKey (a clean skip) rather than a generic failure.
func isChaosKeyError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "invalid api key") ||
		strings.Contains(low, "invalid token") ||
		strings.Contains(low, "invalid key") ||
		strings.Contains(low, "unauthorized") ||
		strings.Contains(low, "wrong key") ||
		(strings.Contains(low, "api key") && strings.Contains(low, "not found")) ||
		(strings.Contains(low, "missing") && strings.Contains(low, "key"))
}

// chaosCandidates reassembles each Chaos subdomain label into a full hostname,
// resolves it via the shared resolver, and emits the non-CDN IPs behind it as
// candidates. Labels are deduped (Chaos can return both a bare label and the
// fully-qualified form), the resolve count is capped at chaosMaxResolve, and a
// per-host resolve failure is skipped rather than failing the whole run.
func chaosCandidates(ctx context.Context, doc chaosResponse, target string) []Candidate {
	apex := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(target), "."))

	hosts := chaosHosts(doc.Subdomains, apex)
	if len(hosts) > chaosMaxResolve {
		hosts = hosts[:chaosMaxResolve]
	}

	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, host := range hosts {
		addrs, err := activeResolver.LookupAddrs(ctx, host)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			a = a.Unmap()
			if seen[a] || cdn.IsCDNIP(a) {
				continue
			}
			seen[a] = true
			out = append(out, Candidate{
				IP: a.String(),
				Evidence: fmt.Sprintf(
					"Chaos: subdomain %s under %s resolved to %s",
					host, apex, a),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// chaosHosts turns Chaos's bare subdomain labels into deduplicated, fully
// qualified hostnames under the apex. Chaos returns labels without the apex
// suffix (e.g. "origin" for origin.example.com); a defensive branch also
// accepts already-qualified entries in case the dataset shape changes. The
// apex itself (an empty or "@" label) is included so a non-CDN apex A record is
// not silently dropped. Output order is deterministic (sorted) so the resolve
// cap selects a stable subset.
func chaosHosts(labels []string, apex string) []string {
	if apex == "" {
		return nil
	}
	set := map[string]struct{}{}
	for _, raw := range labels {
		label := strings.ToLower(strings.TrimSpace(raw))
		label = strings.TrimSuffix(label, ".")
		var host string
		switch {
		case label == "" || label == "@":
			host = apex
		case label == apex || strings.HasSuffix(label, "."+apex):
			// Already fully qualified.
			host = label
		default:
			host = label + "." + apex
		}
		if host != "" {
			set[host] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}
