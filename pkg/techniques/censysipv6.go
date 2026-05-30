package techniques

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(censysIPv6Technique{}) }

// censysIPv6Technique is an IPv6-only asset-discovery pivot against the
// Censys Platform. It is intentionally orthogonal to censys_cert:
//
//   - censys_cert pivots on the target's TLS leaf-certificate SHA-256, which
//     only surfaces hosts that *reuse the front-door certificate*. A
//     dual-stack origin whose IPv6 listener never bound the public cert (a
//     common misconfiguration: the v4 frontend was migrated behind a CDN, the
//     v6 listener was forgotten and continues to serve a stale self-signed or
//     internal cert) is invisible to censys_cert.
//
//   - censys_ipv6 pivots on the target's *DNS apex* via the Platform's
//     host.dns.names field, then keeps only IPv6 hits whose addresses are
//     outside known CDN ranges. This catches the AAAA-leak pattern explicitly:
//     a publicly-resolvable hostname under the target apex (origin.example.com,
//     v6.example.com, a forgotten dev subdomain) whose Censys-indexed IPv6
//     listener bypasses the CDN.
//
// The two techniques corroborate naturally: when both surface the same IPv6
// the noisy-OR ranking combines their weights; when only censys_ipv6 fires
// it's reporting a real coverage gap the cert pivot cannot see.
//
// CENSYS PLATFORM API endpoint — reuses the same global search endpoint that
// censys_cert hits. The CenQL field for DNS forward-resolution is
// `host.dns.names`. Per the Platform schema the field is multi-valued and
// supports both the apex literal and wildcard expansion via OR, so a single
// query enumerates every indexed host whose DNS records reference the apex
// or a subdomain of it.
const (
	censysIPv6SearchURL = censysPlatformSearchURL
	censysIPv6DNSField  = "host.dns.names"
)

const censysIPv6TTL = 1 * time.Hour

type censysIPv6Technique struct{}

func (censysIPv6Technique) Name() string           { return "censys_ipv6" }
func (censysIPv6Technique) Tier() Tier             { return TierPassive }
func (censysIPv6Technique) RequiresAPIKey() bool   { return true }
func (censysIPv6Technique) DefaultWeight() float64 { return 0.78 }

// censysIPv6Response reuses the same envelope shape as censys_cert — the
// Platform's global search endpoint returns {"result":{"hits":[...]}}
// regardless of the CenQL filter — but is declared as its own type so a
// future schema divergence (e.g. asking for additional IPv6-specific fields
// such as `host.ip_version`) doesn't ripple into censys_cert.
type censysIPv6Response struct {
	Result struct {
		Hits []struct {
			Host struct {
				IP string `json:"ip"`
			} `json:"host"`
		} `json:"hits"`
		NextPageToken string `json:"next_page_token"`
	} `json:"result"`
}

func (censysIPv6Technique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if opts.APIKeys.CensysPlatformPAT == "" {
		return nil, ErrMissingAPIKey
	}

	// Cache check before charging the Censys budget. The cache key
	// commits to the target apex and to the api flavor so a later
	// censys_cert hit on the same apex doesn't collide.
	key := cache.Key("censys_ipv6", target, map[string]string{"api": "platform"})
	var cached censysIPv6Response
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return censysIPv6Candidates(cached, target), nil
		}
	}

	// Live call. Charge the Censys budget before each page so a
	// runaway pagination loop cannot drain the user's allowance.
	var merged censysIPv6Response
	pageToken := ""
	for {
		if opts.Budget != nil && !opts.Budget.Charge("censys") {
			return nil, ErrBudgetExhausted
		}
		if err := rateWait(ctx, opts.RateLimiter, "censys"); err != nil {
			return nil, err
		}
		page, err := censysIPv6SearchPage(ctx, opts, target, pageToken)
		if err != nil {
			return nil, err
		}
		merged.Result.Hits = append(merged.Result.Hits, page.Result.Hits...)
		if page.Result.NextPageToken == "" {
			break
		}
		pageToken = page.Result.NextPageToken
	}

	if payload, err := json.Marshal(merged); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, censysIPv6TTL)
	}
	return censysIPv6Candidates(merged, target), nil
}

func censysIPv6SearchPage(ctx context.Context, opts RunOptions, target, pageToken string) (censysIPv6Response, error) {
	var doc censysIPv6Response
	// Query both the apex literal and the wildcard form so subdomains
	// recorded in Censys (origin.target, v6.target, etc.) match. The
	// Platform CenQL accepts comma-separated OR-style alternates inside a
	// quoted multi-value field via the colon-OR pattern documented for
	// `host.dns.names`. We use the explicit `field=value OR field=value`
	// form, which the Platform documents as the portable spelling.
	query := fmt.Sprintf(`%s="%s" OR %s="*.%s"`,
		censysIPv6DNSField, target, censysIPv6DNSField, target)
	body, err := json.Marshal(censysSearchRequest{
		Query:     query,
		Fields:    []string{"host.ip"},
		PageSize:  censysSearchPageSize,
		PageToken: pageToken,
	})
	if err != nil {
		return doc, fmt.Errorf("censys_ipv6 encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, censysIPv6SearchURL, bytes.NewReader(body))
	if err != nil {
		return doc, err
	}
	req.Header.Set("Authorization", "Bearer "+opts.APIKeys.CensysPlatformPAT)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("censys_ipv6: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// 401/403 from the Platform almost always means the PAT is valid
		// but the account tier lacks the host-search capability (Free
		// tier may not include it). Surface as a tier_insufficient skip
		// rather than a scary error, mirroring censys_cert.
		return doc, fmt.Errorf("censys_ipv6: status %d: %w", resp.StatusCode, ErrTierInsufficient)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		// 429 is the documented allowance-exhausted response on the
		// Platform's global endpoint. Same tier-insufficient treatment.
		return doc, fmt.Errorf("censys_ipv6: status 429: %w", ErrTierInsufficient)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return doc, fmt.Errorf("censys_ipv6: %s status %d", censysIPv6SearchURL, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("censys_ipv6 decode: %w", err)
	}
	return doc, nil
}

// censysIPv6Candidates filters the Platform response down to non-CDN IPv6
// addresses. IPv4 hits are intentionally dropped: censys_cert already covers
// the v4 origin-cert-reuse case, and the value of this technique is the v6
// signal that censys_cert misses. Dedup is by address.
func censysIPv6Candidates(doc censysIPv6Response, target string) []Candidate {
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, h := range doc.Result.Hits {
		a, err := netip.ParseAddr(h.Host.IP)
		if err != nil {
			continue
		}
		a = a.Unmap()
		// IPv6 only. An IPv4-mapped v6 address (::ffff:1.2.3.4) is an
		// IPv4 address in disguise; Unmap above collapses it, after which
		// Is4() correctly reports true and we skip it.
		if a.Is4() || !a.Is6() {
			continue
		}
		if seen[a] || cdn.IsCDNIP(a) {
			continue
		}
		seen[a] = true
		out = append(out, Candidate{
			IP: a.String(),
			Evidence: fmt.Sprintf(
				"Censys: IPv6 host %s indexed under DNS name *.%s (origin v6 leak)",
				a, target),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}
