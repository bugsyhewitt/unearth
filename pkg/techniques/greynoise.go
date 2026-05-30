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

func init() { Register(greyNoiseTechnique{}) }

// greyNoiseTechnique queries GreyNoise (greynoise.io), an internet-noise
// intelligence platform that runs a planetary sensor mesh and indexes every
// IP it has observed scanning or interacting with the public internet, with
// per-IP metadata (reverse DNS, organization, ASN, classification). Unlike
// the eight certificate-fingerprint engines (censys_cert, shodan_cert,
// fofa_cert, netlas_cert, criminalip_asset, binaryedge_cert, leakix_cert,
// onyphe_cert), and unlike the asset enumerators (fullhunt_asset,
// zoomeye_asset, chaos_asset), GreyNoise here is NOT a cert pivot and not a
// domain-keyed asset enumerator either: it is a GNQL (GreyNoise Query
// Language) search on the rDNS-and-organization metadata GreyNoise has
// attached to every IP its sensors observed.
//
// Why GreyNoise complements the existing backends: yet another orthogonal
// corpus axis. The cert engines find hosts that reuse the front-door leaf
// cert. FullHunt, ZoomEye, and Chaos find hosts catalogued under the target
// apex by crawl/CT/community aggregation. VirusTotal, URLScan, and OTX find
// hosts via passive-DNS / scan-record / threat-intel telemetry. GreyNoise
// finds hosts that *its own internet-wide sensor mesh has interacted with*
// whose reverse DNS or organization label contains the target apex — i.e. a
// box on the public internet that (a) actually generated traffic GreyNoise
// observed and (b) advertises itself as part of the target's footprint
// through PTR records or org metadata. A forgotten origin (`origin.`,
// `direct.`, `mail.`, `staging.`) that talked to anyone in the last 90 days
// and has a reverse DNS pointing under the apex is exactly the kind of host
// GreyNoise sees that the cert engines and crawl backends often miss.
// GreyNoise offers a free Community tier and the GNQL search is in the paid
// Enterprise tier, but a free trial / Investigate plan exposes it; the
// technique degrades cleanly when the plan disallows the endpoint.
//
// GREYNOISE API endpoint — isolated in a single constant per the codebase's
// "one URL constant per provider" discipline. The GNQL search endpoint
// (GET /v2/experimental/gnql?query=...) authenticates via the `key` header
// and returns paged data with a `scroll` cursor for continuation. Query
// filter is `metadata.rdns:*<target> OR metadata.organization:"<target>"`
// rendered as one GNQL expression to surface both the reverse-DNS and the
// organization-name pivots in a single call.
const (
	greyNoiseGNQLURL = "https://api.greynoise.io/v2/experimental/gnql"
	greyNoiseTTL     = 1 * time.Hour

	// greyNoiseMaxPages caps the scroll loop so a misbehaving cursor cannot
	// drive an unbounded fetch. 10 pages * 1000 default results = 10k IPs,
	// well past any realistic origin-discovery need.
	greyNoiseMaxPages = 10
)

type greyNoiseTechnique struct{}

func (greyNoiseTechnique) Name() string           { return "greynoise_asset" }
func (greyNoiseTechnique) Tier() Tier             { return TierPassive }
func (greyNoiseTechnique) RequiresAPIKey() bool   { return true }
func (greyNoiseTechnique) DefaultWeight() float64 { return 0.65 }

// greyNoiseGNQLResponse models the subset of the GNQL payload we read.
// On success the envelope is
// {"complete":true,"count":N,"data":[{"ip":"...","metadata":{"rdns":"...","organization":"..."}}, ...],"scroll":"...","message":"ok"}.
// On a quota/permission/auth problem GreyNoise answers either a non-2xx
// status or a 2xx body whose "message"/"error" field signals the problem
// and whose data list is empty; classified alongside the HTTP-status checks.
type greyNoiseGNQLResponse struct {
	Complete bool                `json:"complete"`
	Count    int                 `json:"count"`
	Data     []greyNoiseDataItem `json:"data"`
	Scroll   string              `json:"scroll,omitempty"`
	Message  string              `json:"message,omitempty"`
	Error    string              `json:"error,omitempty"`
}

type greyNoiseDataItem struct {
	IP       string            `json:"ip"`
	Metadata greyNoiseMetadata `json:"metadata"`
}

type greyNoiseMetadata struct {
	RDNS         string `json:"rdns"`
	Organization string `json:"organization"`
	ASN          string `json:"asn"`
}

func (greyNoiseTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if opts.APIKeys.GreyNoiseKey == "" {
		return nil, ErrMissingAPIKey
	}

	key := cache.Key("greynoise_asset", target, nil)
	var cached greyNoiseGNQLResponse
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return greyNoiseCandidates(cached, target), nil
		}
	}

	merged, err := greyNoiseFetchAll(ctx, opts, target)
	if err != nil {
		return nil, err
	}

	if payload, err := json.Marshal(merged); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, greyNoiseTTL)
	}
	return greyNoiseCandidates(merged, target), nil
}

func greyNoiseFetchAll(ctx context.Context, opts RunOptions, target string) (greyNoiseGNQLResponse, error) {
	var merged greyNoiseGNQLResponse
	scroll := ""
	for page := 0; page < greyNoiseMaxPages; page++ {
		if err := rateWait(ctx, opts.RateLimiter, "greynoise"); err != nil {
			return merged, err
		}
		doc, err := greyNoiseFetch(ctx, opts, target, scroll)
		if err != nil {
			return merged, err
		}
		merged.Data = append(merged.Data, doc.Data...)
		merged.Count = doc.Count
		merged.Complete = doc.Complete
		if doc.Scroll == "" || len(doc.Data) == 0 || doc.Complete {
			break
		}
		scroll = doc.Scroll
	}
	return merged, nil
}

func greyNoiseFetch(ctx context.Context, opts RunOptions, target, scroll string) (greyNoiseGNQLResponse, error) {
	var doc greyNoiseGNQLResponse

	q := url.Values{}
	q.Set("query", fmt.Sprintf(`metadata.rdns:*%s OR metadata.organization:"%s"`, target, target))
	if scroll != "" {
		q.Set("scroll", scroll)
	}
	u := greyNoiseGNQLURL + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return doc, err
	}
	req.Header.Set("key", opts.APIKeys.GreyNoiseKey)
	req.Header.Set("Accept", "application/json")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("greynoise_asset: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 401 = bad/missing key → clean missing-key skip.
	// 402 = payment required / plan does not include GNQL.
	// 403 = key valid but plan disallows the endpoint.
	// 429 = monthly request allowance exhausted.
	// 402/403/429 all surface as ErrTierInsufficient (clean skip) so a
	// Community-tier account degrades gracefully rather than failing the run.
	if resp.StatusCode == http.StatusUnauthorized {
		return doc, fmt.Errorf("greynoise_asset: status 401: %w", ErrMissingAPIKey)
	}
	if resp.StatusCode == http.StatusPaymentRequired ||
		resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusTooManyRequests {
		return doc, fmt.Errorf("greynoise_asset: status %d: %w", resp.StatusCode, ErrTierInsufficient)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return doc, fmt.Errorf("greynoise_asset: %s status %d", greyNoiseGNQLURL, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("greynoise_asset decode: %w", err)
	}

	if msg := firstNonEmpty(doc.Error, doc.Message); msg != "" && len(doc.Data) == 0 && !isGreyNoiseOKMessage(msg) {
		if isGreyNoiseTierError(msg) {
			return doc, fmt.Errorf("greynoise_asset: %s: %w", msg, ErrTierInsufficient)
		}
		if isGreyNoiseKeyError(msg) {
			return doc, fmt.Errorf("greynoise_asset: %s: %w", msg, ErrMissingAPIKey)
		}
		return doc, errors.New("greynoise_asset: " + msg)
	}
	return doc, nil
}

// isGreyNoiseOKMessage matches GreyNoise's benign success/empty messages so an
// empty-but-successful response is not misclassified as an error envelope.
func isGreyNoiseOKMessage(msg string) bool {
	low := strings.ToLower(strings.TrimSpace(msg))
	return low == "ok" || low == "success" || strings.Contains(low, "no results")
}

func isGreyNoiseTierError(msg string) bool {
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
		strings.Contains(low, "payment required") ||
		strings.Contains(low, "trial") ||
		strings.Contains(low, "feature is not enabled")
}

func isGreyNoiseKeyError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "invalid api key") ||
		strings.Contains(low, "invalid token") ||
		strings.Contains(low, "invalid key") ||
		strings.Contains(low, "unauthorized") ||
		(strings.Contains(low, "api key") && strings.Contains(low, "not found")) ||
		(strings.Contains(low, "missing") && strings.Contains(low, "key"))
}

func greyNoiseCandidates(doc greyNoiseGNQLResponse, target string) []Candidate {
	seen := map[netip.Addr]bool{}
	var out []Candidate
	lowTarget := strings.ToLower(target)
	for _, d := range doc.Data {
		raw := strings.TrimSpace(d.IP)
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

		// Build evidence preferring the most-specific reason for surfacing:
		// rDNS containing the apex beats org-name match (the rDNS pivot is
		// a stronger signal that the IP is actually under the target).
		var why string
		rdns := strings.ToLower(strings.TrimSpace(d.Metadata.RDNS))
		org := strings.TrimSpace(d.Metadata.Organization)
		switch {
		case rdns != "" && strings.Contains(rdns, lowTarget):
			why = fmt.Sprintf("rDNS %s", d.Metadata.RDNS)
		case org != "":
			why = fmt.Sprintf("org %q", org)
		default:
			why = "GNQL match"
		}
		out = append(out, Candidate{
			IP: a.String(),
			Evidence: fmt.Sprintf(
				"GreyNoise: %s observed at %s (%s)",
				target, a, why),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}
