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

func init() { Register(binaryEdgeTechnique{}) }

// binaryEdgeTechnique mirrors censys_cert, shodan_cert, fofa_cert,
// netlas_cert, and criminalip_asset but queries BinaryEdge
// (app.binaryedge.io), an internet-scanning search engine. It takes the
// target's current TLS leaf-certificate SHA-1 fingerprint, asks BinaryEdge
// for every scanned service that presents the same fingerprint, and emits
// the non-CDN hits as origin candidates.
//
// Why BinaryEdge in addition to the existing five engines: BinaryEdge runs
// its own continuous internet-wide scan grid that overlaps only partially
// with Shodan, Censys, FOFA, Netlas, and Criminal IP. A misconfigured
// origin that leaks its real certificate may surface in BinaryEdge when it
// is absent from the others — coverage diversity is the value, not
// redundancy. BinaryEdge offers a free tier with a monthly request
// allowance, so it is reachable without a paid plan.
//
// BINARYEDGE API endpoint — isolated in a single constant per the codebase's
// "one URL constant per provider" discipline. The host-search endpoint
// (GET /v2/query/search) authenticates via the `X-Key` header and takes the
// query in the `query` parameter using BinaryEdge's filter syntax. The
// `ssl.cert.as_dict.fingerprint.sha1` field matches the indexed leaf
// certificate's SHA-1 fingerprint — the same lowercase-hex SHA-1 that
// shodan_cert pivots on (BinaryEdge, like Shodan, indexes the SHA-1 form),
// so the two techniques corroborate.
const (
	binaryEdgeSearchURL = "https://api.binaryedge.io/v2/query/search"
	binaryEdgeCertField = "ssl.cert.as_dict.fingerprint.sha1"
	binaryEdgePageSize  = 100 // BinaryEdge's fixed events-per-page
	binaryEdgeCertTTL   = 1 * time.Hour
)

type binaryEdgeTechnique struct{}

func (binaryEdgeTechnique) Name() string           { return "binaryedge_cert" }
func (binaryEdgeTechnique) Tier() Tier             { return TierPassive }
func (binaryEdgeTechnique) RequiresAPIKey() bool   { return true }
func (binaryEdgeTechnique) DefaultWeight() float64 { return 0.72 }

// binaryEdgeSearchResponse is the subset of /v2/query/search we read. On
// success the envelope is
// {"events": [{"target": {"ip": "..."}}, ...], "total": N, "page": N, "pagesize": N}.
// On a quota/permission problem BinaryEdge may answer 2xx with a "title" /
// "message" envelope instead; we classify those alongside the HTTP-status
// checks.
type binaryEdgeSearchResponse struct {
	Events []struct {
		Target struct {
			IP string `json:"ip"`
		} `json:"target"`
	} `json:"events"`
	Total    int    `json:"total"`
	Page     int    `json:"page"`
	PageSize int    `json:"pagesize"`
	Title    string `json:"title,omitempty"`
	Message  string `json:"message,omitempty"`
}

func (binaryEdgeTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if opts.APIKeys.BinaryEdgeKey == "" {
		return nil, ErrMissingAPIKey
	}

	// BinaryEdge indexes the SHA-1 leaf-cert fingerprint (Shodan's flavor).
	fp, err := tlsFingerprintSHA1(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("binaryedge_cert fingerprint: %w", err)
	}

	key := cache.Key("binaryedge_cert", target, map[string]string{"fp": fp})
	var cached binaryEdgeSearchResponse
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return binaryEdgeCandidates(cached, target, fp), nil
		}
	}

	var merged binaryEdgeSearchResponse
	page := 1
	for {
		if err := rateWait(ctx, opts.RateLimiter, "binaryedge"); err != nil {
			return nil, err
		}
		got, err := binaryEdgeSearchPage(ctx, opts, fp, page)
		if err != nil {
			return nil, err
		}
		merged.Events = append(merged.Events, got.Events...)
		merged.Total = got.Total
		// Stop when this page was empty or we've covered the reported total.
		// BinaryEdge caps pagesize at 100; guard against a zero pagesize so a
		// quirky response cannot spin the loop forever.
		if len(got.Events) == 0 || len(merged.Events) >= got.Total {
			break
		}
		page++
	}

	if payload, err := json.Marshal(merged); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, binaryEdgeCertTTL)
	}
	return binaryEdgeCandidates(merged, target, fp), nil
}

func binaryEdgeSearchPage(ctx context.Context, opts RunOptions, fp string, page int) (binaryEdgeSearchResponse, error) {
	var doc binaryEdgeSearchResponse

	q := url.Values{}
	q.Set("query", fmt.Sprintf("%s:%s", binaryEdgeCertField, fp))
	if page > 1 {
		q.Set("page", fmt.Sprintf("%d", page))
	}
	u := binaryEdgeSearchURL + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return doc, err
	}
	req.Header.Set("X-Key", opts.APIKeys.BinaryEdgeKey)
	req.Header.Set("Accept", "application/json")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("binaryedge_cert: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 401 = bad/missing key → clean missing-key skip.
	// 403 = key valid but plan disallows the search capability.
	// 429 = monthly request allowance exhausted.
	// 403/429 both surface as ErrTierInsufficient (a clean skip, not a hard
	// error) so a quota-capped free account degrades gracefully.
	if resp.StatusCode == http.StatusUnauthorized {
		return doc, fmt.Errorf("binaryedge_cert: status 401: %w", ErrMissingAPIKey)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return doc, fmt.Errorf("binaryedge_cert: status %d: %w", resp.StatusCode, ErrTierInsufficient)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return doc, fmt.Errorf("binaryedge_cert: %s status %d", binaryEdgeSearchURL, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("binaryedge_cert decode: %w", err)
	}
	// BinaryEdge occasionally answers 200 with a {"title","message"} error
	// envelope for quota or permission problems; classify those rather than
	// returning an empty (and misleadingly "successful") result.
	if msg := firstNonEmpty(doc.Message, doc.Title); msg != "" && len(doc.Events) == 0 {
		if isBinaryEdgeTierError(msg) {
			return doc, fmt.Errorf("binaryedge_cert: %s: %w", msg, ErrTierInsufficient)
		}
		if isBinaryEdgeKeyError(msg) {
			return doc, fmt.Errorf("binaryedge_cert: %s: %w", msg, ErrMissingAPIKey)
		}
		return doc, errors.New("binaryedge_cert: " + msg)
	}
	return doc, nil
}

// isBinaryEdgeTierError matches BinaryEdge's plan-gated / quota error
// messages. The API reports quota exhaustion and feature-gating with
// human-readable text, so we classify on the message.
func isBinaryEdgeTierError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "quota") ||
		strings.Contains(low, "limit") ||
		strings.Contains(low, "upgrade") ||
		strings.Contains(low, "subscription") ||
		strings.Contains(low, "plan") ||
		strings.Contains(low, "permission") ||
		strings.Contains(low, "not allowed")
}

// isBinaryEdgeKeyError matches BinaryEdge's credential-rejection messages so
// a bad key degrades to ErrMissingAPIKey (a clean skip) rather than a
// generic failure.
func isBinaryEdgeKeyError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "invalid token") ||
		strings.Contains(low, "invalid key") ||
		strings.Contains(low, "invalid api") ||
		strings.Contains(low, "unauthorized") ||
		(strings.Contains(low, "token") && strings.Contains(low, "not found"))
}

func binaryEdgeCandidates(doc binaryEdgeSearchResponse, target, fp string) []Candidate {
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, ev := range doc.Events {
		raw := strings.TrimSpace(ev.Target.IP)
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
				"BinaryEdge: host %s presents cert sha1:%s also served by %s",
				a, fp, target),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}
