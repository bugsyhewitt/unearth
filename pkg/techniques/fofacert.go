package techniques

import (
	"context"
	"encoding/base64"
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

func init() { Register(fofaCertTechnique{}) }

// fofaCertTechnique mirrors censys_cert and shodan_cert but queries FOFA
// (fofa.info), the China-based internet-asset search engine. It takes the
// target's current TLS leaf-certificate SHA-256 fingerprint, asks FOFA for
// every host that presents the same fingerprint, and emits the non-CDN hits
// as origin candidates.
//
// Why FOFA in addition to Censys/Shodan: Shodan and Censys are both
// US-centric in their scanning focus. FOFA indexes 4B+ assets with
// significantly heavier coverage of APAC IP space — a meaningful fraction of
// targets hosted in Asia simply do not appear in Shodan or Censys but do
// appear in FOFA. Coverage diversity, not redundancy, is the value here.
//
// FOFA API endpoint — isolated in a single constant per the codebase's
// "one URL constant per provider" discipline. The v1 search endpoint takes
// the query base64-encoded in the `qbase64` parameter and authenticates via
// the email+key pair as query parameters. The `cert` field matches against
// the indexed certificate text, in which the lowercase-hex SHA-256
// fingerprint appears — the same fingerprint censys_cert pivots on, so the
// two techniques can corroborate each other.
const (
	fofaSearchURL  = "https://fofa.info/api/v1/search/all"
	fofaCertField  = "cert"
	fofaPageSize   = 100
	fofaCertTTL    = 1 * time.Hour
	fofaResultsKey = "ip" // single result field we request, so each row is one IP
)

type fofaCertTechnique struct{}

func (fofaCertTechnique) Name() string           { return "fofa_cert" }
func (fofaCertTechnique) Tier() Tier             { return TierPassive }
func (fofaCertTechnique) RequiresAPIKey() bool   { return true }
func (fofaCertTechnique) DefaultWeight() float64 { return 0.80 }

// fofaSearchResponse is the subset of /api/v1/search/all we read. FOFA marks
// failures with `error: true` and an `errmsg`; on success `results` is an
// array of rows, each row an array of the requested fields. We request a
// single field (ip), so every row is a one-element array.
type fofaSearchResponse struct {
	Error   bool       `json:"error"`
	ErrMsg  string     `json:"errmsg"`
	Mode    string     `json:"mode"`
	Size    int        `json:"size"`
	Page    int        `json:"page"`
	Results [][]string `json:"results"`
}

func (fofaCertTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if opts.APIKeys.FOFAEmail == "" || opts.APIKeys.FOFAKey == "" {
		return nil, ErrMissingAPIKey
	}

	fp, err := tlsFingerprint(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("fofa_cert fingerprint: %w", err)
	}

	key := cache.Key("fofa_cert", target, map[string]string{"fp": fp})
	var cached fofaSearchResponse
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return fofaCandidates(cached, target, fp), nil
		}
	}

	doc, err := fofaSearchPage(ctx, opts, fp)
	if err != nil {
		return nil, err
	}
	if payload, merr := json.Marshal(doc); merr == nil {
		cacheWrite(opts.Cache, opts, key, payload, fofaCertTTL)
	}
	return fofaCandidates(doc, target, fp), nil
}

func fofaSearchPage(ctx context.Context, opts RunOptions, fp string) (fofaSearchResponse, error) {
	var doc fofaSearchResponse

	query := fmt.Sprintf(`%s="%s"`, fofaCertField, fp)
	qb64 := base64.StdEncoding.EncodeToString([]byte(query))

	q := url.Values{}
	q.Set("email", opts.APIKeys.FOFAEmail)
	q.Set("key", opts.APIKeys.FOFAKey)
	q.Set("qbase64", qb64)
	q.Set("fields", fofaResultsKey)
	q.Set("size", fmt.Sprintf("%d", fofaPageSize))
	u := fofaSearchURL + "?" + q.Encode()

	if err := rateWait(ctx, opts.RateLimiter, "fofa"); err != nil {
		return doc, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return doc, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("fofa_cert: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		return doc, fmt.Errorf("fofa_cert: status 401: %w", ErrMissingAPIKey)
	}
	if resp.StatusCode == http.StatusForbidden {
		return doc, fmt.Errorf("fofa_cert: status 403: %w", ErrTierInsufficient)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return doc, fmt.Errorf("fofa_cert: %s status %d", fofaSearchURL, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("fofa_cert decode: %w", err)
	}
	if doc.Error {
		if isFOFATierError(doc.ErrMsg) {
			return doc, fmt.Errorf("fofa_cert: %s: %w", doc.ErrMsg, ErrTierInsufficient)
		}
		if isFOFAKeyError(doc.ErrMsg) {
			return doc, fmt.Errorf("fofa_cert: %s: %w", doc.ErrMsg, ErrMissingAPIKey)
		}
		return doc, errors.New("fofa_cert: " + doc.ErrMsg)
	}
	return doc, nil
}

// isFOFATierError matches FOFA's plan-gated / quota error messages. FOFA
// returns HTTP 200 with `error: true` and a human-readable `errmsg` for both
// quota exhaustion and feature-gating, so we classify on the message.
func isFOFATierError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "quota") ||
		strings.Contains(low, "upgrade") ||
		strings.Contains(low, "permission") ||
		strings.Contains(low, "membership") ||
		strings.Contains(low, "no privilege") ||
		strings.Contains(low, "f point")
}

// isFOFAKeyError matches FOFA's credential-rejection messages so a bad
// email/key pair degrades to ErrMissingAPIKey (a clean skip) rather than a
// generic failure.
func isFOFAKeyError(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "invalid") && (strings.Contains(low, "key") || strings.Contains(low, "email")) ||
		strings.Contains(low, "account") && strings.Contains(low, "invalid") ||
		strings.Contains(low, "[-700]") // FOFA's "account invalid" code
}

func fofaCandidates(doc fofaSearchResponse, target, fp string) []Candidate {
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, row := range doc.Results {
		if len(row) == 0 {
			continue
		}
		// We requested a single field (ip), so the IP is row[0]. FOFA may
		// return "ip:port" or a bare IP depending on indexing; strip a
		// trailing :port if present, but leave bracketed IPv6 literals alone.
		raw := strings.TrimSpace(row[0])
		raw = stripFOFAPort(raw)
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
				"FOFA: host %s presents cert sha256:%s also served by %s",
				a, fp, target),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// stripFOFAPort removes a trailing ":port" from an IPv4 literal. It leaves
// IPv6 literals (which contain multiple colons, or are bracketed) untouched
// so they parse correctly via netip.ParseAddr.
func stripFOFAPort(s string) string {
	// Bracketed forms like "[2001:db8::1]:443" — take the bracket contents.
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]"); end > 0 {
			return s[1:end]
		}
		return s
	}
	// A single colon means IPv4 host:port. More than one means a bare IPv6
	// literal, which must not be split.
	if strings.Count(s, ":") == 1 {
		return s[:strings.IndexByte(s, ':')]
	}
	return s
}
