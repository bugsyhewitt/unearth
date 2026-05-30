package techniques

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(shodanCVETechnique{}) }

// shodanCVETechnique pivots on a CVE rather than a TLS certificate. Given an
// operator-supplied CVE identifier and the target apex, it asks Shodan for
// every host that (a) is indexed under the target's hostname and (b) is
// known by Shodan's vulnerability scanner to be affected by that CVE. Non-CDN
// hits become origin candidates.
//
// The orthogonality versus shodan_cert is the whole point: shodan_cert
// requires the candidate host to reuse the front-door certificate; shodan_cve
// requires the host to expose a *specific known vulnerability*. A patched,
// CDN-fronted edge will not match — an unpatched, forgotten origin or staging
// host under the same apex will. Operators running CVE-scoped recon during a
// disclosure window (e.g. ScreenConnect CVE-2024-1709, ConnectWise auth
// bypass, or any newly disclosed pre-auth RCE) get a precision pivot the
// cert-fingerprint engines cannot offer.
//
// CVE supply: the CVE ID arrives via RunOptions.CVEID (CLI `--cve` flag),
// mirroring the EmailFile/email_header pattern — operator-supplied scope, no
// guessing. When CVEID is empty the technique skips silently and contributes
// no candidates or errors.
//
// SHODAN API endpoint — reuses the same /shodan/host/search URL as
// shodan_cert per the codebase's one-URL-constant-per-provider discipline.
// Query filter is `vuln:<CVE-ID> hostname:<target>`.
const (
	shodanCVETTL = 1 * time.Hour
)

// cveIDPattern enforces the canonical CVE format (CVE-YYYY-NNNN+, year is
// 4 digits, sequence is at least 4 digits per MITRE). We validate before
// sending to fail fast on operator typos rather than burning a Shodan call.
var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

type shodanCVETechnique struct{}

func (shodanCVETechnique) Name() string           { return "shodan_cve" }
func (shodanCVETechnique) Tier() Tier             { return TierPassive }
func (shodanCVETechnique) RequiresAPIKey() bool   { return true }
func (shodanCVETechnique) DefaultWeight() float64 { return 0.78 }

// shodanCVEMatch is the per-host subset of the search payload we read.
// Shodan returns rich per-host records; we only need ip_str (for the
// candidate) and hostnames (for evidence — proves the host advertises the
// target apex). The vulns map is read defensively to surface in evidence.
type shodanCVEMatch struct {
	IPStr     string   `json:"ip_str"`
	Hostnames []string `json:"hostnames"`
	Port      int      `json:"port"`
	Product   string   `json:"product"`
}

type shodanCVEResponse struct {
	Matches []shodanCVEMatch `json:"matches"`
	Total   int              `json:"total"`
	Error   string           `json:"error,omitempty"`
}

func (shodanCVETechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	cve := strings.ToUpper(strings.TrimSpace(opts.CVEID))
	if cve == "" {
		return nil, nil
	}
	if !cveIDPattern.MatchString(cve) {
		return nil, fmt.Errorf("shodan_cve: invalid CVE id %q (want CVE-YYYY-NNNN)", opts.CVEID)
	}
	if opts.APIKeys.ShodanAPIKey == "" {
		return nil, ErrMissingAPIKey
	}

	key := cache.Key("shodan_cve", target, map[string]string{"cve": cve})
	var cached shodanCVEResponse
	if data, ok := cacheRead(opts.Cache, opts, key); ok {
		if jerr := json.Unmarshal(data, &cached); jerr == nil {
			return shodanCVECandidates(cached, target, cve), nil
		}
	}

	var merged shodanCVEResponse
	page := 1
	for {
		if opts.Budget != nil && !opts.Budget.Charge("shodan") {
			return nil, ErrBudgetExhausted
		}
		if err := rateWait(ctx, opts.RateLimiter, "shodan"); err != nil {
			return nil, err
		}
		got, err := shodanCVESearchPage(ctx, opts, target, cve, page)
		if err != nil {
			return nil, err
		}
		merged.Matches = append(merged.Matches, got.Matches...)
		merged.Total = got.Total
		if len(got.Matches) == 0 || len(merged.Matches) >= got.Total {
			break
		}
		page++
	}
	if payload, err := json.Marshal(merged); err == nil {
		cacheWrite(opts.Cache, opts, key, payload, shodanCVETTL)
	}
	return shodanCVECandidates(merged, target, cve), nil
}

func shodanCVESearchPage(ctx context.Context, opts RunOptions, target, cve string, page int) (shodanCVEResponse, error) {
	var doc shodanCVEResponse
	q := url.Values{}
	q.Set("key", opts.APIKeys.ShodanAPIKey)
	q.Set("query", fmt.Sprintf("vuln:%s hostname:%s", cve, target))
	if page > 1 {
		q.Set("page", fmt.Sprintf("%d", page))
	}
	u := shodanSearchURL + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return doc, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return doc, fmt.Errorf("shodan_cve: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		return doc, fmt.Errorf("shodan_cve: status 401: %w", ErrMissingAPIKey)
	}
	if resp.StatusCode == http.StatusForbidden {
		return doc, fmt.Errorf("shodan_cve: status 403: %w", ErrTierInsufficient)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return doc, fmt.Errorf("shodan_cve: %s status %d", shodanSearchURL, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return doc, fmt.Errorf("shodan_cve decode: %w", err)
	}
	if doc.Error != "" {
		if isShodanTierError(doc.Error) {
			return doc, fmt.Errorf("shodan_cve: %s: %w", doc.Error, ErrTierInsufficient)
		}
		return doc, errors.New("shodan_cve: " + doc.Error)
	}
	return doc, nil
}

func shodanCVECandidates(doc shodanCVEResponse, target, cve string) []Candidate {
	seen := map[netip.Addr]bool{}
	var out []Candidate
	for _, m := range doc.Matches {
		a, err := netip.ParseAddr(m.IPStr)
		if err != nil {
			continue
		}
		a = a.Unmap()
		if seen[a] || cdn.IsCDNIP(a) {
			continue
		}
		seen[a] = true
		evid := fmt.Sprintf(
			"Shodan: host %s exposes %s (hostname matches %s)",
			a, cve, target)
		if m.Product != "" {
			evid += " — " + m.Product
		}
		if len(m.Hostnames) > 0 {
			evid += " [" + strings.Join(m.Hostnames, ",") + "]"
		}
		out = append(out, Candidate{
			IP:       a.String(),
			Evidence: evid,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}
