package techniques

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(txtLeakTechnique{}) }

// txtLeakTechnique mines a target's TXT records — at the apex and at a curated
// set of underscore-prefixed infrastructure / verification names — for bare IP
// literals that reveal a CDN-bypassed origin.
//
// Organizations routinely embed a literal origin IP in a non-SPF TXT record:
// a domain-ownership token that pins an IP, a self-hosted monitoring or ACME
// DNS-01 helper record, a legacy "_origin" / "_direct" pointer, or a vendor
// verification string that happens to carry the backend address. Those records
// are invisible to the spf_mx technique, which only parses v=spf1 mechanisms.
// This technique deliberately skips v=spf1 records so the two never produce
// duplicate evidence for the same address, and scans the names SPF never looks
// at.
//
// It is purely DNS-based: it never contacts the target, requires no API key,
// and adds at most one TXT lookup per probed name.
type txtLeakTechnique struct{}

const txtLeakTTL = 12 * time.Hour

// txtLeakProbeNames are queried for TXT records relative to the target apex.
// The empty string is the apex itself; the rest are underscore-prefixed names
// where verification tokens and infrastructure pointers commonly live and
// where SPF parsing never reaches.
var txtLeakProbeNames = []string{
	"",
	"_origin",
	"_direct",
	"_backend",
	"_monitor",
	"_dmarc",
	"_acme-challenge",
	"default._domainkey",
}

// txtLeakIPv4 matches a dotted-quad. The host-bits range check is left to
// netip.ParseAddr, which rejects out-of-range octets; this pattern only finds
// candidate substrings inside a free-form TXT value.
var txtLeakIPv4 = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)

// txtLeakIPv6 finds the maximal contiguous run of IPv6 literal characters
// (hex digits and colons). Because the character class excludes the spaces,
// '=', and other delimiters TXT values use, each match is naturally bounded
// without a \b anchor — which matters because \b breaks a match at the "::"
// compression marker. netip.ParseAddr is the real validator; the run is only
// a candidate substring, further gated below by requiring at least two colons
// so a lone "a:b" token never reaches the parser.
var txtLeakIPv6 = regexp.MustCompile(`[0-9A-Fa-f:]{3,}`)

func (txtLeakTechnique) Name() string           { return "dns_txt_leak" }
func (txtLeakTechnique) Tier() Tier             { return TierPassive }
func (txtLeakTechnique) RequiresAPIKey() bool   { return false }
func (txtLeakTechnique) DefaultWeight() float64 { return 0.55 }

// txtLeakCache is the cached payload: the de-duplicated candidate set, so a
// re-run reproduces identical output without re-resolving.
type txtLeakCache struct {
	Items []Candidate `json:"items"`
}

func (txtLeakTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	target = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
	if target == "" {
		return nil, nil
	}

	key := cache.Key("dns_txt_leak", target, nil)
	if cached, ok := cacheRead(opts.Cache, opts, key); ok {
		var c txtLeakCache
		if err := json.Unmarshal(cached, &c); err == nil {
			return c.Items, nil
		}
	}

	seen := map[netip.Addr]bool{}
	var out []Candidate
	add := func(a netip.Addr, name, txt string) {
		a = a.Unmap()
		if !publicOriginAddr(a) || seen[a] || cdn.IsCDNIP(a) {
			return
		}
		seen[a] = true
		out = append(out, Candidate{
			IP: a.String(),
			Evidence: fmt.Sprintf(
				"TXT record at %s for %s contains non-CDN IP %s (%q)",
				name, target, a, txt),
		})
	}

	for _, label := range txtLeakProbeNames {
		host := target
		display := target
		if label != "" {
			host = label + "." + target
			display = host
		}
		if err := rateWait(ctx, opts.RateLimiter, "dns"); err != nil {
			continue
		}
		txts, err := activeResolver.LookupTXT(ctx, host)
		if err != nil {
			continue
		}
		for _, txt := range txts {
			// SPF records are spf_mx's job; skip them so the two techniques
			// never surface the same IP with two different evidence strings.
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=spf1") {
				continue
			}
			for _, m := range txtLeakIPv4.FindAllString(txt, -1) {
				if a, err := netip.ParseAddr(m); err == nil {
					add(a, display, txt)
				}
			}
			for _, m := range txtLeakIPv6.FindAllString(txt, -1) {
				// The character class also matches pure-hex or single-colon
				// runs; require at least two colons before bothering the
				// parser, so "ab:cd" and "deadbeef" never reach it.
				if strings.Count(m, ":") < 2 {
					continue
				}
				if a, err := netip.ParseAddr(m); err == nil && a.Is6() {
					add(a, display, txt)
				}
			}
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	cacheWrite(opts.Cache, opts, key, mustMarshal(txtLeakCache{Items: out}), txtLeakTTL)
	return out, nil
}

// publicOriginAddr reports whether a is a globally-routable unicast address
// worth surfacing as an origin candidate. It rejects the unspecified address,
// loopback, link-local (v4 and v6), multicast, RFC1918 / unique-local private
// space, and IPv4 broadcast — the same non-origin classes the email_header and
// spf_mx techniques exclude.
func publicOriginAddr(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsPrivate() || a.IsInterfaceLocalMulticast() {
		return false
	}
	if a.Is4() && a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	return true
}
