package techniques

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/unearth-tool/unearth/pkg/cache"
	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(splitDNSTechnique{}) }

// splitDNSTechnique detects partial-proxy ("split-DNS") misconfigurations. Many
// organizations route only the www hostname through a CDN while leaving the apex
// — or a mail/admin subdomain — in DNS-only mode pointing straight at the
// origin. When the primary web hostname resolves to CDN IPs but a sibling label
// resolves to a non-CDN IP, that non-CDN IP is a high-confidence origin
// candidate.
//
// The technique is purely DNS-based: it never contacts the target, requires no
// API key, and adds at most one lookup per probed label.
type splitDNSTechnique struct{}

const splitDNSTTL = 6 * time.Hour

// splitDNSProbeLabels are the sibling hostnames compared against the primary
// web hostname. They are the labels most commonly left un-proxied in real
// split-DNS configurations.
var splitDNSProbeLabels = []string{
	"mail", "smtp", "ftp", "direct", "origin", "backend", "cpanel", "webmail",
}

func (splitDNSTechnique) Name() string           { return "split_dns" }
func (splitDNSTechnique) Tier() Tier             { return TierPassive }
func (splitDNSTechnique) RequiresAPIKey() bool   { return false }
func (splitDNSTechnique) DefaultWeight() float64 { return 0.80 }

// splitDNSCache is the cached payload: the de-duplicated candidate set, so a
// re-run reproduces identical output without re-resolving.
type splitDNSCache struct {
	Items []Candidate `json:"items"`
}

func (splitDNSTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	target = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
	if target == "" {
		return nil, nil
	}

	key := cache.Key("split_dns", target, nil)
	if cached, ok := cacheRead(opts.Cache, opts, key); ok {
		var c splitDNSCache
		if err := json.Unmarshal(cached, &c); err == nil {
			return c.Items, nil
		}
	}

	// Resolve the primary web hostnames. The apex is the target; www is its
	// most common CDN-fronted sibling. We need at least one of them to be
	// CDN-fronted for the split-DNS signal to mean anything: if nothing is
	// behind a CDN, a non-CDN sibling is unremarkable.
	apexAddrs := lookupSilently(ctx, opts, target)
	wwwHost := "www." + target
	wwwAddrs := lookupSilently(ctx, opts, wwwHost)

	apexCDN := allCDN(apexAddrs)
	wwwCDN := allCDN(wwwAddrs)

	// The split-DNS signal requires a CDN-fronted "front door". Prefer www as
	// the reference because the canonical pattern is www-proxied / apex-direct,
	// but fall back to the apex being fronted if www is not.
	frontFronted := wwwCDN && len(wwwAddrs) > 0
	if !frontFronted && apexCDN && len(apexAddrs) > 0 {
		frontFronted = true
	}
	if !frontFronted {
		// Nothing behind a CDN — no split to detect. Cache the empty result so
		// repeated runs stay cheap.
		cacheWrite(opts.Cache, opts, key, mustMarshal(splitDNSCache{}), splitDNSTTL)
		return nil, nil
	}

	frontName := wwwHost
	if !wwwCDN {
		frontName = target
	}

	seen := map[netip.Addr]bool{}
	var out []Candidate
	add := func(a netip.Addr, host string) {
		a = a.Unmap()
		if !a.IsValid() || seen[a] || cdn.IsCDNIP(a) {
			return
		}
		seen[a] = true
		out = append(out, Candidate{
			IP: a.String(),
			Evidence: fmt.Sprintf(
				"split-DNS: %s resolves to non-CDN %s while %s is CDN-fronted",
				host, a, frontName),
		})
	}

	// The apex itself, when www is the fronted reference and the apex points
	// directly at a non-CDN IP, is the classic productive case.
	if frontName == wwwHost {
		for _, a := range apexAddrs {
			add(a, target)
		}
	}

	// Probe common un-proxied siblings and compare against the fronted front
	// door.
	for _, label := range splitDNSProbeLabels {
		host := label + "." + target
		for _, a := range lookupSilently(ctx, opts, host) {
			add(a, host)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	cacheWrite(opts.Cache, opts, key, mustMarshal(splitDNSCache{Items: out}), splitDNSTTL)
	return out, nil
}

// lookupSilently resolves host's A/AAAA records, swallowing NXDOMAIN and other
// resolution errors — a missing sibling is the common case, not a failure.
func lookupSilently(ctx context.Context, opts RunOptions, host string) []netip.Addr {
	if err := rateWait(ctx, opts.RateLimiter, "dns"); err != nil {
		return nil
	}
	addrs, err := activeResolver.LookupAddrs(ctx, host)
	if err != nil {
		return nil
	}
	return addrs
}

// allCDN reports whether every resolved address is a known CDN IP. It returns
// false for an empty set: "no addresses" is not "all CDN".
func allCDN(addrs []netip.Addr) bool {
	if len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		if !cdn.IsCDNIP(a.Unmap()) {
			return false
		}
	}
	return true
}

// mustMarshal serializes v, returning nil on the (here impossible) error so
// callers can treat it as best-effort cache payload.
func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}
