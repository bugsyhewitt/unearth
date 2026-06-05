// Package cdn detects which CDN, if any, fronts a target and decides whether
// a given IP address belongs to a known CDN range. Both jobs are needed by
// the engine and by individual techniques: the engine surfaces CDN-fronting
// status to the caller; techniques drop candidates that are still inside a
// CDN, because they cannot be the real origin.
//
// CDN coverage: Cloudflare, CloudFront, Fastly, Sucuri, Akamai, Imperva
// (Incapsula), Azure Front Door, Google Cloud CDN, StackPath/Highwinds,
// BunnyCDN, CDN77, Edgio (Limelight / Edgecast), KeyCDN, Gcore (G-Core Labs),
// CacheFly (CacheNetworks), Vercel Edge Network, and Netlify CDN.
// The code is structured so adding further providers is a matter of dropping
// in a Provider value with detection markers and an embedded range snapshot.
package cdn

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SnapshotDate records when the embedded range data was captured. Refresh
// callers can compare against this to decide whether to fetch fresh ranges.
const SnapshotDate = "2026-05-29"

// refreshMaxAge is how long a cached refresh file is considered fresh.
const refreshMaxAge = 24 * time.Hour

//go:embed data/cloudflare-v4.txt
var cloudflareV4Raw []byte

//go:embed data/cloudflare-v6.txt
var cloudflareV6Raw []byte

//go:embed data/cloudfront.json
var cloudfrontRaw []byte

//go:embed data/fastly-v4.txt
var fastlyV4Raw []byte

//go:embed data/fastly-v6.txt
var fastlyV6Raw []byte

//go:embed data/sucuri-v4.txt
var sucuriV4Raw []byte

//go:embed data/sucuri-v6.txt
var sucuriV6Raw []byte

//go:embed data/akamai-v4.txt
var akamaiV4Raw []byte

//go:embed data/akamai-v6.txt
var akamaiV6Raw []byte

//go:embed data/imperva-v4.txt
var impervaV4Raw []byte

//go:embed data/imperva-v6.txt
var impervaV6Raw []byte

//go:embed data/azurefd-v4.txt
var azureFDV4Raw []byte

//go:embed data/azurefd-v6.txt
var azureFDV6Raw []byte

//go:embed data/googlecdn-v4.txt
var googleCDNV4Raw []byte

//go:embed data/googlecdn-v6.txt
var googleCDNV6Raw []byte

//go:embed data/stackpath-v4.txt
var stackpathV4Raw []byte

//go:embed data/stackpath-v6.txt
var stackpathV6Raw []byte

//go:embed data/bunnycdn-v4.txt
var bunnyCDNV4Raw []byte

//go:embed data/bunnycdn-v6.txt
var bunnyCDNV6Raw []byte

//go:embed data/cdn77-v4.txt
var cdn77V4Raw []byte

//go:embed data/cdn77-v6.txt
var cdn77V6Raw []byte

//go:embed data/edgio-v4.txt
var edgioV4Raw []byte

//go:embed data/edgio-v6.txt
var edgioV6Raw []byte

//go:embed data/keycdn-v4.txt
var keyCDNV4Raw []byte

//go:embed data/keycdn-v6.txt
var keyCDNV6Raw []byte

//go:embed data/gcore-v4.txt
var gcoreV4Raw []byte

//go:embed data/gcore-v6.txt
var gcoreV6Raw []byte

//go:embed data/cachefly-v4.txt
var cacheflyV4Raw []byte

//go:embed data/cachefly-v6.txt
var cacheflyV6Raw []byte

//go:embed data/vercel-v4.txt
var vercelV4Raw []byte

//go:embed data/vercel-v6.txt
var vercelV6Raw []byte

//go:embed data/netlify-v4.txt
var netlifyV4Raw []byte

//go:embed data/netlify-v6.txt
var netlifyV6Raw []byte

// Provider describes one known CDN: its canonical name, the DNS / HTTP
// signals that identify it, and the IP prefixes it owns.
type Provider struct {
	Name     string
	dnsHints []string // suffixes (case-insensitive) checked against CNAME / NS
	prefixes []netip.Prefix
}

// Indirections used by Detect so tests can stub DNS without faking
// net.DefaultResolver. Production code points at net.DefaultResolver.
var (
	detectLookupCNAME  = net.DefaultResolver.LookupCNAME
	detectLookupNS     = net.DefaultResolver.LookupNS
	detectLookupIPAddr = net.DefaultResolver.LookupIPAddr
)

// providers is the in-process registry of every CDN we know about. The
// slice order matters for tie-breaking in ProviderForIP (first match wins),
// but Cloudflare and CloudFront ranges don't overlap.
var providers []*Provider

func init() {
	cf, err := buildCloudflare()
	if err != nil {
		// Embedded data is part of the binary; a parse failure here is a
		// build-time bug, not a runtime condition.
		panic(fmt.Sprintf("cdn: parsing embedded Cloudflare ranges: %v", err))
	}
	providers = append(providers, cf)

	cfront, err := buildCloudFront()
	if err != nil {
		panic(fmt.Sprintf("cdn: parsing embedded CloudFront ranges: %v", err))
	}
	providers = append(providers, cfront)

	fastly, err := buildFastly()
	if err != nil {
		panic(fmt.Sprintf("cdn: parsing embedded Fastly ranges: %v", err))
	}
	providers = append(providers, fastly)

	sucuri, err := buildSucuri()
	if err != nil {
		panic(fmt.Sprintf("cdn: parsing embedded Sucuri ranges: %v", err))
	}
	providers = append(providers, sucuri)

	akamai, err := buildAkamai()
	if err != nil {
		panic(fmt.Sprintf("cdn: parsing embedded Akamai ranges: %v", err))
	}
	providers = append(providers, akamai)

	imperva, err := buildImperva()
	if err != nil {
		panic(fmt.Sprintf("cdn: parsing embedded Imperva ranges: %v", err))
	}
	providers = append(providers, imperva)

	azurefd, err := buildAzureFrontDoor()
	if err != nil {
		panic(fmt.Sprintf("cdn: parsing embedded Azure Front Door ranges: %v", err))
	}
	providers = append(providers, azurefd)

	googlecdn, err := buildGoogleCDN()
	if err != nil {
		panic(fmt.Sprintf("cdn: parsing embedded Google Cloud CDN ranges: %v", err))
	}
	providers = append(providers, googlecdn)

	stackpath, err := buildStackPath()
	if err != nil {
		panic(fmt.Sprintf("cdn: parsing embedded StackPath ranges: %v", err))
	}
	providers = append(providers, stackpath)

	bunnycdn, err := buildBunnyCDN()
	if err != nil {
		panic(fmt.Sprintf("cdn: parsing embedded BunnyCDN ranges: %v", err))
	}
	providers = append(providers, bunnycdn)

	cdn77, err := buildCDN77()
	if err != nil {
		panic(fmt.Sprintf("cdn: parsing embedded CDN77 ranges: %v", err))
	}
	providers = append(providers, cdn77)

	edgio, err := buildEdgio()
	if err != nil {
		panic(fmt.Sprintf("cdn: parsing embedded Edgio ranges: %v", err))
	}
	providers = append(providers, edgio)

	keycdn, err := buildKeyCDN()
	if err != nil {
		panic(fmt.Sprintf("cdn: parsing embedded KeyCDN ranges: %v", err))
	}
	providers = append(providers, keycdn)

	gcore, err := buildGcore()
	if err != nil {
		panic(fmt.Sprintf("cdn: parsing embedded Gcore ranges: %v", err))
	}
	providers = append(providers, gcore)

	cachefly, err := buildCacheFly()
	if err != nil {
		panic(fmt.Sprintf("cdn: parsing embedded CacheFly ranges: %v", err))
	}
	providers = append(providers, cachefly)

	vercel, err := buildVercel()
	if err != nil {
		panic(fmt.Sprintf("cdn: parsing embedded Vercel ranges: %v", err))
	}
	providers = append(providers, vercel)

	netlify, err := buildNetlify()
	if err != nil {
		panic(fmt.Sprintf("cdn: parsing embedded Netlify ranges: %v", err))
	}
	providers = append(providers, netlify)
}

func buildCacheFly() (*Provider, error) {
	prefixes, err := parsePlainPrefixes(cacheflyV4Raw)
	if err != nil {
		return nil, fmt.Errorf("cachefly v4: %w", err)
	}
	v6, err := parsePlainPrefixes(cacheflyV6Raw)
	if err != nil {
		return nil, fmt.Errorf("cachefly v6: %w", err)
	}
	prefixes = append(prefixes, v6...)
	return &Provider{
		Name: "cachefly",
		dnsHints: []string{
			".cachefly.net",
		},
		prefixes: prefixes,
	}, nil
}

func buildVercel() (*Provider, error) {
	prefixes, err := parsePlainPrefixes(vercelV4Raw)
	if err != nil {
		return nil, fmt.Errorf("vercel v4: %w", err)
	}
	v6, err := parsePlainPrefixes(vercelV6Raw)
	if err != nil {
		return nil, fmt.Errorf("vercel v6: %w", err)
	}
	prefixes = append(prefixes, v6...)
	return &Provider{
		Name: "vercel",
		dnsHints: []string{
			".vercel.app",
			".vercel-dns.com",
			".now.sh",
		},
		prefixes: prefixes,
	}, nil
}

func buildNetlify() (*Provider, error) {
	prefixes, err := parsePlainPrefixes(netlifyV4Raw)
	if err != nil {
		return nil, fmt.Errorf("netlify v4: %w", err)
	}
	v6, err := parsePlainPrefixes(netlifyV6Raw)
	if err != nil {
		return nil, fmt.Errorf("netlify v6: %w", err)
	}
	prefixes = append(prefixes, v6...)
	return &Provider{
		Name: "netlify",
		dnsHints: []string{
			".netlify.app",
			".netlify.com",
			".netlify.net",
		},
		prefixes: prefixes,
	}, nil
}

func buildGcore() (*Provider, error) {
	prefixes, err := parsePlainPrefixes(gcoreV4Raw)
	if err != nil {
		return nil, fmt.Errorf("gcore v4: %w", err)
	}
	v6, err := parsePlainPrefixes(gcoreV6Raw)
	if err != nil {
		return nil, fmt.Errorf("gcore v6: %w", err)
	}
	prefixes = append(prefixes, v6...)
	return &Provider{
		Name: "gcore",
		dnsHints: []string{
			".gcdn.co",
			".gcorelabs.com",
			".gcore.com",
		},
		prefixes: prefixes,
	}, nil
}

func buildKeyCDN() (*Provider, error) {
	prefixes, err := parsePlainPrefixes(keyCDNV4Raw)
	if err != nil {
		return nil, fmt.Errorf("keycdn v4: %w", err)
	}
	v6, err := parsePlainPrefixes(keyCDNV6Raw)
	if err != nil {
		return nil, fmt.Errorf("keycdn v6: %w", err)
	}
	prefixes = append(prefixes, v6...)
	return &Provider{
		Name: "keycdn",
		dnsHints: []string{
			".kxcdn.com",
			".keycdn.com",
		},
		prefixes: prefixes,
	}, nil
}

func buildEdgio() (*Provider, error) {
	prefixes, err := parsePlainPrefixes(edgioV4Raw)
	if err != nil {
		return nil, fmt.Errorf("edgio v4: %w", err)
	}
	v6, err := parsePlainPrefixes(edgioV6Raw)
	if err != nil {
		return nil, fmt.Errorf("edgio v6: %w", err)
	}
	prefixes = append(prefixes, v6...)
	return &Provider{
		Name: "edgio",
		dnsHints: []string{
			".llnwd.net",
			".llnw.com",
			".lldns.net",
			".edgecastcdn.net",
			".systemcdn.net",
			".edgio.net",
		},
		prefixes: prefixes,
	}, nil
}

func buildCDN77() (*Provider, error) {
	prefixes, err := parsePlainPrefixes(cdn77V4Raw)
	if err != nil {
		return nil, fmt.Errorf("cdn77 v4: %w", err)
	}
	v6, err := parsePlainPrefixes(cdn77V6Raw)
	if err != nil {
		return nil, fmt.Errorf("cdn77 v6: %w", err)
	}
	prefixes = append(prefixes, v6...)
	return &Provider{
		Name: "cdn77",
		dnsHints: []string{
			".cdn77.org",
			".cdn77-ssl.net",
			".cdn77.net",
			".cdn77.com",
		},
		prefixes: prefixes,
	}, nil
}

func buildFastly() (*Provider, error) {
	prefixes, err := parsePlainPrefixes(fastlyV4Raw)
	if err != nil {
		return nil, fmt.Errorf("fastly v4: %w", err)
	}
	v6, err := parsePlainPrefixes(fastlyV6Raw)
	if err != nil {
		return nil, fmt.Errorf("fastly v6: %w", err)
	}
	prefixes = append(prefixes, v6...)
	return &Provider{
		Name:     "fastly",
		dnsHints: []string{".fastly.net", ".fastlylb.net", ".fastly.com"},
		prefixes: prefixes,
	}, nil
}

func buildSucuri() (*Provider, error) {
	prefixes, err := parsePlainPrefixes(sucuriV4Raw)
	if err != nil {
		return nil, fmt.Errorf("sucuri v4: %w", err)
	}
	v6, err := parsePlainPrefixes(sucuriV6Raw)
	if err != nil {
		return nil, fmt.Errorf("sucuri v6: %w", err)
	}
	prefixes = append(prefixes, v6...)
	return &Provider{
		Name:     "sucuri",
		dnsHints: []string{".sucuri.net"},
		prefixes: prefixes,
	}, nil
}

func buildAkamai() (*Provider, error) {
	prefixes, err := parsePlainPrefixes(akamaiV4Raw)
	if err != nil {
		return nil, fmt.Errorf("akamai v4: %w", err)
	}
	v6, err := parsePlainPrefixes(akamaiV6Raw)
	if err != nil {
		return nil, fmt.Errorf("akamai v6: %w", err)
	}
	prefixes = append(prefixes, v6...)
	return &Provider{
		Name: "akamai",
		dnsHints: []string{
			".edgesuite.net",
			".edgekey.net",
			".akamaized.net",
			".akamaitechnologies.com",
			".akamai.net",
		},
		prefixes: prefixes,
	}, nil
}

func buildImperva() (*Provider, error) {
	prefixes, err := parsePlainPrefixes(impervaV4Raw)
	if err != nil {
		return nil, fmt.Errorf("imperva v4: %w", err)
	}
	v6, err := parsePlainPrefixes(impervaV6Raw)
	if err != nil {
		return nil, fmt.Errorf("imperva v6: %w", err)
	}
	prefixes = append(prefixes, v6...)
	return &Provider{
		Name: "imperva",
		dnsHints: []string{
			".incapdns.net",
			".incapdns.com",
			".incapsula.com",
		},
		prefixes: prefixes,
	}, nil
}

func buildAzureFrontDoor() (*Provider, error) {
	prefixes, err := parsePlainPrefixes(azureFDV4Raw)
	if err != nil {
		return nil, fmt.Errorf("azurefd v4: %w", err)
	}
	v6, err := parsePlainPrefixes(azureFDV6Raw)
	if err != nil {
		return nil, fmt.Errorf("azurefd v6: %w", err)
	}
	prefixes = append(prefixes, v6...)
	return &Provider{
		Name: "azurefd",
		dnsHints: []string{
			".azurefd.net",
			".azureedge.net",
			".t-msedge.net",
			".trafficmanager.net",
		},
		prefixes: prefixes,
	}, nil
}

func buildGoogleCDN() (*Provider, error) {
	prefixes, err := parsePlainPrefixes(googleCDNV4Raw)
	if err != nil {
		return nil, fmt.Errorf("googlecdn v4: %w", err)
	}
	v6, err := parsePlainPrefixes(googleCDNV6Raw)
	if err != nil {
		return nil, fmt.Errorf("googlecdn v6: %w", err)
	}
	prefixes = append(prefixes, v6...)
	return &Provider{
		Name: "googlecdn",
		dnsHints: []string{
			".googlehosted.com",
			".googleusercontent.com",
			".storage.googleapis.com",
			".l.google.com",
		},
		prefixes: prefixes,
	}, nil
}

func buildStackPath() (*Provider, error) {
	prefixes, err := parsePlainPrefixes(stackpathV4Raw)
	if err != nil {
		return nil, fmt.Errorf("stackpath v4: %w", err)
	}
	v6, err := parsePlainPrefixes(stackpathV6Raw)
	if err != nil {
		return nil, fmt.Errorf("stackpath v6: %w", err)
	}
	prefixes = append(prefixes, v6...)
	return &Provider{
		Name: "stackpath",
		dnsHints: []string{
			".stackpathcdn.com",
			".stackpathdns.com",
			".hwcdn.net",
			".netdna-cdn.com",
			".netdna-ssl.com",
			".netdna.com",
		},
		prefixes: prefixes,
	}, nil
}

func buildBunnyCDN() (*Provider, error) {
	prefixes, err := parsePlainPrefixes(bunnyCDNV4Raw)
	if err != nil {
		return nil, fmt.Errorf("bunnycdn v4: %w", err)
	}
	v6, err := parsePlainPrefixes(bunnyCDNV6Raw)
	if err != nil {
		return nil, fmt.Errorf("bunnycdn v6: %w", err)
	}
	prefixes = append(prefixes, v6...)
	return &Provider{
		Name: "bunnycdn",
		dnsHints: []string{
			".b-cdn.net",
			".bunnycdn.com",
			".bunny.net",
		},
		prefixes: prefixes,
	}, nil
}

func buildCloudflare() (*Provider, error) {
	prefixes, err := parsePlainPrefixes(cloudflareV4Raw)
	if err != nil {
		return nil, fmt.Errorf("cloudflare v4: %w", err)
	}
	v6, err := parsePlainPrefixes(cloudflareV6Raw)
	if err != nil {
		return nil, fmt.Errorf("cloudflare v6: %w", err)
	}
	prefixes = append(prefixes, v6...)
	return &Provider{
		Name:     "cloudflare",
		dnsHints: []string{".cloudflare.net", ".cloudflare.com", ".ns.cloudflare.com"},
		prefixes: prefixes,
	}, nil
}

func buildCloudFront() (*Provider, error) {
	type rawIPv4 struct {
		IPPrefix string `json:"ip_prefix"`
		Service  string `json:"service"`
	}
	type rawIPv6 struct {
		IPv6Prefix string `json:"ipv6_prefix"`
		Service    string `json:"service"`
	}
	var raw struct {
		Prefixes     []rawIPv4 `json:"prefixes"`
		IPv6Prefixes []rawIPv6 `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(cloudfrontRaw, &raw); err != nil {
		return nil, err
	}
	var prefixes []netip.Prefix
	for _, p := range raw.Prefixes {
		if p.Service != "CLOUDFRONT" {
			continue
		}
		pref, err := netip.ParsePrefix(p.IPPrefix)
		if err != nil {
			return nil, fmt.Errorf("ipv4 prefix %q: %w", p.IPPrefix, err)
		}
		prefixes = append(prefixes, pref)
	}
	for _, p := range raw.IPv6Prefixes {
		if p.Service != "CLOUDFRONT" {
			continue
		}
		pref, err := netip.ParsePrefix(p.IPv6Prefix)
		if err != nil {
			return nil, fmt.Errorf("ipv6 prefix %q: %w", p.IPv6Prefix, err)
		}
		prefixes = append(prefixes, pref)
	}
	return &Provider{
		Name:     "cloudfront",
		dnsHints: []string{".cloudfront.net"},
		prefixes: prefixes,
	}, nil
}

func parsePlainPrefixes(b []byte) ([]netip.Prefix, error) {
	var out []netip.Prefix
	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("line %q: %w", line, err)
		}
		out = append(out, p)
	}
	return out, s.Err()
}

// IsCDNIP reports whether ip is owned by any known CDN provider.
func IsCDNIP(ip netip.Addr) bool {
	return ProviderForIP(ip) != ""
}

// ProviderForIP returns the canonical CDN name that owns ip, or "" when no
// known provider claims it. RFC1918, loopback, and similarly private
// addresses are simply not in any provider's list and therefore yield "".
func ProviderForIP(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	for _, p := range providers {
		for _, pref := range p.prefixes {
			if pref.Contains(ip) {
				return p.Name
			}
		}
	}
	return ""
}

// Detection is the result of CDN fingerprinting for one target.
type Detection struct {
	// CDN is the canonical provider name ("" when no CDN is detected).
	CDN string
	// Signals lists every matched detection rule, suitable for evidence
	// strings or debug logging.
	Signals []string
}

// Detect determines which CDN, if any, fronts target. It uses three signal
// sources: DNS (CNAME chain and NS records), HTTP response headers from one
// GET to https://target/, and the target's resolved A/AAAA records compared
// against embedded CDN range tables.
//
// At most one HTTP request is made to the target. That is the standard way
// to fingerprint a CDN — a normal browser visit produces the same request —
// and is documented as the only target-touching action in this otherwise
// fully passive layer.
//
// A nil hc is treated as http.DefaultClient. A non-nil hc lets the engine
// share its tuned client across techniques and the CDN detector.
//
// Detect returns the first detection it finds plus every signal that
// matched, so callers can present rich evidence. Errors from DNS or HTTP
// are non-fatal in spirit — the function still returns a usable Detection
// reflecting whatever signals did match — but the underlying error, if any,
// is also returned so the caller can surface it as a warning.
func Detect(ctx context.Context, target string, hc *http.Client) (Detection, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	det := Detection{}
	var firstErr error
	captureErr := func(err error) {
		if err == nil || firstErr != nil {
			return
		}
		firstErr = err
	}
	setCDN := func(name, signal string) {
		if det.CDN == "" {
			det.CDN = name
		}
		det.Signals = append(det.Signals, signal)
	}

	// 1) DNS CNAME chain.
	if cname, err := detectLookupCNAME(ctx, target); err == nil {
		cname = strings.TrimSuffix(strings.ToLower(cname), ".")
		if cname != "" && cname != strings.ToLower(target) {
			if p, hit := providerByDNS(cname); hit {
				setCDN(p, fmt.Sprintf("CNAME %s matches %s", cname, p))
			}
		}
	} else {
		captureErr(err)
	}

	// 2) NS records.
	if nss, err := detectLookupNS(ctx, target); err == nil {
		for _, ns := range nss {
			host := strings.TrimSuffix(strings.ToLower(ns.Host), ".")
			if p, hit := providerByDNS(host); hit {
				setCDN(p, fmt.Sprintf("NS %s matches %s", host, p))
				break
			}
		}
	} else {
		captureErr(err)
	}

	// 3) A/AAAA → IP range.
	if ipAddrs, err := detectLookupIPAddr(ctx, target); err == nil {
		for _, ia := range ipAddrs {
			a, ok := netip.AddrFromSlice(ia.IP)
			if !ok {
				continue
			}
			a = a.Unmap()
			if p := ProviderForIP(a); p != "" {
				setCDN(p, fmt.Sprintf("A/AAAA %s in %s range", a, p))
				break
			}
		}
	} else {
		captureErr(err)
	}

	// 4) One HTTP request for header inspection.
	if hdrCDN, signals, err := headerProbe(ctx, target, hc); err == nil {
		for _, s := range signals {
			setCDN(hdrCDN, s)
		}
	} else {
		captureErr(err)
	}

	return det, firstErr
}

func providerByDNS(host string) (string, bool) {
	host = strings.ToLower(host)
	for _, p := range providers {
		for _, hint := range p.dnsHints {
			if strings.HasSuffix(host, hint) {
				return p.Name, true
			}
		}
	}
	return "", false
}

func headerProbe(ctx context.Context, target string, hc *http.Client) (string, []string, error) {
	url := "https://" + target + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return classifyHeaders(resp.Header), collectHeaderSignals(resp.Header), nil
}

// classifyHeaders chooses the most likely CDN from response headers.
// Cloudflare markers (cf-ray, server:cloudflare) win over all others
// because they are the strongest and hardest to fake.
func classifyHeaders(h http.Header) string {
	if strings.EqualFold(h.Get("Server"), "cloudflare") || h.Get("Cf-Ray") != "" {
		return "cloudflare"
	}
	if h.Get("X-Amz-Cf-Id") != "" {
		return "cloudfront"
	}
	if strings.Contains(strings.ToLower(h.Get("Via")), "cloudfront") {
		return "cloudfront"
	}
	if strings.Contains(strings.ToLower(h.Get("X-Cache")), "cloudfront") {
		return "cloudfront"
	}
	if h.Get("X-Served-By") != "" && strings.Contains(strings.ToLower(h.Get("X-Served-By")), "cache-") {
		return "fastly"
	}
	if h.Get("X-Fastly-Request-Id") != "" {
		return "fastly"
	}
	if strings.EqualFold(h.Get("X-Sucuri-ID"), "") && h.Get("X-Sucuri-Cache") != "" {
		return "sucuri"
	}
	if h.Get("X-Check-Cacheable") != "" || h.Get("X-Akamai-Transformed") != "" {
		return "akamai"
	}
	if isImpervaHeaders(h) {
		return "imperva"
	}
	if isAzureFrontDoorHeaders(h) {
		return "azurefd"
	}
	if isGoogleCDNHeaders(h) {
		return "googlecdn"
	}
	if isStackPathHeaders(h) {
		return "stackpath"
	}
	if isBunnyCDNHeaders(h) {
		return "bunnycdn"
	}
	if isCDN77Headers(h) {
		return "cdn77"
	}
	if isEdgioHeaders(h) {
		return "edgio"
	}
	if isKeyCDNHeaders(h) {
		return "keycdn"
	}
	if isGcoreHeaders(h) {
		return "gcore"
	}
	if isCacheFlyHeaders(h) {
		return "cachefly"
	}
	if isVercelHeaders(h) {
		return "vercel"
	}
	if isNetlifyHeaders(h) {
		return "netlify"
	}
	return ""
}

// isCacheFlyHeaders reports whether the response headers carry a CacheFly
// (CacheNetworks, LLC) signature. CacheFly edge nodes advertise "Server:
// CacheFly" on every edge response and stamp the proprietary X-CF1 / X-CF2
// request-tracking headers; some configurations also emit an "X-CDN: CacheFly"
// marker. Any of these markers identifies the provider.
func isCacheFlyHeaders(h http.Header) bool {
	if strings.Contains(strings.ToLower(h.Get("Server")), "cachefly") {
		return true
	}
	if h.Get("X-CF1") != "" || h.Get("X-CF2") != "" {
		return true
	}
	if strings.Contains(strings.ToLower(h.Get("X-CDN")), "cachefly") {
		return true
	}
	return false
}

// isGcoreHeaders reports whether the response headers carry a Gcore (G-Core
// Labs S.A.) signature. Gcore edge nodes advertise "Server: gcore" on edge
// responses and stamp the proprietary X-Gcore-* header family (such as
// X-Gcore-Pop identifying the serving POP); some configurations also emit an
// "X-CDN: Gcore" marker. Any of these markers identifies the provider.
func isGcoreHeaders(h http.Header) bool {
	if strings.Contains(strings.ToLower(h.Get("Server")), "gcore") {
		return true
	}
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "x-gcore-") {
			return true
		}
	}
	if strings.Contains(strings.ToLower(h.Get("X-CDN")), "gcore") {
		return true
	}
	return false
}

// isKeyCDNHeaders reports whether the response headers carry a KeyCDN (proinity
// GmbH) signature. KeyCDN edge nodes advertise "Server: keycdn-engine" on every
// edge response and stamp the proprietary X-Edge-Location header (the serving
// POP) plus an X-Pull header on pull-zone responses. Some configurations also
// emit an "X-CDN: KeyCDN" marker. Any of these markers identifies the provider.
func isKeyCDNHeaders(h http.Header) bool {
	if strings.Contains(strings.ToLower(h.Get("Server")), "keycdn-engine") {
		return true
	}
	if h.Get("X-Edge-Location") != "" || h.Get("X-Pull") != "" {
		return true
	}
	if strings.Contains(strings.ToLower(h.Get("X-CDN")), "keycdn") {
		return true
	}
	return false
}

// isEdgioHeaders reports whether the response headers carry an Edgio (the 2022
// merger of Limelight Networks and Edgecast / Verizon Media) signature. Edgecast
// edge nodes advertise "Server: ECS" or "Server: ECAcc" and stamp the
// proprietary X-EC-* header family on edge responses; the legacy Limelight edge
// stamps "Server: LimeLight" and an X-LLID request-tracking header; newer Edgio
// POPs emit an "X-CDN: Edgio" marker. Any of these markers identifies the
// provider.
func isEdgioHeaders(h http.Header) bool {
	server := strings.ToLower(h.Get("Server"))
	if server == "ecs" || strings.HasPrefix(server, "ecacc") || strings.Contains(server, "limelight") {
		return true
	}
	if h.Get("X-LLID") != "" {
		return true
	}
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "x-ec-") {
			return true
		}
	}
	if strings.Contains(strings.ToLower(h.Get("X-CDN")), "edgio") {
		return true
	}
	return false
}

// isCDN77Headers reports whether the response headers carry a CDN77 (DataCamp /
// CDN77 s.r.o.) signature. CDN77 edge nodes stamp the proprietary X-77-* family
// of headers (X-77-Cache hit/miss status, X-77-Nzt request tracking, X-77-Pop
// serving POP) on every edge response, and many POPs advertise "Server: CDN77"
// or an "X-CDN: CDN77" marker. Any of these markers identifies the provider.
func isCDN77Headers(h http.Header) bool {
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "x-77-") {
			return true
		}
	}
	if strings.Contains(strings.ToLower(h.Get("Server")), "cdn77") {
		return true
	}
	if strings.Contains(strings.ToLower(h.Get("X-CDN")), "cdn77") {
		return true
	}
	return false
}

// isBunnyCDNHeaders reports whether the response headers carry a BunnyCDN
// (bunny.net) signature. Every BunnyCDN edge response stamps a "Server:
// BunnyCDN-<pop>" value identifying the serving POP, and pull zones emit the
// proprietary CDN-PullZone and CDN-RequestCountryCode headers on every
// response. Either marker identifies the provider.
func isBunnyCDNHeaders(h http.Header) bool {
	if strings.HasPrefix(strings.ToLower(h.Get("Server")), "bunnycdn") {
		return true
	}
	if h.Get("CDN-PullZone") != "" || h.Get("CDN-RequestCountryCode") != "" {
		return true
	}
	return false
}

// isStackPathHeaders reports whether the response headers carry a StackPath /
// Highwinds (formerly NetDNA / MaxCDN) signature. StackPath edge nodes stamp
// the proprietary X-HW Highwinds tracking header on every edge response, and
// the legacy NetDNA/MaxCDN edge cache still advertises "Server: NetDNA-cache"
// on many POPs. An "X-CDN: Stackpath" marker also appears on some
// configurations.
func isStackPathHeaders(h http.Header) bool {
	if h.Get("X-HW") != "" {
		return true
	}
	if strings.Contains(strings.ToLower(h.Get("Server")), "netdna-cache") {
		return true
	}
	if strings.Contains(strings.ToLower(h.Get("X-CDN")), "stackpath") {
		return true
	}
	return false
}

// isGoogleCDNHeaders reports whether the response headers carry a Google Front
// End / Google Cloud CDN signature. Google's edge stamps "Server: Google
// Frontend" (or the legacy "gws") on GFE responses, and Cloud CDN adds
// "Via: 1.1 google" on every cached/proxied response. Either marker, or the
// X-Goog-* family of headers Cloud CDN emits, identifies the provider.
func isGoogleCDNHeaders(h http.Header) bool {
	server := strings.ToLower(h.Get("Server"))
	if server == "google frontend" || server == "gws" || strings.HasPrefix(server, "gfe") {
		return true
	}
	if strings.Contains(strings.ToLower(h.Get("Via")), "google") {
		return true
	}
	if h.Get("X-Goog-Hash") != "" || h.Get("X-Goog-Generation") != "" {
		return true
	}
	return false
}

// isAzureFrontDoorHeaders reports whether the response headers carry an Azure
// Front Door signature: the proprietary X-Azure-Ref tracking header that Front
// Door stamps on every edge response, or an X-Cache value mentioning the Front
// Door cache node.
func isAzureFrontDoorHeaders(h http.Header) bool {
	if h.Get("X-Azure-Ref") != "" {
		return true
	}
	if strings.Contains(strings.ToLower(h.Get("X-Cache")), "frontdoor") {
		return true
	}
	return false
}

// isImpervaHeaders reports whether the response headers carry an Incapsula /
// Imperva signature: the proprietary X-Iinfo header, an X-CDN: Incapsula
// marker, or the incap_ses / visid_incap session cookies Incapsula sets on
// every fronted response.
func isImpervaHeaders(h http.Header) bool {
	if h.Get("X-Iinfo") != "" {
		return true
	}
	if strings.Contains(strings.ToLower(h.Get("X-CDN")), "incapsula") {
		return true
	}
	for _, c := range h.Values("Set-Cookie") {
		lc := strings.ToLower(c)
		if strings.HasPrefix(lc, "incap_ses") || strings.HasPrefix(lc, "visid_incap") {
			return true
		}
	}
	return false
}

// isVercelHeaders reports whether the response headers carry a Vercel Edge
// Network signature. Vercel edge nodes stamp the X-Vercel-Id request-tracking
// header on every edge response; the proprietary X-Vercel-Cache header
// (HIT/MISS/BYPASS) is present whenever Vercel's edge caches the response.
// The Server header is also set to "Vercel" on most Vercel-fronted deployments.
func isVercelHeaders(h http.Header) bool {
	if h.Get("X-Vercel-Id") != "" {
		return true
	}
	if h.Get("X-Vercel-Cache") != "" {
		return true
	}
	if strings.EqualFold(h.Get("Server"), "Vercel") {
		return true
	}
	if strings.Contains(strings.ToLower(h.Get("X-CDN")), "vercel") {
		return true
	}
	return false
}

// isNetlifyHeaders reports whether the response headers carry a Netlify CDN
// signature. Netlify edge nodes stamp the X-Nf-Request-Id request-tracking
// header on every proxied response; the X-Cache header may contain "HIT from
// Netlify"; and the Server header is "Netlify" on most Netlify-fronted sites.
func isNetlifyHeaders(h http.Header) bool {
	if h.Get("X-Nf-Request-Id") != "" {
		return true
	}
	if strings.EqualFold(h.Get("Server"), "Netlify") {
		return true
	}
	if strings.Contains(strings.ToLower(h.Get("X-Cache")), "netlify") {
		return true
	}
	if strings.Contains(strings.ToLower(h.Get("X-CDN")), "netlify") {
		return true
	}
	return false
}

func collectHeaderSignals(h http.Header) []string {
	var out []string
	if strings.EqualFold(h.Get("Server"), "cloudflare") {
		out = append(out, "header server: cloudflare")
	}
	if h.Get("Cf-Ray") != "" {
		out = append(out, "header cf-ray present")
	}
	if h.Get("X-Amz-Cf-Id") != "" {
		out = append(out, "header x-amz-cf-id present")
	}
	if via := strings.ToLower(h.Get("Via")); strings.Contains(via, "cloudfront") {
		out = append(out, "header via mentions cloudfront")
	}
	if xc := strings.ToLower(h.Get("X-Cache")); strings.Contains(xc, "cloudfront") {
		out = append(out, "header x-cache mentions cloudfront")
	}
	if h.Get("X-Fastly-Request-Id") != "" {
		out = append(out, "header x-fastly-request-id present")
	}
	if sv := h.Get("X-Served-By"); sv != "" && strings.Contains(strings.ToLower(sv), "cache-") {
		out = append(out, "header x-served-by mentions fastly cache node")
	}
	if h.Get("X-Sucuri-Cache") != "" {
		out = append(out, "header x-sucuri-cache present")
	}
	if h.Get("X-Check-Cacheable") != "" {
		out = append(out, "header x-check-cacheable present (akamai)")
	}
	if h.Get("X-Akamai-Transformed") != "" {
		out = append(out, "header x-akamai-transformed present")
	}
	if h.Get("X-Iinfo") != "" {
		out = append(out, "header x-iinfo present (imperva)")
	}
	if strings.Contains(strings.ToLower(h.Get("X-CDN")), "incapsula") {
		out = append(out, "header x-cdn mentions incapsula")
	}
	for _, c := range h.Values("Set-Cookie") {
		lc := strings.ToLower(c)
		if strings.HasPrefix(lc, "incap_ses") || strings.HasPrefix(lc, "visid_incap") {
			out = append(out, "incapsula session cookie present")
			break
		}
	}
	if h.Get("X-Azure-Ref") != "" {
		out = append(out, "header x-azure-ref present (azure front door)")
	}
	if strings.Contains(strings.ToLower(h.Get("X-Cache")), "frontdoor") {
		out = append(out, "header x-cache mentions frontdoor")
	}
	if server := strings.ToLower(h.Get("Server")); server == "google frontend" || server == "gws" || strings.HasPrefix(server, "gfe") {
		out = append(out, "header server: google frontend (google cloud cdn)")
	}
	if strings.Contains(strings.ToLower(h.Get("Via")), "google") {
		out = append(out, "header via mentions google (google cloud cdn)")
	}
	if h.Get("X-Goog-Hash") != "" || h.Get("X-Goog-Generation") != "" {
		out = append(out, "header x-goog-* present (google cloud cdn)")
	}
	if h.Get("X-HW") != "" {
		out = append(out, "header x-hw present (stackpath/highwinds)")
	}
	if strings.Contains(strings.ToLower(h.Get("Server")), "netdna-cache") {
		out = append(out, "header server: netdna-cache (stackpath)")
	}
	if strings.Contains(strings.ToLower(h.Get("X-CDN")), "stackpath") {
		out = append(out, "header x-cdn mentions stackpath")
	}
	if strings.HasPrefix(strings.ToLower(h.Get("Server")), "bunnycdn") {
		out = append(out, "header server: bunnycdn pop (bunnycdn)")
	}
	if h.Get("CDN-PullZone") != "" {
		out = append(out, "header cdn-pullzone present (bunnycdn)")
	}
	if h.Get("CDN-RequestCountryCode") != "" {
		out = append(out, "header cdn-requestcountrycode present (bunnycdn)")
	}
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "x-77-") {
			out = append(out, "header x-77-* present (cdn77)")
			break
		}
	}
	if strings.Contains(strings.ToLower(h.Get("Server")), "cdn77") {
		out = append(out, "header server: cdn77 (cdn77)")
	}
	if strings.Contains(strings.ToLower(h.Get("X-CDN")), "cdn77") {
		out = append(out, "header x-cdn mentions cdn77")
	}
	if server := strings.ToLower(h.Get("Server")); server == "ecs" || strings.HasPrefix(server, "ecacc") {
		out = append(out, "header server: edgecast/edgio edge (edgio)")
	}
	if strings.Contains(strings.ToLower(h.Get("Server")), "limelight") {
		out = append(out, "header server: limelight (edgio)")
	}
	if h.Get("X-LLID") != "" {
		out = append(out, "header x-llid present (edgio/limelight)")
	}
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "x-ec-") {
			out = append(out, "header x-ec-* present (edgio/edgecast)")
			break
		}
	}
	if strings.Contains(strings.ToLower(h.Get("X-CDN")), "edgio") {
		out = append(out, "header x-cdn mentions edgio")
	}
	if strings.Contains(strings.ToLower(h.Get("Server")), "keycdn-engine") {
		out = append(out, "header server: keycdn-engine (keycdn)")
	}
	if h.Get("X-Edge-Location") != "" {
		out = append(out, "header x-edge-location present (keycdn)")
	}
	if h.Get("X-Pull") != "" {
		out = append(out, "header x-pull present (keycdn)")
	}
	if strings.Contains(strings.ToLower(h.Get("X-CDN")), "keycdn") {
		out = append(out, "header x-cdn mentions keycdn")
	}
	if strings.Contains(strings.ToLower(h.Get("Server")), "gcore") {
		out = append(out, "header server: gcore (gcore)")
	}
	for k := range h {
		if strings.HasPrefix(strings.ToLower(k), "x-gcore-") {
			out = append(out, "header x-gcore-* present (gcore)")
			break
		}
	}
	if strings.Contains(strings.ToLower(h.Get("X-CDN")), "gcore") {
		out = append(out, "header x-cdn mentions gcore")
	}
	if strings.Contains(strings.ToLower(h.Get("Server")), "cachefly") {
		out = append(out, "header server: cachefly (cachefly)")
	}
	if h.Get("X-CF1") != "" || h.Get("X-CF2") != "" {
		out = append(out, "header x-cf1/x-cf2 present (cachefly)")
	}
	if strings.Contains(strings.ToLower(h.Get("X-CDN")), "cachefly") {
		out = append(out, "header x-cdn mentions cachefly")
	}
	return out
}

// Refresh fetches fresh range data from upstream sources and rebuilds the
// in-memory provider tables. Results are also written to the XDG cache dir
// so subsequent process starts can load fresh data without re-fetching.
//
// Refresh is safe to call at any time but is not goroutine-safe with
// concurrent IsCDNIP/ProviderForIP calls — callers serialize it themselves.
func Refresh(ctx context.Context, hc *http.Client) error {
	return RefreshFrom(ctx, hc, refreshURLs{
		cloudflareV4: "https://www.cloudflare.com/ips-v4",
		cloudflareV6: "https://www.cloudflare.com/ips-v6",
		cloudfront:   "https://ip-ranges.amazonaws.com/ip-ranges.json",
		fastly:       "https://api.fastly.com/public-ip-list",
	})
}

// refreshURLs groups the upstream URLs so tests can override them.
type refreshURLs struct {
	cloudflareV4 string
	cloudflareV6 string
	cloudfront   string
	fastly       string
}

// RefreshFrom is the testable core of Refresh.
func RefreshFrom(ctx context.Context, hc *http.Client, urls refreshURLs) error {
	if hc == nil {
		hc = http.DefaultClient
	}
	v4, err := fetch(ctx, hc, urls.cloudflareV4)
	if err != nil {
		return fmt.Errorf("cdn refresh cloudflare v4: %w", err)
	}
	v6, err := fetch(ctx, hc, urls.cloudflareV6)
	if err != nil {
		return fmt.Errorf("cdn refresh cloudflare v6: %w", err)
	}
	aws, err := fetch(ctx, hc, urls.cloudfront)
	if err != nil {
		return fmt.Errorf("cdn refresh cloudfront: %w", err)
	}
	fastlyJSON, err := fetch(ctx, hc, urls.fastly)
	if err != nil {
		return fmt.Errorf("cdn refresh fastly: %w", err)
	}

	cfPrefixes, err := parsePlainPrefixes(v4)
	if err != nil {
		return err
	}
	cfV6, err := parsePlainPrefixes(v6)
	if err != nil {
		return err
	}
	cfPrefixes = append(cfPrefixes, cfV6...)

	// CloudFront: reuse the build helper by temporarily swapping the source bytes.
	prev := cloudfrontRaw
	cloudfrontRaw = aws
	cfront, err := buildCloudFront()
	cloudfrontRaw = prev
	if err != nil {
		return err
	}

	// Fastly: parse the JSON list endpoint.
	fastlyPrefixes, err := parseFastlyJSON(fastlyJSON)
	if err != nil {
		return fmt.Errorf("cdn refresh fastly parse: %w", err)
	}

	newProviders := []*Provider{
		{Name: "cloudflare", dnsHints: providers[0].dnsHints, prefixes: cfPrefixes},
		cfront,
		{Name: "fastly", dnsHints: providers[2].dnsHints, prefixes: fastlyPrefixes},
		// Sucuri ranges are small and stable; not refreshed from upstream.
		providers[3],
	}
	providers = newProviders

	// Persist refreshed data to XDG cache for future process starts.
	_ = persistRefreshCache(v4, v6, aws, fastlyJSON) // non-fatal
	return nil
}

// parseFastlyJSON parses the Fastly public-ip-list JSON response:
// {"addresses":["..."],"ipv6_addresses":["..."]}
func parseFastlyJSON(data []byte) ([]netip.Prefix, error) {
	var doc struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, s := range append(doc.Addresses, doc.IPv6Addresses...) {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("fastly prefix %q: %w", s, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// cdnCacheDir returns the XDG-based directory for CDN range caches.
func cdnCacheDir() (string, error) {
	if dir := os.Getenv("XDG_CACHE_HOME"); dir != "" {
		return filepath.Join(dir, "unearth", "cdn"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cache", "unearth", "cdn"), nil
}

// persistRefreshCache writes freshly fetched range bytes to the XDG cache
// so future process starts can load them without re-fetching. Errors are
// non-fatal — the caller proceeds with the in-memory update regardless.
func persistRefreshCache(cfV4, cfV6, awsJSON, fastlyJSON []byte) error {
	dir, err := cdnCacheDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	files := map[string][]byte{
		"cloudflare-v4.txt": cfV4,
		"cloudflare-v6.txt": cfV6,
		"cloudfront.json":   awsJSON,
		"fastly-list.json":  fastlyJSON,
	}
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// LoadCachedRefresh loads previously-refreshed range data from the XDG
// cache directory, if present and fresher than refreshMaxAge, and applies
// it to the in-memory provider tables. This is called at process start by
// the CLI and MCP server so they benefit from a prior refresh without
// re-fetching.
//
// Returns nil when no usable cached data is found — the caller falls back
// to the embedded snapshot, which is always valid.
func LoadCachedRefresh() error {
	dir, err := cdnCacheDir()
	if err != nil {
		return nil // XDG lookup failed; use embedded snapshot
	}
	check := func(name string) ([]byte, bool) {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil || time.Since(info.ModTime()) > refreshMaxAge {
			return nil, false
		}
		data, err := os.ReadFile(path) // #nosec G304
		if err != nil {
			return nil, false
		}
		return data, true
	}
	cfV4, ok1 := check("cloudflare-v4.txt")
	cfV6, ok2 := check("cloudflare-v6.txt")
	awsJSON, ok3 := check("cloudfront.json")
	fastlyJSON, ok4 := check("fastly-list.json")
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return nil // fall back to embedded snapshot
	}

	cfPrefixes, err := parsePlainPrefixes(cfV4)
	if err != nil {
		return nil
	}
	cfV6Parsed, err := parsePlainPrefixes(cfV6)
	if err != nil {
		return nil
	}
	cfPrefixes = append(cfPrefixes, cfV6Parsed...)

	prev := cloudfrontRaw
	cloudfrontRaw = awsJSON
	cfront, err := buildCloudFront()
	cloudfrontRaw = prev
	if err != nil {
		return nil
	}

	fastlyPrefixes, err := parseFastlyJSON(fastlyJSON)
	if err != nil {
		return nil
	}

	providers[0] = &Provider{Name: "cloudflare", dnsHints: providers[0].dnsHints, prefixes: cfPrefixes}
	providers[1] = cfront
	providers[2] = &Provider{Name: "fastly", dnsHints: providers[2].dnsHints, prefixes: fastlyPrefixes}
	// providers[3] (sucuri) unchanged — no cached refresh for it
	return nil
}

func fetch(ctx context.Context, hc *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	buf := bytes.NewBuffer(nil)
	const maxRefresh = 16 << 20 // 16 MiB cap
	if _, err := buf.ReadFrom(http.MaxBytesReader(nil, resp.Body, maxRefresh)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
