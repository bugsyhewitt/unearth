package cdn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestIsCDNIP_KnownCloudflare(t *testing.T) {
	// 1.1.1.1 is Cloudflare's public DNS, in 1.0.0.0/24 — but Cloudflare's
	// edge ranges don't include 1.1.1.1. Use a documented edge address
	// inside 104.16.0.0/13 instead.
	addr := netip.MustParseAddr("104.16.0.1")
	if !IsCDNIP(addr) {
		t.Errorf("104.16.0.1 should be Cloudflare CDN IP")
	}
	if got := ProviderForIP(addr); got != "cloudflare" {
		t.Errorf("ProviderForIP(104.16.0.1) = %q, want cloudflare", got)
	}
}

func TestIsCDNIP_NonCDNAddresses(t *testing.T) {
	for _, s := range []string{
		"8.8.8.8",     // Google DNS, not a CDN edge
		"10.0.0.1",    // RFC1918
		"192.168.1.1", // RFC1918
		"127.0.0.1",   // loopback
		"203.0.113.5", // TEST-NET-3 (documentation range)
	} {
		a := netip.MustParseAddr(s)
		if IsCDNIP(a) {
			t.Errorf("%s should NOT be CDN", s)
		}
		if got := ProviderForIP(a); got != "" {
			t.Errorf("ProviderForIP(%s) = %q, want empty", s, got)
		}
	}
}

func TestIsCDNIP_InvalidAddr(t *testing.T) {
	if IsCDNIP(netip.Addr{}) {
		t.Error("zero Addr should not match any CDN")
	}
	if ProviderForIP(netip.Addr{}) != "" {
		t.Error("zero Addr should yield empty provider")
	}
}

func TestIsCDNIP_CloudFront(t *testing.T) {
	// Pick the first ipv4 prefix from the CloudFront provider's table and
	// use its network address — guaranteed to be inside the range.
	var pickedV4 netip.Prefix
	for _, p := range providers {
		if p.Name == "cloudfront" {
			for _, pref := range p.prefixes {
				if pref.Addr().Is4() {
					pickedV4 = pref
					break
				}
			}
		}
	}
	if !pickedV4.IsValid() {
		t.Skip("no CloudFront v4 prefix in embedded snapshot")
	}
	a := pickedV4.Addr()
	if got := ProviderForIP(a); got != "cloudfront" {
		t.Errorf("ProviderForIP(%s) = %q, want cloudfront", a, got)
	}
}

func TestProviderByDNS(t *testing.T) {
	cases := map[string]string{
		"foo.cloudflare.net":     "cloudflare",
		"d123abc.cloudfront.net": "cloudfront",
		"example.com":            "",
		"www.example.org":        "",
	}
	for host, want := range cases {
		got, _ := providerByDNS(host)
		if got != want {
			t.Errorf("providerByDNS(%s) = %q, want %q", host, got, want)
		}
	}
}

func TestClassifyHeaders(t *testing.T) {
	cases := []struct {
		name string
		h    http.Header
		want string
	}{
		{
			name: "server: cloudflare",
			h:    http.Header{"Server": []string{"cloudflare"}},
			want: "cloudflare",
		},
		{
			name: "cf-ray",
			h:    http.Header{"Cf-Ray": []string{"abc-DFW"}},
			want: "cloudflare",
		},
		{
			name: "x-amz-cf-id",
			h:    http.Header{"X-Amz-Cf-Id": []string{"id123"}},
			want: "cloudfront",
		},
		{
			name: "via cloudfront",
			h:    http.Header{"Via": []string{"1.1 abc.cloudfront.net"}},
			want: "cloudfront",
		},
		{
			name: "x-cache cloudfront",
			h:    http.Header{"X-Cache": []string{"Hit from cloudfront"}},
			want: "cloudfront",
		},
		{
			name: "no markers",
			h:    http.Header{"Server": []string{"nginx"}},
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyHeaders(c.h); got != c.want {
				t.Errorf("classifyHeaders: got %q, want %q", got, c.want)
			}
		})
	}
}

func TestCollectHeaderSignals(t *testing.T) {
	h := http.Header{
		"Server":      []string{"cloudflare"},
		"Cf-Ray":      []string{"x"},
		"X-Amz-Cf-Id": []string{"y"},
	}
	sigs := collectHeaderSignals(h)
	if len(sigs) < 3 {
		t.Errorf("want at least 3 signals, got %v", sigs)
	}
}

func TestParsePlainPrefixes_Errors(t *testing.T) {
	if _, err := parsePlainPrefixes([]byte("not-a-prefix\n")); err == nil {
		t.Error("expected error on garbage line")
	}
	// Comments and blank lines ignored.
	if got, err := parsePlainPrefixes([]byte("# comment\n\n104.16.0.0/13\n")); err != nil || len(got) != 1 {
		t.Errorf("comment/blank handling: err=%v len=%d", err, len(got))
	}
}

func TestDetect_HTTPHeadersOnly(t *testing.T) {
	// Drive Detect with an httptest server returning cloudflare-style
	// headers. The DNS calls for the test hostname will fail (host doesn't
	// resolve); only the header probe should still fire and set CDN.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Cf-Ray", "abc-LAX")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	// Build a client that accepts the test cert and rewrites the host to the
	// test server. We can't change the request URL inside Detect, so use a
	// transport that redirects every request to srv.URL.
	target := strings.TrimPrefix(srv.URL, "https://")
	det, _ := Detect(context.Background(), target, srv.Client())
	// We may not have DNS for the synthetic target; that's fine — header
	// probe should still set CDN.
	if det.CDN != "cloudflare" {
		t.Errorf("Detect via headers: CDN=%q signals=%v", det.CDN, det.Signals)
	}
	foundHeader := false
	for _, s := range det.Signals {
		if strings.Contains(s, "cf-ray") || strings.Contains(s, "server: cloudflare") {
			foundHeader = true
		}
	}
	if !foundHeader {
		t.Errorf("want at least one header signal, got %v", det.Signals)
	}
}

func TestDetect_NilClientUsesDefault(_ *testing.T) {
	// Calling with nil hc must not panic. Use a target that won't resolve
	// so DNS/HTTP both fail; we only assert no panic and a usable
	// Detection result.
	det, _ := Detect(context.Background(), "definitely-not-a-real-host.invalid", nil)
	_ = det
}

func TestSnapshotDateNonEmpty(t *testing.T) {
	if SnapshotDate == "" {
		t.Error("SnapshotDate constant should record when ranges were captured")
	}
}

// ── Fastly ────────────────────────────────────────────────────────────────────

func TestIsCDNIP_Fastly(t *testing.T) {
	// 151.101.0.0/16 is in the embedded Fastly snapshot.
	addr := netip.MustParseAddr("151.101.1.1")
	if !IsCDNIP(addr) {
		t.Errorf("151.101.1.1 should be Fastly CDN IP")
	}
	if got := ProviderForIP(addr); got != "fastly" {
		t.Errorf("ProviderForIP(151.101.1.1) = %q, want fastly", got)
	}
}

func TestIsCDNIP_FastlyRange2(t *testing.T) {
	// 199.232.0.0/16 is another embedded Fastly range.
	addr := netip.MustParseAddr("199.232.100.50")
	if !IsCDNIP(addr) {
		t.Errorf("199.232.100.50 should be Fastly CDN IP")
	}
	if got := ProviderForIP(addr); got != "fastly" {
		t.Errorf("ProviderForIP(199.232.100.50) = %q, want fastly", got)
	}
}

func TestProviderByDNS_Fastly(t *testing.T) {
	cases := map[string]string{
		"foo.fastly.net":   "fastly",
		"bar.fastlylb.net": "fastly",
	}
	for host, want := range cases {
		got, _ := providerByDNS(host)
		if got != want {
			t.Errorf("providerByDNS(%s) = %q, want %q", host, got, want)
		}
	}
}

// ── Sucuri ────────────────────────────────────────────────────────────────────

func TestIsCDNIP_Sucuri(t *testing.T) {
	// 192.88.134.0/23 is the first embedded Sucuri range.
	addr := netip.MustParseAddr("192.88.134.5")
	if !IsCDNIP(addr) {
		t.Errorf("192.88.134.5 should be Sucuri CDN IP")
	}
	if got := ProviderForIP(addr); got != "sucuri" {
		t.Errorf("ProviderForIP(192.88.134.5) = %q, want sucuri", got)
	}
}

func TestIsCDNIP_Sucuri_IPv6(t *testing.T) {
	// 2a02:fe80::/29 is the embedded Sucuri IPv6 range.
	addr := netip.MustParseAddr("2a02:fe80::1")
	if !IsCDNIP(addr) {
		t.Errorf("2a02:fe80::1 should be Sucuri CDN IP")
	}
}

func TestProviderByDNS_Sucuri(t *testing.T) {
	got, _ := providerByDNS("site.sucuri.net")
	if got != "sucuri" {
		t.Errorf("providerByDNS(site.sucuri.net) = %q, want sucuri", got)
	}
}

// ── classifyHeaders additions ─────────────────────────────────────────────────

func TestClassifyHeaders_Fastly(t *testing.T) {
	h := http.Header{}
	h.Set("X-Fastly-Request-Id", "abc123") // canonical MIME form
	if got := classifyHeaders(h); got != "fastly" {
		t.Errorf("classifyHeaders with x-fastly-request-id = %q, want fastly", got)
	}
}

func TestClassifyHeaders_Sucuri(t *testing.T) {
	h := http.Header{"X-Sucuri-Cache": []string{"HIT"}}
	if got := classifyHeaders(h); got != "sucuri" {
		t.Errorf("classifyHeaders with x-sucuri-cache = %q, want sucuri", got)
	}
}

// ── parseFastlyJSON ───────────────────────────────────────────────────────────

func TestParseFastlyJSON_Happy(t *testing.T) {
	data := []byte(`{"addresses":["1.2.3.0/24"],"ipv6_addresses":["2a04:4e40::/32"]}`)
	prefs, err := parseFastlyJSON(data)
	if err != nil {
		t.Fatalf("parseFastlyJSON: %v", err)
	}
	if len(prefs) != 2 {
		t.Errorf("expected 2 prefixes, got %d", len(prefs))
	}
}

func TestParseFastlyJSON_Malformed(t *testing.T) {
	if _, err := parseFastlyJSON([]byte("not json")); err == nil {
		t.Error("expected error on bad JSON")
	}
}

func TestParseFastlyJSON_BadPrefix(t *testing.T) {
	data := []byte(`{"addresses":["not-a-cidr"],"ipv6_addresses":[]}`)
	if _, err := parseFastlyJSON(data); err == nil {
		t.Error("expected error on non-CIDR string")
	}
}

// ── Akamai ────────────────────────────────────────────────────────────────────

func TestIsCDNIP_Akamai(t *testing.T) {
	// 23.32.0.1 is inside 23.32.0.0/11, an Akamai AS20940 range.
	addr := netip.MustParseAddr("23.32.0.1")
	if !IsCDNIP(addr) {
		t.Errorf("23.32.0.1 should be Akamai CDN IP")
	}
	if got := ProviderForIP(addr); got != "akamai" {
		t.Errorf("ProviderForIP(23.32.0.1) = %q, want akamai", got)
	}
}

func TestIsCDNIP_Akamai_IPv6(t *testing.T) {
	// 2600:1400::1 is inside 2600:1400::/24, an Akamai IPv6 range.
	addr := netip.MustParseAddr("2600:1400::1")
	if !IsCDNIP(addr) {
		t.Errorf("2600:1400::1 should be Akamai CDN IP")
	}
	if got := ProviderForIP(addr); got != "akamai" {
		t.Errorf("ProviderForIP(2600:1400::1) = %q, want akamai", got)
	}
}

func TestProviderByDNS_Akamai(t *testing.T) {
	cases := map[string]string{
		"foo.edgesuite.net":          "akamai",
		"bar.edgekey.net":            "akamai",
		"example.akamaized.net":      "akamai",
		"cdn.akamaitechnologies.com": "akamai",
		"edge.akamai.net":            "akamai",
	}
	for host, want := range cases {
		got, _ := providerByDNS(host)
		if got != want {
			t.Errorf("providerByDNS(%s) = %q, want %q", host, got, want)
		}
	}
}

func TestClassifyHeaders_Akamai(t *testing.T) {
	t.Run("x-check-cacheable", func(t *testing.T) {
		h := http.Header{"X-Check-Cacheable": []string{"YES"}}
		if got := classifyHeaders(h); got != "akamai" {
			t.Errorf("classifyHeaders with x-check-cacheable = %q, want akamai", got)
		}
	})
	t.Run("x-akamai-transformed", func(t *testing.T) {
		h := http.Header{"X-Akamai-Transformed": []string{"9 - 0 pmb=mRUM,1"}}
		if got := classifyHeaders(h); got != "akamai" {
			t.Errorf("classifyHeaders with x-akamai-transformed = %q, want akamai", got)
		}
	})
}

func TestIsCDNIP_Imperva(t *testing.T) {
	// 199.83.128.1 is inside 199.83.128.0/21, an Imperva AS19551 range.
	addr := netip.MustParseAddr("199.83.128.1")
	if !IsCDNIP(addr) {
		t.Errorf("199.83.128.1 should be Imperva CDN IP")
	}
	if got := ProviderForIP(addr); got != "imperva" {
		t.Errorf("ProviderForIP(199.83.128.1) = %q, want imperva", got)
	}
}

func TestIsCDNIP_Imperva_IPv6(t *testing.T) {
	// 2a02:e980::1 is inside 2a02:e980::/29, an Imperva IPv6 range.
	addr := netip.MustParseAddr("2a02:e980::1")
	if !IsCDNIP(addr) {
		t.Errorf("2a02:e980::1 should be Imperva CDN IP")
	}
	if got := ProviderForIP(addr); got != "imperva" {
		t.Errorf("ProviderForIP(2a02:e980::1) = %q, want imperva", got)
	}
}

func TestProviderByDNS_Imperva(t *testing.T) {
	cases := map[string]string{
		"site-12345.incapdns.net": "imperva",
		"foo.incapdns.com":        "imperva",
		"portal.incapsula.com":    "imperva",
	}
	for host, want := range cases {
		got, _ := providerByDNS(host)
		if got != want {
			t.Errorf("providerByDNS(%s) = %q, want %q", host, got, want)
		}
	}
}

func TestClassifyHeaders_Imperva(t *testing.T) {
	t.Run("x-iinfo", func(t *testing.T) {
		h := http.Header{"X-Iinfo": []string{"7-12345678-12345679 NNNN CT(0 0 0) RT(...)"}}
		if got := classifyHeaders(h); got != "imperva" {
			t.Errorf("classifyHeaders with x-iinfo = %q, want imperva", got)
		}
	})
	t.Run("x-cdn-incapsula", func(t *testing.T) {
		h := http.Header{}
		h.Set("X-CDN", "Incapsula")
		if got := classifyHeaders(h); got != "imperva" {
			t.Errorf("classifyHeaders with x-cdn incapsula = %q, want imperva", got)
		}
	})
	t.Run("incap-session-cookie", func(t *testing.T) {
		h := http.Header{"Set-Cookie": []string{"incap_ses_123_456=abcdef; path=/"}}
		if got := classifyHeaders(h); got != "imperva" {
			t.Errorf("classifyHeaders with incap_ses cookie = %q, want imperva", got)
		}
	})
	t.Run("visid-cookie", func(t *testing.T) {
		h := http.Header{"Set-Cookie": []string{"visid_incap_456=xyz; path=/; HttpOnly"}}
		if got := classifyHeaders(h); got != "imperva" {
			t.Errorf("classifyHeaders with visid_incap cookie = %q, want imperva", got)
		}
	})
	t.Run("collectHeaderSignals", func(t *testing.T) {
		h := http.Header{
			"X-Iinfo":    []string{"7-1-2 NNNN"},
			"Set-Cookie": []string{"incap_ses_1_2=foo"},
		}
		sigs := collectHeaderSignals(h)
		var sawIinfo, sawCookie bool
		for _, s := range sigs {
			if s == "header x-iinfo present (imperva)" {
				sawIinfo = true
			}
			if s == "incapsula session cookie present" {
				sawCookie = true
			}
		}
		if !sawIinfo || !sawCookie {
			t.Errorf("expected imperva signals, got %v", sigs)
		}
	})
}

// ── Azure Front Door ────────────────────────────────────────────────────────

func TestIsCDNIP_AzureFrontDoor(t *testing.T) {
	// 13.107.21.1 is inside 13.107.21.0/24, an Azure Front Door anycast range.
	addr := netip.MustParseAddr("13.107.21.1")
	if !IsCDNIP(addr) {
		t.Errorf("13.107.21.1 should be Azure Front Door CDN IP")
	}
	if got := ProviderForIP(addr); got != "azurefd" {
		t.Errorf("ProviderForIP(13.107.21.1) = %q, want azurefd", got)
	}
}

func TestIsCDNIP_AzureFrontDoor_IPv6(t *testing.T) {
	// 2620:1ec::1 is inside 2620:1ec::/36, an Azure Front Door IPv6 range.
	addr := netip.MustParseAddr("2620:1ec::1")
	if !IsCDNIP(addr) {
		t.Errorf("2620:1ec::1 should be Azure Front Door CDN IP")
	}
	if got := ProviderForIP(addr); got != "azurefd" {
		t.Errorf("ProviderForIP(2620:1ec::1) = %q, want azurefd", got)
	}
}

func TestProviderByDNS_AzureFrontDoor(t *testing.T) {
	cases := map[string]string{
		"contoso.azurefd.net":    "azurefd",
		"assets.azureedge.net":   "azurefd",
		"foo.t-msedge.net":       "azurefd",
		"app.trafficmanager.net": "azurefd",
	}
	for host, want := range cases {
		got, _ := providerByDNS(host)
		if got != want {
			t.Errorf("providerByDNS(%s) = %q, want %q", host, got, want)
		}
	}
}

func TestClassifyHeaders_AzureFrontDoor(t *testing.T) {
	t.Run("x-azure-ref", func(t *testing.T) {
		h := http.Header{"X-Azure-Ref": []string{"0abc1ZQAAAAB..."}}
		if got := classifyHeaders(h); got != "azurefd" {
			t.Errorf("classifyHeaders with x-azure-ref = %q, want azurefd", got)
		}
	})
	t.Run("x-cache-frontdoor", func(t *testing.T) {
		h := http.Header{"X-Cache": []string{"TCP_HIT from FrontDoor"}}
		if got := classifyHeaders(h); got != "azurefd" {
			t.Errorf("classifyHeaders with x-cache frontdoor = %q, want azurefd", got)
		}
	})
	t.Run("collectHeaderSignals", func(t *testing.T) {
		h := http.Header{
			"X-Azure-Ref": []string{"ref123"},
			"X-Cache":     []string{"TCP_MISS from FrontDoor"},
		}
		sigs := collectHeaderSignals(h)
		var sawRef, sawCache bool
		for _, s := range sigs {
			if s == "header x-azure-ref present (azure front door)" {
				sawRef = true
			}
			if s == "header x-cache mentions frontdoor" {
				sawCache = true
			}
		}
		if !sawRef || !sawCache {
			t.Errorf("expected azure front door signals, got %v", sigs)
		}
	})
}

// ── Google Cloud CDN ────────────────────────────────────────────────────────

func TestIsCDNIP_GoogleCDN(t *testing.T) {
	// 130.211.0.1 is inside 130.211.0.0/22, a Google GFE / Cloud CDN range.
	addr := netip.MustParseAddr("130.211.0.1")
	if !IsCDNIP(addr) {
		t.Errorf("130.211.0.1 should be Google Cloud CDN IP")
	}
	if got := ProviderForIP(addr); got != "googlecdn" {
		t.Errorf("ProviderForIP(130.211.0.1) = %q, want googlecdn", got)
	}
}

func TestIsCDNIP_GoogleCDN_IPv6(t *testing.T) {
	// 2607:f8b0::1 is inside 2607:f8b0::/32, a Google IPv6 range.
	addr := netip.MustParseAddr("2607:f8b0::1")
	if !IsCDNIP(addr) {
		t.Errorf("2607:f8b0::1 should be Google Cloud CDN IP")
	}
	if got := ProviderForIP(addr); got != "googlecdn" {
		t.Errorf("ProviderForIP(2607:f8b0::1) = %q, want googlecdn", got)
	}
}

func TestProviderByDNS_GoogleCDN(t *testing.T) {
	cases := map[string]string{
		"ghs.googlehosted.com":      "googlecdn",
		"foo.googleusercontent.com": "googlecdn",
		"c.storage.googleapis.com":  "googlecdn",
		"any.l.google.com":          "googlecdn",
	}
	for host, want := range cases {
		got, _ := providerByDNS(host)
		if got != want {
			t.Errorf("providerByDNS(%s) = %q, want %q", host, got, want)
		}
	}
}

func TestClassifyHeaders_GoogleCDN(t *testing.T) {
	t.Run("server-google-frontend", func(t *testing.T) {
		h := http.Header{"Server": []string{"Google Frontend"}}
		if got := classifyHeaders(h); got != "googlecdn" {
			t.Errorf("classifyHeaders with server Google Frontend = %q, want googlecdn", got)
		}
	})
	t.Run("via-google", func(t *testing.T) {
		h := http.Header{"Via": []string{"1.1 google"}}
		if got := classifyHeaders(h); got != "googlecdn" {
			t.Errorf("classifyHeaders with via 1.1 google = %q, want googlecdn", got)
		}
	})
	t.Run("x-goog-hash", func(t *testing.T) {
		h := http.Header{"X-Goog-Hash": []string{"crc32c=abc"}}
		if got := classifyHeaders(h); got != "googlecdn" {
			t.Errorf("classifyHeaders with x-goog-hash = %q, want googlecdn", got)
		}
	})
	t.Run("collectHeaderSignals", func(t *testing.T) {
		h := http.Header{
			"Server":      []string{"Google Frontend"},
			"Via":         []string{"1.1 google"},
			"X-Goog-Hash": []string{"crc32c=abc"},
		}
		sigs := collectHeaderSignals(h)
		var sawServer, sawVia, sawGoog bool
		for _, s := range sigs {
			switch s {
			case "header server: google frontend (google cloud cdn)":
				sawServer = true
			case "header via mentions google (google cloud cdn)":
				sawVia = true
			case "header x-goog-* present (google cloud cdn)":
				sawGoog = true
			}
		}
		if !sawServer || !sawVia || !sawGoog {
			t.Errorf("expected google cloud cdn signals, got %v", sigs)
		}
	})
}

// ── StackPath / Highwinds ─────────────────────────────────────────────────────

func TestIsCDNIP_StackPath(t *testing.T) {
	// 151.139.0.1 is inside 151.139.0.0/16, a Highwinds / StackPath range.
	addr := netip.MustParseAddr("151.139.0.1")
	if !IsCDNIP(addr) {
		t.Errorf("151.139.0.1 should be StackPath CDN IP")
	}
	if got := ProviderForIP(addr); got != "stackpath" {
		t.Errorf("ProviderForIP(151.139.0.1) = %q, want stackpath", got)
	}
}

func TestIsCDNIP_StackPath_Range2(t *testing.T) {
	// 205.185.216.10 is inside 205.185.192.0/18, another StackPath range.
	addr := netip.MustParseAddr("205.185.216.10")
	if !IsCDNIP(addr) {
		t.Errorf("205.185.216.10 should be StackPath CDN IP")
	}
	if got := ProviderForIP(addr); got != "stackpath" {
		t.Errorf("ProviderForIP(205.185.216.10) = %q, want stackpath", got)
	}
}

func TestIsCDNIP_StackPath_IPv6(t *testing.T) {
	// 2606:2800::1 is inside 2606:2800::/32, a StackPath IPv6 range.
	addr := netip.MustParseAddr("2606:2800::1")
	if !IsCDNIP(addr) {
		t.Errorf("2606:2800::1 should be StackPath CDN IP")
	}
	if got := ProviderForIP(addr); got != "stackpath" {
		t.Errorf("ProviderForIP(2606:2800::1) = %q, want stackpath", got)
	}
}

func TestProviderByDNS_StackPath(t *testing.T) {
	cases := map[string]string{
		"site.stackpathcdn.com": "stackpath",
		"foo.stackpathdns.com":  "stackpath",
		"edge.hwcdn.net":        "stackpath",
		"assets.netdna-cdn.com": "stackpath",
		"secure.netdna-ssl.com": "stackpath",
		"cdn.netdna.com":        "stackpath",
	}
	for host, want := range cases {
		got, _ := providerByDNS(host)
		if got != want {
			t.Errorf("providerByDNS(%s) = %q, want %q", host, got, want)
		}
	}
}

func TestClassifyHeaders_StackPath(t *testing.T) {
	t.Run("x-hw", func(t *testing.T) {
		h := http.Header{"X-Hw": []string{"1709145600.cds123.ord1.h"}}
		if got := classifyHeaders(h); got != "stackpath" {
			t.Errorf("classifyHeaders with x-hw = %q, want stackpath", got)
		}
	})
	t.Run("server-netdna-cache", func(t *testing.T) {
		h := http.Header{"Server": []string{"NetDNA-cache/2.2"}}
		if got := classifyHeaders(h); got != "stackpath" {
			t.Errorf("classifyHeaders with server NetDNA-cache = %q, want stackpath", got)
		}
	})
	t.Run("x-cdn-stackpath", func(t *testing.T) {
		h := http.Header{}
		h.Set("X-CDN", "Stackpath")
		if got := classifyHeaders(h); got != "stackpath" {
			t.Errorf("classifyHeaders with x-cdn stackpath = %q, want stackpath", got)
		}
	})
	t.Run("collectHeaderSignals", func(t *testing.T) {
		h := http.Header{
			"X-Hw":   []string{"ref123"},
			"Server": []string{"NetDNA-cache/2.2"},
		}
		sigs := collectHeaderSignals(h)
		var sawHW, sawServer bool
		for _, s := range sigs {
			switch s {
			case "header x-hw present (stackpath/highwinds)":
				sawHW = true
			case "header server: netdna-cache (stackpath)":
				sawServer = true
			}
		}
		if !sawHW || !sawServer {
			t.Errorf("expected stackpath signals, got %v", sigs)
		}
	})
}

// ── BunnyCDN ──────────────────────────────────────────────────────────────────

func TestIsCDNIP_BunnyCDN(t *testing.T) {
	// 89.187.160.1 is inside 89.187.160.0/19, a BunnyCDN AS200325 range.
	addr := netip.MustParseAddr("89.187.160.1")
	if !IsCDNIP(addr) {
		t.Errorf("89.187.160.1 should be BunnyCDN CDN IP")
	}
	if got := ProviderForIP(addr); got != "bunnycdn" {
		t.Errorf("ProviderForIP(89.187.160.1) = %q, want bunnycdn", got)
	}
}

func TestIsCDNIP_BunnyCDN_Range2(t *testing.T) {
	// 138.199.50.10 is inside 138.199.0.0/16, another BunnyCDN range.
	addr := netip.MustParseAddr("138.199.50.10")
	if !IsCDNIP(addr) {
		t.Errorf("138.199.50.10 should be BunnyCDN CDN IP")
	}
	if got := ProviderForIP(addr); got != "bunnycdn" {
		t.Errorf("ProviderForIP(138.199.50.10) = %q, want bunnycdn", got)
	}
}

func TestIsCDNIP_BunnyCDN_IPv6(t *testing.T) {
	// 2a0a:f900::1 is inside 2a0a:f900::/29, a BunnyCDN IPv6 range.
	addr := netip.MustParseAddr("2a0a:f900::1")
	if !IsCDNIP(addr) {
		t.Errorf("2a0a:f900::1 should be BunnyCDN CDN IP")
	}
	if got := ProviderForIP(addr); got != "bunnycdn" {
		t.Errorf("ProviderForIP(2a0a:f900::1) = %q, want bunnycdn", got)
	}
}

func TestProviderByDNS_BunnyCDN(t *testing.T) {
	cases := map[string]string{
		"mypullzone.b-cdn.net": "bunnycdn",
		"assets.bunnycdn.com":  "bunnycdn",
		"video.bunny.net":      "bunnycdn",
	}
	for host, want := range cases {
		got, _ := providerByDNS(host)
		if got != want {
			t.Errorf("providerByDNS(%s) = %q, want %q", host, got, want)
		}
	}
}

func TestClassifyHeaders_BunnyCDN(t *testing.T) {
	t.Run("server-bunnycdn-pop", func(t *testing.T) {
		h := http.Header{"Server": []string{"BunnyCDN-FR1-823"}}
		if got := classifyHeaders(h); got != "bunnycdn" {
			t.Errorf("classifyHeaders with server BunnyCDN-FR1 = %q, want bunnycdn", got)
		}
	})
	t.Run("cdn-pullzone", func(t *testing.T) {
		h := http.Header{}
		h.Set("CDN-PullZone", "123456")
		if got := classifyHeaders(h); got != "bunnycdn" {
			t.Errorf("classifyHeaders with cdn-pullzone = %q, want bunnycdn", got)
		}
	})
	t.Run("cdn-requestcountrycode", func(t *testing.T) {
		h := http.Header{}
		h.Set("CDN-RequestCountryCode", "SI")
		if got := classifyHeaders(h); got != "bunnycdn" {
			t.Errorf("classifyHeaders with cdn-requestcountrycode = %q, want bunnycdn", got)
		}
	})
	t.Run("collectHeaderSignals", func(t *testing.T) {
		h := http.Header{}
		h.Set("Server", "BunnyCDN-DE1-1099")
		h.Set("CDN-PullZone", "123456")
		h.Set("CDN-RequestCountryCode", "SI")
		sigs := collectHeaderSignals(h)
		var sawServer, sawPullZone, sawCountry bool
		for _, s := range sigs {
			switch s {
			case "header server: bunnycdn pop (bunnycdn)":
				sawServer = true
			case "header cdn-pullzone present (bunnycdn)":
				sawPullZone = true
			case "header cdn-requestcountrycode present (bunnycdn)":
				sawCountry = true
			}
		}
		if !sawServer || !sawPullZone || !sawCountry {
			t.Errorf("expected bunnycdn signals, got %v", sigs)
		}
	})
}

// TestNoDuplicatePrefixAcrossProviders guards the provider registry against the
// silent-masking failure mode: ProviderForIP is first-match-wins, so if two
// providers claim the same prefix the second provider becomes unreachable for
// that range. Every embedded prefix must belong to exactly one provider.
func TestNoDuplicatePrefixAcrossProviders(t *testing.T) {
	seen := make(map[string]string)
	for _, p := range providers {
		for _, pref := range p.prefixes {
			key := pref.String()
			if owner, dup := seen[key]; dup && owner != p.Name {
				t.Errorf("prefix %s claimed by both %q and %q", key, owner, p.Name)
			}
			seen[key] = p.Name
		}
	}
}

// ── CDN77 ──────────────────────────────────────────────────────────────────────

func TestIsCDNIP_CDN77(t *testing.T) {
	// 185.59.220.1 is inside 185.59.220.0/22, a CDN77 AS60068 range.
	addr := netip.MustParseAddr("185.59.220.1")
	if !IsCDNIP(addr) {
		t.Errorf("185.59.220.1 should be CDN77 CDN IP")
	}
	if got := ProviderForIP(addr); got != "cdn77" {
		t.Errorf("ProviderForIP(185.59.220.1) = %q, want cdn77", got)
	}
}

func TestIsCDNIP_CDN77_Range2(t *testing.T) {
	// 212.102.40.10 is inside 212.102.32.0/19, another CDN77 range.
	addr := netip.MustParseAddr("212.102.40.10")
	if !IsCDNIP(addr) {
		t.Errorf("212.102.40.10 should be CDN77 CDN IP")
	}
	if got := ProviderForIP(addr); got != "cdn77" {
		t.Errorf("ProviderForIP(212.102.40.10) = %q, want cdn77", got)
	}
}

func TestIsCDNIP_CDN77_IPv6(t *testing.T) {
	// 2a03:90c0::1 is inside 2a03:90c0::/29, a CDN77 IPv6 range.
	addr := netip.MustParseAddr("2a03:90c0::1")
	if !IsCDNIP(addr) {
		t.Errorf("2a03:90c0::1 should be CDN77 CDN IP")
	}
	if got := ProviderForIP(addr); got != "cdn77" {
		t.Errorf("ProviderForIP(2a03:90c0::1) = %q, want cdn77", got)
	}
}

func TestProviderByDNS_CDN77(t *testing.T) {
	cases := map[string]string{
		"mypull.cdn77.org":     "cdn77",
		"assets.cdn77-ssl.net": "cdn77",
		"static.cdn77.net":     "cdn77",
		"www.cdn77.com":        "cdn77",
	}
	for host, want := range cases {
		got, _ := providerByDNS(host)
		if got != want {
			t.Errorf("providerByDNS(%s) = %q, want %q", host, got, want)
		}
	}
}

func TestClassifyHeaders_CDN77(t *testing.T) {
	t.Run("x-77-cache", func(t *testing.T) {
		h := http.Header{}
		h.Set("X-77-Cache", "HIT")
		if got := classifyHeaders(h); got != "cdn77" {
			t.Errorf("classifyHeaders with x-77-cache = %q, want cdn77", got)
		}
	})
	t.Run("x-77-nzt", func(t *testing.T) {
		h := http.Header{}
		h.Set("X-77-Nzt", "1")
		if got := classifyHeaders(h); got != "cdn77" {
			t.Errorf("classifyHeaders with x-77-nzt = %q, want cdn77", got)
		}
	})
	t.Run("server-cdn77", func(t *testing.T) {
		h := http.Header{"Server": []string{"CDN77"}}
		if got := classifyHeaders(h); got != "cdn77" {
			t.Errorf("classifyHeaders with server CDN77 = %q, want cdn77", got)
		}
	})
	t.Run("x-cdn-cdn77", func(t *testing.T) {
		h := http.Header{}
		h.Set("X-CDN", "CDN77")
		if got := classifyHeaders(h); got != "cdn77" {
			t.Errorf("classifyHeaders with x-cdn CDN77 = %q, want cdn77", got)
		}
	})
	t.Run("collectHeaderSignals", func(t *testing.T) {
		h := http.Header{}
		h.Set("X-77-Pop", "prague")
		h.Set("Server", "CDN77")
		h.Set("X-CDN", "CDN77")
		sigs := collectHeaderSignals(h)
		var sawX77, sawServer, sawXCDN bool
		for _, s := range sigs {
			switch s {
			case "header x-77-* present (cdn77)":
				sawX77 = true
			case "header server: cdn77 (cdn77)":
				sawServer = true
			case "header x-cdn mentions cdn77":
				sawXCDN = true
			}
		}
		if !sawX77 || !sawServer || !sawXCDN {
			t.Errorf("expected cdn77 signals, got %v", sigs)
		}
	})
}

// ── Edgio (Limelight / Edgecast) ─────────────────────────────────────────────

func TestIsCDNIP_Edgio_Limelight(t *testing.T) {
	// 68.142.64.1 is inside 68.142.64.0/18, a Limelight AS22822 range.
	addr := netip.MustParseAddr("68.142.64.1")
	if !IsCDNIP(addr) {
		t.Errorf("68.142.64.1 should be Edgio CDN IP")
	}
	if got := ProviderForIP(addr); got != "edgio" {
		t.Errorf("ProviderForIP(68.142.64.1) = %q, want edgio", got)
	}
}

func TestIsCDNIP_Edgio_Edgecast(t *testing.T) {
	// 152.195.10.20 is inside 152.195.0.0/16, an Edgecast AS15133 range.
	addr := netip.MustParseAddr("152.195.10.20")
	if !IsCDNIP(addr) {
		t.Errorf("152.195.10.20 should be Edgio CDN IP")
	}
	if got := ProviderForIP(addr); got != "edgio" {
		t.Errorf("ProviderForIP(152.195.10.20) = %q, want edgio", got)
	}
}

func TestIsCDNIP_Edgio_Edgecast_Classic(t *testing.T) {
	// 93.184.216.34 (the classic example.com IP) is inside 93.184.208.0/20,
	// an Edgecast / Edgio AS15133 range.
	addr := netip.MustParseAddr("93.184.216.34")
	if !IsCDNIP(addr) {
		t.Errorf("93.184.216.34 should be Edgio CDN IP")
	}
	if got := ProviderForIP(addr); got != "edgio" {
		t.Errorf("ProviderForIP(93.184.216.34) = %q, want edgio", got)
	}
}

func TestIsCDNIP_Edgio_IPv6(t *testing.T) {
	// 2607:f680::1 is inside 2607:f680::/32, a Limelight / Edgio IPv6 range.
	addr := netip.MustParseAddr("2607:f680::1")
	if !IsCDNIP(addr) {
		t.Errorf("2607:f680::1 should be Edgio CDN IP")
	}
	if got := ProviderForIP(addr); got != "edgio" {
		t.Errorf("ProviderForIP(2607:f680::1) = %q, want edgio", got)
	}
}

func TestProviderByDNS_Edgio(t *testing.T) {
	cases := map[string]string{
		"vod.llnwd.net":        "edgio",
		"assets.llnw.com":      "edgio",
		"target.lldns.net":     "edgio",
		"wac.edgecastcdn.net":  "edgio",
		"static.systemcdn.net": "edgio",
		"delivery.edgio.net":   "edgio",
	}
	for host, want := range cases {
		got, _ := providerByDNS(host)
		if got != want {
			t.Errorf("providerByDNS(%s) = %q, want %q", host, got, want)
		}
	}
}

func TestClassifyHeaders_Edgio(t *testing.T) {
	t.Run("server-ecs", func(t *testing.T) {
		h := http.Header{"Server": []string{"ECS"}}
		if got := classifyHeaders(h); got != "edgio" {
			t.Errorf("classifyHeaders with server ECS = %q, want edgio", got)
		}
	})
	t.Run("server-ecacc", func(t *testing.T) {
		h := http.Header{"Server": []string{"ECAcc (dcb/7F5E)"}}
		if got := classifyHeaders(h); got != "edgio" {
			t.Errorf("classifyHeaders with server ECAcc = %q, want edgio", got)
		}
	})
	t.Run("server-limelight", func(t *testing.T) {
		h := http.Header{"Server": []string{"LimeLight"}}
		if got := classifyHeaders(h); got != "edgio" {
			t.Errorf("classifyHeaders with server LimeLight = %q, want edgio", got)
		}
	})
	t.Run("x-llid", func(t *testing.T) {
		h := http.Header{}
		h.Set("X-LLID", "abc123")
		if got := classifyHeaders(h); got != "edgio" {
			t.Errorf("classifyHeaders with x-llid = %q, want edgio", got)
		}
	})
	t.Run("x-ec-header", func(t *testing.T) {
		h := http.Header{}
		h.Set("X-EC-Custom-Error", "0")
		if got := classifyHeaders(h); got != "edgio" {
			t.Errorf("classifyHeaders with x-ec-* = %q, want edgio", got)
		}
	})
	t.Run("x-cdn-edgio", func(t *testing.T) {
		h := http.Header{}
		h.Set("X-CDN", "Edgio")
		if got := classifyHeaders(h); got != "edgio" {
			t.Errorf("classifyHeaders with x-cdn Edgio = %q, want edgio", got)
		}
	})
	t.Run("collectHeaderSignals", func(t *testing.T) {
		h := http.Header{}
		h.Set("Server", "ECAcc (dcb/7F5E)")
		h.Set("X-LLID", "abc123")
		h.Set("X-EC-Custom-Error", "0")
		h.Set("X-CDN", "Edgio")
		sigs := collectHeaderSignals(h)
		var sawServer, sawLLID, sawEC, sawXCDN bool
		for _, s := range sigs {
			switch s {
			case "header server: edgecast/edgio edge (edgio)":
				sawServer = true
			case "header x-llid present (edgio/limelight)":
				sawLLID = true
			case "header x-ec-* present (edgio/edgecast)":
				sawEC = true
			case "header x-cdn mentions edgio":
				sawXCDN = true
			}
		}
		if !sawServer || !sawLLID || !sawEC || !sawXCDN {
			t.Errorf("expected edgio signals, got %v", sigs)
		}
	})
}

// ── KeyCDN (proinity GmbH) ───────────────────────────────────────────────────

func TestIsCDNIP_KeyCDN(t *testing.T) {
	// 185.156.232.1 is inside 185.156.232.0/22, a KeyCDN AS199653 range.
	addr := netip.MustParseAddr("185.156.232.1")
	if !IsCDNIP(addr) {
		t.Errorf("185.156.232.1 should be KeyCDN CDN IP")
	}
	if got := ProviderForIP(addr); got != "keycdn" {
		t.Errorf("ProviderForIP(185.156.232.1) = %q, want keycdn", got)
	}
}

func TestIsCDNIP_KeyCDN_Range2(t *testing.T) {
	// 45.142.176.10 is inside 45.142.176.0/22, another KeyCDN range.
	addr := netip.MustParseAddr("45.142.176.10")
	if !IsCDNIP(addr) {
		t.Errorf("45.142.176.10 should be KeyCDN CDN IP")
	}
	if got := ProviderForIP(addr); got != "keycdn" {
		t.Errorf("ProviderForIP(45.142.176.10) = %q, want keycdn", got)
	}
}

func TestIsCDNIP_KeyCDN_IPv6(t *testing.T) {
	// 2a05:d014:275::1 is inside 2a05:d014:275::/48, a KeyCDN IPv6 range.
	addr := netip.MustParseAddr("2a05:d014:275::1")
	if !IsCDNIP(addr) {
		t.Errorf("2a05:d014:275::1 should be KeyCDN CDN IP")
	}
	if got := ProviderForIP(addr); got != "keycdn" {
		t.Errorf("ProviderForIP(2a05:d014:275::1) = %q, want keycdn", got)
	}
}

// TestProviderForIP_KeyCDN_Negative confirms an address just outside the
// embedded KeyCDN blocks is not misattributed to KeyCDN.
func TestProviderForIP_KeyCDN_Negative(t *testing.T) {
	// 185.156.236.1 is one /22 above 185.156.232.0/22 and is not in any
	// embedded range.
	addr := netip.MustParseAddr("185.156.236.1")
	if got := ProviderForIP(addr); got == "keycdn" {
		t.Errorf("ProviderForIP(185.156.236.1) = keycdn, want non-keycdn")
	}
}

func TestProviderByDNS_KeyCDN(t *testing.T) {
	cases := map[string]string{
		"mypull.kxcdn.com":  "keycdn",
		"assets.keycdn.com": "keycdn",
	}
	for host, want := range cases {
		got, _ := providerByDNS(host)
		if got != want {
			t.Errorf("providerByDNS(%s) = %q, want %q", host, got, want)
		}
	}
}

func TestProviderByDNS_KeyCDN_Negative(t *testing.T) {
	// A lookalike that is not a KeyCDN suffix must not match.
	if got, _ := providerByDNS("kxcdn.com.evil.example"); got == "keycdn" {
		t.Errorf("providerByDNS(kxcdn.com.evil.example) = keycdn, want non-keycdn")
	}
}

func TestClassifyHeaders_KeyCDN(t *testing.T) {
	t.Run("server-keycdn-engine", func(t *testing.T) {
		h := http.Header{"Server": []string{"keycdn-engine"}}
		if got := classifyHeaders(h); got != "keycdn" {
			t.Errorf("classifyHeaders with server keycdn-engine = %q, want keycdn", got)
		}
	})
	t.Run("x-edge-location", func(t *testing.T) {
		h := http.Header{}
		h.Set("X-Edge-Location", "uskc")
		if got := classifyHeaders(h); got != "keycdn" {
			t.Errorf("classifyHeaders with x-edge-location = %q, want keycdn", got)
		}
	})
	t.Run("x-pull", func(t *testing.T) {
		h := http.Header{}
		h.Set("X-Pull", "HIT")
		if got := classifyHeaders(h); got != "keycdn" {
			t.Errorf("classifyHeaders with x-pull = %q, want keycdn", got)
		}
	})
	t.Run("x-cdn-keycdn", func(t *testing.T) {
		h := http.Header{}
		h.Set("X-CDN", "KeyCDN")
		if got := classifyHeaders(h); got != "keycdn" {
			t.Errorf("classifyHeaders with x-cdn KeyCDN = %q, want keycdn", got)
		}
	})
	t.Run("negative-no-keycdn-marker", func(t *testing.T) {
		h := http.Header{"Server": []string{"nginx"}}
		if got := classifyHeaders(h); got == "keycdn" {
			t.Errorf("classifyHeaders with plain nginx = keycdn, want non-keycdn")
		}
	})
	t.Run("collectHeaderSignals", func(t *testing.T) {
		h := http.Header{}
		h.Set("Server", "keycdn-engine")
		h.Set("X-Edge-Location", "uskc")
		h.Set("X-Pull", "HIT")
		h.Set("X-CDN", "KeyCDN")
		sigs := collectHeaderSignals(h)
		var sawServer, sawEdge, sawPull, sawXCDN bool
		for _, s := range sigs {
			switch s {
			case "header server: keycdn-engine (keycdn)":
				sawServer = true
			case "header x-edge-location present (keycdn)":
				sawEdge = true
			case "header x-pull present (keycdn)":
				sawPull = true
			case "header x-cdn mentions keycdn":
				sawXCDN = true
			}
		}
		if !sawServer || !sawEdge || !sawPull || !sawXCDN {
			t.Errorf("expected keycdn signals, got %v", sigs)
		}
	})
}
