package techniques

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestTXTLeak_ApexBareIP(t *testing.T) {
	fr := newFakeResolver()
	fr.TXT = map[string][]string{
		"example.test": {"origin-host=203.0.113.10 region=us"},
	}
	withFakeResolver(t, fr)

	out, err := txtLeakTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 || out[0].IP != "203.0.113.10" {
		t.Fatalf("want apex origin 203.0.113.10, got %+v", out)
	}
	if !strings.Contains(out[0].Evidence, "TXT record") ||
		!strings.Contains(out[0].Evidence, "example.test") {
		t.Errorf("evidence: %q", out[0].Evidence)
	}
}

func TestTXTLeak_UnderscoreNameLeak(t *testing.T) {
	fr := newFakeResolver()
	fr.TXT = map[string][]string{
		"_origin.example.test": {"198.51.100.20"},
	}
	withFakeResolver(t, fr)

	out, _ := txtLeakTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if len(out) != 1 || out[0].IP != "198.51.100.20" {
		t.Fatalf("want _origin leak 198.51.100.20, got %+v", out)
	}
	if !strings.Contains(out[0].Evidence, "_origin.example.test") {
		t.Errorf("evidence should name the underscore record: %q", out[0].Evidence)
	}
}

func TestTXTLeak_SkipsSPFRecord(t *testing.T) {
	// An SPF record carrying an ip4 mechanism is spf_mx's responsibility; this
	// technique must not also surface that IP, or the engine would show the
	// same address twice with conflicting evidence.
	fr := newFakeResolver()
	fr.TXT = map[string][]string{
		"example.test": {"v=spf1 ip4:203.0.113.10 -all"},
	}
	withFakeResolver(t, fr)

	out, _ := txtLeakTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if len(out) != 0 {
		t.Fatalf("SPF records must be skipped, got %+v", out)
	}
}

func TestTXTLeak_FiltersPrivateAndBroadcast(t *testing.T) {
	fr := newFakeResolver()
	fr.TXT = map[string][]string{
		"example.test": {
			"a=10.0.0.1 b=192.168.1.1 c=172.16.5.5 " +
				"d=127.0.0.1 e=255.255.255.255 f=169.254.1.1",
		},
	}
	withFakeResolver(t, fr)

	out, _ := txtLeakTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if len(out) != 0 {
		t.Fatalf("private/loopback/broadcast/link-local must be filtered, got %+v", out)
	}
}

func TestTXTLeak_FiltersCDNIP(t *testing.T) {
	fr := newFakeResolver()
	fr.TXT = map[string][]string{
		// cdnFrontIP (104.16.0.5) is inside Cloudflare 104.16.0.0/13.
		"example.test": {"front=" + cdnFrontIP + " origin=203.0.113.77"},
	}
	withFakeResolver(t, fr)

	out, _ := txtLeakTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if len(out) != 1 || out[0].IP != "203.0.113.77" {
		t.Fatalf("CDN IP must be filtered, only origin kept, got %+v", out)
	}
}

func TestTXTLeak_IPv6Leak(t *testing.T) {
	fr := newFakeResolver()
	fr.TXT = map[string][]string{
		// 2001:db8::/32 is the documentation range — global unicast, not in
		// any CDN snapshot.
		"_backend.example.test": {"v6=2001:db8::1234"},
	}
	withFakeResolver(t, fr)

	out, _ := txtLeakTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if len(out) != 1 || out[0].IP != "2001:db8::1234" {
		t.Fatalf("want IPv6 origin 2001:db8::1234, got %+v", out)
	}
}

func TestTXTLeak_DedupsAcrossNames(t *testing.T) {
	fr := newFakeResolver()
	fr.TXT = map[string][]string{
		"example.test":         {"origin=203.0.113.10"},
		"_origin.example.test": {"203.0.113.10"}, // same IP, different name
	}
	withFakeResolver(t, fr)

	out, _ := txtLeakTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if len(out) != 1 {
		t.Fatalf("duplicate IP across names should appear once, got %+v", out)
	}
}

func TestTXTLeak_ToleratesNXDomainAndEmpty(t *testing.T) {
	// No TXT records anywhere: every probe name returns empty/NXDOMAIN. The
	// technique must return cleanly with no candidates and no error.
	fr := newFakeResolver()
	withFakeResolver(t, fr)

	out, err := txtLeakTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if err != nil || len(out) != 0 {
		t.Fatalf("empty/NXDOMAIN: out=%+v err=%v", out, err)
	}
}

func TestTXTLeak_NoFalsePositiveOnPlainText(t *testing.T) {
	// A version-looking token must not be misread as an IPv4 address, and a
	// short hex pair must not be misread as IPv6.
	fr := newFakeResolver()
	fr.TXT = map[string][]string{
		"example.test": {"google-site-verification=abc123 ver 1.2.3 tag=ab:cd"},
	}
	withFakeResolver(t, fr)

	out, _ := txtLeakTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if len(out) != 0 {
		t.Fatalf("plain text must not yield IP candidates, got %+v", out)
	}
}

func TestTXTLeakTechnique_Metadata(t *testing.T) {
	tt := txtLeakTechnique{}
	if tt.Name() != "dns_txt_leak" || tt.Tier() != TierPassive ||
		tt.RequiresAPIKey() || tt.DefaultWeight() != 0.55 {
		t.Errorf("metadata wrong: %+v", tt)
	}
}

func TestTXTLeak_EmptyTarget(t *testing.T) {
	out, err := txtLeakTechnique{}.Run(context.Background(), "  ", RunOptions{})
	if err != nil || len(out) != 0 {
		t.Errorf("empty target: out=%+v err=%v", out, err)
	}
}

func TestPublicOriginAddr(t *testing.T) {
	cases := map[string]bool{
		"203.0.113.10":    true,  // TEST-NET-3, global unicast
		"8.8.8.8":         true,  // global unicast
		"2001:db8::1":     true,  // documentation global unicast
		"10.0.0.1":        false, // RFC1918
		"192.168.0.1":     false, // RFC1918
		"172.16.0.1":      false, // RFC1918
		"127.0.0.1":       false, // loopback
		"::1":             false, // loopback
		"169.254.0.1":     false, // link-local
		"fe80::1":         false, // link-local
		"224.0.0.1":       false, // multicast
		"255.255.255.255": false, // broadcast
		"0.0.0.0":         false, // unspecified
		"fc00::1":         false, // unique-local
	}
	for s, want := range cases {
		a := netip.MustParseAddr(s)
		if got := publicOriginAddr(a); got != want {
			t.Errorf("publicOriginAddr(%s) = %v, want %v", s, got, want)
		}
	}
}
