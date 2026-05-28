package techniques

import (
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// withFakeJARMProber swaps the package jarmProber for one that returns a
// fingerprint keyed by host (the host portion of host:port), restoring the real
// prober when the test ends.
func withFakeJARMProber(t *testing.T, byHost map[string]jarmProbeResult) {
	t.Helper()
	prev := jarmProber
	jarmProber = func(_ context.Context, hostport string) jarmProbeResult {
		host, _, err := net.SplitHostPort(hostport)
		if err != nil {
			return jarmProbeResult{err: err}
		}
		if r, ok := byHost[host]; ok {
			return r
		}
		// Unknown host → all-zero (no handshake).
		return jarmProbeResult{fingerprint: jarmEmptyFP}
	}
	t.Cleanup(func() { jarmProber = prev })
}

func seeds(ips ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ips))
	for _, s := range ips {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

const sampleFP = "07d14d16d21d21d07c42d43d000000aaffbbccddee0011223344556677889900"

func TestJARM_MatchingCandidateIsOrigin(t *testing.T) {
	withFakeJARMProber(t, map[string]jarmProbeResult{
		"example.test": {fingerprint: sampleFP}, // reference
		"203.0.113.10": {fingerprint: sampleFP}, // origin: same JARM
		"203.0.113.11": {fingerprint: "00abc" + sampleFP[5:]},
	})

	out, err := jarmTechnique{}.Run(context.Background(), "example.test", RunOptions{
		SeedIPs: seeds("203.0.113.10", "203.0.113.11"),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 matching candidate, got %d: %+v", len(out), out)
	}
	if out[0].IP != "203.0.113.10" {
		t.Errorf("want origin 203.0.113.10, got %s", out[0].IP)
	}
	if !strings.Contains(out[0].Evidence, "jarm_fingerprint") ||
		!strings.Contains(out[0].Evidence, sampleFP) {
		t.Errorf("evidence: %q", out[0].Evidence)
	}
	if out[0].Metadata["jarm"] != sampleFP {
		t.Errorf("metadata jarm = %v", out[0].Metadata["jarm"])
	}
}

func TestJARM_NoSeedsNoWork(t *testing.T) {
	// Prober must never be called when there are no seed IPs.
	called := false
	prev := jarmProber
	jarmProber = func(context.Context, string) jarmProbeResult {
		called = true
		return jarmProbeResult{fingerprint: jarmEmptyFP}
	}
	t.Cleanup(func() { jarmProber = prev })

	out, err := jarmTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if err != nil || len(out) != 0 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if called {
		t.Error("prober called despite no seed IPs")
	}
}

func TestJARM_UnreachableReferenceNoMatch(t *testing.T) {
	// Target never completes a handshake → all-zero reference → no candidates.
	withFakeJARMProber(t, map[string]jarmProbeResult{
		"example.test": {fingerprint: jarmEmptyFP},
		"203.0.113.10": {fingerprint: sampleFP},
	})

	out, err := jarmTechnique{}.Run(context.Background(), "example.test", RunOptions{
		SeedIPs: seeds("203.0.113.10"),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("no usable reference must yield no candidates, got %+v", out)
	}
}

func TestJARM_CandidateMatchingCDNSignatureRejected(t *testing.T) {
	// Reference equals an origin JARM, but the candidate presents a known CDN
	// signature — it is an edge node, not the origin, and must be dropped.
	var cdnSig string
	for sig := range knownCDNJARM {
		cdnSig = sig
		break
	}
	withFakeJARMProber(t, map[string]jarmProbeResult{
		"example.test": {fingerprint: cdnSig}, // reference happens to be CDN
		"203.0.113.10": {fingerprint: cdnSig}, // candidate also CDN-shaped
	})

	out, err := jarmTechnique{}.Run(context.Background(), "example.test", RunOptions{
		SeedIPs: seeds("203.0.113.10"),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("candidate matching a CDN signature must be rejected, got %+v", out)
	}
}

func TestJARM_NonMatchingCandidateDropped(t *testing.T) {
	withFakeJARMProber(t, map[string]jarmProbeResult{
		"example.test": {fingerprint: sampleFP},
		"203.0.113.10": {fingerprint: "11d11d11d11d11d11c11d11d000000aaffbbccddee0011223344556677889900"},
	})
	out, _ := jarmTechnique{}.Run(context.Background(), "example.test", RunOptions{
		SeedIPs: seeds("203.0.113.10"),
	})
	if len(out) != 0 {
		t.Errorf("mismatched JARM must not produce a candidate, got %+v", out)
	}
}

func TestJARM_CDNSeedIPSkipped(t *testing.T) {
	// 104.16.0.5 is a Cloudflare range IP; it must be skipped before probing.
	probed := map[string]bool{}
	prev := jarmProber
	jarmProber = func(_ context.Context, hostport string) jarmProbeResult {
		host, _, _ := net.SplitHostPort(hostport)
		probed[host] = true
		if host == "example.test" {
			return jarmProbeResult{fingerprint: sampleFP}
		}
		return jarmProbeResult{fingerprint: sampleFP}
	}
	t.Cleanup(func() { jarmProber = prev })

	out, _ := jarmTechnique{}.Run(context.Background(), "example.test", RunOptions{
		SeedIPs: seeds("104.16.0.5", "203.0.113.10"),
	})
	if probed["104.16.0.5"] {
		t.Error("CDN seed IP must not be probed")
	}
	// The non-CDN seed matched the reference → it is the origin.
	if len(out) != 1 || out[0].IP != "203.0.113.10" {
		t.Errorf("want only non-CDN origin, got %+v", out)
	}
}

func TestJARMTechnique_Metadata(t *testing.T) {
	j := jarmTechnique{}
	if j.Name() != "jarm_fingerprint" {
		t.Errorf("name = %q", j.Name())
	}
	if j.Tier() != TierActive {
		t.Errorf("tier = %v, want active", j.Tier())
	}
	if j.RequiresAPIKey() {
		t.Error("jarm must not require an API key")
	}
	if j.DefaultWeight() != 0.70 {
		t.Errorf("weight = %v, want 0.70", j.DefaultWeight())
	}
	if !j.ConsumesCandidates() {
		t.Error("jarm must be a phase-2 candidate consumer")
	}
}

func TestJARMTechnique_Registered(t *testing.T) {
	tq, ok := Get("jarm_fingerprint")
	if !ok {
		t.Fatal("jarm_fingerprint not registered")
	}
	if _, ok := tq.(jarmTechnique); !ok {
		t.Errorf("registered type = %T", tq)
	}
}

// ── pure-algorithm unit tests (no network) ──────────────────────────────────

func TestJARMHash_AllEmptyIsZero(t *testing.T) {
	if got := jarmHash([]string{"", "", "", "", "", "", "", "", "", ""}); got != jarmEmptyFP {
		t.Errorf("all-empty responses must hash to the zero fingerprint, got %q", got)
	}
}

func TestJARMHash_DeterministicAnd62Chars(t *testing.T) {
	resp := make([]string, 10)
	for i := range resp {
		resp[i] = "1301|0017-002b-0033"
	}
	a := jarmHash(resp)
	b := jarmHash(resp)
	if a != b {
		t.Errorf("jarmHash not deterministic: %q vs %q", a, b)
	}
	if len(a) != 62 {
		t.Errorf("fingerprint length = %d, want 62 (%q)", len(a), a)
	}
	if a == jarmEmptyFP {
		t.Error("non-empty responses must not hash to the zero fingerprint")
	}
}

func TestJARMHash_DifferentExtensionsDiffer(t *testing.T) {
	base := make([]string, 10)
	alt := make([]string, 10)
	for i := range base {
		base[i] = "1301|0017-0033"
		alt[i] = "1301|0017-002b" // different extension ordering
	}
	if jarmHash(base) == jarmHash(alt) {
		t.Error("different extension descriptors must produce different fingerprints")
	}
}

func TestCipherIndex(t *testing.T) {
	if got := cipherIndex(""); got != "000" {
		t.Errorf("empty cipher index = %q, want 000", got)
	}
	// First cipher in the table is 0016 → 1-based index 1 → base36 "1" → "001".
	first := hex.EncodeToString(jarmCipherTable[0])
	if got := cipherIndex(first); got != "001" {
		t.Errorf("first cipher index = %q, want 001", got)
	}
	if got := cipherIndex("ffff"); got != "0a0" {
		t.Errorf("unknown cipher index = %q, want 0a0", got)
	}
}

func TestPad3(t *testing.T) {
	cases := map[string]string{"": "000", "1": "001", "ab": "0ab", "abcd": "bcd"}
	for in, want := range cases {
		if got := pad3(in); got != want {
			t.Errorf("pad3(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReadServerHello_RejectsAlert(t *testing.T) {
	alert := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}
	if got := readServerHello(alert); got != "" {
		t.Errorf("alert record must yield empty descriptor, got %q", got)
	}
}

func TestReadServerHello_ParsesCipher(t *testing.T) {
	// Hand-build a minimal ServerHello selecting cipher 0x1301 with no
	// extensions. Record: 16 0303 LEN | handshake: 02 LEN3 0303 random(32)
	// sessLen(0) cipher(1301) compression(00) extLen(0000).
	var hs []byte
	hs = append(hs, 0x03, 0x03)          // server version
	hs = append(hs, make([]byte, 32)...) // random
	hs = append(hs, 0x00)                // session id length 0
	hs = append(hs, 0x13, 0x01)          // cipher
	hs = append(hs, 0x00)                // compression
	hs = append(hs, 0x00, 0x00)          // extensions length 0
	body := append([]byte{0x02}, uint24(len(hs))...)
	body = append(body, hs...)
	rec := append([]byte{0x16, 0x03, 0x03}, uint16b(len(body))...)
	rec = append(rec, body...)

	got := readServerHello(rec)
	cipher, _ := splitResponse(got)
	if cipher != "1301" {
		t.Errorf("parsed cipher = %q, want 1301 (full=%q)", cipher, got)
	}
}

func TestBuildClientHello_WellFormedRecord(t *testing.T) {
	spec := jarmProbeSpecs("example.test")[0]
	hello := buildClientHello("example.test", spec)
	if len(hello) < 45 {
		t.Fatalf("client hello too short: %d bytes", len(hello))
	}
	if hello[0] != 0x16 {
		t.Errorf("record type = %#x, want 0x16 (handshake)", hello[0])
	}
	// Record version is the spec's TLS version (1.2 → 0303).
	if hello[1] != 0x03 || hello[2] != 0x03 {
		t.Errorf("record version = %#x%#x, want 0303", hello[1], hello[2])
	}
	// Declared record length must match the remaining bytes.
	recLen := int(hello[3])<<8 | int(hello[4])
	if recLen != len(hello)-5 {
		t.Errorf("record length field = %d, but %d bytes follow", recLen, len(hello)-5)
	}
	// Handshake type is ClientHello.
	if hello[5] != 0x01 {
		t.Errorf("handshake type = %#x, want 0x01 (ClientHello)", hello[5])
	}
}

func TestOrderCiphers(t *testing.T) {
	list := [][]byte{{0x01}, {0x02}, {0x03}, {0x04}}
	if got := orderCiphers(list, "FORWARD"); got[0][0] != 0x01 || got[3][0] != 0x04 {
		t.Errorf("FORWARD changed order: %v", got)
	}
	if got := orderCiphers(list, "REVERSE"); got[0][0] != 0x04 || got[3][0] != 0x01 {
		t.Errorf("REVERSE wrong: %v", got)
	}
	if got := orderCiphers(list, "BOTTOM_HALF"); len(got) != 2 || got[0][0] != 0x03 {
		t.Errorf("BOTTOM_HALF wrong: %v", got)
	}
	if got := orderCiphers(list, "TOP_HALF"); len(got) != 2 || got[0][0] != 0x01 {
		t.Errorf("TOP_HALF wrong: %v", got)
	}
	if got := orderCiphers(list, "MIDDLE_OUT"); len(got) != 4 {
		t.Errorf("MIDDLE_OUT length = %d, want 4: %v", len(got), got)
	}
}

func TestJARMProbeSpecs_TenVariants(t *testing.T) {
	specs := jarmProbeSpecs("example.test")
	if len(specs) != 10 {
		t.Fatalf("JARM must send exactly 10 probes, got %d", len(specs))
	}
}
