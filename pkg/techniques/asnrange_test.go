package techniques

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

// withStubASNFetch swaps fetchASN and fetchPrefixes for the duration of a test.
func withStubASNFetch(t *testing.T, asnFn func(context.Context, netip.Addr, *http.Client) (int, error), prefFn func(context.Context, int, *http.Client) ([]string, error)) {
	t.Helper()
	prevASN := fetchASN
	prevPref := fetchPrefixes
	fetchASN = asnFn
	fetchPrefixes = prefFn
	t.Cleanup(func() {
		fetchASN = prevASN
		fetchPrefixes = prevPref
	})
}

// withStubASNProbeClient swaps the insecure client builder so ASN sweep probes
// route through the test's RoundTripper instead of real network connections.
func withStubASNProbeClient(t *testing.T, hc *http.Client) {
	t.Helper()
	prev := newHostHeaderInsecureClient
	newHostHeaderInsecureClient = func() *http.Client { return hc }
	t.Cleanup(func() { newHostHeaderInsecureClient = prev })
}

func TestAsnSweep_Metadata(t *testing.T) {
	a := asnSweepTechnique{}
	if a.Name() != "asn_sweep" {
		t.Errorf("Name = %q, want asn_sweep", a.Name())
	}
	if a.Tier() != TierActive {
		t.Errorf("Tier = %v, want TierActive", a.Tier())
	}
	if a.RequiresAPIKey() {
		t.Error("RequiresAPIKey should be false")
	}
	if a.DefaultWeight() != 0.70 {
		t.Errorf("DefaultWeight = %v, want 0.70", a.DefaultWeight())
	}
}

func TestAsnSweep_BGPViewIPLookupReturnsASN(t *testing.T) {
	// Verify the real BGPView IP parsing logic via the stub path.
	// We inject a known ASN and confirm it flows through to the prefix call.
	fr := newFakeResolver()
	fr.A["example.test"] = []string{"203.0.113.1"}
	withFakeResolver(t, fr)

	wantASN := 64500
	prefetchCalled := false

	withStubASNFetch(t,
		func(_ context.Context, ip netip.Addr, _ *http.Client) (int, error) {
			if ip.String() != "203.0.113.1" {
				t.Errorf("fetchASN: got IP %s, want 203.0.113.1", ip)
			}
			return wantASN, nil
		},
		func(_ context.Context, asn int, _ *http.Client) ([]string, error) {
			if asn != wantASN {
				t.Errorf("fetchPrefixes: got ASN %d, want %d", asn, wantASN)
			}
			prefetchCalled = true
			// Return an empty list — no IPs to probe.
			return []string{}, nil
		},
	)

	baselineBody := strings.Repeat("z", 300)
	rt := &hostHeaderStubRT{baselineBody: baselineBody, byHost: map[string]func(*http.Request) (*http.Response, error){}}
	hc := &http.Client{Transport: rt}
	withStubASNProbeClient(t, hc)

	out, err := asnSweepTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !prefetchCalled {
		t.Error("fetchPrefixes was not called")
	}
	if len(out) != 0 {
		t.Errorf("expected no candidates (empty prefix list), got %+v", out)
	}
}

func TestAsnSweep_BGPViewPrefixLookupReturnsPrefixes(t *testing.T) {
	// Verify that IPs from the returned prefix are probed.
	fr := newFakeResolver()
	fr.A["example.test"] = []string{"203.0.113.1"}
	withFakeResolver(t, fr)

	withStubASNFetch(t,
		func(_ context.Context, _ netip.Addr, _ *http.Client) (int, error) { return 64500, nil },
		func(_ context.Context, _ int, _ *http.Client) ([]string, error) {
			// Return a /30 prefix with 4 IPs — exactly one will match (203.0.113.4).
			return []string{"203.0.113.4/30"}, nil
		},
	)

	baselineBody := strings.Repeat("abc", 200)
	// asn_sweep probes the prefix IPs concurrently, so this counter is
	// incremented from multiple goroutines — use atomic to stay race-free.
	var probeCount atomic.Int64
	rt := &hostHeaderStubRT{
		baselineBody: baselineBody,
		byHost: map[string]func(*http.Request) (*http.Response, error){
			"203.0.113.4": func(req *http.Request) (*http.Response, error) {
				probeCount.Add(1)
				return stubResponse(200, baselineBody), nil
			},
			"203.0.113.5": func(_ *http.Request) (*http.Response, error) {
				probeCount.Add(1)
				return stubResponse(200, "different content"), nil
			},
			"203.0.113.6": func(_ *http.Request) (*http.Response, error) {
				probeCount.Add(1)
				return stubResponse(200, "different content"), nil
			},
			"203.0.113.7": func(_ *http.Request) (*http.Response, error) {
				probeCount.Add(1)
				return stubResponse(200, "different content"), nil
			},
		},
	}
	hc := &http.Client{Transport: rt}
	withStubASNProbeClient(t, hc)

	out, err := asnSweepTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// 203.0.113.4 should match (same body), others should not.
	if len(out) != 1 {
		t.Fatalf("expected 1 candidate, got %d: %+v", len(out), out)
	}
	if out[0].IP != "203.0.113.4" {
		t.Errorf("expected candidate 203.0.113.4, got %s", out[0].IP)
	}
	if !strings.Contains(out[0].Evidence, "asn_sweep") {
		t.Errorf("evidence missing asn_sweep prefix: %q", out[0].Evidence)
	}
	if !strings.Contains(out[0].Evidence, "AS64500") {
		t.Errorf("evidence missing AS number: %q", out[0].Evidence)
	}
}

func TestAsnSweep_ReservedIPsSkipped(t *testing.T) {
	// RFC1918 prefix — no IPs should be probed.
	fr := newFakeResolver()
	fr.A["example.test"] = []string{"203.0.113.1"}
	withFakeResolver(t, fr)

	withStubASNFetch(t,
		func(_ context.Context, _ netip.Addr, _ *http.Client) (int, error) { return 64500, nil },
		func(_ context.Context, _ int, _ *http.Client) ([]string, error) {
			return []string{"192.168.1.0/30"}, nil
		},
	)

	probed := false
	rt := &hostHeaderStubRT{
		baselineBody: "base",
		byHost: map[string]func(*http.Request) (*http.Response, error){
			"192.168.1.0": func(_ *http.Request) (*http.Response, error) {
				probed = true
				t.Error("RFC1918 IP must not be probed")
				return stubResponse(200, "base"), nil
			},
			"192.168.1.1": func(_ *http.Request) (*http.Response, error) {
				probed = true
				t.Error("RFC1918 IP must not be probed")
				return stubResponse(200, "base"), nil
			},
		},
	}
	hc := &http.Client{Transport: rt}
	withStubASNProbeClient(t, hc)

	out, err := asnSweepTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if probed {
		t.Error("reserved address was probed")
	}
	if len(out) != 0 {
		t.Errorf("expected no candidates from reserved range, got %+v", out)
	}
}

func TestAsnSweep_CDNIPsFiltered(t *testing.T) {
	// 104.16.0.0/12 is a Cloudflare range — IPs there must be dropped.
	fr := newFakeResolver()
	fr.A["example.test"] = []string{"203.0.113.1"}
	withFakeResolver(t, fr)

	withStubASNFetch(t,
		func(_ context.Context, _ netip.Addr, _ *http.Client) (int, error) { return 13335, nil },
		func(_ context.Context, _ int, _ *http.Client) ([]string, error) {
			// 104.16.0.0/30 is Cloudflare space.
			return []string{"104.16.0.0/30"}, nil
		},
	)

	probed := false
	body := strings.Repeat("x", 400)
	rt := &hostHeaderStubRT{
		baselineBody: body,
		byHost: map[string]func(*http.Request) (*http.Response, error){
			"104.16.0.0": func(_ *http.Request) (*http.Response, error) {
				probed = true
				return stubResponse(200, body), nil
			},
			"104.16.0.1": func(_ *http.Request) (*http.Response, error) {
				probed = true
				return stubResponse(200, body), nil
			},
		},
	}
	hc := &http.Client{Transport: rt}
	withStubASNProbeClient(t, hc)

	out, err := asnSweepTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if probed {
		t.Error("CDN IP was probed (should have been filtered)")
	}
	if len(out) != 0 {
		t.Errorf("expected no candidates from CDN range, got %+v", out)
	}
}

func TestAsnSweep_NonCDNIPBecomesCandidates(t *testing.T) {
	// Non-CDN, non-reserved IP with matching body must surface as a candidate.
	fr := newFakeResolver()
	fr.A["example.test"] = []string{"203.0.113.1"}
	withFakeResolver(t, fr)

	withStubASNFetch(t,
		func(_ context.Context, _ netip.Addr, _ *http.Client) (int, error) { return 64501, nil },
		func(_ context.Context, _ int, _ *http.Client) ([]string, error) {
			return []string{"198.51.100.0/30"}, nil
		},
	)

	body := strings.Repeat("hello-world", 50) // 550 bytes — above the 256 threshold
	rt := &hostHeaderStubRT{
		baselineBody: body,
		byHost: map[string]func(*http.Request) (*http.Response, error){
			"198.51.100.0": func(_ *http.Request) (*http.Response, error) {
				return stubResponse(200, body), nil
			},
			"198.51.100.1": func(_ *http.Request) (*http.Response, error) {
				return stubResponse(404, "not found"), nil
			},
			"198.51.100.2": func(_ *http.Request) (*http.Response, error) {
				return stubResponse(200, body), nil
			},
			"198.51.100.3": func(_ *http.Request) (*http.Response, error) {
				return stubResponse(200, "completely different"), nil
			},
		},
	}
	hc := &http.Client{Transport: rt}
	withStubASNProbeClient(t, hc)

	out, err := asnSweepTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// .0 and .2 serve the same body → both are candidates.
	if len(out) != 2 {
		t.Fatalf("expected 2 candidates (.0 and .2), got %d: %+v", len(out), out)
	}
	ipSet := map[string]bool{}
	for _, c := range out {
		ipSet[c.IP] = true
	}
	for _, want := range []string{"198.51.100.0", "198.51.100.2"} {
		if !ipSet[want] {
			t.Errorf("missing expected candidate %s", want)
		}
	}
}

func TestAsnSweep_ZeroASNReturnsNil(t *testing.T) {
	// BGPView returning ASN=0 should produce no candidates without error.
	fr := newFakeResolver()
	fr.A["example.test"] = []string{"203.0.113.1"}
	withFakeResolver(t, fr)

	withStubASNFetch(t,
		func(_ context.Context, _ netip.Addr, _ *http.Client) (int, error) { return 0, nil },
		func(_ context.Context, _ int, _ *http.Client) ([]string, error) {
			t.Error("fetchPrefixes must not be called when ASN is 0")
			return nil, nil
		},
	)

	rt := &hostHeaderStubRT{baselineBody: "x", byHost: map[string]func(*http.Request) (*http.Response, error){}}
	hc := &http.Client{Transport: rt}
	withStubASNProbeClient(t, hc)

	out, err := asnSweepTechnique{}.Run(context.Background(), "example.test", RunOptions{HTTPClient: hc})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected nil/empty, got %+v", out)
	}
}

func TestAsnSweep_DNSFailureReturnsError(t *testing.T) {
	fr := newFakeResolver()
	// example.test has no A record → LookupAddrs returns NXDOMAIN.
	withFakeResolver(t, fr)

	_, err := asnSweepTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if err == nil {
		t.Fatal("expected error on DNS failure, got nil")
	}
	if !strings.Contains(err.Error(), "asn_sweep") {
		t.Errorf("error should mention asn_sweep: %v", err)
	}
}

func TestIsReservedPrefix(t *testing.T) {
	tests := []struct {
		cidr     string
		reserved bool
	}{
		{"10.0.0.0/8", true},
		{"10.5.0.0/16", true},
		{"172.16.0.0/12", true},
		{"172.20.0.0/16", true},
		{"192.168.0.0/16", true},
		{"192.168.1.0/24", true},
		{"127.0.0.0/8", true},
		{"127.0.0.1/32", true},
		{"224.0.0.0/4", true},
		{"239.0.0.0/8", true},
		{"203.0.113.0/24", false},
		{"198.51.100.0/24", false},
		{"1.1.1.0/24", false},
	}
	for _, tc := range tests {
		p, err := netip.ParsePrefix(tc.cidr)
		if err != nil {
			t.Fatalf("parse %s: %v", tc.cidr, err)
		}
		if got := isReservedPrefix(p.Masked()); got != tc.reserved {
			t.Errorf("isReservedPrefix(%s) = %v, want %v", tc.cidr, got, tc.reserved)
		}
	}
}

func TestIsReservedAddr(t *testing.T) {
	reserved := []string{"10.0.0.1", "172.17.0.1", "192.168.1.1", "127.0.0.1", "224.0.0.1"}
	public := []string{"203.0.113.1", "198.51.100.1", "8.8.8.8"}
	for _, s := range reserved {
		a := netip.MustParseAddr(s)
		if !isReservedAddr(a) {
			t.Errorf("isReservedAddr(%s) = false, want true", s)
		}
	}
	for _, s := range public {
		a := netip.MustParseAddr(s)
		if isReservedAddr(a) {
			t.Errorf("isReservedAddr(%s) = true, want false", s)
		}
	}
}
