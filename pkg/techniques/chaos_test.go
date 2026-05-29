package techniques

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// chaosPayload is a /dns/{domain}/subdomains success payload. The labels are
// bare (apex-relative) as Chaos returns them. "alias" and "origin" resolve to
// the same IP to exercise dedup; "edge" resolves to a Cloudflare IP that must
// be filtered; "@" is the apex; "missing" does not resolve (NXDOMAIN) and is
// skipped.
const chaosPayload = `{
  "domain": "example.test",
  "subdomains": ["origin", "direct", "alias", "edge", "@", "missing"],
  "count": 6
}`

func chaosKeys() APIKeys { return APIKeys{ChaosKey: "pdcp-tok"} }

// chaosResolver wires the fake DNS answers the happy-path test depends on.
func chaosResolver() *fakeResolver {
	fr := newFakeResolver()
	fr.A["origin.example.test"] = []string{"203.0.113.50"}
	fr.A["direct.example.test"] = []string{"203.0.113.51"}
	fr.A["alias.example.test"] = []string{"203.0.113.50"} // dup of origin
	fr.A["edge.example.test"] = []string{"104.16.0.5"}    // Cloudflare → filtered
	fr.A["example.test"] = []string{"203.0.113.52"}       // apex
	// "missing.example.test" intentionally absent → NXDOMAIN, skipped.
	return fr
}

func TestChaos_MissingKey(t *testing.T) {
	if _, err := (chaosTechnique{}).Run(context.Background(), "x", RunOptions{}); !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("no creds: want ErrMissingAPIKey, got %v", err)
	}
}

func TestChaos_Happy(t *testing.T) {
	withFakeResolver(t, chaosResolver())
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://dns.projectdiscovery.io/": func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("Authorization") != "pdcp-tok" {
				t.Errorf("Authorization header: got %q", req.Header.Get("Authorization"))
			}
			if !strings.Contains(req.URL.Path, "example.test") {
				t.Errorf("path missing domain: %q", req.URL.Path)
			}
			if !strings.Contains(req.URL.Path, "/subdomains") {
				t.Errorf("path missing /subdomains: %q", req.URL.Path)
			}
			return stubResponse(200, chaosPayload), nil
		},
	})
	out, err := (chaosTechnique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    chaosKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// origin/alias collapse to 203.0.113.50, direct=.51, apex=.52; edge is
	// Cloudflare (filtered); missing does not resolve. Expect 3 unique IPs.
	if len(out) != 3 {
		t.Fatalf("want 3 non-CDN deduped IPs, got %d: %+v", len(out), out)
	}
	gotIPs := map[string]bool{}
	for _, c := range out {
		gotIPs[c.IP] = true
		if !strings.Contains(c.Evidence, "Chaos") || !strings.Contains(c.Evidence, "example.test") {
			t.Errorf("evidence: %q", c.Evidence)
		}
	}
	if !gotIPs["203.0.113.50"] || !gotIPs["203.0.113.51"] || !gotIPs["203.0.113.52"] {
		t.Errorf("expected 203.0.113.50/51/52, got %v", gotIPs)
	}
	if gotIPs["104.16.0.5"] {
		t.Errorf("Cloudflare edge IP should have been filtered")
	}
	// The subdomains endpoint returns the full list in one envelope, so the
	// technique makes exactly one HTTP call.
	if len(rt.calls) != 1 {
		t.Errorf("want one HTTP call, got %d", len(rt.calls))
	}
}

func TestChaos_EmptyList_IsEmpty(t *testing.T) {
	withFakeResolver(t, newFakeResolver())
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://dns.projectdiscovery.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"domain":"x","subdomains":[],"count":0}`), nil
		},
	})
	out, err := (chaosTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    chaosKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want zero candidates for empty list, got %v", out)
	}
}

func TestChaos_401_IsMissingKey(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://dns.projectdiscovery.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(401, ""), nil
		},
	})
	_, err := (chaosTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    chaosKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("401 should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestChaos_403_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://dns.projectdiscovery.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(403, ""), nil
		},
	})
	_, err := (chaosTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    chaosKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("403 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestChaos_429_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://dns.projectdiscovery.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(429, ""), nil
		},
	})
	_, err := (chaosTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    chaosKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("429 (allowance) should produce ErrTierInsufficient, got %v", err)
	}
}

func TestChaos_QuotaEnvelope_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://dns.projectdiscovery.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"message":"You have reached your quota, please upgrade your plan"}`), nil
		},
	})
	_, err := (chaosTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    chaosKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("quota envelope should map to ErrTierInsufficient, got %v", err)
	}
}

func TestChaos_BadKeyEnvelope_IsMissingKey(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://dns.projectdiscovery.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"error":"invalid api key"}`), nil
		},
	})
	_, err := (chaosTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    chaosKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("invalid-key envelope should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestChaos_GenericError(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://dns.projectdiscovery.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"message":"something unexpected"}`), nil
		},
	})
	_, err := (chaosTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    chaosKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for error envelope")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("generic error should not be classified, got %v", err)
	}
}

func TestChaos_5xx_IsHardError(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://dns.projectdiscovery.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(500, ""), nil
		},
	})
	_, err := (chaosTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    chaosKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for 500 status")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("500 should not be classified as tier/key error, got %v", err)
	}
}

func TestChaos_MalformedJSON(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://dns.projectdiscovery.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{garbage`), nil
		},
	})
	_, err := (chaosTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    chaosKeys(),
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestChaosTechnique_Metadata(t *testing.T) {
	c := chaosTechnique{}
	if c.Name() != "chaos_asset" || c.Tier() != TierPassive || !c.RequiresAPIKey() || c.DefaultWeight() != 0.66 {
		t.Errorf("metadata wrong: %+v", c)
	}
}

func TestChaosHosts(t *testing.T) {
	got := chaosHosts(
		[]string{"origin", "WWW", "@", "", "dev.", "already.example.test", "example.test"},
		"example.test",
	)
	want := map[string]bool{
		"origin.example.test":  true,
		"www.example.test":     true,
		"example.test":         true, // from "@" and bare apex
		"dev.example.test":     true,
		"already.example.test": true,
	}
	if len(got) != len(want) {
		t.Fatalf("chaosHosts len = %d (%v), want %d", len(got), got, len(want))
	}
	for _, h := range got {
		if !want[h] {
			t.Errorf("unexpected host %q", h)
		}
	}
	// Empty apex yields nothing.
	if h := chaosHosts([]string{"a", "b"}, ""); len(h) != 0 {
		t.Errorf("empty apex should yield no hosts, got %v", h)
	}
}

func TestChaos_ResolveCap(t *testing.T) {
	// Build a payload with more than chaosMaxResolve labels, each resolving to
	// a unique IP. The cap must bound the number resolved.
	withFakeResolver(t, func() *fakeResolver {
		fr := newFakeResolver()
		var sb strings.Builder
		sb.WriteString(`{"domain":"example.test","subdomains":[`)
		for i := 0; i < chaosMaxResolve+50; i++ {
			if i > 0 {
				sb.WriteString(",")
			}
			label := "h" + itoa(i)
			sb.WriteString(`"` + label + `"`)
			fr.A[label+".example.test"] = []string{"203.0." + itoa(i/256%256) + "." + itoa(i%256)}
		}
		sb.WriteString(`]}`)
		capPayload = sb.String()
		return fr
	}())
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://dns.projectdiscovery.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, capPayload), nil
		},
	})
	out, err := (chaosTechnique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    chaosKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) > chaosMaxResolve {
		t.Fatalf("resolve cap not honored: got %d candidates, cap is %d", len(out), chaosMaxResolve)
	}
}

// capPayload is set by TestChaos_ResolveCap before the stub fires.
var capPayload string

// itoa is a tiny strconv.Itoa stand-in to keep the test import list minimal.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
