package techniques

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// otxPayload is a /api/v1/indicators/domain/{d}/passive_dns success payload.
// origin and direct resolve to distinct non-CDN IPs; alias is a duplicate of
// origin's IP under a different hostname (must dedup); edge resolves to a
// Cloudflare IP that must be filtered by the CDN registry; bogus has an
// unparseable address and must be skipped; cname is a non-A record-type and
// must be skipped even though its address would otherwise parse.
const otxPayload = `{
  "passive_dns": [
    {"address":"203.0.113.70","hostname":"origin.example.test","record_type":"A","first":"2024-01-02T03:04:05","last":"2025-01-02T03:04:05"},
    {"address":"203.0.113.71","hostname":"direct.example.test","record_type":"A","first":"2024-02-02T03:04:05","last":"2025-02-02T03:04:05"},
    {"address":"203.0.113.70","hostname":"alias.example.test","record_type":"A","first":"2024-03-02T03:04:05","last":"2025-03-02T03:04:05"},
    {"address":"104.16.0.5","hostname":"edge.example.test","record_type":"A","first":"2024-04-02T03:04:05","last":"2025-04-02T03:04:05"},
    {"address":"not-an-ip","hostname":"bogus.example.test","record_type":"A","first":"2024-05-02T03:04:05","last":"2025-05-02T03:04:05"},
    {"address":"cname.target.test","hostname":"cname.example.test","record_type":"CNAME","first":"2024-06-02T03:04:05","last":"2025-06-02T03:04:05"}
  ],
  "count": 6
}`

func otxKeys() APIKeys { return APIKeys{OTXKey: "otx-tok"} }

// TestOTX_NoKey_StillRuns confirms the documented "key-optional" contract:
// otx_passivedns is the only OSINT backend that does not return
// ErrMissingAPIKey when no credentials are present. With no key on the
// request the technique must still issue the call and process the response.
func TestOTX_NoKey_StillRuns(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://otx.alienvault.com/": func(req *http.Request) (*http.Response, error) {
			if got := req.Header.Get("X-OTX-API-KEY"); got != "" {
				t.Errorf("X-OTX-API-KEY should be unset with no key, got %q", got)
			}
			return stubResponse(200, otxPayload), nil
		},
	})
	out, err := (otxPassiveDNSTechnique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
	})
	if err != nil {
		t.Fatalf("Run (no key): %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("expected candidates from anonymous run, got 0")
	}
}

func TestOTX_Happy(t *testing.T) {
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://otx.alienvault.com/": func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("X-OTX-API-KEY") != "otx-tok" {
				t.Errorf("X-OTX-API-KEY header: got %q", req.Header.Get("X-OTX-API-KEY"))
			}
			if !strings.Contains(req.URL.Path, "/api/v1/indicators/domain/example.test/passive_dns") {
				t.Errorf("unexpected URL path: %q", req.URL.Path)
			}
			return stubResponse(200, otxPayload), nil
		},
	})
	out, err := (otxPassiveDNSTechnique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    otxKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// origin and alias collapse to 203.0.113.70, direct=.71; edge is
	// Cloudflare (filtered); bogus has invalid address; cname is non-A
	// record-type (skipped). Expect 2 unique non-CDN IPs.
	if len(out) != 2 {
		t.Fatalf("want 2 non-CDN deduped IPs, got %d: %+v", len(out), out)
	}
	gotIPs := map[string]bool{}
	for _, c := range out {
		gotIPs[c.IP] = true
		if !strings.Contains(c.Evidence, "AlienVault OTX") || !strings.Contains(c.Evidence, "example.test") {
			t.Errorf("evidence: %q", c.Evidence)
		}
	}
	if !gotIPs["203.0.113.70"] || !gotIPs["203.0.113.71"] {
		t.Errorf("expected 203.0.113.70 and .71, got %v", gotIPs)
	}
	if gotIPs["104.16.0.5"] {
		t.Errorf("Cloudflare edge IP should have been filtered")
	}
	if len(rt.calls) != 1 {
		t.Errorf("want one HTTP call, got %d", len(rt.calls))
	}
}

func TestOTX_EmptyList_IsEmpty(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://otx.alienvault.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"passive_dns":[],"count":0}`), nil
		},
	})
	out, err := (otxPassiveDNSTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    otxKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want zero candidates for empty list, got %v", out)
	}
}

// TestOTX_404_IsEmptySuccess confirms that an unknown indicator (OTX has no
// passive-DNS data for the target apex) is treated as a clean empty result,
// not a hard error — same as virustotal_passivedns.
func TestOTX_404_IsEmptySuccess(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://otx.alienvault.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(404, ""), nil
		},
	})
	out, err := (otxPassiveDNSTechnique{}).Run(context.Background(), "unknown.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    otxKeys(),
	})
	if err != nil {
		t.Fatalf("404 should be empty success, got error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("404 should yield zero candidates, got %v", out)
	}
}

func TestOTX_401_IsMissingKey(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://otx.alienvault.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(401, ""), nil
		},
	})
	_, err := (otxPassiveDNSTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    otxKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("401 should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestOTX_403_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://otx.alienvault.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(403, ""), nil
		},
	})
	_, err := (otxPassiveDNSTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    otxKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("403 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestOTX_429_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://otx.alienvault.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(429, ""), nil
		},
	})
	_, err := (otxPassiveDNSTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    otxKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("429 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestOTX_QuotaEnvelope_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://otx.alienvault.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(400, `{"detail":"Request was throttled. Expected available in 60 seconds; upgrade for higher quota."}`), nil
		},
	})
	_, err := (otxPassiveDNSTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    otxKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("throttle envelope should map to ErrTierInsufficient, got %v", err)
	}
}

func TestOTX_AuthEnvelope_IsMissingKey(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://otx.alienvault.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(400, `{"detail":"Invalid API key supplied; check your credentials."}`), nil
		},
	})
	_, err := (otxPassiveDNSTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    otxKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("auth envelope should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestOTX_GenericError(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://otx.alienvault.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"passive_dns":[],"detail":"weird unclassified problem"}`), nil
		},
	})
	_, err := (otxPassiveDNSTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    otxKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for unclassified envelope")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("generic error should not be classified, got %v", err)
	}
}

func TestOTX_5xx_IsHardError(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://otx.alienvault.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(500, ""), nil
		},
	})
	_, err := (otxPassiveDNSTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    otxKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for 500 status")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("500 should not be classified as tier/key error, got %v", err)
	}
}

func TestOTX_MalformedJSON(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://otx.alienvault.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{garbage`), nil
		},
	})
	_, err := (otxPassiveDNSTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    otxKeys(),
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestOTX_EmptyTarget(t *testing.T) {
	_, err := (otxPassiveDNSTechnique{}).Run(context.Background(), "  ", RunOptions{
		APIKeys: otxKeys(),
	})
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

func TestOTX_Metadata(t *testing.T) {
	c := otxPassiveDNSTechnique{}
	if c.Name() != "otx_passivedns" {
		t.Errorf("Name = %q, want %q", c.Name(), "otx_passivedns")
	}
	if c.Tier() != TierPassive {
		t.Errorf("Tier = %v, want TierPassive", c.Tier())
	}
	if c.RequiresAPIKey() {
		t.Errorf("RequiresAPIKey = true, want false (OTX key is optional)")
	}
	if c.DefaultWeight() != 0.64 {
		t.Errorf("DefaultWeight = %v, want 0.64", c.DefaultWeight())
	}
}
