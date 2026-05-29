package techniques

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// criminalIPPage is a banner-search payload. 104.16.0.5 is a Cloudflare edge
// IP and must be filtered. 203.0.113.50 appears twice to exercise dedup.
const criminalIPPage = `{
  "status": 200,
  "data": {
    "result": [
      {"ip_address": "203.0.113.50"},
      {"ip_address": "104.16.0.5"},
      {"ip_address": "203.0.113.51"},
      {"ip_address": "203.0.113.50"}
    ]
  }
}`

func criminalIPKeys() APIKeys { return APIKeys{CriminalIPKey: "cip-tok"} }

func TestCriminalIP_MissingKey(t *testing.T) {
	if _, err := (criminalIPAssetTechnique{}).Run(context.Background(), "x", RunOptions{}); !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("no creds: want ErrMissingAPIKey, got %v", err)
	}
}

func TestCriminalIP_Happy(t *testing.T) {
	withStubFingerprint(t, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", nil)
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.criminalip.io/": func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("x-api-key") != "cip-tok" {
				t.Errorf("x-api-key header: got %q", req.Header.Get("x-api-key"))
			}
			qv := req.URL.Query().Get("query")
			if !strings.Contains(qv, "certificate") {
				t.Errorf("query missing cert field: %q", qv)
			}
			if !strings.Contains(qv, "deadbeef") {
				t.Errorf("query missing fingerprint: %q", qv)
			}
			return stubResponse(200, criminalIPPage), nil
		},
	})
	out, err := (criminalIPAssetTechnique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    criminalIPKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 non-CDN deduped IPs (cloudflare filtered), got %d: %+v", len(out), out)
	}
	gotIPs := map[string]bool{}
	for _, c := range out {
		gotIPs[c.IP] = true
		if !strings.Contains(c.Evidence, "Criminal IP") || !strings.Contains(c.Evidence, "sha256:") {
			t.Errorf("evidence: %q", c.Evidence)
		}
	}
	if !gotIPs["203.0.113.50"] || !gotIPs["203.0.113.51"] {
		t.Errorf("expected both 203.0.113.50 and 203.0.113.51, got %v", gotIPs)
	}
	if len(rt.calls) != 1 {
		t.Errorf("want one HTTP call, got %d", len(rt.calls))
	}
}

func TestCriminalIP_EmptyResult(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.criminalip.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"status":200,"data":{"result":[]}}`), nil
		},
	})
	out, err := (criminalIPAssetTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    criminalIPKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want zero candidates, got %v", out)
	}
}

func TestCriminalIP_401_IsMissingKey(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.criminalip.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(401, ""), nil
		},
	})
	_, err := (criminalIPAssetTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    criminalIPKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("401 should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestCriminalIP_403_IsTierInsufficient(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.criminalip.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(403, ""), nil
		},
	})
	_, err := (criminalIPAssetTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    criminalIPKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("403 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestCriminalIP_429_IsTierInsufficient(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.criminalip.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(429, ""), nil
		},
	})
	_, err := (criminalIPAssetTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    criminalIPKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("429 (allowance) should produce ErrTierInsufficient, got %v", err)
	}
}

func TestCriminalIP_StatusEnvelope_403_IsTierInsufficient(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.criminalip.io/": func(*http.Request) (*http.Response, error) {
			// HTTP 200 with a 403 status field — Criminal IP's common shape.
			return stubResponse(200, `{"status":403,"message":"Forbidden"}`), nil
		},
	})
	_, err := (criminalIPAssetTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    criminalIPKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("status:403 envelope should map to ErrTierInsufficient, got %v", err)
	}
}

func TestCriminalIP_QuotaEnvelope_IsTierInsufficient(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.criminalip.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"status":406,"message":"Request limit exceeded, please upgrade your plan"}`), nil
		},
	})
	_, err := (criminalIPAssetTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    criminalIPKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("quota envelope should map to ErrTierInsufficient, got %v", err)
	}
}

func TestCriminalIP_BadKeyEnvelope_IsMissingKey(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.criminalip.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"status":401,"message":"Invalid API key"}`), nil
		},
	})
	_, err := (criminalIPAssetTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    criminalIPKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("invalid-key envelope should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestCriminalIP_GenericEnvelope(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.criminalip.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"status":500,"message":"something unexpected"}`), nil
		},
	})
	_, err := (criminalIPAssetTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    criminalIPKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for error envelope")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("generic error should not be classified, got %v", err)
	}
}

func TestCriminalIP_5xx_IsHardError(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.criminalip.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(500, ""), nil
		},
	})
	_, err := (criminalIPAssetTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    criminalIPKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for 500 status")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("500 should not be classified as tier/key error, got %v", err)
	}
}

func TestCriminalIP_MalformedJSON(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.criminalip.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{garbage`), nil
		},
	})
	_, err := (criminalIPAssetTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    criminalIPKeys(),
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestCriminalIP_FingerprintError(t *testing.T) {
	withStubFingerprint(t, "", errors.New("dial failed"))
	hc, _ := stubClient(nil)
	_, err := (criminalIPAssetTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    criminalIPKeys(),
	})
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("want fingerprint error, got %v", err)
	}
}

func TestCriminalIPTechnique_Metadata(t *testing.T) {
	n := criminalIPAssetTechnique{}
	if n.Name() != "criminalip_asset" || n.Tier() != TierPassive || !n.RequiresAPIKey() || n.DefaultWeight() != 0.70 {
		t.Errorf("metadata wrong: %+v", n)
	}
}
