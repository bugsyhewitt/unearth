package techniques

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// zoomEyePayload is a /domain/search?type=1 success payload. 104.16.0.5 is a
// Cloudflare edge IP and must be filtered. 203.0.113.50 appears in two hosts
// to exercise dedup. The host with a bare-string ip exercises the
// string→array fallback. The empty-IP entry is skipped.
const zoomEyePayload = `{
  "status": 200,
  "total": 5,
  "list": [
    {"name": "origin.example.test", "ip": ["203.0.113.50", "104.16.0.5"]},
    {"name": "direct.example.test", "ip": ["203.0.113.51"]},
    {"name": "alias.example.test", "ip": ["203.0.113.50"]},
    {"name": "single.example.test", "ip": "203.0.113.52"},
    {"name": "blank.example.test", "ip": [""]}
  ]
}`

func zoomEyeKeys() APIKeys { return APIKeys{ZoomEyeKey: "ze-tok"} }

func TestZoomEye_MissingKey(t *testing.T) {
	if _, err := (zoomEyeTechnique{}).Run(context.Background(), "x", RunOptions{}); !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("no creds: want ErrMissingAPIKey, got %v", err)
	}
}

func TestZoomEye_Happy(t *testing.T) {
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.zoomeye.org/": func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("API-KEY") != "ze-tok" {
				t.Errorf("API-KEY header: got %q", req.Header.Get("API-KEY"))
			}
			if !strings.Contains(req.URL.RawQuery, "example.test") {
				t.Errorf("query missing domain: %q", req.URL.RawQuery)
			}
			if !strings.Contains(req.URL.Path, "/domain/search") {
				t.Errorf("path missing /domain/search: %q", req.URL.Path)
			}
			return stubResponse(200, zoomEyePayload), nil
		},
	})
	out, err := (zoomEyeTechnique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    zoomEyeKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("want 3 non-CDN deduped IPs (cloudflare filtered), got %d: %+v", len(out), out)
	}
	gotIPs := map[string]bool{}
	for _, c := range out {
		gotIPs[c.IP] = true
		if !strings.Contains(c.Evidence, "ZoomEye") || !strings.Contains(c.Evidence, "example.test") {
			t.Errorf("evidence: %q", c.Evidence)
		}
	}
	if !gotIPs["203.0.113.50"] || !gotIPs["203.0.113.51"] || !gotIPs["203.0.113.52"] {
		t.Errorf("expected 203.0.113.50/51/52, got %v", gotIPs)
	}
	// The domain-search endpoint returns the inventory in one envelope, so the
	// technique makes exactly one HTTP call.
	if len(rt.calls) != 1 {
		t.Errorf("want one HTTP call, got %d", len(rt.calls))
	}
}

func TestZoomEye_EmptyList_IsEmpty(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.zoomeye.org/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"status":200,"total":0,"list":[]}`), nil
		},
	})
	out, err := (zoomEyeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    zoomEyeKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want zero candidates for empty list, got %v", out)
	}
}

func TestZoomEye_401_IsMissingKey(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.zoomeye.org/": func(*http.Request) (*http.Response, error) {
			return stubResponse(401, ""), nil
		},
	})
	_, err := (zoomEyeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    zoomEyeKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("401 should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestZoomEye_403_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.zoomeye.org/": func(*http.Request) (*http.Response, error) {
			return stubResponse(403, ""), nil
		},
	})
	_, err := (zoomEyeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    zoomEyeKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("403 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestZoomEye_429_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.zoomeye.org/": func(*http.Request) (*http.Response, error) {
			return stubResponse(429, ""), nil
		},
	})
	_, err := (zoomEyeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    zoomEyeKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("429 (monthly allowance) should produce ErrTierInsufficient, got %v", err)
	}
}

func TestZoomEye_QuotaEnvelope_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.zoomeye.org/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"message":"You have reached your monthly quota, please upgrade your plan"}`), nil
		},
	})
	_, err := (zoomEyeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    zoomEyeKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("quota envelope should map to ErrTierInsufficient, got %v", err)
	}
}

func TestZoomEye_BadKeyEnvelope_IsMissingKey(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.zoomeye.org/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"error":"invalid api key"}`), nil
		},
	})
	_, err := (zoomEyeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    zoomEyeKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("invalid-key envelope should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestZoomEye_GenericError(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.zoomeye.org/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"message":"something unexpected"}`), nil
		},
	})
	_, err := (zoomEyeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    zoomEyeKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for error envelope")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("generic error should not be classified, got %v", err)
	}
}

func TestZoomEye_5xx_IsHardError(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.zoomeye.org/": func(*http.Request) (*http.Response, error) {
			return stubResponse(500, ""), nil
		},
	})
	_, err := (zoomEyeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    zoomEyeKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for 500 status")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("500 should not be classified as tier/key error, got %v", err)
	}
}

func TestZoomEye_MalformedJSON(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.zoomeye.org/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{garbage`), nil
		},
	})
	_, err := (zoomEyeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    zoomEyeKeys(),
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestZoomEyeTechnique_Metadata(t *testing.T) {
	z := zoomEyeTechnique{}
	if z.Name() != "zoomeye_asset" || z.Tier() != TierPassive || !z.RequiresAPIKey() || z.DefaultWeight() != 0.68 {
		t.Errorf("metadata wrong: %+v", z)
	}
}

func TestIsZoomEyeTierError(t *testing.T) {
	for _, m := range []string{"monthly quota reached", "rate limit exceeded", "please upgrade your plan", "subscription required", "no permission", "insufficient privileges"} {
		if !isZoomEyeTierError(m) {
			t.Errorf("expected tier error for %q", m)
		}
	}
	if isZoomEyeTierError("internal server error") {
		t.Errorf("did not expect tier error for generic message")
	}
}

func TestIsZoomEyeKeyError(t *testing.T) {
	for _, m := range []string{"invalid api key", "unauthorized request", "invalid token", "missing api key", "wrong key"} {
		if !isZoomEyeKeyError(m) {
			t.Errorf("expected key error for %q", m)
		}
	}
	if isZoomEyeKeyError("monthly quota reached") {
		t.Errorf("did not expect key error for quota message")
	}
}
