package techniques

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// greyNoisePayload is a GNQL success payload. 104.16.0.5 is a Cloudflare edge
// IP and must be filtered. 203.0.113.50 appears twice (rDNS match + plain
// org-only match on a different metadata shape) to exercise dedup. The empty
// IP entry and the malformed-IP entry are skipped.
const greyNoisePayload = `{
  "complete": true,
  "count": 5,
  "data": [
    {"ip": "203.0.113.50", "metadata": {"rdns": "origin.example.test", "organization": "Example Inc"}},
    {"ip": "203.0.113.51", "metadata": {"rdns": "direct.example.test", "organization": "Example Inc"}},
    {"ip": "203.0.113.50", "metadata": {"rdns": "", "organization": "Example Inc"}},
    {"ip": "203.0.113.52", "metadata": {"rdns": "", "organization": "Example Inc"}},
    {"ip": "104.16.0.5",   "metadata": {"rdns": "edge.cdn.cloudflare.net", "organization": "Example Inc"}},
    {"ip": "",             "metadata": {"rdns": "blank", "organization": ""}},
    {"ip": "not-an-ip",    "metadata": {"rdns": "x", "organization": "y"}}
  ],
  "message": "ok"
}`

func greyNoiseKeys() APIKeys { return APIKeys{GreyNoiseKey: "gn-tok"} }

func TestGreyNoise_MissingKey(t *testing.T) {
	if _, err := (greyNoiseTechnique{}).Run(context.Background(), "x", RunOptions{}); !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("no creds: want ErrMissingAPIKey, got %v", err)
	}
}

func TestGreyNoise_Happy(t *testing.T) {
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.greynoise.io/": func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("key") != "gn-tok" {
				t.Errorf("key header: got %q", req.Header.Get("key"))
			}
			q := req.URL.Query().Get("query")
			if !strings.Contains(q, "example.test") {
				t.Errorf("query missing target: %q", q)
			}
			if !strings.Contains(q, "metadata.rdns") || !strings.Contains(q, "metadata.organization") {
				t.Errorf("query missing GNQL fields: %q", q)
			}
			return stubResponse(200, greyNoisePayload), nil
		},
	})
	out, err := (greyNoiseTechnique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    greyNoiseKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("want 3 non-CDN deduped IPs (cloudflare and bad IPs filtered), got %d: %+v", len(out), out)
	}
	gotIPs := map[string]string{}
	for _, c := range out {
		gotIPs[c.IP] = c.Evidence
		if !strings.Contains(c.Evidence, "GreyNoise") || !strings.Contains(c.Evidence, "example.test") {
			t.Errorf("evidence: %q", c.Evidence)
		}
	}
	if _, ok := gotIPs["203.0.113.50"]; !ok {
		t.Errorf("expected 203.0.113.50, got %v", gotIPs)
	}
	if !strings.Contains(gotIPs["203.0.113.50"], "rDNS origin.example.test") {
		t.Errorf("203.0.113.50 should prefer rDNS evidence, got %q", gotIPs["203.0.113.50"])
	}
	if !strings.Contains(gotIPs["203.0.113.52"], `org "Example Inc"`) {
		t.Errorf("203.0.113.52 should use org evidence, got %q", gotIPs["203.0.113.52"])
	}
	if _, ok := gotIPs["203.0.113.51"]; !ok {
		t.Errorf("missing 203.0.113.51")
	}
	if len(rt.calls) != 1 {
		t.Errorf("want one HTTP call (single page, complete=true), got %d", len(rt.calls))
	}
}

func TestGreyNoise_Pagination(t *testing.T) {
	page := 0
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.greynoise.io/": func(req *http.Request) (*http.Response, error) {
			page++
			scroll := req.URL.Query().Get("scroll")
			switch page {
			case 1:
				if scroll != "" {
					t.Errorf("page 1 scroll: want empty, got %q", scroll)
				}
				return stubResponse(200, `{"complete":false,"count":2,"data":[{"ip":"203.0.113.10","metadata":{"rdns":"a.example.test","organization":"X"}}],"scroll":"cursor-1","message":"ok"}`), nil
			case 2:
				if scroll != "cursor-1" {
					t.Errorf("page 2 scroll: want cursor-1, got %q", scroll)
				}
				return stubResponse(200, `{"complete":true,"count":2,"data":[{"ip":"203.0.113.11","metadata":{"rdns":"b.example.test","organization":"X"}}],"message":"ok"}`), nil
			}
			t.Errorf("unexpected page %d", page)
			return stubResponse(500, ""), nil
		},
	})
	out, err := (greyNoiseTechnique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    greyNoiseKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 IPs across pages, got %d", len(out))
	}
	if len(rt.calls) != 2 {
		t.Errorf("want 2 calls, got %d", len(rt.calls))
	}
}

func TestGreyNoise_EmptyData(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.greynoise.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"complete":true,"count":0,"data":[],"message":"ok"}`), nil
		},
	})
	out, err := (greyNoiseTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    greyNoiseKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want zero candidates for empty data, got %v", out)
	}
}

func TestGreyNoise_401_IsMissingKey(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.greynoise.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(401, ""), nil
		},
	})
	_, err := (greyNoiseTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    greyNoiseKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("401 should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestGreyNoise_402_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.greynoise.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(402, ""), nil
		},
	})
	_, err := (greyNoiseTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    greyNoiseKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("402 (Community plan, GNQL is paid) should produce ErrTierInsufficient, got %v", err)
	}
}

func TestGreyNoise_403_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.greynoise.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(403, ""), nil
		},
	})
	_, err := (greyNoiseTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    greyNoiseKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("403 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestGreyNoise_429_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.greynoise.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(429, ""), nil
		},
	})
	_, err := (greyNoiseTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    greyNoiseKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("429 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestGreyNoise_QuotaEnvelope_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.greynoise.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"complete":true,"count":0,"data":[],"message":"This feature is not enabled for your plan, please upgrade"}`), nil
		},
	})
	_, err := (greyNoiseTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    greyNoiseKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("quota/plan envelope should map to ErrTierInsufficient, got %v", err)
	}
}

func TestGreyNoise_BadKeyEnvelope_IsMissingKey(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.greynoise.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"complete":true,"count":0,"data":[],"error":"Invalid API key"}`), nil
		},
	})
	_, err := (greyNoiseTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    greyNoiseKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("invalid-key envelope should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestGreyNoise_OKMessageEmpty_NotError(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.greynoise.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"complete":true,"count":0,"data":[],"message":"ok"}`), nil
		},
	})
	out, err := (greyNoiseTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    greyNoiseKeys(),
	})
	if err != nil {
		t.Fatalf("ok+empty data should not error, got %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want empty, got %v", out)
	}
}

func TestGreyNoise_GenericError(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.greynoise.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"complete":false,"count":0,"data":[],"message":"something unexpected"}`), nil
		},
	})
	_, err := (greyNoiseTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    greyNoiseKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for error envelope")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("generic error should not be classified, got %v", err)
	}
}

func TestGreyNoise_5xx_IsHardError(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.greynoise.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(500, ""), nil
		},
	})
	_, err := (greyNoiseTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    greyNoiseKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for 500 status")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("500 should not be classified as tier/key error, got %v", err)
	}
}

func TestGreyNoise_MalformedJSON(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.greynoise.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{garbage`), nil
		},
	})
	_, err := (greyNoiseTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    greyNoiseKeys(),
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestGreyNoiseTechnique_Metadata(t *testing.T) {
	g := greyNoiseTechnique{}
	if g.Name() != "greynoise_asset" || g.Tier() != TierPassive || !g.RequiresAPIKey() || g.DefaultWeight() != 0.65 {
		t.Errorf("metadata wrong: %+v", g)
	}
}

func TestIsGreyNoiseTierError(t *testing.T) {
	for _, m := range []string{"monthly quota reached", "rate limit exceeded", "please upgrade your plan", "subscription required", "no permission", "payment required", "this feature is not enabled"} {
		if !isGreyNoiseTierError(m) {
			t.Errorf("expected tier error for %q", m)
		}
	}
	if isGreyNoiseTierError("internal server error") {
		t.Errorf("did not expect tier error for generic message")
	}
}

func TestIsGreyNoiseKeyError(t *testing.T) {
	for _, m := range []string{"Invalid API key", "unauthorized request", "invalid token", "missing api key"} {
		if !isGreyNoiseKeyError(m) {
			t.Errorf("expected key error for %q", m)
		}
	}
	if isGreyNoiseKeyError("monthly quota reached") {
		t.Errorf("did not expect key error for quota message")
	}
}

func TestIsGreyNoiseOKMessage(t *testing.T) {
	for _, m := range []string{"ok", "OK", "success", "no results found"} {
		if !isGreyNoiseOKMessage(m) {
			t.Errorf("expected OK for %q", m)
		}
	}
	if isGreyNoiseOKMessage("Invalid API key") {
		t.Errorf("did not expect OK for error message")
	}
}
