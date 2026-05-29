package techniques

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// leakIXPage is a /search payload (the documented bare-array success shape).
// 104.16.0.5 is a Cloudflare edge IP and must be filtered. 203.0.113.50
// appears twice to exercise dedup. The host with an empty ip but a populated
// host field exercises the ip→host fallback.
const leakIXPage = `[
  {"ip": "203.0.113.50"},
  {"ip": "104.16.0.5"},
  {"ip": "203.0.113.51"},
  {"ip": "203.0.113.50"},
  {"ip": "", "host": "203.0.113.52"}
]`

func leakIXKeys() APIKeys { return APIKeys{LeakIXKey: "lx-tok"} }

func TestLeakIX_MissingKey(t *testing.T) {
	if _, err := (leakIXCertTechnique{}).Run(context.Background(), "x", RunOptions{}); !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("no creds: want ErrMissingAPIKey, got %v", err)
	}
}

func TestLeakIX_Happy(t *testing.T) {
	withStubFingerprintSHA1(t, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", nil)
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://leakix.net/": func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("api-key") != "lx-tok" {
				t.Errorf("api-key header: got %q", req.Header.Get("api-key"))
			}
			if req.URL.Query().Get("scope") != "service" {
				t.Errorf("scope: got %q", req.URL.Query().Get("scope"))
			}
			qv := req.URL.Query().Get("q")
			if !strings.Contains(qv, "ssl.certificate.fingerprint") {
				t.Errorf("query missing cert field: %q", qv)
			}
			if !strings.Contains(qv, "deadbeef") {
				t.Errorf("query missing fingerprint: %q", qv)
			}
			return stubResponse(200, leakIXPage), nil
		},
	})
	out, err := (leakIXCertTechnique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    leakIXKeys(),
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
		if !strings.Contains(c.Evidence, "LeakIX") || !strings.Contains(c.Evidence, "sha1:") {
			t.Errorf("evidence: %q", c.Evidence)
		}
	}
	if !gotIPs["203.0.113.50"] || !gotIPs["203.0.113.51"] || !gotIPs["203.0.113.52"] {
		t.Errorf("expected 203.0.113.50/51/52, got %v", gotIPs)
	}
	// A 5-event page is shorter than the 100 page ceiling, so paging stops
	// after one call.
	if len(rt.calls) != 1 {
		t.Errorf("want one HTTP call, got %d", len(rt.calls))
	}
}

func TestLeakIX_NullBody_IsEmpty(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://leakix.net/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `null`), nil
		},
	})
	out, err := (leakIXCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    leakIXKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want zero candidates for null body, got %v", out)
	}
}

func TestLeakIX_EmptyArray_IsEmpty(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://leakix.net/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `[]`), nil
		},
	})
	out, err := (leakIXCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    leakIXKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want zero candidates, got %v", out)
	}
}

func TestLeakIX_401_IsMissingKey(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://leakix.net/": func(*http.Request) (*http.Response, error) {
			return stubResponse(401, ""), nil
		},
	})
	_, err := (leakIXCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    leakIXKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("401 should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestLeakIX_403_IsTierInsufficient(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://leakix.net/": func(*http.Request) (*http.Response, error) {
			return stubResponse(403, ""), nil
		},
	})
	_, err := (leakIXCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    leakIXKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("403 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestLeakIX_429_IsTierInsufficient(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://leakix.net/": func(*http.Request) (*http.Response, error) {
			return stubResponse(429, ""), nil
		},
	})
	_, err := (leakIXCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    leakIXKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("429 (daily allowance) should produce ErrTierInsufficient, got %v", err)
	}
}

func TestLeakIX_QuotaEnvelope_IsTierInsufficient(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://leakix.net/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"error":"Too Many Requests","message":"You have reached your daily rate limit, please upgrade your plan"}`), nil
		},
	})
	_, err := (leakIXCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    leakIXKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("quota envelope should map to ErrTierInsufficient, got %v", err)
	}
}

func TestLeakIX_BadKeyEnvelope_IsMissingKey(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://leakix.net/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"error":"Unauthorized","message":"Invalid API key"}`), nil
		},
	})
	_, err := (leakIXCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    leakIXKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("invalid-key envelope should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestLeakIX_GenericError(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://leakix.net/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"message":"something unexpected"}`), nil
		},
	})
	_, err := (leakIXCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    leakIXKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for error envelope")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("generic error should not be classified, got %v", err)
	}
}

func TestLeakIX_5xx_IsHardError(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://leakix.net/": func(*http.Request) (*http.Response, error) {
			return stubResponse(500, ""), nil
		},
	})
	_, err := (leakIXCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    leakIXKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for 500 status")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("500 should not be classified as tier/key error, got %v", err)
	}
}

func TestLeakIX_MalformedJSON(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://leakix.net/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `[garbage`), nil
		},
	})
	_, err := (leakIXCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    leakIXKeys(),
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestLeakIX_FingerprintError(t *testing.T) {
	withStubFingerprintSHA1(t, "", errors.New("dial failed"))
	hc, _ := stubClient(nil)
	_, err := (leakIXCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    leakIXKeys(),
	})
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("want fingerprint error, got %v", err)
	}
}

func TestLeakIX_Pagination(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	// A full first page (leakIXPageSize events) forces a second fetch; the
	// short second page ends paging.
	var fullPage strings.Builder
	fullPage.WriteByte('[')
	for i := 0; i < leakIXPageSize; i++ {
		if i > 0 {
			fullPage.WriteByte(',')
		}
		// 198.51.100.0/24 has 256 addresses — enough for a 100-event page —
		// and is a documentation range (not CDN), so none are filtered.
		fmt.Fprintf(&fullPage, `{"ip":"198.51.100.%d"}`, i)
	}
	fullPage.WriteByte(']')
	page2 := `[{"ip":"203.0.113.200"}]`
	calls := 0
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://leakix.net/": func(req *http.Request) (*http.Response, error) {
			calls++
			if req.URL.Query().Get("page") == "1" {
				return stubResponse(200, page2), nil
			}
			return stubResponse(200, fullPage.String()), nil
		},
	})
	out, err := (leakIXCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    leakIXKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if calls != 2 {
		t.Errorf("want two HTTP calls for paginated result, got %d", calls)
	}
	if len(out) != leakIXPageSize+1 {
		t.Fatalf("want %d candidates across pages, got %d", leakIXPageSize+1, len(out))
	}
}

func TestLeakIXTechnique_Metadata(t *testing.T) {
	l := leakIXCertTechnique{}
	if l.Name() != "leakix_cert" || l.Tier() != TierPassive || !l.RequiresAPIKey() || l.DefaultWeight() != 0.71 {
		t.Errorf("metadata wrong: %+v", l)
	}
}

func TestIsLeakIXTierError(t *testing.T) {
	for _, m := range []string{"daily quota reached", "rate limit exceeded", "please upgrade your plan", "subscription required", "no permission"} {
		if !isLeakIXTierError(m) {
			t.Errorf("expected tier error for %q", m)
		}
	}
	if isLeakIXTierError("internal server error") {
		t.Errorf("did not expect tier error for generic message")
	}
}

func TestIsLeakIXKeyError(t *testing.T) {
	for _, m := range []string{"Invalid API key", "unauthorized request", "invalid token", "missing api key"} {
		if !isLeakIXKeyError(m) {
			t.Errorf("expected key error for %q", m)
		}
	}
	if isLeakIXKeyError("daily quota reached") {
		t.Errorf("did not expect key error for quota message")
	}
}
