package techniques

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// onyphePage is a /api/v2/search/datascan payload mirroring Onyphe's
// documented success envelope. 104.16.0.5 is a Cloudflare edge IP and must
// be filtered. 203.0.113.50 appears twice to exercise dedup. The hit with
// an empty `ip` but a populated `host` array (carrying an IP literal)
// exercises the ip→host fallback. `error:0` is the canonical success
// marker.
const onyphePage = `{
  "error": 0,
  "status": "ok",
  "total": 5,
  "page": 1,
  "max_page": 1,
  "results": [
    {"ip": "203.0.113.50"},
    {"ip": "104.16.0.5"},
    {"ip": "203.0.113.51"},
    {"ip": "203.0.113.50"},
    {"ip": "", "host": ["203.0.113.52"]}
  ]
}`

func onypheKeys() APIKeys { return APIKeys{OnypheKey: "oy-tok"} }

func TestOnyphe_MissingKey(t *testing.T) {
	if _, err := (onypheCertTechnique{}).Run(context.Background(), "x", RunOptions{}); !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("no creds: want ErrMissingAPIKey, got %v", err)
	}
}

func TestOnyphe_Happy(t *testing.T) {
	withStubFingerprint(t, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", nil)
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.onyphe.io/": func(req *http.Request) (*http.Response, error) {
			if got := req.Header.Get("Authorization"); got != "bearer oy-tok" {
				t.Errorf("Authorization header: got %q", got)
			}
			qv := req.URL.Query().Get("q")
			if !strings.Contains(qv, "category:datascan") {
				t.Errorf("query missing category gate: %q", qv)
			}
			if !strings.Contains(qv, "tls.fingerprint.sha256") {
				t.Errorf("query missing cert field: %q", qv)
			}
			if !strings.Contains(qv, "deadbeef") {
				t.Errorf("query missing fingerprint: %q", qv)
			}
			return stubResponse(200, onyphePage), nil
		},
	})
	out, err := (onypheCertTechnique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    onypheKeys(),
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
		if !strings.Contains(c.Evidence, "Onyphe") || !strings.Contains(c.Evidence, "sha256:") {
			t.Errorf("evidence: %q", c.Evidence)
		}
	}
	if !gotIPs["203.0.113.50"] || !gotIPs["203.0.113.51"] || !gotIPs["203.0.113.52"] {
		t.Errorf("expected 203.0.113.50/51/52, got %v", gotIPs)
	}
	// A 5-result page is shorter than the 100-result page ceiling, and
	// max_page=1 also stops the loop, so paging ends after one call.
	if len(rt.calls) != 1 {
		t.Errorf("want one HTTP call, got %d", len(rt.calls))
	}
}

func TestOnyphe_EmptyResults_IsEmpty(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.onyphe.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"error":0,"status":"ok","total":0,"page":1,"max_page":1,"results":[]}`), nil
		},
	})
	out, err := (onypheCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    onypheKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want zero candidates, got %v", out)
	}
}

func TestOnyphe_HostStringScalar(t *testing.T) {
	// Some Onyphe payloads emit `host` as a bare string instead of an
	// array. The custom unmarshaler must tolerate that.
	withStubFingerprint(t, "fp", nil)
	body := `{"error":0,"results":[{"ip":"","host":"203.0.113.77"}]}`
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.onyphe.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, body), nil
		},
	})
	out, err := (onypheCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    onypheKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 || out[0].IP != "203.0.113.77" {
		t.Fatalf("scalar host fallback: %+v", out)
	}
}

func TestOnyphe_HostNonIP_Skipped(t *testing.T) {
	// When `host` carries a hostname (not an IP literal), the technique
	// skips it — resolving hostnames belongs to the engine, not here.
	withStubFingerprint(t, "fp", nil)
	body := `{"error":0,"results":[{"ip":"","host":["origin.example.test"]}]}`
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.onyphe.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, body), nil
		},
	})
	out, err := (onypheCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    onypheKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("hostname in host field should not emit a candidate, got %v", out)
	}
}

func TestOnyphe_401_IsMissingKey(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.onyphe.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(401, ""), nil
		},
	})
	_, err := (onypheCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    onypheKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("401 should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestOnyphe_403_IsTierInsufficient(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.onyphe.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(403, ""), nil
		},
	})
	_, err := (onypheCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    onypheKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("403 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestOnyphe_429_IsTierInsufficient(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.onyphe.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(429, ""), nil
		},
	})
	_, err := (onypheCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    onypheKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("429 (monthly allowance) should produce ErrTierInsufficient, got %v", err)
	}
}

func TestOnyphe_QuotaEnvelope_IsTierInsufficient(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.onyphe.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"error":429,"status":"nok","text":"Rate limit exceeded, please upgrade your plan"}`), nil
		},
	})
	_, err := (onypheCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    onypheKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("quota envelope should map to ErrTierInsufficient, got %v", err)
	}
}

func TestOnyphe_BadKeyEnvelope_IsMissingKey(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.onyphe.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"error":401,"status":"nok","text":"Invalid API key"}`), nil
		},
	})
	_, err := (onypheCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    onypheKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("invalid-key envelope should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestOnyphe_GenericError(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.onyphe.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"error":1,"text":"something unexpected"}`), nil
		},
	})
	_, err := (onypheCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    onypheKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for non-zero error envelope")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("generic error should not be classified, got %v", err)
	}
}

func TestOnyphe_5xx_IsHardError(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.onyphe.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(500, ""), nil
		},
	})
	_, err := (onypheCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    onypheKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for 500 status")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("500 should not be classified as tier/key error, got %v", err)
	}
}

func TestOnyphe_MalformedJSON(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.onyphe.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{garbage`), nil
		},
	})
	_, err := (onypheCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    onypheKeys(),
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestOnyphe_FingerprintError(t *testing.T) {
	withStubFingerprint(t, "", errors.New("dial failed"))
	hc, _ := stubClient(nil)
	_, err := (onypheCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    onypheKeys(),
	})
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("want fingerprint error, got %v", err)
	}
}

func TestOnyphe_Pagination(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	// Build a full first page (onyphePageSize results) that also reports
	// max_page=2 — both signals would cue a second fetch. The short second
	// page (one result) ends paging.
	var fullPage strings.Builder
	fullPage.WriteString(`{"error":0,"status":"ok","total":101,"page":1,"max_page":2,"results":[`)
	for i := 0; i < onyphePageSize; i++ {
		if i > 0 {
			fullPage.WriteByte(',')
		}
		// 198.51.100.0/24 has 256 addresses — enough for a 100-result page
		// — and is a TEST-NET documentation range (not CDN).
		fmt.Fprintf(&fullPage, `{"ip":"198.51.100.%d"}`, i)
	}
	fullPage.WriteString(`]}`)
	page2 := `{"error":0,"status":"ok","total":101,"page":2,"max_page":2,"results":[{"ip":"203.0.113.200"}]}`
	calls := 0
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.onyphe.io/": func(req *http.Request) (*http.Response, error) {
			calls++
			if req.URL.Query().Get("page") == "2" {
				return stubResponse(200, page2), nil
			}
			return stubResponse(200, fullPage.String()), nil
		},
	})
	out, err := (onypheCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    onypheKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if calls != 2 {
		t.Errorf("want two HTTP calls for paginated result, got %d", calls)
	}
	if len(out) != onyphePageSize+1 {
		t.Fatalf("want %d candidates across pages, got %d", onyphePageSize+1, len(out))
	}
}

func TestOnyphe_MaxPageHonored(t *testing.T) {
	// When the API reports max_page=1 but the page happens to be full, the
	// loop must still terminate — Onyphe's `max_page` is the authoritative
	// stop condition.
	withStubFingerprint(t, "fp", nil)
	var fullPage strings.Builder
	fullPage.WriteString(`{"error":0,"max_page":1,"results":[`)
	for i := 0; i < onyphePageSize; i++ {
		if i > 0 {
			fullPage.WriteByte(',')
		}
		fmt.Fprintf(&fullPage, `{"ip":"198.51.100.%d"}`, i)
	}
	fullPage.WriteString(`]}`)
	calls := 0
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.onyphe.io/": func(*http.Request) (*http.Response, error) {
			calls++
			return stubResponse(200, fullPage.String()), nil
		},
	})
	_, err := (onypheCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    onypheKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if calls != 1 {
		t.Errorf("max_page=1 should stop after one call, got %d", calls)
	}
}

func TestOnypheTechnique_Metadata(t *testing.T) {
	o := onypheCertTechnique{}
	if o.Name() != "onyphe_cert" || o.Tier() != TierPassive || !o.RequiresAPIKey() || o.DefaultWeight() != 0.69 {
		t.Errorf("metadata wrong: %+v", o)
	}
}

func TestIsOnypheTierError(t *testing.T) {
	for _, m := range []string{"daily quota reached", "rate limit exceeded", "please upgrade your plan", "subscription required", "no permission", "forbidden"} {
		if !isOnypheTierError(m) {
			t.Errorf("expected tier error for %q", m)
		}
	}
	if isOnypheTierError("internal server error") {
		t.Errorf("did not expect tier error for generic message")
	}
}

func TestIsOnypheKeyError(t *testing.T) {
	for _, m := range []string{"Invalid API key", "Invalid APIKEY", "unauthorized request", "invalid token", "missing api key"} {
		if !isOnypheKeyError(m) {
			t.Errorf("expected key error for %q", m)
		}
	}
	if isOnypheKeyError("daily quota reached") {
		t.Errorf("did not expect key error for quota message")
	}
}

func TestTrimJSON(t *testing.T) {
	cases := map[string]string{
		"":               "",
		"   ":            "",
		"abc":            "abc",
		" \t\nabc \r":    "abc",
		"\n\n[1,2]\n\n":  "[1,2]",
		"trailing only ": "trailing only",
	}
	for in, want := range cases {
		got := string(trimJSON([]byte(in)))
		if got != want {
			t.Errorf("trimJSON(%q) = %q, want %q", in, got, want)
		}
	}
}
