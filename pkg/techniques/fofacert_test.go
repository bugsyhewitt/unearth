package techniques

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// fofaPage is a single-field (ip) FOFA response: one row per host, each a
// one-element array. 104.16.0.5 is a Cloudflare edge IP and must be filtered.
const fofaPage = `{
  "error": false,
  "mode": "extended",
  "page": 1,
  "size": 3,
  "results": [
    ["203.0.113.50"],
    ["104.16.0.5"],
    ["203.0.113.51:443"]
  ]
}`

func fofaKeys() APIKeys { return APIKeys{FOFAEmail: "a@b.test", FOFAKey: "fofa-tok"} }

func TestFOFA_MissingKey(t *testing.T) {
	// Both absent.
	if _, err := (fofaCertTechnique{}).Run(context.Background(), "x", RunOptions{}); !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("no creds: want ErrMissingAPIKey, got %v", err)
	}
	// Email present, key absent — still missing.
	_, err := (fofaCertTechnique{}).Run(context.Background(), "x", RunOptions{
		APIKeys: APIKeys{FOFAEmail: "a@b.test"},
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("partial creds: want ErrMissingAPIKey, got %v", err)
	}
}

func TestFOFA_Happy(t *testing.T) {
	withStubFingerprint(t, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", nil)
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://fofa.info/": func(req *http.Request) (*http.Response, error) {
			q := req.URL.Query()
			if q.Get("email") != "a@b.test" {
				t.Errorf("email param: got %q", q.Get("email"))
			}
			if q.Get("key") != "fofa-tok" {
				t.Errorf("key param: got %q", q.Get("key"))
			}
			if q.Get("fields") != "ip" {
				t.Errorf("fields param: got %q", q.Get("fields"))
			}
			dec, derr := base64.StdEncoding.DecodeString(q.Get("qbase64"))
			if derr != nil {
				t.Errorf("qbase64 not base64: %v", derr)
			}
			if !strings.Contains(string(dec), `cert="`) {
				t.Errorf("decoded query missing cert filter: %q", dec)
			}
			if !strings.Contains(string(dec), "deadbeef") {
				t.Errorf("decoded query missing fingerprint: %q", dec)
			}
			return stubResponse(200, fofaPage), nil
		},
	})
	out, err := (fofaCertTechnique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    fofaKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 non-CDN IPs (cloudflare filtered), got %d: %+v", len(out), out)
	}
	// The ip:port row must have been stripped to a bare IP.
	gotIPs := map[string]bool{}
	for _, c := range out {
		gotIPs[c.IP] = true
		if !strings.Contains(c.Evidence, "FOFA") || !strings.Contains(c.Evidence, "sha256:") {
			t.Errorf("evidence: %q", c.Evidence)
		}
	}
	if !gotIPs["203.0.113.50"] || !gotIPs["203.0.113.51"] {
		t.Errorf("expected both 203.0.113.50 and 203.0.113.51 (port stripped), got %v", gotIPs)
	}
	if len(rt.calls) != 1 {
		t.Errorf("want one HTTP call, got %d", len(rt.calls))
	}
}

func TestFOFA_EmptyResult(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://fofa.info/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"error":false,"results":[]}`), nil
		},
	})
	out, err := (fofaCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    fofaKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want zero candidates, got %v", out)
	}
}

func TestFOFA_QuotaError_IsTierInsufficient(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://fofa.info/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"error":true,"errmsg":"[820000] Your account F point quota is insufficient, please upgrade"}`), nil
		},
	})
	_, err := (fofaCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    fofaKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("quota error should map to ErrTierInsufficient, got %v", err)
	}
}

func TestFOFA_BadCreds_IsMissingKey(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://fofa.info/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"error":true,"errmsg":"[-700] account invalid"}`), nil
		},
	})
	_, err := (fofaCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    fofaKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("account-invalid should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestFOFA_403_IsTierInsufficient(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://fofa.info/": func(*http.Request) (*http.Response, error) {
			return stubResponse(403, ""), nil
		},
	})
	_, err := (fofaCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    fofaKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("403 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestFOFA_GenericError(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://fofa.info/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"error":true,"errmsg":"something unexpected"}`), nil
		},
	})
	_, err := (fofaCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    fofaKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for error:true")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("generic error should not be classified, got %v", err)
	}
}

func TestFOFA_MalformedJSON(t *testing.T) {
	withStubFingerprint(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://fofa.info/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{garbage`), nil
		},
	})
	_, err := (fofaCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    fofaKeys(),
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestFOFA_FingerprintError(t *testing.T) {
	withStubFingerprint(t, "", errors.New("dial failed"))
	hc, _ := stubClient(nil)
	_, err := (fofaCertTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    fofaKeys(),
	})
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("want fingerprint error, got %v", err)
	}
}

func TestFOFATechnique_Metadata(t *testing.T) {
	f := fofaCertTechnique{}
	if f.Name() != "fofa_cert" || f.Tier() != TierPassive || !f.RequiresAPIKey() || f.DefaultWeight() != 0.80 {
		t.Errorf("metadata wrong: %+v", f)
	}
}

func TestStripFOFAPort(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":           "1.2.3.4",
		"1.2.3.4:443":       "1.2.3.4",
		"2001:db8::1":       "2001:db8::1",
		"[2001:db8::1]:443": "2001:db8::1",
		"  1.2.3.4:80  ":    "1.2.3.4", // trimmed by caller, but ensure no panic if passed raw
	}
	for in, want := range cases {
		got := stripFOFAPort(strings.TrimSpace(in))
		if got != want {
			t.Errorf("stripFOFAPort(%q) = %q, want %q", in, got, want)
		}
	}
}
