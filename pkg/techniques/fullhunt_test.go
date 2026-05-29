package techniques

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// fullHuntPayload is a /api/v1/domain/{domain}/details success payload.
// 104.16.0.5 is a Cloudflare edge IP and must be filtered. 203.0.113.50
// appears in two hosts to exercise dedup. The host with a bare-string
// ip_address exercises the string→array fallback. The empty-IP entry is
// skipped.
const fullHuntPayload = `{
  "domain": "example.test",
  "hosts": [
    {"host": "origin.example.test", "ip_address": ["203.0.113.50", "104.16.0.5"]},
    {"host": "direct.example.test", "ip_address": ["203.0.113.51"]},
    {"host": "alias.example.test", "ip_address": ["203.0.113.50"]},
    {"host": "single.example.test", "ip_address": "203.0.113.52"},
    {"host": "blank.example.test", "ip_address": [""]}
  ]
}`

func fullHuntKeys() APIKeys { return APIKeys{FullHuntKey: "fh-tok"} }

func TestFullHunt_MissingKey(t *testing.T) {
	if _, err := (fullHuntTechnique{}).Run(context.Background(), "x", RunOptions{}); !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("no creds: want ErrMissingAPIKey, got %v", err)
	}
}

func TestFullHunt_Happy(t *testing.T) {
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://fullhunt.io/": func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("X-API-KEY") != "fh-tok" {
				t.Errorf("X-API-KEY header: got %q", req.Header.Get("X-API-KEY"))
			}
			if !strings.Contains(req.URL.Path, "example.test") {
				t.Errorf("path missing domain: %q", req.URL.Path)
			}
			if !strings.Contains(req.URL.Path, "/details") {
				t.Errorf("path missing /details: %q", req.URL.Path)
			}
			return stubResponse(200, fullHuntPayload), nil
		},
	})
	out, err := (fullHuntTechnique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    fullHuntKeys(),
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
		if !strings.Contains(c.Evidence, "FullHunt") || !strings.Contains(c.Evidence, "example.test") {
			t.Errorf("evidence: %q", c.Evidence)
		}
	}
	if !gotIPs["203.0.113.50"] || !gotIPs["203.0.113.51"] || !gotIPs["203.0.113.52"] {
		t.Errorf("expected 203.0.113.50/51/52, got %v", gotIPs)
	}
	// FullHunt's domain-details endpoint returns the full inventory in one
	// object, so the technique makes exactly one HTTP call.
	if len(rt.calls) != 1 {
		t.Errorf("want one HTTP call, got %d", len(rt.calls))
	}
}

func TestFullHunt_EmptyHosts_IsEmpty(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://fullhunt.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"domain":"x","hosts":[]}`), nil
		},
	})
	out, err := (fullHuntTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    fullHuntKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want zero candidates for empty hosts, got %v", out)
	}
}

func TestFullHunt_401_IsMissingKey(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://fullhunt.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(401, ""), nil
		},
	})
	_, err := (fullHuntTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    fullHuntKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("401 should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestFullHunt_403_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://fullhunt.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(403, ""), nil
		},
	})
	_, err := (fullHuntTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    fullHuntKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("403 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestFullHunt_429_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://fullhunt.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(429, ""), nil
		},
	})
	_, err := (fullHuntTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    fullHuntKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("429 (monthly allowance) should produce ErrTierInsufficient, got %v", err)
	}
}

func TestFullHunt_QuotaEnvelope_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://fullhunt.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"message":"You have reached your monthly quota, please upgrade your plan"}`), nil
		},
	})
	_, err := (fullHuntTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    fullHuntKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("quota envelope should map to ErrTierInsufficient, got %v", err)
	}
}

func TestFullHunt_BadKeyEnvelope_IsMissingKey(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://fullhunt.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"error":"Invalid API key"}`), nil
		},
	})
	_, err := (fullHuntTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    fullHuntKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("invalid-key envelope should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestFullHunt_GenericError(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://fullhunt.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"message":"something unexpected"}`), nil
		},
	})
	_, err := (fullHuntTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    fullHuntKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for error envelope")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("generic error should not be classified, got %v", err)
	}
}

func TestFullHunt_5xx_IsHardError(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://fullhunt.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(500, ""), nil
		},
	})
	_, err := (fullHuntTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    fullHuntKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for 500 status")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("500 should not be classified as tier/key error, got %v", err)
	}
}

func TestFullHunt_MalformedJSON(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://fullhunt.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{garbage`), nil
		},
	})
	_, err := (fullHuntTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    fullHuntKeys(),
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestFullHuntTechnique_Metadata(t *testing.T) {
	f := fullHuntTechnique{}
	if f.Name() != "fullhunt_asset" || f.Tier() != TierPassive || !f.RequiresAPIKey() || f.DefaultWeight() != 0.70 {
		t.Errorf("metadata wrong: %+v", f)
	}
}

func TestIsFullHuntTierError(t *testing.T) {
	for _, m := range []string{"monthly quota reached", "rate limit exceeded", "please upgrade your plan", "subscription required", "no permission"} {
		if !isFullHuntTierError(m) {
			t.Errorf("expected tier error for %q", m)
		}
	}
	if isFullHuntTierError("internal server error") {
		t.Errorf("did not expect tier error for generic message")
	}
}

func TestIsFullHuntKeyError(t *testing.T) {
	for _, m := range []string{"Invalid API key", "unauthorized request", "invalid token", "missing api key"} {
		if !isFullHuntKeyError(m) {
			t.Errorf("expected key error for %q", m)
		}
	}
	if isFullHuntKeyError("monthly quota reached") {
		t.Errorf("did not expect key error for quota message")
	}
}
