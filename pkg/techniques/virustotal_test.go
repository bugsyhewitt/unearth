package techniques

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// virusTotalPayload is a /api/v3/domains/{domain}/resolutions success payload.
// origin and direct resolve to distinct non-CDN IPs; alias is a duplicate of
// origin's IP under a different hostname (must dedup); edge resolves to a
// Cloudflare IP that must be filtered by the CDN registry; bogus has an
// unparseable ip_address and must be skipped.
const virusTotalPayload = `{
  "data": [
    {"attributes":{"ip_address":"203.0.113.50","host_name":"origin.example.test","date":1700000000}},
    {"attributes":{"ip_address":"203.0.113.51","host_name":"direct.example.test","date":1700000001}},
    {"attributes":{"ip_address":"203.0.113.50","host_name":"alias.example.test","date":1700000002}},
    {"attributes":{"ip_address":"104.16.0.5","host_name":"edge.example.test","date":1700000003}},
    {"attributes":{"ip_address":"not-an-ip","host_name":"bogus.example.test","date":1700000004}}
  ],
  "meta": {}
}`

func virusTotalKeys() APIKeys { return APIKeys{VirusTotalKey: "vt-tok"} }

func TestVirusTotal_MissingKey(t *testing.T) {
	if _, err := (virusTotalPassiveDNSTechnique{}).Run(context.Background(), "x", RunOptions{}); !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("no creds: want ErrMissingAPIKey, got %v", err)
	}
}

func TestVirusTotal_Happy(t *testing.T) {
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.virustotal.com/": func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("x-apikey") != "vt-tok" {
				t.Errorf("x-apikey header: got %q", req.Header.Get("x-apikey"))
			}
			if !strings.Contains(req.URL.Path, "example.test") {
				t.Errorf("path missing domain: %q", req.URL.Path)
			}
			if !strings.Contains(req.URL.Path, "/resolutions") {
				t.Errorf("path missing /resolutions: %q", req.URL.Path)
			}
			return stubResponse(200, virusTotalPayload), nil
		},
	})
	out, err := (virusTotalPassiveDNSTechnique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    virusTotalKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// origin and alias collapse to 203.0.113.50, direct=.51; edge is
	// Cloudflare (filtered); bogus has an invalid IP (skipped). Expect 2
	// unique IPs.
	if len(out) != 2 {
		t.Fatalf("want 2 non-CDN deduped IPs, got %d: %+v", len(out), out)
	}
	gotIPs := map[string]bool{}
	for _, c := range out {
		gotIPs[c.IP] = true
		if !strings.Contains(c.Evidence, "VirusTotal") || !strings.Contains(c.Evidence, "example.test") {
			t.Errorf("evidence: %q", c.Evidence)
		}
	}
	if !gotIPs["203.0.113.50"] || !gotIPs["203.0.113.51"] {
		t.Errorf("expected 203.0.113.50 and .51, got %v", gotIPs)
	}
	if gotIPs["104.16.0.5"] {
		t.Errorf("Cloudflare edge IP should have been filtered")
	}
	// Single page (no cursor), so one HTTP call.
	if len(rt.calls) != 1 {
		t.Errorf("want one HTTP call, got %d", len(rt.calls))
	}
}

func TestVirusTotal_EmptyList_IsEmpty(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.virustotal.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"data":[],"meta":{}}`), nil
		},
	})
	out, err := (virusTotalPassiveDNSTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    virusTotalKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want zero candidates for empty list, got %v", out)
	}
}

func TestVirusTotal_404_IsEmpty(t *testing.T) {
	// 404 from the resolutions endpoint means "we have no passive-DNS data
	// for this apex" — a clean empty success, not an error.
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.virustotal.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(404, `{"error":{"code":"NotFoundError","message":"Domain not found"}}`), nil
		},
	})
	out, err := (virusTotalPassiveDNSTechnique{}).Run(context.Background(), "unknown.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    virusTotalKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want zero candidates for 404, got %v", out)
	}
}

func TestVirusTotal_401_IsMissingKey(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.virustotal.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(401, ""), nil
		},
	})
	_, err := (virusTotalPassiveDNSTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    virusTotalKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("401 should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestVirusTotal_403_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.virustotal.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(403, ""), nil
		},
	})
	_, err := (virusTotalPassiveDNSTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    virusTotalKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("403 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestVirusTotal_429_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.virustotal.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(429, ""), nil
		},
	})
	_, err := (virusTotalPassiveDNSTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    virusTotalKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("429 (quota) should produce ErrTierInsufficient, got %v", err)
	}
}

func TestVirusTotal_QuotaEnvelope_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.virustotal.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(400, `{"error":{"code":"QuotaExceededError","message":"You have reached your daily quota"}}`), nil
		},
	})
	_, err := (virusTotalPassiveDNSTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    virusTotalKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("QuotaExceededError envelope should map to ErrTierInsufficient, got %v", err)
	}
}

func TestVirusTotal_AuthEnvelope_IsMissingKey(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.virustotal.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(400, `{"error":{"code":"AuthenticationRequiredError","message":"Header x-apikey is required"}}`), nil
		},
	})
	_, err := (virusTotalPassiveDNSTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    virusTotalKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("AuthenticationRequiredError envelope should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestVirusTotal_WrongCredentialsEnvelope_IsMissingKey(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.virustotal.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(401, `{"error":{"code":"WrongCredentialsError","message":"Wrong API key"}}`), nil
		},
	})
	_, err := (virusTotalPassiveDNSTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    virusTotalKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("401 should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestVirusTotal_GenericError(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.virustotal.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"error":{"code":"WeirdError","message":"something unexpected"}}`), nil
		},
	})
	_, err := (virusTotalPassiveDNSTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    virusTotalKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for error envelope")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("generic error should not be classified, got %v", err)
	}
}

func TestVirusTotal_5xx_IsHardError(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.virustotal.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(500, ""), nil
		},
	})
	_, err := (virusTotalPassiveDNSTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    virusTotalKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for 500 status")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("500 should not be classified as tier/key error, got %v", err)
	}
}

func TestVirusTotal_MalformedJSON(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.virustotal.com/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{garbage`), nil
		},
	})
	_, err := (virusTotalPassiveDNSTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    virusTotalKeys(),
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestVirusTotal_Pagination(t *testing.T) {
	// First call returns a full page (size virusTotalPageSize) plus a cursor;
	// second call returns a short page with no cursor. Total candidates =
	// unique non-CDN IPs across both pages.
	var sb1 strings.Builder
	sb1.WriteString(`{"data":[`)
	for i := 0; i < virusTotalPageSize; i++ {
		if i > 0 {
			sb1.WriteString(",")
		}
		sb1.WriteString(`{"attributes":{"ip_address":"198.51.100.`)
		sb1.WriteString(itoa(i))
		sb1.WriteString(`","host_name":"h`)
		sb1.WriteString(itoa(i))
		sb1.WriteString(`.example.test","date":1}}`)
	}
	sb1.WriteString(`],"meta":{"cursor":"next-page-token"}}`)
	page1 := sb1.String()

	page2 := `{"data":[
		{"attributes":{"ip_address":"198.51.101.1","host_name":"late.example.test","date":2}}
	],"meta":{}}`

	callCount := 0
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://www.virustotal.com/": func(req *http.Request) (*http.Response, error) {
			callCount++
			if callCount == 1 {
				if req.URL.Query().Get("cursor") != "" {
					t.Errorf("first call should have no cursor, got %q", req.URL.Query().Get("cursor"))
				}
				return stubResponse(200, page1), nil
			}
			if req.URL.Query().Get("cursor") != "next-page-token" {
				t.Errorf("second call missing cursor, got %q", req.URL.Query().Get("cursor"))
			}
			return stubResponse(200, page2), nil
		},
	})
	out, err := (virusTotalPassiveDNSTechnique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    virusTotalKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != virusTotalPageSize+1 {
		t.Fatalf("want %d candidates across both pages, got %d", virusTotalPageSize+1, len(out))
	}
	if len(rt.calls) != 2 {
		t.Errorf("want exactly two HTTP calls (one per page), got %d", len(rt.calls))
	}
}

func TestVirusTotal_Metadata(t *testing.T) {
	c := virusTotalPassiveDNSTechnique{}
	if c.Name() != "virustotal_passivedns" {
		t.Errorf("Name = %q, want %q", c.Name(), "virustotal_passivedns")
	}
	if c.Tier() != TierPassive {
		t.Errorf("Tier = %v, want TierPassive", c.Tier())
	}
	if !c.RequiresAPIKey() {
		t.Errorf("RequiresAPIKey = false, want true")
	}
	if c.DefaultWeight() != 0.67 {
		t.Errorf("DefaultWeight = %v, want 0.67", c.DefaultWeight())
	}
}
