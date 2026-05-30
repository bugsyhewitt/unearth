package techniques

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// urlscanPayload is a /api/v1/search/ success payload. origin and direct
// resolve to distinct non-CDN IPs; alias is a duplicate of origin's IP under a
// different scan (must dedup); edge resolves to a Cloudflare IP that must be
// filtered by the CDN registry; bogus has an unparseable page.ip and must be
// skipped.
const urlscanPayload = `{
  "results": [
    {"page":{"ip":"203.0.113.60","domain":"origin.example.test","url":"https://origin.example.test/","asnname":"AS-EXAMPLE"},"task":{"time":"2025-01-02T03:04:05.000Z"}},
    {"page":{"ip":"203.0.113.61","domain":"direct.example.test","url":"https://direct.example.test/path","asnname":"AS-EXAMPLE"},"task":{"time":"2025-01-03T03:04:05.000Z"}},
    {"page":{"ip":"203.0.113.60","domain":"alias.example.test","url":"https://alias.example.test/","asnname":"AS-EXAMPLE"},"task":{"time":"2025-01-04T03:04:05.000Z"}},
    {"page":{"ip":"104.16.0.5","domain":"edge.example.test","url":"https://edge.example.test/","asnname":"AS-CLOUDFLARE"},"task":{"time":"2025-01-05T03:04:05.000Z"}},
    {"page":{"ip":"not-an-ip","domain":"bogus.example.test","url":"https://bogus.example.test/","asnname":"AS-X"},"task":{"time":"2025-01-06T03:04:05.000Z"}}
  ],
  "total": 5,
  "has_more": false
}`

func urlscanKeys() APIKeys { return APIKeys{URLScanKey: "us-tok"} }

func TestURLScan_MissingKey(t *testing.T) {
	if _, err := (urlscanAssetTechnique{}).Run(context.Background(), "x", RunOptions{}); !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("no creds: want ErrMissingAPIKey, got %v", err)
	}
}

func TestURLScan_Happy(t *testing.T) {
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://urlscan.io/": func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("API-Key") != "us-tok" {
				t.Errorf("API-Key header: got %q", req.Header.Get("API-Key"))
			}
			if !strings.Contains(req.URL.RawQuery, "domain%3Aexample.test") &&
				!strings.Contains(req.URL.Query().Get("q"), "domain:example.test") {
				t.Errorf("query missing domain filter: %q", req.URL.RawQuery)
			}
			if !strings.HasPrefix(req.URL.String(), "https://urlscan.io/api/v1/search/") {
				t.Errorf("unexpected URL: %q", req.URL.String())
			}
			return stubResponse(200, urlscanPayload), nil
		},
	})
	out, err := (urlscanAssetTechnique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    urlscanKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// origin and alias collapse to 203.0.113.60, direct=.61; edge is
	// Cloudflare (filtered); bogus has an invalid IP (skipped). Expect 2
	// unique non-CDN IPs.
	if len(out) != 2 {
		t.Fatalf("want 2 non-CDN deduped IPs, got %d: %+v", len(out), out)
	}
	gotIPs := map[string]bool{}
	for _, c := range out {
		gotIPs[c.IP] = true
		if !strings.Contains(c.Evidence, "URLScan.io") || !strings.Contains(c.Evidence, "example.test") {
			t.Errorf("evidence: %q", c.Evidence)
		}
	}
	if !gotIPs["203.0.113.60"] || !gotIPs["203.0.113.61"] {
		t.Errorf("expected 203.0.113.60 and .61, got %v", gotIPs)
	}
	if gotIPs["104.16.0.5"] {
		t.Errorf("Cloudflare edge IP should have been filtered")
	}
	// Single page (has_more=false), so one HTTP call.
	if len(rt.calls) != 1 {
		t.Errorf("want one HTTP call, got %d", len(rt.calls))
	}
}

func TestURLScan_EmptyList_IsEmpty(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://urlscan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"results":[],"total":0,"has_more":false}`), nil
		},
	})
	out, err := (urlscanAssetTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    urlscanKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want zero candidates for empty list, got %v", out)
	}
}

func TestURLScan_401_IsMissingKey(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://urlscan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(401, ""), nil
		},
	})
	_, err := (urlscanAssetTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    urlscanKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("401 should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestURLScan_403_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://urlscan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(403, ""), nil
		},
	})
	_, err := (urlscanAssetTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    urlscanKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("403 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestURLScan_429_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://urlscan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(429, ""), nil
		},
	})
	_, err := (urlscanAssetTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    urlscanKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("429 (quota) should produce ErrTierInsufficient, got %v", err)
	}
}

func TestURLScan_QuotaEnvelope_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://urlscan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(400, `{"message":"Rate limit reached","description":"You have exhausted your daily quota; please upgrade."}`), nil
		},
	})
	_, err := (urlscanAssetTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    urlscanKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("quota envelope should map to ErrTierInsufficient, got %v", err)
	}
}

func TestURLScan_AuthEnvelope_IsMissingKey(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://urlscan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(400, `{"message":"Invalid API key","description":"The supplied API-Key header is not recognized."}`), nil
		},
	})
	_, err := (urlscanAssetTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    urlscanKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("auth envelope should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestURLScan_GenericError(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://urlscan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"results":[],"message":"weird unclassified problem"}`), nil
		},
	})
	_, err := (urlscanAssetTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    urlscanKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for unclassified envelope")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("generic error should not be classified, got %v", err)
	}
}

func TestURLScan_5xx_IsHardError(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://urlscan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(500, ""), nil
		},
	})
	_, err := (urlscanAssetTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    urlscanKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for 500 status")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("500 should not be classified as tier/key error, got %v", err)
	}
}

func TestURLScan_MalformedJSON(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://urlscan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{garbage`), nil
		},
	})
	_, err := (urlscanAssetTechnique{}).Run(context.Background(), "x.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    urlscanKeys(),
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestURLScan_Pagination(t *testing.T) {
	// First call returns a full page (urlscanPageSize results) with
	// has_more=true and a sort cursor; second call returns a short page
	// with has_more=false. Total candidates = unique non-CDN IPs across
	// both pages.
	var sb1 strings.Builder
	sb1.WriteString(`{"results":[`)
	for i := 0; i < urlscanPageSize; i++ {
		if i > 0 {
			sb1.WriteString(",")
		}
		sb1.WriteString(`{"page":{"ip":"198.51.100.`)
		sb1.WriteString(itoa(i))
		sb1.WriteString(`","domain":"h`)
		sb1.WriteString(itoa(i))
		sb1.WriteString(`.example.test","url":"https://h`)
		sb1.WriteString(itoa(i))
		sb1.WriteString(`.example.test/"},"task":{"time":"2025-01-01T00:00:00.000Z"},"sort":[1700000000,"scan-`)
		sb1.WriteString(itoa(i))
		sb1.WriteString(`"]}`)
	}
	sb1.WriteString(`],"total":101,"has_more":true}`)
	page1 := sb1.String()

	page2 := `{"results":[
		{"page":{"ip":"198.51.101.1","domain":"late.example.test","url":"https://late.example.test/"},"task":{"time":"2025-02-01T00:00:00.000Z"}}
	],"total":101,"has_more":false}`

	callCount := 0
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://urlscan.io/": func(req *http.Request) (*http.Response, error) {
			callCount++
			if callCount == 1 {
				if req.URL.Query().Get("search_after") != "" {
					t.Errorf("first call should have no search_after, got %q", req.URL.Query().Get("search_after"))
				}
				return stubResponse(200, page1), nil
			}
			if req.URL.Query().Get("search_after") == "" {
				t.Errorf("second call missing search_after cursor")
			}
			return stubResponse(200, page2), nil
		},
	})
	out, err := (urlscanAssetTechnique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    urlscanKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != urlscanPageSize+1 {
		t.Fatalf("want %d candidates across both pages, got %d", urlscanPageSize+1, len(out))
	}
	if len(rt.calls) != 2 {
		t.Errorf("want exactly two HTTP calls (one per page), got %d", len(rt.calls))
	}
}

func TestURLScan_Metadata(t *testing.T) {
	c := urlscanAssetTechnique{}
	if c.Name() != "urlscan_asset" {
		t.Errorf("Name = %q, want %q", c.Name(), "urlscan_asset")
	}
	if c.Tier() != TierPassive {
		t.Errorf("Tier = %v, want TierPassive", c.Tier())
	}
	if !c.RequiresAPIKey() {
		t.Errorf("RequiresAPIKey = false, want true")
	}
	if c.DefaultWeight() != 0.66 {
		t.Errorf("DefaultWeight = %v, want 0.66", c.DefaultWeight())
	}
}
