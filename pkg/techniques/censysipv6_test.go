package techniques

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// censysIPv6Page is the Platform search-response shape this technique
// consumes — the same envelope censys_cert uses (cosmetic differences would
// indicate a Platform-API drift either technique would need to absorb).
// Mix of IPv6 documentation prefixes (RFC 3849, non-CDN) and one
// Cloudflare IPv6 edge inside 2606:4700::/32 (must be filtered), plus one
// IPv4 hit (must be dropped because this technique is IPv6-only) and one
// duplicate (must be deduped).
const censysIPv6Page = `{
  "result": {
    "hits": [
      {"host":{"ip":"2001:db8::1"}},
      {"host":{"ip":"203.0.113.50"}},
      {"host":{"ip":"2606:4700::1"}},
      {"host":{"ip":"2001:db8::2"}},
      {"host":{"ip":"2001:db8::1"}}
    ],
    "next_page_token": ""
  }
}`

const censysIPv6PageWithMore = `{
  "result": {
    "hits": [{"host":{"ip":"2001:db8::1"}}],
    "next_page_token": "page-2-v6-token"
  }
}`

const censysIPv6Page2 = `{
  "result": {
    "hits": [{"host":{"ip":"2001:db8::99"}}],
    "next_page_token": ""
  }
}`

func TestCensysIPv6_MissingPAT(t *testing.T) {
	_, err := censysIPv6Technique{}.Run(context.Background(), "x", RunOptions{})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("want ErrMissingAPIKey, got %v", err)
	}
	_, err = censysIPv6Technique{}.Run(context.Background(), "x",
		RunOptions{APIKeys: APIKeys{CensysPlatformPAT: ""}})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("empty PAT should be ErrMissingAPIKey, got %v", err)
	}
}

func TestCensysIPv6_Happy(t *testing.T) {
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.platform.censys.io/": func(req *http.Request) (*http.Response, error) {
			if got := req.Header.Get("Authorization"); got != "Bearer pat-token" {
				t.Errorf("Authorization header: got %q want %q", got, "Bearer pat-token")
			}
			if got := req.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type: got %q", got)
			}
			body, _ := io.ReadAll(req.Body)
			var parsed censysSearchRequest
			if err := json.Unmarshal(body, &parsed); err != nil {
				t.Fatalf("body not valid JSON: %v", err)
			}
			if !strings.Contains(parsed.Query, "example.test") {
				t.Errorf("query missing target: %q", parsed.Query)
			}
			if !strings.Contains(parsed.Query, censysIPv6DNSField) {
				t.Errorf("query missing DNS field: %q", parsed.Query)
			}
			if !strings.Contains(parsed.Query, "*.example.test") {
				t.Errorf("query missing wildcard alternate: %q", parsed.Query)
			}
			return stubResponse(200, censysIPv6Page), nil
		},
	})
	out, err := (censysIPv6Technique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{CensysPlatformPAT: "pat-token"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Expect exactly the two non-CDN, deduped IPv6 candidates. IPv4
	// (203.0.113.50) and the Cloudflare-edge IPv6 (2606:4700::1) must be
	// excluded; 2001:db8::1 deduplicated.
	if len(out) != 2 {
		t.Fatalf("want 2 non-CDN deduped IPv6 candidates, got %d: %+v", len(out), out)
	}
	gotIPs := map[string]bool{}
	for _, c := range out {
		gotIPs[c.IP] = true
		if !strings.Contains(c.Evidence, "Censys") || !strings.Contains(c.Evidence, "IPv6") {
			t.Errorf("evidence should mention Censys and IPv6: %q", c.Evidence)
		}
		if !strings.Contains(c.Evidence, "example.test") {
			t.Errorf("evidence should mention the target apex: %q", c.Evidence)
		}
	}
	if !gotIPs["2001:db8::1"] || !gotIPs["2001:db8::2"] {
		t.Errorf("expected 2001:db8::1 and 2001:db8::2, got %v", gotIPs)
	}
	if gotIPs["203.0.113.50"] {
		t.Error("IPv4 hit must be excluded by an IPv6-only technique")
	}
	if gotIPs["2606:4700::1"] {
		t.Error("Cloudflare IPv6 edge must be filtered by the CDN check")
	}
	if len(rt.calls) != 1 {
		t.Errorf("want one HTTP call, got %d", len(rt.calls))
	}
}

func TestCensysIPv6_Pagination(t *testing.T) {
	page := 0
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.platform.censys.io/": func(req *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(req.Body)
			var parsed censysSearchRequest
			_ = json.Unmarshal(body, &parsed)
			page++
			switch page {
			case 1:
				if parsed.PageToken != "" {
					t.Errorf("first page must have empty token, got %q", parsed.PageToken)
				}
				return stubResponse(200, censysIPv6PageWithMore), nil
			case 2:
				if parsed.PageToken != "page-2-v6-token" {
					t.Errorf("second page expected token %q, got %q", "page-2-v6-token", parsed.PageToken)
				}
				return stubResponse(200, censysIPv6Page2), nil
			default:
				t.Fatalf("unexpected third page request")
				return nil, nil
			}
		},
	})
	out, err := (censysIPv6Technique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{CensysPlatformPAT: "pat-token"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 candidates after pagination, got %d: %+v", len(out), out)
	}
	if page != 2 {
		t.Errorf("want 2 pages fetched, got %d", page)
	}
}

func TestCensysIPv6_403_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.platform.censys.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(403, ""), nil
		},
	})
	_, err := (censysIPv6Technique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{CensysPlatformPAT: "pat-token"},
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("403 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestCensysIPv6_401_IsTierInsufficient(t *testing.T) {
	// censys_cert maps 401 to the same tier-insufficient bucket: a 401
	// arrives only when a PAT was sent (we short-circuit empty PATs
	// upstream as ErrMissingAPIKey), so the only realistic cause is the
	// account tier being unable to use this endpoint.
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.platform.censys.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(401, ""), nil
		},
	})
	_, err := (censysIPv6Technique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{CensysPlatformPAT: "pat-token"},
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("401 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestCensysIPv6_429_IsTierInsufficient(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.platform.censys.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(429, ""), nil
		},
	})
	_, err := (censysIPv6Technique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{CensysPlatformPAT: "pat-token"},
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("429 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestCensysIPv6_500_IsError(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.platform.censys.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(500, ""), nil
		},
	})
	_, err := (censysIPv6Technique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{CensysPlatformPAT: "pat-token"},
	})
	if err == nil {
		t.Fatal("500 must surface as an error")
	}
	if errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("500 is not a tier issue: %v", err)
	}
}

func TestCensysIPv6_EmptyResult(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.platform.censys.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"result":{"hits":[],"next_page_token":""}}`), nil
		},
	})
	out, err := (censysIPv6Technique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{CensysPlatformPAT: "pat-token"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want zero candidates, got %+v", out)
	}
}

func TestCensysIPv6_IPv4MappedDropped(t *testing.T) {
	// An IPv4-mapped IPv6 address (::ffff:1.2.3.4) is an IPv4 address in
	// a v6 wrapper. After Unmap it must be classified as v4 and dropped.
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.platform.censys.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"result":{"hits":[{"host":{"ip":"::ffff:203.0.113.99"}}],"next_page_token":""}}`), nil
		},
	})
	out, err := (censysIPv6Technique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{CensysPlatformPAT: "pat-token"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("IPv4-mapped v6 must be dropped, got %+v", out)
	}
}

func TestCensysIPv6_Metadata(t *testing.T) {
	// Sanity: name, tier, weight, key-requirement are stable wires the
	// engine and config layer depend on. A drift here would silently
	// break wiring in unearth.go / config.go.
	tech := censysIPv6Technique{}
	if got := tech.Name(); got != "censys_ipv6" {
		t.Errorf("Name: got %q want censys_ipv6", got)
	}
	if got := tech.Tier(); got != TierPassive {
		t.Errorf("Tier: got %v want TierPassive", got)
	}
	if !tech.RequiresAPIKey() {
		t.Error("RequiresAPIKey must be true (Censys PAT required)")
	}
	if got := tech.DefaultWeight(); got <= 0 || got > 1 {
		t.Errorf("DefaultWeight out of range: %v", got)
	}
}
