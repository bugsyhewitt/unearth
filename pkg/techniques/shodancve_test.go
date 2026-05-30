package techniques

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

const shodanCVEPage1 = `{
  "matches": [
    {"ip_str":"203.0.113.50","hostnames":["legacy.example.test"],"port":443,"product":"ScreenConnect"},
    {"ip_str":"104.16.0.5","hostnames":["edge.example.test"]},
    {"ip_str":"203.0.113.51","hostnames":["staging.example.test"]}
  ],
  "total": 3
}`

const shodanCVEPage1WithMore = `{"matches":[{"ip_str":"203.0.113.50"}],"total":2}`
const shodanCVEPage2 = `{"matches":[{"ip_str":"203.0.113.99"}],"total":2}`

func TestShodanCVE_NoCVE_Skips(t *testing.T) {
	out, err := shodanCVETechnique{}.Run(context.Background(), "example.test", RunOptions{
		APIKeys: APIKeys{ShodanAPIKey: "k"},
	})
	if err != nil {
		t.Fatalf("expected silent skip, got err: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected zero candidates on empty CVEID, got %d", len(out))
	}
}

func TestShodanCVE_BadCVE(t *testing.T) {
	_, err := shodanCVETechnique{}.Run(context.Background(), "x", RunOptions{
		APIKeys: APIKeys{ShodanAPIKey: "k"},
		CVEID:   "not-a-cve",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid CVE id") {
		t.Fatalf("want invalid CVE id error, got %v", err)
	}
}

func TestShodanCVE_MissingKey(t *testing.T) {
	_, err := shodanCVETechnique{}.Run(context.Background(), "x", RunOptions{
		CVEID: "CVE-2024-1709",
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("want ErrMissingAPIKey, got %v", err)
	}
}

func TestShodanCVE_Happy(t *testing.T) {
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(req *http.Request) (*http.Response, error) {
			q := req.URL.Query()
			if q.Get("key") != "shodan-tok" {
				t.Errorf("key param: got %q", q.Get("key"))
			}
			query := q.Get("query")
			if !strings.Contains(query, "vuln:CVE-2024-1709") {
				t.Errorf("query missing vuln filter: %q", query)
			}
			if !strings.Contains(query, "hostname:example.test") {
				t.Errorf("query missing hostname filter: %q", query)
			}
			return stubResponse(200, shodanCVEPage1), nil
		},
	})
	out, err := shodanCVETechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "shodan-tok"},
		CVEID:      "CVE-2024-1709",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 non-CDN candidates, got %d: %+v", len(out), out)
	}
	for _, c := range out {
		if !strings.Contains(c.Evidence, "CVE-2024-1709") {
			t.Errorf("evidence missing CVE: %q", c.Evidence)
		}
		if !strings.Contains(c.Evidence, "example.test") {
			t.Errorf("evidence missing target: %q", c.Evidence)
		}
	}
	if len(rt.calls) != 1 {
		t.Errorf("want one HTTP call, got %d", len(rt.calls))
	}
}

func TestShodanCVE_LowercaseCVENormalized(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(req *http.Request) (*http.Response, error) {
			if !strings.Contains(req.URL.Query().Get("query"), "vuln:CVE-2023-1234") {
				t.Errorf("CVE should be upper-cased; got %q", req.URL.Query().Get("query"))
			}
			return stubResponse(200, `{"matches":[],"total":0}`), nil
		},
	})
	_, err := shodanCVETechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "k"},
		CVEID:      "  cve-2023-1234  ",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestShodanCVE_Pagination(t *testing.T) {
	pageNum := 0
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(req *http.Request) (*http.Response, error) {
			pageNum++
			q := req.URL.Query()
			switch pageNum {
			case 1:
				if q.Get("page") != "" {
					t.Errorf("page 1 should not set page param, got %q", q.Get("page"))
				}
				return stubResponse(200, shodanCVEPage1WithMore), nil
			case 2:
				if q.Get("page") != "2" {
					t.Errorf("page 2 param: %q", q.Get("page"))
				}
				return stubResponse(200, shodanCVEPage2), nil
			default:
				t.Errorf("unexpected page %d", pageNum)
				return stubResponse(500, ""), nil
			}
		},
	})
	out, err := shodanCVETechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "k"},
		CVEID:      "CVE-2024-1709",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pageNum != 2 {
		t.Errorf("expected 2 page requests, got %d", pageNum)
	}
	if len(out) != 2 {
		t.Errorf("merged candidates: %+v", out)
	}
}

func TestShodanCVE_TierInsufficient_403(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(403, ""), nil
		},
	})
	_, err := shodanCVETechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "k"},
		CVEID:      "CVE-2024-1709",
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("403 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestShodanCVE_TierInsufficient_200WithUpgradeError(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"error":"Access denied (please upgrade your API plan)"}`), nil
		},
	})
	_, err := shodanCVETechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "k"},
		CVEID:      "CVE-2024-1709",
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("200+upgrade should produce ErrTierInsufficient, got %v", err)
	}
}

func TestShodanCVE_BadKey_401(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(401, `{"error":"Invalid API key"}`), nil
		},
	})
	_, err := shodanCVETechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "bogus"},
		CVEID:      "CVE-2024-1709",
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("401 should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestShodanCVE_BudgetExhausted(t *testing.T) {
	hc, _ := stubClient(nil)
	_, err := shodanCVETechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "k"},
		CVEID:      "CVE-2024-1709",
		Budget:     exhaustedBudget{},
	})
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("want ErrBudgetExhausted, got %v", err)
	}
}

func TestShodanCVE_EmptyResult(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"matches":[],"total":0}`), nil
		},
	})
	out, err := shodanCVETechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "k"},
		CVEID:      "CVE-2024-1709",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want zero candidates, got %v", out)
	}
}

func TestShodanCVE_MalformedJSON(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{garbage`), nil
		},
	})
	_, err := shodanCVETechnique{}.Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "k"},
		CVEID:      "CVE-2024-1709",
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestShodanCVE_Metadata(t *testing.T) {
	s := shodanCVETechnique{}
	if s.Name() != "shodan_cve" || s.Tier() != TierPassive || !s.RequiresAPIKey() || s.DefaultWeight() != 0.78 {
		t.Errorf("metadata wrong: %+v", s)
	}
}
