package techniques

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// binaryEdgePage is a /v2/query/search payload. 104.16.0.5 is a Cloudflare
// edge IP and must be filtered. 203.0.113.50 appears twice to exercise
// dedup. total==3 keeps pagination to a single page (3 events fit in one
// page of 100).
const binaryEdgePage = `{
  "events": [
    {"target": {"ip": "203.0.113.50"}},
    {"target": {"ip": "104.16.0.5"}},
    {"target": {"ip": "203.0.113.51"}},
    {"target": {"ip": "203.0.113.50"}}
  ],
  "total": 4,
  "page": 1,
  "pagesize": 100
}`

func binaryEdgeKeys() APIKeys { return APIKeys{BinaryEdgeKey: "be-tok"} }

func TestBinaryEdge_MissingKey(t *testing.T) {
	if _, err := (binaryEdgeTechnique{}).Run(context.Background(), "x", RunOptions{}); !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("no creds: want ErrMissingAPIKey, got %v", err)
	}
}

func TestBinaryEdge_Happy(t *testing.T) {
	withStubFingerprintSHA1(t, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", nil)
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.binaryedge.io/": func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("X-Key") != "be-tok" {
				t.Errorf("X-Key header: got %q", req.Header.Get("X-Key"))
			}
			qv := req.URL.Query().Get("query")
			if !strings.Contains(qv, "ssl.cert.as_dict.fingerprint.sha1") {
				t.Errorf("query missing cert field: %q", qv)
			}
			if !strings.Contains(qv, "deadbeef") {
				t.Errorf("query missing fingerprint: %q", qv)
			}
			return stubResponse(200, binaryEdgePage), nil
		},
	})
	out, err := (binaryEdgeTechnique{}).Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    binaryEdgeKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 non-CDN deduped IPs (cloudflare filtered), got %d: %+v", len(out), out)
	}
	gotIPs := map[string]bool{}
	for _, c := range out {
		gotIPs[c.IP] = true
		if !strings.Contains(c.Evidence, "BinaryEdge") || !strings.Contains(c.Evidence, "sha1:") {
			t.Errorf("evidence: %q", c.Evidence)
		}
	}
	if !gotIPs["203.0.113.50"] || !gotIPs["203.0.113.51"] {
		t.Errorf("expected both 203.0.113.50 and 203.0.113.51, got %v", gotIPs)
	}
	// total==4 but the single page returns 4 events, so len>=total ends paging.
	if len(rt.calls) != 1 {
		t.Errorf("want one HTTP call, got %d", len(rt.calls))
	}
}

func TestBinaryEdge_EmptyResult(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.binaryedge.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"events":[],"total":0}`), nil
		},
	})
	out, err := (binaryEdgeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    binaryEdgeKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("want zero candidates, got %v", out)
	}
}

func TestBinaryEdge_401_IsMissingKey(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.binaryedge.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(401, ""), nil
		},
	})
	_, err := (binaryEdgeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    binaryEdgeKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("401 should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestBinaryEdge_403_IsTierInsufficient(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.binaryedge.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(403, ""), nil
		},
	})
	_, err := (binaryEdgeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    binaryEdgeKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("403 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestBinaryEdge_429_IsTierInsufficient(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.binaryedge.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(429, ""), nil
		},
	})
	_, err := (binaryEdgeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    binaryEdgeKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("429 (monthly allowance) should produce ErrTierInsufficient, got %v", err)
	}
}

func TestBinaryEdge_QuotaEnvelope_IsTierInsufficient(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.binaryedge.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"title":"Bad Request","message":"You have reached your monthly request limit, please upgrade your plan"}`), nil
		},
	})
	_, err := (binaryEdgeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    binaryEdgeKeys(),
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("quota envelope should map to ErrTierInsufficient, got %v", err)
	}
}

func TestBinaryEdge_BadKeyEnvelope_IsMissingKey(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.binaryedge.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"title":"Unauthorized","message":"Invalid token"}`), nil
		},
	})
	_, err := (binaryEdgeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    binaryEdgeKeys(),
	})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("invalid-token envelope should map to ErrMissingAPIKey, got %v", err)
	}
}

func TestBinaryEdge_GenericError(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.binaryedge.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"message":"something unexpected"}`), nil
		},
	})
	_, err := (binaryEdgeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    binaryEdgeKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for error envelope")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("generic error should not be classified, got %v", err)
	}
}

func TestBinaryEdge_5xx_IsHardError(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.binaryedge.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(500, ""), nil
		},
	})
	_, err := (binaryEdgeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    binaryEdgeKeys(),
	})
	if err == nil {
		t.Fatal("expected an error for 500 status")
	}
	if errors.Is(err, ErrTierInsufficient) || errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("500 should not be classified as tier/key error, got %v", err)
	}
}

func TestBinaryEdge_MalformedJSON(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.binaryedge.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{garbage`), nil
		},
	})
	_, err := (binaryEdgeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    binaryEdgeKeys(),
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestBinaryEdge_FingerprintError(t *testing.T) {
	withStubFingerprintSHA1(t, "", errors.New("dial failed"))
	hc, _ := stubClient(nil)
	_, err := (binaryEdgeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    binaryEdgeKeys(),
	})
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("want fingerprint error, got %v", err)
	}
}

func TestBinaryEdge_Pagination(t *testing.T) {
	withStubFingerprintSHA1(t, "fp", nil)
	// total==2 spread across two single-event pages forces a second fetch.
	page1 := `{"events":[{"target":{"ip":"203.0.113.10"}}],"total":2,"page":1,"pagesize":1}`
	page2 := `{"events":[{"target":{"ip":"203.0.113.11"}}],"total":2,"page":2,"pagesize":1}`
	calls := 0
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.binaryedge.io/": func(req *http.Request) (*http.Response, error) {
			calls++
			if req.URL.Query().Get("page") == "2" {
				return stubResponse(200, page2), nil
			}
			return stubResponse(200, page1), nil
		},
	})
	out, err := (binaryEdgeTechnique{}).Run(context.Background(), "x", RunOptions{
		HTTPClient: hc,
		APIKeys:    binaryEdgeKeys(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if calls != 2 {
		t.Errorf("want two HTTP calls for paginated result, got %d", calls)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 candidates across pages, got %d: %+v", len(out), out)
	}
}

func TestBinaryEdgeTechnique_Metadata(t *testing.T) {
	b := binaryEdgeTechnique{}
	if b.Name() != "binaryedge_cert" || b.Tier() != TierPassive || !b.RequiresAPIKey() || b.DefaultWeight() != 0.72 {
		t.Errorf("metadata wrong: %+v", b)
	}
}

func TestIsBinaryEdgeTierError(t *testing.T) {
	for _, m := range []string{"monthly limit reached", "please upgrade your plan", "subscription required", "no permission"} {
		if !isBinaryEdgeTierError(m) {
			t.Errorf("expected tier error for %q", m)
		}
	}
	if isBinaryEdgeTierError("internal server error") {
		t.Errorf("did not expect tier error for generic message")
	}
}

func TestIsBinaryEdgeKeyError(t *testing.T) {
	for _, m := range []string{"Invalid token", "unauthorized request", "invalid api key"} {
		if !isBinaryEdgeKeyError(m) {
			t.Errorf("expected key error for %q", m)
		}
	}
	if isBinaryEdgeKeyError("monthly limit reached") {
		t.Errorf("did not expect key error for quota message")
	}
}
