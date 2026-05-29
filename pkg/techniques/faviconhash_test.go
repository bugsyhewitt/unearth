package techniques

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// withStubFavicon swaps fetchFavicon for a fake during a test, returning the
// supplied bytes/error for any target.
func withStubFavicon(t *testing.T, raw []byte, err error) {
	t.Helper()
	prev := fetchFavicon
	fetchFavicon = func(context.Context, string, *http.Client) ([]byte, error) { return raw, err }
	t.Cleanup(func() { fetchFavicon = prev })
}

// faviconTestBytes is a fixed payload whose Shodan-convention mmh3 hash is
// known (-384845062). The technique's query must carry this value.
var faviconTestBytes = []byte("unearth-favicon-test")

const faviconTestHash = -384845062

func TestFaviconHash_Metadata(t *testing.T) {
	f := faviconHashTechnique{}
	if f.Name() != "favicon_hash" || f.Tier() != TierActive || !f.RequiresAPIKey() || f.DefaultWeight() != 0.75 {
		t.Errorf("metadata wrong: name=%s tier=%s reqkey=%v weight=%v",
			f.Name(), f.Tier(), f.RequiresAPIKey(), f.DefaultWeight())
	}
}

func TestFaviconHash_MMH3Convention(t *testing.T) {
	// Lock the Shodan-convention hash: mmh3(base64.encodebytes(raw)) as a
	// signed int32. A regression here means we'd query the wrong index and
	// silently return zero candidates against real Shodan.
	if got := faviconMMH3(faviconTestBytes); got != faviconTestHash {
		t.Fatalf("faviconMMH3 = %d, want %d", got, faviconTestHash)
	}
}

func TestMurmurHash3X86_32_CanonicalVectors(t *testing.T) {
	// Lock the pure-Go MurmurHash3 x86_32 implementation against the public
	// reference vectors. These guard equivalence with the algorithm Shodan,
	// Censys, FOFA and ZoomEye index on, independent of the favicon base64
	// wrapping. A mismatch here means our hash diverged from every search
	// engine's index and pivots would silently return nothing.
	cases := []struct {
		in   string
		seed uint32
		want uint32
	}{
		{"", 0, 0x00000000},
		{"", 0x9747b28c, 0xebb6c228},
		{"test", 0, 0xba6bd213},
		{"Hello, world!", 0, 0xc0363e43},
		{"Hello, world!", 0x9747b28c, 0x24884cba},
		{"aaaa", 0x9747b28c, 0x5a97808a},
	}
	for _, c := range cases {
		if got := murmurHash3X86_32([]byte(c.in), c.seed); got != c.want {
			t.Errorf("murmurHash3X86_32(%q, %#x) = %#x, want %#x", c.in, c.seed, got, c.want)
		}
	}
}

func TestFaviconHash_NoKeys_Skip(t *testing.T) {
	// Neither SHODAN nor CENSYS key present → graceful skip, no fetch.
	fetched := false
	prev := fetchFavicon
	fetchFavicon = func(context.Context, string, *http.Client) ([]byte, error) {
		fetched = true
		return faviconTestBytes, nil
	}
	t.Cleanup(func() { fetchFavicon = prev })

	_, err := faviconHashTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Fatalf("want ErrMissingAPIKey, got %v", err)
	}
	if fetched {
		t.Error("favicon should not be fetched when no API keys are configured")
	}
}

func TestFaviconHash_Shodan_Happy(t *testing.T) {
	withStubFavicon(t, faviconTestBytes, nil)
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(req *http.Request) (*http.Response, error) {
			q := req.URL.Query()
			if q.Get("key") != "shodan-tok" {
				t.Errorf("key param: got %q", q.Get("key"))
			}
			if !strings.Contains(q.Get("query"), "http.favicon.hash:") {
				t.Errorf("query missing favicon filter: %q", q.Get("query"))
			}
			if !strings.Contains(q.Get("query"), strconv.Itoa(faviconTestHash)) {
				t.Errorf("query missing hash %d: %q", faviconTestHash, q.Get("query"))
			}
			// One non-CDN origin, one Cloudflare edge IP that must be filtered.
			return stubResponse(200, `{"matches":[{"ip_str":"203.0.113.7"},{"ip_str":"104.16.0.5"}],"total":2}`), nil
		},
	})

	out, err := faviconHashTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "shodan-tok"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 non-CDN candidate, got %d: %+v", len(out), out)
	}
	if out[0].IP != "203.0.113.7" {
		t.Errorf("candidate IP: got %q", out[0].IP)
	}
	if !strings.Contains(out[0].Evidence, "Shodan") || !strings.Contains(out[0].Evidence, "mmh3:") {
		t.Errorf("evidence: %q", out[0].Evidence)
	}
	if len(rt.calls) != 1 {
		t.Errorf("want one HTTP call, got %d", len(rt.calls))
	}
}

func TestFaviconHash_NotFound_NoFinding(t *testing.T) {
	// realFetchFavicon returns (nil, nil) on a 404 — model that here. With an
	// empty body the technique must return no candidates and no error, and
	// must not query the backend at all.
	withStubFavicon(t, nil, nil)
	hc, rt := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(*http.Request) (*http.Response, error) {
			t.Error("backend should not be queried when no favicon was found")
			return stubResponse(200, `{"matches":[],"total":0}`), nil
		},
	})

	out, err := faviconHashTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "shodan-tok"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("want zero candidates on missing favicon, got %+v", out)
	}
	if len(rt.calls) != 0 {
		t.Errorf("want no backend calls, got %d", len(rt.calls))
	}
}

func TestFaviconHash_AllCDN_NoFinding(t *testing.T) {
	// Every match is a known CDN edge IP → all filtered → no candidates.
	withStubFavicon(t, faviconTestBytes, nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"matches":[{"ip_str":"104.16.0.5"},{"ip_str":"104.16.0.6"}],"total":2}`), nil
		},
	})

	out, err := faviconHashTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "shodan-tok"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("want zero candidates when all hits are CDN, got %+v", out)
	}
}

func TestFaviconHash_Censys_Happy(t *testing.T) {
	withStubFavicon(t, faviconTestBytes, nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.platform.censys.io/": func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("Authorization") != "Bearer pat" {
				t.Errorf("auth header: got %q", req.Header.Get("Authorization"))
			}
			return stubResponse(200, `{"result":{"hits":[{"host":{"ip":"198.51.100.9"}},{"host":{"ip":"104.16.0.5"}}],"next_page_token":""}}`), nil
		},
	})

	out, err := faviconHashTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{CensysPlatformPAT: "pat"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 || out[0].IP != "198.51.100.9" {
		t.Fatalf("want single non-CDN Censys candidate, got %+v", out)
	}
	if !strings.Contains(out[0].Evidence, "Censys") {
		t.Errorf("evidence: %q", out[0].Evidence)
	}
}

func TestFaviconHash_BothBackends_Dedup(t *testing.T) {
	// Shodan and Censys both return 203.0.113.7; the merged result must list
	// it once. Censys also adds a unique IP.
	withStubFavicon(t, faviconTestBytes, nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"matches":[{"ip_str":"203.0.113.7"}],"total":1}`), nil
		},
		"https://api.platform.censys.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, `{"result":{"hits":[{"host":{"ip":"203.0.113.7"}},{"host":{"ip":"198.51.100.9"}}],"next_page_token":""}}`), nil
		},
	})

	out, err := faviconHashTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "k", CensysPlatformPAT: "pat"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 deduped candidates, got %d: %+v", len(out), out)
	}
	if out[0].IP != "198.51.100.9" || out[1].IP != "203.0.113.7" {
		t.Errorf("expected sorted [198.51.100.9 203.0.113.7], got %+v", out)
	}
}

func TestFaviconHash_FetchError(t *testing.T) {
	withStubFavicon(t, nil, errors.New("dial failed"))
	hc, _ := stubClient(nil)
	_, err := faviconHashTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "k"},
	})
	if err == nil {
		t.Fatal("expected error when favicon fetch fails")
	}
}

func TestFaviconHash_Shodan_TierInsufficient_403(t *testing.T) {
	withStubFavicon(t, faviconTestBytes, nil)
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://api.shodan.io/": func(*http.Request) (*http.Response, error) {
			return stubResponse(403, ""), nil
		},
	})
	_, err := faviconHashTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "k"},
	})
	if !errors.Is(err, ErrTierInsufficient) {
		t.Fatalf("403 should produce ErrTierInsufficient, got %v", err)
	}
}

func TestFaviconHash_BudgetExhausted(t *testing.T) {
	withStubFavicon(t, faviconTestBytes, nil)
	hc, _ := stubClient(nil)
	_, err := faviconHashTechnique{}.Run(context.Background(), "example.test", RunOptions{
		HTTPClient: hc,
		APIKeys:    APIKeys{ShodanAPIKey: "k"},
		Budget:     exhaustedBudget{},
	})
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("want ErrBudgetExhausted, got %v", err)
	}
}

// --- realFetchFavicon (the un-stubbed fetcher) tests ---

func TestRealFetchFavicon_HTTPSHappy(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://example.test/favicon.ico": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, "ICONBYTES"), nil
		},
	})
	raw, err := realFetchFavicon(context.Background(), "example.test", hc)
	if err != nil {
		t.Fatalf("realFetchFavicon: %v", err)
	}
	if string(raw) != "ICONBYTES" {
		t.Errorf("body: got %q", string(raw))
	}
}

func TestRealFetchFavicon_404_NoBody(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://example.test/favicon.ico": func(*http.Request) (*http.Response, error) {
			return stubResponse(404, "nope"), nil
		},
	})
	raw, err := realFetchFavicon(context.Background(), "example.test", hc)
	if err != nil {
		t.Fatalf("realFetchFavicon should not error on 404, got %v", err)
	}
	if raw != nil {
		t.Errorf("404 should yield nil body, got %q", string(raw))
	}
}

func TestRealFetchFavicon_HTTPSFails_HTTPFallback(t *testing.T) {
	hc, _ := stubClient(map[string]func(*http.Request) (*http.Response, error){
		"https://example.test/favicon.ico": func(*http.Request) (*http.Response, error) {
			return nil, errors.New("tls handshake failed")
		},
		"http://example.test/favicon.ico": func(*http.Request) (*http.Response, error) {
			return stubResponse(200, "PLAINICON"), nil
		},
	})
	raw, err := realFetchFavicon(context.Background(), "example.test", hc)
	if err != nil {
		t.Fatalf("realFetchFavicon fallback: %v", err)
	}
	if string(raw) != "PLAINICON" {
		t.Errorf("fallback body: got %q", string(raw))
	}
}
