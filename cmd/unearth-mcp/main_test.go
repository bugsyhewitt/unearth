package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/unearth-tool/unearth/pkg/techniques"

	_ "github.com/unearth-tool/unearth/pkg/techniques"
)

// newTestServer builds an MCPServer with all tools registered and no real keys.
func newTestServer(t *testing.T) *server.MCPServer {
	t.Helper()
	keys := techniques.APIKeys{} // no keys — tests the keyless path
	s := server.NewMCPServer("test", "0.0.0", server.WithToolCapabilities(false))
	registerDiscover(s, keys)
	registerCertFingerprint(s, keys)
	registerDNSHistory(s, keys)
	registerSubdomainEnum(s, keys)
	registerHostHeaderProbe(s, keys)
	registerCheckCDN(s)
	registerIsCDNIP(s)
	registerListTechniques(s)
	return s
}

// callTool invokes a tool by name by getting its handler and calling it directly.
func callTool(t *testing.T, s *server.MCPServer, toolName string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	st := s.GetTool(toolName)
	if st == nil {
		t.Fatalf("tool %q not registered", toolName)
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = toolName
	req.Params.Arguments = args
	result, err := st.Handler(context.Background(), req)
	if err != nil {
		t.Fatalf("tool handler %q returned unexpected transport error: %v", toolName, err)
	}
	return result
}

// ── unearth_discover ─────────────────────────────────────────────────────────

func TestDiscover_MissingTarget(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_discover", map[string]any{})
	if !res.IsError {
		t.Fatal("expected error result for missing target, got non-error")
	}
}

func TestDiscover_EmptyTarget(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_discover", map[string]any{"target": ""})
	if !res.IsError {
		t.Fatal("expected error result for empty target")
	}
}

// ── unearth_cert_fingerprint ─────────────────────────────────────────────────

func TestCertFingerprint_MissingTarget(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_cert_fingerprint", map[string]any{})
	if !res.IsError {
		t.Fatal("expected error for missing target")
	}
}

func TestCertFingerprint_EmptyTarget(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_cert_fingerprint", map[string]any{"target": ""})
	if !res.IsError {
		t.Fatal("expected error for empty target")
	}
}

// ── unearth_dns_history ───────────────────────────────────────────────────────

func TestDNSHistory_MissingTarget(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_dns_history", map[string]any{})
	if !res.IsError {
		t.Fatal("expected error for missing target")
	}
}

// ── unearth_subdomain_enum ────────────────────────────────────────────────────

func TestSubdomainEnum_MissingTarget(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_subdomain_enum", map[string]any{})
	if !res.IsError {
		t.Fatal("expected error for missing target")
	}
}

// ── unearth_host_header_probe ─────────────────────────────────────────────────

func TestHostHeaderProbe_MissingTarget(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_host_header_probe", map[string]any{
		"ips": []any{"1.2.3.4"},
	})
	if !res.IsError {
		t.Fatal("expected error for missing target")
	}
}

func TestHostHeaderProbe_MissingIPs(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_host_header_probe", map[string]any{
		"target": "example.com",
	})
	if !res.IsError {
		t.Fatal("expected error for missing ips")
	}
}

func TestHostHeaderProbe_EmptyIPList(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_host_header_probe", map[string]any{
		"target": "example.com",
		"ips":    []any{},
	})
	if !res.IsError {
		t.Fatal("expected error for empty ips list")
	}
}

func TestHostHeaderProbe_InvalidIPsFiltered(t *testing.T) {
	// All entries are non-IP strings — after filtering, seedIPs is empty.
	s := newTestServer(t)
	res := callTool(t, s, "unearth_host_header_probe", map[string]any{
		"target": "example.com",
		"ips":    []any{"not-an-ip", 42.0, nil},
	})
	if !res.IsError {
		t.Fatal("expected error when all ips entries are invalid")
	}
}

// ── keyless path (no API keys) ────────────────────────────────────────────────

func TestKeylessPath_ServerBuildsWithNoKeys(t *testing.T) {
	// The server must register all tools without panicking when no API keys are set.
	s := newTestServer(t)
	if s == nil {
		t.Fatal("server is nil")
	}
	// Verify all eight tools are registered.
	tools := []string{
		"unearth_discover",
		"unearth_cert_fingerprint",
		"unearth_dns_history",
		"unearth_subdomain_enum",
		"unearth_host_header_probe",
		"unearth_check_cdn",
		"unearth_is_cdn_ip",
		"unearth_list_techniques",
	}
	for _, name := range tools {
		if s.GetTool(name) == nil {
			t.Errorf("tool %q not registered on keyless server", name)
		}
	}
}

// ── result shape ─────────────────────────────────────────────────────────────

func TestResultJSON_WellFormed(t *testing.T) {
	type sample struct {
		Foo string `json:"foo"`
	}
	out := resultToJSON(sample{Foo: "bar"})
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("resultToJSON produced invalid JSON: %v — output: %s", err, out)
	}
	if m["foo"] != "bar" {
		t.Fatalf("expected foo=bar, got %v", m["foo"])
	}
}

// ── baseOpts tier parsing ─────────────────────────────────────────────────────

func TestBaseOpts_TierParsing(t *testing.T) {
	cases := []struct {
		in   string
		want techniques.Tier
	}{
		{"passive", techniques.TierPassive},
		{"active", techniques.TierActive},
		{"aggressive", techniques.TierAggressive},
		{"", techniques.TierPassive},
		{"unknown", techniques.TierPassive},
	}
	for _, tc := range cases {
		got := baseOpts(tc.in, techniques.APIKeys{}).Tier
		if got != tc.want {
			t.Errorf("baseOpts(%q).Tier = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// ── MCP server does not panic on a bad tool call ──────────────────────────────

func TestBadToolCall_UnknownTool(t *testing.T) {
	s := newTestServer(t)
	// GetTool returns nil for unknown tools — that is the expected behavior.
	if st := s.GetTool("nonexistent_tool"); st != nil {
		t.Fatalf("expected nil for unknown tool, got %v", st)
	}
}

// ── dns_history returns key-missing error with no keys ────────────────────────

func TestDNSHistory_KeyMissingError(t *testing.T) {
	// With no API keys, dns_history requires a key and the handler returns an
	// IsError result (via RunTechnique's RequiresAPIKey check), not a panic.
	s := newTestServer(t)
	res := callTool(t, s, "unearth_dns_history", map[string]any{"target": "example.com"})
	if !res.IsError {
		t.Fatal("expected IsError=true for dns_history with no keys, got non-error")
	}
}

// ── subdomain_enum: valid target, no keys (no key required) ──────────────────

func TestSubdomainEnum_ValidTarget_NoKeys(t *testing.T) {
	// subdomain_enum doesn't require an API key. With a cancelled context,
	// the tool should return a tool-level error (context cancelled), not panic.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	s := newTestServer(t)
	st := s.GetTool("unearth_subdomain_enum")
	if st == nil {
		t.Fatal("unearth_subdomain_enum not registered")
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = "unearth_subdomain_enum"
	req.Params.Arguments = map[string]any{"target": "example.com"}
	// Use the cancelled context directly — the handler receives it and passes
	// it through to RunTechnique, which honours context cancellation.
	result, err := st.Handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	// Result may or may not be IsError depending on how quickly the technique
	// sees the cancellation, but it must not panic.
	_ = result
}

// ── cert_fingerprint: valid target, no keys (only ct_fingerprint runs) ───────

func TestCertFingerprint_ValidTarget_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := newTestServer(t)
	st := s.GetTool("unearth_cert_fingerprint")
	if st == nil {
		t.Fatal("unearth_cert_fingerprint not registered")
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = "unearth_cert_fingerprint"
	req.Params.Arguments = map[string]any{"target": "example.com"}
	result, err := st.Handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	_ = result
}

// ── host_header_probe: valid target + IPs, cancelled context ─────────────────

func TestHostHeaderProbe_ValidArgs_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := newTestServer(t)
	st := s.GetTool("unearth_host_header_probe")
	if st == nil {
		t.Fatal("unearth_host_header_probe not registered")
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = "unearth_host_header_probe"
	req.Params.Arguments = map[string]any{
		"target": "example.com",
		"ips":    []any{"1.2.3.4"},
	}
	result, err := st.Handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	_ = result
}

// ── discover: valid target, cancelled context ─────────────────────────────────

func TestDiscover_ValidTarget_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := newTestServer(t)
	st := s.GetTool("unearth_discover")
	if st == nil {
		t.Fatal("unearth_discover not registered")
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = "unearth_discover"
	req.Params.Arguments = map[string]any{"target": "example.com"}
	result, err := st.Handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	// With cancelled context, Discover returns a "context cancelled" error —
	// the handler should surface it as IsError=true, not panic.
	if result == nil {
		t.Fatal("result should not be nil")
	}
}

// ── unearth_check_cdn ────────────────────────────────────────────────────────

func TestCheckCDN_MissingTarget(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_check_cdn", map[string]any{})
	if !res.IsError {
		t.Fatal("expected error result for missing target")
	}
}

func TestCheckCDN_EmptyTarget(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_check_cdn", map[string]any{"target": ""})
	if !res.IsError {
		t.Fatal("expected error result for empty target")
	}
}

func TestCheckCDN_ValidTarget_CancelledContext(t *testing.T) {
	// With a cancelled context the DNS/HTTP probes fail immediately; the tool
	// must still return a well-formed (non-panic) result, not a transport error.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := newTestServer(t)
	st := s.GetTool("unearth_check_cdn")
	if st == nil {
		t.Fatal("unearth_check_cdn not registered")
	}
	req := mcp.CallToolRequest{}
	req.Params.Name = "unearth_check_cdn"
	req.Params.Arguments = map[string]any{"target": "example.com"}
	result, err := st.Handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if result == nil {
		t.Fatal("result must not be nil")
	}
	// Result should not be IsError — detection failure surfaces as a Warning
	// field in the JSON, not as a tool-level error.
	if result.IsError {
		t.Error("check_cdn should return a result envelope even when DNS/HTTP fail, not IsError")
	}
}

func TestCheckCDN_ResultJSON_WellFormed(t *testing.T) {
	// Use a cancelled context to avoid real network calls; we only care about
	// the JSON shape of the result.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := newTestServer(t)
	st := s.GetTool("unearth_check_cdn")
	req := mcp.CallToolRequest{}
	req.Params.Name = "unearth_check_cdn"
	req.Params.Arguments = map[string]any{"target": "example.com"}
	result, _ := st.Handler(ctx, req)
	if result == nil || result.IsError {
		t.Skip("skipping JSON shape check: no result or error result")
	}
	if len(result.Content) == 0 {
		t.Fatal("result content is empty")
	}
	text, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatal("result content[0] is not TextContent")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(text.Text), &m); err != nil {
		t.Fatalf("result JSON is invalid: %v — text: %s", err, text.Text)
	}
	// Required keys: target, cdn, signals.
	for _, key := range []string{"target", "cdn", "signals"} {
		if _, ok := m[key]; !ok {
			t.Errorf("result JSON missing key %q", key)
		}
	}
}

// ── unearth_is_cdn_ip ────────────────────────────────────────────────────────

func TestIsCDNIP_MissingIPs(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_is_cdn_ip", map[string]any{})
	if !res.IsError {
		t.Fatal("expected error for missing ips")
	}
}

func TestIsCDNIP_EmptyIPList(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_is_cdn_ip", map[string]any{"ips": []any{}})
	if !res.IsError {
		t.Fatal("expected error for empty ips list")
	}
}

func TestIsCDNIP_KnownCDNIP(t *testing.T) {
	// 104.16.0.1 is in Cloudflare's 104.16.0.0/12 range.
	s := newTestServer(t)
	res := callTool(t, s, "unearth_is_cdn_ip", map[string]any{
		"ips": []any{"104.16.0.1"},
	})
	if res.IsError {
		t.Fatalf("unexpected error: %v", res.Content)
	}
	text, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatal("expected TextContent")
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(text.Text), &rows); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 result, got %d", len(rows))
	}
	if rows[0]["is_cdn"] != true {
		t.Errorf("expected is_cdn=true for Cloudflare IP, got %v", rows[0]["is_cdn"])
	}
	if rows[0]["provider"] == "" {
		t.Error("expected non-empty provider for CDN IP")
	}
}

func TestIsCDNIP_NonCDNIP(t *testing.T) {
	// 192.0.2.1 is in TEST-NET-1 (documentation range) and not in any CDN range.
	s := newTestServer(t)
	res := callTool(t, s, "unearth_is_cdn_ip", map[string]any{
		"ips": []any{"192.0.2.1"},
	})
	if res.IsError {
		t.Fatalf("unexpected error: %v", res.Content)
	}
	text, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatal("expected TextContent")
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(text.Text), &rows); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 result, got %d", len(rows))
	}
	if rows[0]["is_cdn"] != false {
		t.Errorf("expected is_cdn=false for non-CDN IP, got %v", rows[0]["is_cdn"])
	}
}

func TestIsCDNIP_InvalidIP(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_is_cdn_ip", map[string]any{
		"ips": []any{"not-an-ip"},
	})
	if res.IsError {
		t.Fatal("invalid IP in list should not cause a tool-level error; each entry gets an error field")
	}
	text, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatal("expected TextContent")
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(text.Text), &rows); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 result, got %d", len(rows))
	}
	if rows[0]["error"] == "" || rows[0]["error"] == nil {
		t.Error("expected error field for invalid IP")
	}
}

func TestIsCDNIP_MixedBatch(t *testing.T) {
	// Three IPs: one CDN, one non-CDN, one invalid. Result order matches input.
	s := newTestServer(t)
	res := callTool(t, s, "unearth_is_cdn_ip", map[string]any{
		"ips": []any{"104.16.0.1", "192.0.2.1", "bad"},
	})
	if res.IsError {
		t.Fatalf("unexpected tool error")
	}
	text, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatal("expected TextContent")
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(text.Text), &rows); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 results, got %d", len(rows))
	}
	if rows[0]["is_cdn"] != true {
		t.Errorf("row[0]: expected is_cdn=true")
	}
	if rows[1]["is_cdn"] != false {
		t.Errorf("row[1]: expected is_cdn=false")
	}
	if rows[2]["error"] == "" || rows[2]["error"] == nil {
		t.Errorf("row[2]: expected error field for invalid IP")
	}
}

// ── unearth_list_techniques ───────────────────────────────────────────────────

func TestListTechniques_ReturnsNonEmptyList(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_list_techniques", map[string]any{})
	if res.IsError {
		t.Fatalf("unexpected error: %v", res.Content)
	}
	text, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatal("expected TextContent")
	}
	var items []map[string]any
	if err := json.Unmarshal([]byte(text.Text), &items); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(items) == 0 {
		t.Fatal("expected at least one technique in the list")
	}
}

func TestListTechniques_ItemShape(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_list_techniques", map[string]any{})
	if res.IsError {
		t.Fatalf("unexpected error: %v", res.Content)
	}
	text, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatal("expected TextContent")
	}
	var items []map[string]any
	if err := json.Unmarshal([]byte(text.Text), &items); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for i, item := range items {
		for _, key := range []string{"name", "tier", "requires_api_key", "default_weight"} {
			if _, ok := item[key]; !ok {
				t.Errorf("items[%d] missing key %q", i, key)
			}
		}
		name, _ := item["name"].(string)
		if name == "" {
			t.Errorf("items[%d]: name is empty", i)
		}
		tier, _ := item["tier"].(string)
		validTiers := map[string]bool{"passive": true, "active": true, "aggressive": true}
		if !validTiers[tier] {
			t.Errorf("items[%d] (%s): unexpected tier %q", i, name, tier)
		}
		weight, _ := item["default_weight"].(float64)
		if weight <= 0 || weight > 1 {
			t.Errorf("items[%d] (%s): default_weight %v not in (0,1]", i, name, weight)
		}
	}
}

func TestListTechniques_ContainsKnownTechniques(t *testing.T) {
	s := newTestServer(t)
	res := callTool(t, s, "unearth_list_techniques", map[string]any{})
	if res.IsError {
		t.Fatalf("unexpected error: %v", res.Content)
	}
	text, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatal("expected TextContent")
	}
	var items []map[string]any
	if err := json.Unmarshal([]byte(text.Text), &items); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	names := make(map[string]bool, len(items))
	for _, item := range items {
		if n, ok := item["name"].(string); ok {
			names[n] = true
		}
	}
	for _, must := range []string{"ct_fingerprint", "crtsh", "host_header", "fofa_cert", "netlas_cert", "criminalip_asset", "jarm_fingerprint"} {
		if !names[must] {
			t.Errorf("technique %q not found in list_techniques output", must)
		}
	}
}
