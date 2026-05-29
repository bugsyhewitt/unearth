// Command unearth-mcp exposes unearth's origin-discovery capabilities over
// the Model Context Protocol via a stdio transport.
//
// The server reads JSON-RPC requests from stdin and writes responses to
// stdout. All diagnostics are written to stderr. An AI agent that launches
// this process and wires up the stdio streams gets access to five tools:
//
//   - unearth_discover          — full ranked pipeline
//   - unearth_cert_fingerprint  — keyless cert-pivot technique
//   - unearth_dns_history       — DNS history lookup
//   - unearth_subdomain_enum    — subdomain enumeration
//   - unearth_host_header_probe — host-header validation against caller-supplied IPs
//
// API keys are loaded from the environment using the same env vars as the CLI.
// With no keys, keyless techniques (ct_fingerprint, crtsh, spf_mx, …) still run.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/unearth-tool/unearth/pkg/config"
	"github.com/unearth-tool/unearth/pkg/techniques"
	"github.com/unearth-tool/unearth/pkg/unearth"

	// Register all techniques via their init functions.
	_ "github.com/unearth-tool/unearth/pkg/techniques"
)

func main() {
	keys := config.LoadAPIKeys()

	s := server.NewMCPServer(
		"unearth-mcp",
		"1.0.0",
		server.WithToolCapabilities(false),
		server.WithRecovery(),
	)

	registerDiscover(s, keys)
	registerCertFingerprint(s, keys)
	registerDNSHistory(s, keys)
	registerSubdomainEnum(s, keys)
	registerHostHeaderProbe(s, keys)

	if err := server.ServeStdio(s); err != nil {
		fmt.Fprintf(os.Stderr, "unearth-mcp: %v\n", err)
		os.Exit(1)
	}
}

// baseOpts returns Options populated from a tools-supplied tier string and
// the process-level API keys. It is used by the single-technique tools.
func baseOpts(tier string, keys techniques.APIKeys) unearth.Options {
	opts := unearth.DefaultOptions()
	opts.APIKeys = keys
	switch tier {
	case "active":
		opts.Tier = techniques.TierActive
	case "aggressive":
		opts.Tier = techniques.TierAggressive
	default:
		opts.Tier = techniques.TierPassive
	}
	return opts
}

// resultToJSON marshals v to a compact JSON string for tool result content.
func resultToJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"error":"marshal failed"}`
	}
	return string(b)
}

// ── unearth_discover ─────────────────────────────────────────────────────────

func registerDiscover(s *server.MCPServer, keys techniques.APIKeys) {
	tool := mcp.NewTool("unearth_discover",
		mcp.WithDescription("Run the full unearth origin-discovery pipeline against a target and return ranked candidate IPs."),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("The domain name to investigate, e.g. example.com"),
		),
		mcp.WithString("tier",
			mcp.Description("Technique aggression tier: passive (default), active, or aggressive"),
		),
	)
	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		target, err := req.RequireString("target")
		if err != nil || target == "" {
			return mcp.NewToolResultError("target is required"), nil
		}
		tier, _ := req.GetArguments()["tier"].(string)

		opts := baseOpts(tier, keys)
		result, err := unearth.Discover(ctx, target, opts)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("discover failed: %v", err)), nil
		}
		return mcp.NewToolResultText(resultToJSON(result)), nil
	})
}

// ── unearth_cert_fingerprint ─────────────────────────────────────────────────

func registerCertFingerprint(s *server.MCPServer, keys techniques.APIKeys) {
	tool := mcp.NewTool("unearth_cert_fingerprint",
		mcp.WithDescription("Run cert-fingerprint pivoting techniques against a target. Always runs ct_fingerprint (keyless). Also runs censys_cert, shodan_cert, fofa_cert, netlas_cert, and criminalip_asset if the required API keys are set in the server's environment."),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("The domain name to investigate, e.g. example.com"),
		),
	)
	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		target, err := req.RequireString("target")
		if err != nil || target == "" {
			return mcp.NewToolResultError("target is required"), nil
		}

		opts := baseOpts("passive", keys)
		techNames := []string{"ct_fingerprint"}
		if keys.CensysPlatformPAT != "" {
			techNames = append(techNames, "censys_cert")
		}
		if keys.ShodanAPIKey != "" {
			techNames = append(techNames, "shodan_cert")
		}
		if keys.FOFAEmail != "" && keys.FOFAKey != "" {
			techNames = append(techNames, "fofa_cert")
		}
		if keys.NetlasAPIKey != "" {
			techNames = append(techNames, "netlas_cert")
		}
		if keys.CriminalIPKey != "" {
			techNames = append(techNames, "criminalip_asset")
		}

		type techResult struct {
			Technique  string                 `json:"technique"`
			Candidates []techniques.Candidate `json:"candidates,omitempty"`
			Error      string                 `json:"error,omitempty"`
		}
		var results []techResult
		for _, name := range techNames {
			cands, err := unearth.RunTechnique(ctx, name, target, opts, nil)
			r := techResult{Technique: name}
			if err != nil {
				r.Error = err.Error()
			} else {
				r.Candidates = cands
			}
			results = append(results, r)
		}
		return mcp.NewToolResultText(resultToJSON(results)), nil
	})
}

// ── unearth_dns_history ───────────────────────────────────────────────────────

func registerDNSHistory(s *server.MCPServer, keys techniques.APIKeys) {
	tool := mcp.NewTool("unearth_dns_history",
		mcp.WithDescription("Query historical DNS records for a target via the dns_history technique. Requires SECURITYTRAILS_API_KEY or VIEWDNS_API_KEY in the server's environment."),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("The domain name to investigate, e.g. example.com"),
		),
	)
	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		target, err := req.RequireString("target")
		if err != nil || target == "" {
			return mcp.NewToolResultError("target is required"), nil
		}
		opts := baseOpts("passive", keys)
		cands, err := unearth.RunTechnique(ctx, "dns_history", target, opts, nil)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(resultToJSON(cands)), nil
	})
}

// ── unearth_subdomain_enum ────────────────────────────────────────────────────

func registerSubdomainEnum(s *server.MCPServer, keys techniques.APIKeys) {
	tool := mcp.NewTool("unearth_subdomain_enum",
		mcp.WithDescription("Enumerate subdomains of a target using the subdomain_enum technique and resolve them to candidate origin IPs."),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("The domain name to investigate, e.g. example.com"),
		),
	)
	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		target, err := req.RequireString("target")
		if err != nil || target == "" {
			return mcp.NewToolResultError("target is required"), nil
		}
		opts := baseOpts("passive", keys)
		cands, err := unearth.RunTechnique(ctx, "subdomain_enum", target, opts, nil)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(resultToJSON(cands)), nil
	})
}

// ── unearth_host_header_probe ─────────────────────────────────────────────────

func registerHostHeaderProbe(s *server.MCPServer, keys techniques.APIKeys) {
	tool := mcp.NewTool("unearth_host_header_probe",
		mcp.WithDescription("Send HTTP requests with the Host header set to target against a caller-supplied list of candidate IPs. IPs that serve the target's content without CDN markers are returned as confirmed origin candidates."),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("The domain name to use as the Host header value, e.g. example.com"),
		),
		mcp.WithArray("ips",
			mcp.Required(),
			mcp.Description("Array of IP address strings to probe, e.g. [\"1.2.3.4\", \"5.6.7.8\"]"),
		),
	)
	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		target, err := req.RequireString("target")
		if err != nil || target == "" {
			return mcp.NewToolResultError("target is required"), nil
		}

		rawIPs, ok := req.GetArguments()["ips"].([]any)
		if !ok || len(rawIPs) == 0 {
			return mcp.NewToolResultError("ips must be a non-empty array of IP strings"), nil
		}
		var seedIPs []string
		for _, v := range rawIPs {
			ipStr, ok := v.(string)
			if !ok || ipStr == "" {
				continue
			}
			if _, err := netip.ParseAddr(ipStr); err != nil {
				continue // skip non-IP strings silently
			}
			seedIPs = append(seedIPs, ipStr)
		}
		if len(seedIPs) == 0 {
			return mcp.NewToolResultError("ips must contain at least one valid IP address string"), nil
		}

		opts := baseOpts("active", keys)
		cands, err := unearth.RunTechnique(ctx, "host_header", target, opts, seedIPs)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(resultToJSON(cands)), nil
	})
}
