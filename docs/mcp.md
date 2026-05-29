# MCP Server Integration Guide

`unearth-mcp` is an MCP (Model Context Protocol) server that exposes `unearth`'s discovery capabilities as discrete tools. An AI agent can call these tools directly instead of shelling out to the `unearth` CLI.

The server uses a **stdio transport**: it reads JSON-RPC requests from stdin and writes responses to stdout. All diagnostics go to stderr — stdout is the exclusive protocol channel.

---

## Building

```sh
# Build both binaries
make build

# Build only the MCP server
make mcp

# Both land in ./dist/
ls dist/
# unearth  unearth-mcp
```

Or install directly:

```sh
go install github.com/unearth-tool/unearth/cmd/unearth-mcp@latest
```

---

## Client configuration

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or the equivalent on your platform:

```json
{
  "mcpServers": {
    "unearth": {
      "command": "/path/to/unearth-mcp",
      "env": {
        "CENSYS_PLATFORM_PAT": "your-censys-pat",
        "SECURITYTRAILS_API_KEY": "your-st-key",
        "SHODAN_API_KEY": "your-shodan-key"
      }
    }
  }
}
```

No environment keys are required. Omitting a key causes the corresponding technique to be skipped gracefully.

### Generic MCP client

Any MCP client that supports stdio transport can launch the server:

```json
{
  "command": "unearth-mcp",
  "transport": "stdio"
}
```

---

## API keys

The server loads API keys from its process environment using the same variable names as the CLI:

| Env var | Unlocks |
|---|---|
| `CENSYS_PLATFORM_PAT` | `censys_cert` in `unearth_discover` and `unearth_cert_fingerprint` |
| `SECURITYTRAILS_API_KEY` | `dns_history` |
| `VIEWDNS_API_KEY` | `dns_history` (fallback) |
| `SHODAN_API_KEY` | `shodan_cert` in `unearth_discover` |
| `FOFA_EMAIL` + `FOFA_KEY` | `fofa_cert` in `unearth_discover` and `unearth_cert_fingerprint` (both required) |
| `NETLAS_API_KEY` | `netlas_cert` in `unearth_discover` and `unearth_cert_fingerprint` |
| `CRIMINALIP_API_KEY` | `criminalip_asset` in `unearth_discover` and `unearth_cert_fingerprint` |

Keys are passed via the MCP client's `env` configuration block (see above) — the server never prompts for them.

---

## Tools

### `unearth_discover`

Runs the full origin-discovery pipeline and returns ranked candidate IPs.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `target` | string | Yes | Domain name to investigate, e.g. `example.com` |
| `tier` | string | No | Technique tier: `passive` (default), `active`, or `aggressive` |

**Result:** A JSON object matching `pkg/unearth.Result`:

```json
{
  "target": "example.com",
  "cdn_detected": "cloudflare",
  "candidates": [
    {
      "candidate_ip": "93.184.216.34",
      "score": 0.82,
      "corroboration": 3,
      "single_source": false,
      "techniques": [
        {"name": "ct_fingerprint", "weight": 0.70, "evidence": "ct_fingerprint/kaeferjaeger: ..."},
        {"name": "crtsh", "weight": 0.55, "evidence": "crt.sh: certificate for origin.example.com resolves to ..."},
        {"name": "spf_mx", "weight": 0.50, "evidence": "MX mail.example.com resolves to ..."}
      ]
    }
  ],
  "timestamp": "2026-05-17T10:00:00Z",
  "errors": [
    {"technique": "dns_history", "error": "technique requires an API key", "reason": "missing_api_key"}
  ]
}
```

---

### `unearth_cert_fingerprint`

Runs certificate-fingerprint pivot techniques. Always runs `ct_fingerprint` (keyless). Also runs `censys_cert`, `shodan_cert`, `fofa_cert`, `netlas_cert`, and `criminalip_asset` when their API keys are present.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `target` | string | Yes | Domain name to investigate |

**Result:** A JSON array of per-technique results:

```json
[
  {
    "technique": "ct_fingerprint",
    "candidates": [
      {"ip": "93.184.216.34", "evidence": "ct_fingerprint/kaeferjaeger: ..."}
    ]
  },
  {
    "technique": "censys_cert",
    "error": "technique \"censys_cert\" requires an API key (missing_api_key)"
  }
]
```

---

### `unearth_dns_history`

Queries historical DNS A/AAAA records for the target via the `dns_history` technique.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `target` | string | Yes | Domain name to investigate |

**Result:** JSON array of `techniques.Candidate` objects:

```json
[{"ip": "203.0.113.5", "evidence": "SecurityTrails: historical A record for example.com → 203.0.113.5"}]
```

**Note:** Returns a tool-level error (`isError: true`) when no DNS history key is configured.

---

### `unearth_subdomain_enum`

Enumerates subdomains of the target and resolves them to candidate origin IPs.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `target` | string | Yes | Domain name to investigate |

**Result:** JSON array of `techniques.Candidate` objects.

---

### `unearth_host_header_probe`

Probes a caller-supplied list of IPs by sending HTTP requests with `Host: target`. IPs that serve the target's content without CDN markers are returned as confirmed origin candidates.

**Parameters:**

| Name | Type | Required | Description |
|---|---|---|---|
| `target` | string | Yes | Domain name to use as the `Host` header value |
| `ips` | array of strings | Yes | IP addresses to probe, e.g. `["93.184.216.34", "1.2.3.4"]` |

**Result:** JSON array of `techniques.Candidate` objects for IPs that passed the probe.

**Note:** This tool uses the active tier. Pass IPs from a prior `unearth_discover` or `unearth_cert_fingerprint` call.

---

## Error handling

All tools return structured results even on failure. A tool-level error (parameter validation failure, technique error, network failure) sets `isError: true` in the result — the server process does not crash. Context cancellation from the MCP layer propagates to the underlying library calls and terminates them cleanly.

---

## Diagnostics

The server writes startup diagnostics and per-run warnings to stderr. In Claude Desktop, these appear in the server log. In a custom client, capture stderr separately from stdout.

Example stderr output (key status):

```
unearth: censys:         skipped (no key)
unearth: shodan:         unlocked
unearth: securitytrails: unlocked
unearth: viewdns:        skipped (no key)
```
