package techniques

import (
	"context"
	"net/mail"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(emailHeaderTechnique{}) }

// emailHeaderTechnique mines the Received: header chain of an operator-supplied
// email message (.eml file) for IP addresses that frequently reveal a
// CDN-bypassed origin.
//
// Email infrastructure is almost never routed through the CDN that fronts a
// website, yet it often shares the same datacenter — or even the same host — as
// the web origin. The Received: chain that a mail transfer agent stamps onto an
// inbound message records each relay hop, exposing internal relay IPs with high
// confidence.
//
// Only the passive variant is implemented: it reads a local .eml file the
// operator already possesses (a newsletter, a password-reset mail, a bounce)
// and never contacts the target. When no file is supplied via
// RunOptions.EmailFile, the technique skips gracefully and returns no
// candidates. The active "send a probe and read the bounce" variant described
// in POST_V01.md requires operator SMTP infrastructure and is deliberately left
// out of scope.
type emailHeaderTechnique struct{}

func (emailHeaderTechnique) Name() string           { return "email_header" }
func (emailHeaderTechnique) Tier() Tier             { return TierPassive }
func (emailHeaderTechnique) RequiresAPIKey() bool   { return false }
func (emailHeaderTechnique) DefaultWeight() float64 { return 0.85 }

// receivedIPPattern matches bracketed or bare IPv4/IPv6 literals as they appear
// inside Received: headers, e.g. "from mx.example.com ([203.0.113.10])" or
// "from relay (HELO relay) ([2001:db8::1])". The address itself is captured in
// group 1.
var receivedIPPattern = regexp.MustCompile(
	`[\[\(]?\b(` +
		// IPv4
		`(?:\d{1,3}\.){3}\d{1,3}` +
		`|` +
		// IPv6 (loose: hex groups and colons, at least one "::" or two colons)
		`(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}` +
		`)[\]\)]?`,
)

func (emailHeaderTechnique) Run(ctx context.Context, _ string, opts RunOptions) ([]Candidate, error) {
	if strings.TrimSpace(opts.EmailFile) == "" {
		// No operator-supplied message — nothing to parse. Skip silently.
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	raw, err := os.ReadFile(opts.EmailFile) // #nosec G304 — operator-supplied path is the point
	if err != nil {
		return nil, err
	}

	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		return nil, err
	}

	// The Received: chain is ordered most-recent-first. Walk every Received:
	// header and extract candidate literals from each.
	received := msg.Header["Received"]

	seen := map[netip.Addr]bool{}
	var out []Candidate
	add := func(a netip.Addr, header string) {
		a = a.Unmap()
		if !a.IsValid() || seen[a] {
			return
		}
		if isPrivateAddr(a) || cdn.IsCDNIP(a) {
			return
		}
		seen[a] = true
		out = append(out, Candidate{
			IP: a.String(),
			Evidence: "email Received: header exposes non-CDN relay IP " + a.String() +
				" (" + summarizeReceived(header) + ")",
		})
	}

	for _, hdr := range received {
		for _, m := range receivedIPPattern.FindAllStringSubmatch(hdr, -1) {
			lit := strings.Trim(m[1], "[]()")
			a, err := netip.ParseAddr(lit)
			if err != nil {
				continue
			}
			add(a, hdr)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, nil
}

// isPrivateAddr reports whether a is an address class that can never be a real
// public origin: RFC1918 / unique-local, loopback, link-local, multicast, or
// the unspecified address.
func isPrivateAddr(a netip.Addr) bool {
	return a.IsPrivate() ||
		a.IsLoopback() ||
		a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() ||
		a.IsMulticast() ||
		a.IsUnspecified()
}

// summarizeReceived collapses a Received: header to a single compact line so it
// reads cleanly as evidence. Multi-line headers (folded with leading
// whitespace) are joined and runs of whitespace are squeezed.
func summarizeReceived(hdr string) string {
	s := strings.Join(strings.Fields(hdr), " ")
	const max = 120
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}
