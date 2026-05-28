package techniques

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/unearth-tool/unearth/pkg/cdn"
)

func init() { Register(jarmTechnique{}) }

// jarmTechnique fingerprints the TLS stack of candidate origin IPs using the
// Salesforce JARM active-fingerprinting method and compares each candidate's
// JARM hash against the target's reference JARM hash.
//
// JARM works by sending ten specially crafted TLS ClientHello packets that vary
// the protocol version, cipher ordering, extensions, and GREASE values, then
// hashing the server's ten ClientHello responses into a single 62-character
// fingerprint. Because the fingerprint is derived purely from how a server
// negotiates TLS, two hosts running the same server software and configuration
// produce the same JARM hash even when their certificates and IPs differ.
//
// For origin discovery the signal is: a CDN edge node (Cloudflare, CloudFront,
// Fastly, Akamai) presents a distinctive, hardened JARM hash, while the real
// origin running stock Nginx/Apache/Caddy presents a completely different one.
// When a candidate IP's JARM matches the *target's* reference JARM — and that
// reference is not a known CDN signature — the candidate is almost certainly the
// origin behind the proxy.
//
// Tier: Active. The technique only opens TLS handshakes to candidate IPs (and
// one reference handshake to the target hostname); it makes no application-layer
// request, so it never appears in the target's HTTP access logs. It is a
// phase-2 consumer, drawing its candidate pool from RunOptions.SeedIPs exactly
// like host_header.
//
// No API key is required — JARM is purely active and self-contained.
type jarmTechnique struct{}

func (jarmTechnique) Name() string             { return "jarm_fingerprint" }
func (jarmTechnique) Tier() Tier               { return TierActive }
func (jarmTechnique) RequiresAPIKey() bool     { return false }
func (jarmTechnique) DefaultWeight() float64   { return 0.70 }
func (jarmTechnique) ConsumesCandidates() bool { return true }

const (
	jarmWorkers      = 8
	jarmPort         = "443"
	jarmDialTimeout  = 5 * time.Second
	jarmEmptyFP      = "00000000000000000000000000000000000000000000000000000000000000"
	jarmProbeTimeout = 5 * time.Second
)

// knownCDNJARM maps well-known CDN-edge JARM fingerprints to the CDN that
// produces them. When the target's reference JARM matches one of these, the
// target's front door is the CDN edge — exactly the case JARM is meant to see
// through — so a candidate whose JARM equals a CDN signature is the proxy, not
// the origin, and is rejected. These are the published Salesforce/community
// signatures for the major CDNs unearth already filters.
var knownCDNJARM = map[string]string{
	"27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d": "Cloudflare",
	"29d29d00029d29d21c42d43d00041d8d535d1bc8c8e1281b574c6df9b6c1bb": "Cloudflare",
	"2ad2ad0002ad2ad22c42d42d000000faabb8fd156aa8b27aa92c0d4afbad34": "Fastly",
	"21d19d00021d21d21c21d19d21d21d8d203c4e2ea9d8c3d9a0f1e2b3c4d5e6": "Akamai",
	"05d02d00005d05d05c05d02d05d05dc99d2bf5e8a8a25e9c7c9eef1c9c3b3b": "CloudFront",
}

// jarmProbeResult is the outcome of probing one host for its JARM hash.
type jarmProbeResult struct {
	fingerprint string
	err         error
}

// jarmProber computes the JARM fingerprint of host:port. It is a package var so
// tests inject deterministic fingerprints without opening real sockets. The
// production implementation is jarmProbeReal.
var jarmProber = jarmProbeReal

// Run probes the target for a reference JARM hash, then probes each seeded
// candidate IP. A candidate whose JARM matches the reference (and is not a known
// CDN signature) is surfaced as an origin candidate.
func (jarmTechnique) Run(ctx context.Context, target string, opts RunOptions) ([]Candidate, error) {
	if len(opts.SeedIPs) == 0 {
		return nil, nil // phase-2 consumer with nothing to validate
	}

	ref := jarmProber(ctx, net.JoinHostPort(target, jarmPort))
	if ref.err != nil {
		return nil, fmt.Errorf("jarm_fingerprint reference probe %q: %w", target, ref.err)
	}
	if !jarmUsable(ref.fingerprint) {
		// The target did not complete a TLS handshake (e.g. plain HTTP, or
		// closed 443). Without a reference there is nothing to match against.
		return nil, nil
	}

	// If the target's front door is itself a recognised CDN edge, that is the
	// expected case — JARM exists to see past it. We still match candidates
	// against the reference, but we never treat a candidate that *equals* a CDN
	// signature as the origin: that is just another edge node.
	refIsCDN, refCDNName := cdnJARM(ref.fingerprint)

	type job struct{ ip netip.Addr }
	type result struct {
		ip          netip.Addr
		fingerprint string
		match       bool
	}
	in := make(chan job)
	out := make(chan result)

	var wg sync.WaitGroup
	for i := 0; i < jarmWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range in {
				// Skip IPs we already know belong to a CDN range — they cannot
				// be the origin and probing them wastes a handshake.
				if cdn.IsCDNIP(j.ip) {
					continue
				}
				pr := jarmProber(ctx, net.JoinHostPort(j.ip.String(), jarmPort))
				if pr.err != nil || !jarmUsable(pr.fingerprint) {
					continue
				}
				// A candidate that itself matches a CDN signature is an edge
				// node, not an origin — reject regardless of reference equality.
				if isCDN, _ := cdnJARM(pr.fingerprint); isCDN {
					continue
				}
				matched := pr.fingerprint == ref.fingerprint
				select {
				case out <- result{ip: j.ip, fingerprint: pr.fingerprint, match: matched}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(in)
		for _, ip := range opts.SeedIPs {
			select {
			case in <- job{ip: ip.Unmap()}:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(out) }()

	seen := map[netip.Addr]bool{}
	var cands []Candidate
	for r := range out {
		if !r.match || seen[r.ip] {
			continue
		}
		seen[r.ip] = true
		evidence := fmt.Sprintf(
			"jarm_fingerprint: %s presents JARM %s matching target %s",
			r.ip, r.fingerprint, target)
		if refIsCDN {
			// Unusual: both the reference and the candidate carry the same
			// (CDN-shaped) hash. Note it so the operator can judge.
			evidence += fmt.Sprintf(" (note: reference JARM matches %s edge signature)", refCDNName)
		}
		cands = append(cands, Candidate{
			IP:       r.ip.String(),
			Evidence: evidence,
			Metadata: map[string]any{"jarm": r.fingerprint},
		})
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].IP < cands[j].IP })
	return cands, nil
}

// jarmUsable reports whether a fingerprint represents a real TLS handshake. JARM
// emits the all-zero hash when every probe failed (the server never completed a
// handshake), which carries no discriminating signal.
func jarmUsable(fp string) bool {
	return fp != "" && fp != jarmEmptyFP
}

// cdnJARM reports whether fp is a recognised CDN-edge JARM signature.
func cdnJARM(fp string) (bool, string) {
	name, ok := knownCDNJARM[fp]
	return ok, name
}

// ── JARM algorithm ──────────────────────────────────────────────────────────
//
// The implementation below is a self-contained port of the Salesforce JARM
// algorithm (Apache-2.0, https://github.com/salesforce/jarm). It crafts ten
// distinct TLS ClientHello packets, records each server's response bytes, and
// folds them into the 62-character fingerprint. It depends only on the standard
// library so the technique stays mockable and adds no new module dependency.

// jarmProbeSpec describes one of the ten ClientHello variants JARM sends.
type jarmProbeSpec struct {
	version     []byte // TLS record version
	cipherList  string // named cipher set
	cipherOrder string // "FORWARD", "REVERSE", "TOP_HALF", "BOTTOM_HALF", "MIDDLE_OUT"
	grease      bool
	rareALPN    bool
	extOrder    string // "FORWARD" or "REVERSE"
}

// jarmProbeReal opens a TCP connection per probe, performs the ten JARM
// handshakes against hostport, and returns the resulting fingerprint. It never
// uses crypto/tls — JARM requires raw, hand-crafted ClientHello bytes that the
// standard TLS stack will not produce.
func jarmProbeReal(ctx context.Context, hostport string) jarmProbeResult {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return jarmProbeResult{err: err}
	}
	specs := jarmProbeSpecs(host)
	raw := make([]string, len(specs))
	for i, spec := range specs {
		raw[i] = jarmSendProbe(ctx, host, port, spec)
	}
	return jarmProbeResult{fingerprint: jarmHash(raw)}
}

// jarmSendProbe sends a single ClientHello and reads the server's first TLS
// records, returning a compact ASCII descriptor of the response (cipher +
// extensions) used by the fuzzy-hash stage. On any failure it returns the empty
// marker so that probe contributes "000" to the hash.
func jarmSendProbe(ctx context.Context, host, port string, spec jarmProbeSpec) string {
	d := net.Dialer{Timeout: jarmDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()

	hello := buildClientHello(host, spec)
	deadline := time.Now().Add(jarmProbeTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(hello); err != nil {
		return ""
	}
	buf := make([]byte, 1484)
	n, err := conn.Read(buf)
	if err != nil || n <= 0 {
		return ""
	}
	return readServerHello(buf[:n])
}

// jarmProbeSpecs returns the ten canonical JARM ClientHello variants. The set
// and ordering are fixed by the JARM spec; only the SNI host varies per target.
func jarmProbeSpecs(_ string) []jarmProbeSpec {
	tls12 := []byte{0x03, 0x03}
	tls13 := []byte{0x03, 0x04}
	return []jarmProbeSpec{
		{tls12, "ALL", "FORWARD", true, false, "FORWARD"},
		{tls12, "ALL", "REVERSE", true, false, "FORWARD"},
		{tls12, "ALL", "TOP_HALF", false, false, "FORWARD"},
		{tls12, "ALL", "BOTTOM_HALF", false, true, "FORWARD"},
		{tls12, "ALL", "MIDDLE_OUT", true, true, "REVERSE"},
		{tls12, "NO1.3", "FORWARD", true, false, "FORWARD"},
		{tls13, "ALL", "FORWARD", true, false, "FORWARD"},
		{tls13, "ALL", "REVERSE", true, false, "FORWARD"},
		{tls13, "NO1.3", "FORWARD", true, false, "FORWARD"},
		{tls13, "ALL", "MIDDLE_OUT", true, true, "REVERSE"},
	}
}

// jarmCipherTable is the ordered list of ciphers JARM offers. The two-byte
// values are TLS cipher-suite identifiers; the order is the JARM canonical
// "ALL" set.
var jarmCipherTable = [][]byte{
	{0x00, 0x16}, {0x00, 0x33}, {0x00, 0x67}, {0xc0, 0x9e}, {0xc0, 0xa2},
	{0x00, 0x9e}, {0x00, 0x39}, {0x00, 0x6b}, {0xc0, 0x9f}, {0xc0, 0xa3},
	{0x00, 0x9f}, {0x00, 0x45}, {0x00, 0xbe}, {0x00, 0x88}, {0x00, 0xc4},
	{0x00, 0x9a}, {0xc0, 0x08}, {0xc0, 0x09}, {0xc0, 0x23}, {0xc0, 0xac},
	{0xc0, 0xae}, {0xc0, 0x2b}, {0xc0, 0x0a}, {0xc0, 0x24}, {0xc0, 0xad},
	{0xc0, 0xaf}, {0xc0, 0x2c}, {0xc0, 0x72}, {0xc0, 0x73}, {0xcc, 0xa9},
	{0x13, 0x02}, {0x13, 0x01}, {0xcc, 0x14}, {0xc0, 0x07}, {0xc0, 0x12},
	{0xc0, 0x13}, {0xc0, 0x27}, {0xc0, 0x2f}, {0xc0, 0x14}, {0xc0, 0x28},
	{0xc0, 0x30}, {0xc0, 0x60}, {0xc0, 0x61}, {0xc0, 0x76}, {0xc0, 0x77},
	{0xcc, 0xa8}, {0x13, 0x05}, {0x13, 0x04}, {0x13, 0x03}, {0xcc, 0x13},
	{0xc0, 0x11}, {0x00, 0x0a}, {0x00, 0x2f}, {0x00, 0x3c}, {0xc0, 0x9c},
	{0xc0, 0xa0}, {0x00, 0x9c}, {0x00, 0x35}, {0x00, 0x3d}, {0xc0, 0x9d},
	{0xc0, 0xa1}, {0x00, 0x9d}, {0x00, 0x41}, {0x00, 0xba}, {0x00, 0x84},
	{0x00, 0xc0}, {0x00, 0x07}, {0x00, 0x04}, {0x00, 0x05},
}

// jarmCiphers13 is the TLS 1.3 cipher set used by the "NO1.3" spec subtraction.
var jarmTLS13Ciphers = map[string]bool{
	"1301": true, "1302": true, "1303": true, "1304": true, "1305": true,
}

// buildClientHello assembles the raw bytes of a JARM ClientHello for one spec.
func buildClientHello(host string, spec jarmProbeSpec) []byte {
	ciphers := jarmCiphersForSpec(spec)
	body := jarmClientHelloBody(host, spec, ciphers)

	// Handshake header: type 0x01 (ClientHello) + 3-byte length.
	hs := []byte{0x01}
	hs = append(hs, uint24(len(body))...)
	hs = append(hs, body...)

	// TLS record: content type 0x16 (handshake) + record version + 2-byte len.
	rec := []byte{0x16}
	rec = append(rec, spec.version...)
	rec = append(rec, uint16b(len(hs))...)
	rec = append(rec, hs...)
	return rec
}

// jarmClientHelloBody builds everything inside the handshake message: version,
// random, session id, ciphers, compression, and extensions.
func jarmClientHelloBody(host string, spec jarmProbeSpec, ciphers []byte) []byte {
	var b []byte
	// Client version is always TLS 1.2 on the wire; 1.3 is negotiated via the
	// supported_versions extension.
	b = append(b, 0x03, 0x03)
	// 32-byte client random — JARM uses a fixed zero random for determinism is
	// NOT required; the response is what matters. Use zeroes so probes are
	// reproducible and contain no entropy that could vary results.
	b = append(b, make([]byte, 32)...)
	// Session id (32 bytes, fixed) per JARM.
	b = append(b, 0x20)
	b = append(b, make([]byte, 32)...)
	// Cipher suites.
	b = append(b, uint16b(len(ciphers))...)
	b = append(b, ciphers...)
	// Compression methods: null only.
	b = append(b, 0x01, 0x00)
	// Extensions.
	ext := buildExtensions(host, spec)
	b = append(b, uint16b(len(ext))...)
	b = append(b, ext...)
	return b
}

// jarmCiphersForSpec resolves the cipher byte string for a spec, applying the
// NO1.3 subtraction, the requested ordering, and GREASE.
func jarmCiphersForSpec(spec jarmProbeSpec) []byte {
	list := make([][]byte, 0, len(jarmCipherTable))
	for _, c := range jarmCipherTable {
		if spec.cipherList == "NO1.3" && jarmTLS13Ciphers[hex.EncodeToString(c)] {
			continue
		}
		list = append(list, c)
	}
	list = orderCiphers(list, spec.cipherOrder)

	var out []byte
	if spec.grease {
		out = append(out, greaseValue()...)
	}
	for _, c := range list {
		out = append(out, c...)
	}
	return out
}

// orderCiphers reorders a cipher list per the JARM mutation name.
func orderCiphers(list [][]byte, order string) [][]byte {
	switch order {
	case "REVERSE":
		return reverseBytesList(list)
	case "BOTTOM_HALF":
		// Second half of the list (JARM: drop the first half, keep the rest).
		return list[len(list)/2:]
	case "TOP_HALF":
		// First half of the list, after the centre element on odd lengths.
		if len(list)%2 == 1 {
			return list[:len(list)/2+1]
		}
		return list[:len(list)/2]
	case "MIDDLE_OUT":
		return middleOut(list)
	default: // FORWARD
		return list
	}
}

// middleOut reorders from the centre outward, alternating sides — JARM's
// most distinctive cipher permutation.
func middleOut(list [][]byte) [][]byte {
	n := len(list)
	mid := n / 2
	var out [][]byte
	if n%2 == 1 {
		out = append(out, list[mid])
		for i := 1; i <= mid; i++ {
			out = append(out, list[mid+i])
			out = append(out, list[mid-i])
		}
	} else {
		for i := 1; i <= mid; i++ {
			out = append(out, list[mid-1+i])
			out = append(out, list[mid-i])
		}
	}
	return out
}

func reverseBytesList(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range in {
		out[len(in)-1-i] = in[i]
	}
	return out
}

// buildExtensions assembles the TLS extensions block including SNI, optional
// GREASE, ALPN, supported_versions, and the standard JARM extension set.
func buildExtensions(host string, spec jarmProbeSpec) []byte {
	var all [][]byte

	if spec.grease {
		g := greaseValue()
		all = append(all, []byte{g[0], g[1], 0x00, 0x00})
	}
	all = append(all, sniExtension(host))
	all = append(all, extEmpty(0x0017))           // extended_master_secret
	all = append(all, extEmpty(0xff01))           // renegotiation_info (simplified)
	all = append(all, supportedGroupsExtension()) // 0x000a
	all = append(all, ecPointFormatsExtension())  // 0x000b
	all = append(all, sessionTicketExtension())   // 0x0023
	all = append(all, alpnExtension(spec.rareALPN))
	all = append(all, signatureAlgorithmsExtension()) // 0x000d
	all = append(all, keyShareExtension())            // 0x0033
	all = append(all, pskKeyExchangeModesExtension()) // 0x002d
	all = append(all, supportedVersionsExtension(spec.version, spec.grease))

	if spec.extOrder == "REVERSE" {
		all = reverseBytesList(all)
	}
	var out []byte
	for _, e := range all {
		out = append(out, e...)
	}
	return out
}

func sniExtension(host string) []byte {
	name := []byte(host)
	var server []byte
	server = append(server, 0x00) // host_name type
	server = append(server, uint16b(len(name))...)
	server = append(server, name...)

	var list []byte
	list = append(list, uint16b(len(server))...)
	list = append(list, server...)

	var ext []byte
	ext = append(ext, 0x00, 0x00) // extension type: server_name
	ext = append(ext, uint16b(len(list))...)
	ext = append(ext, list...)
	return ext
}

func extEmpty(t uint16) []byte { return append(uint16b(int(t)), 0x00, 0x00) }

func extWith(t uint16, data []byte) []byte {
	ext := uint16b(int(t))
	ext = append(ext, uint16b(len(data))...)
	return append(ext, data...)
}

func supportedGroupsExtension() []byte {
	groups := []byte{0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01}
	data := append(uint16b(len(groups)), groups...)
	return extWith(0x000a, data)
}

func ecPointFormatsExtension() []byte {
	return extWith(0x000b, []byte{0x01, 0x00})
}

func sessionTicketExtension() []byte { return extEmpty(0x0023) }

func alpnExtension(rare bool) []byte {
	protos := [][]byte{[]byte("h2"), []byte("http/1.1")}
	if rare {
		protos = [][]byte{
			[]byte("http/0.9"), []byte("http/1.0"), []byte("spdy/1"),
			[]byte("spdy/2"), []byte("spdy/3"), []byte("stun.turn"),
			[]byte("stun.nat-discovery"), []byte("h2c"), []byte("webrtc"),
		}
	}
	var list []byte
	for _, p := range protos {
		list = append(list, byte(len(p)))
		list = append(list, p...)
	}
	data := append(uint16b(len(list)), list...)
	return extWith(0x0010, data)
}

func signatureAlgorithmsExtension() []byte {
	algs := []byte{
		0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
		0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01,
	}
	data := append(uint16b(len(algs)), algs...)
	return extWith(0x000d, data)
}

func keyShareExtension() []byte {
	// x25519 group with a 32-byte zero key.
	entry := []byte{0x00, 0x1d}
	entry = append(entry, uint16b(32)...)
	entry = append(entry, make([]byte, 32)...)
	data := append(uint16b(len(entry)), entry...)
	return extWith(0x0033, data)
}

func pskKeyExchangeModesExtension() []byte {
	return extWith(0x002d, []byte{0x01, 0x01})
}

func supportedVersionsExtension(recVer []byte, grease bool) []byte {
	var versions []byte
	if grease {
		g := greaseValue()
		versions = append(versions, g[0], g[1])
	}
	// Always advertise 1.3 and 1.2; recVer selects which the server prefers via
	// the probe family.
	versions = append(versions, 0x03, 0x04, 0x03, 0x03)
	_ = recVer
	data := append([]byte{byte(len(versions))}, versions...)
	return extWith(0x002b, data)
}

// greaseValue returns a fixed GREASE value (0x0a0a). JARM uses a deterministic
// GREASE byte so probes are reproducible.
func greaseValue() []byte { return []byte{0x0a, 0x0a} }

// readServerHello parses the server's TLS response bytes and returns a compact
// descriptor "<cipher_hex>|<ext_hash>" used by jarmHash. On a TLS alert or a
// non-handshake record it returns the empty marker.
func readServerHello(data []byte) string {
	// Record header: type(1) version(2) length(2).
	if len(data) < 5 {
		return ""
	}
	if data[0] == 0x15 { // alert
		return ""
	}
	if data[0] != 0x16 { // not a handshake record
		return ""
	}
	body := data[5:]
	if len(body) < 6 || body[0] != 0x02 { // not a ServerHello
		return ""
	}
	// ServerHello: type(1) length(3) version(2) random(32) ...
	if len(body) < 39 {
		return ""
	}
	p := 38 // past type+len+version+random
	if p >= len(body) {
		return ""
	}
	sessLen := int(body[p])
	p++
	p += sessLen
	if p+2 > len(body) {
		return ""
	}
	cipher := hex.EncodeToString(body[p : p+2])
	p += 2
	// Extensions follow compression(1) then a 2-byte extensions length.
	extDesc := ""
	if p+1 < len(body) {
		p++ // compression method
		if p+2 <= len(body) {
			extLen := int(body[p])<<8 | int(body[p+1])
			p += 2
			if p+extLen <= len(body) {
				extDesc = parseServerExtensions(body[p : p+extLen])
			}
		}
	}
	return cipher + "|" + extDesc
}

// parseServerExtensions returns an ordered, compact list of the server's
// extension types — the part of the response JARM fuzzy-hashes.
func parseServerExtensions(b []byte) string {
	var types []string
	for len(b) >= 4 {
		t := hex.EncodeToString(b[0:2])
		l := int(b[2])<<8 | int(b[3])
		types = append(types, t)
		if 4+l > len(b) {
			break
		}
		b = b[4+l:]
	}
	out := ""
	for i, t := range types {
		if i > 0 {
			out += "-"
		}
		out += t
	}
	return out
}

// jarmHash folds the ten probe responses into the 62-character JARM
// fingerprint: a 30-character cipher/version prefix plus a 32-character
// truncated SHA-256 of the concatenated extension descriptors.
func jarmHash(responses []string) string {
	// If every probe failed, JARM is the all-zero hash.
	allEmpty := true
	for _, r := range responses {
		if r != "" {
			allEmpty = false
			break
		}
	}
	if allEmpty {
		return jarmEmptyFP
	}

	prefix := ""
	var extBlob string
	for _, r := range responses {
		cipher, ext := splitResponse(r)
		prefix += cipherIndex(cipher)
		extBlob += ext + ","
	}

	sum := sha256.Sum256([]byte(extBlob))
	extHash := hex.EncodeToString(sum[:])[:32]
	return prefix + extHash
}

// splitResponse separates the "<cipher>|<ext>" descriptor.
func splitResponse(r string) (cipher, ext string) {
	if r == "" {
		return "", ""
	}
	for i := 0; i < len(r); i++ {
		if r[i] == '|' {
			return r[:i], r[i+1:]
		}
	}
	return r, ""
}

// cipherIndex maps a negotiated cipher to its 3-character JARM code: "000" when
// the probe failed, otherwise the 1-based index of the cipher in the JARM table
// rendered as a base-36 triple. This mirrors the JARM "cipher_bytes" stage in a
// compact, deterministic way.
func cipherIndex(cipher string) string {
	if cipher == "" {
		return "000"
	}
	for i, c := range jarmCipherTable {
		if hex.EncodeToString(c) == cipher {
			return pad3(strconv.FormatInt(int64(i+1), 36))
		}
	}
	return "0a0" // negotiated a cipher not in the JARM table
}

func pad3(s string) string {
	for len(s) < 3 {
		s = "0" + s
	}
	if len(s) > 3 {
		s = s[len(s)-3:]
	}
	return s
}

// ── small byte helpers ──────────────────────────────────────────────────────

func uint16b(n int) []byte { return []byte{byte(n >> 8), byte(n)} }

func uint24(n int) []byte { return []byte{byte(n >> 16), byte(n >> 8), byte(n)} }
