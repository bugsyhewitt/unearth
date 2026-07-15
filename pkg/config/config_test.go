package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unearth-tool/unearth/pkg/techniques"
)

func TestLoadWeights_EmbeddedDefaults(t *testing.T) {
	// XDG_CONFIG_HOME points at an empty dir so no user file is consulted.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	w, warns, err := LoadWeights("")
	if err != nil {
		t.Fatalf("LoadWeights: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("expected no warnings, got %v", warns)
	}
	for _, name := range []string{"crtsh", "censys_cert", "ipv6_probe"} {
		v, ok := w.Weight(name)
		if !ok {
			t.Errorf("default weight missing for %s", name)
		}
		if v < 0 || v > 1 {
			t.Errorf("weight %s out of range: %g", name, v)
		}
	}
	got, _ := w.Weight("censys_cert")
	if got != 0.90 {
		t.Errorf("censys_cert: want 0.90, got %g", got)
	}
}

func TestLoadWeights_AllKnownTechniquesPresent(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	w, _, err := LoadWeights("")
	if err != nil {
		t.Fatal(err)
	}
	for _, tech := range techniques.All() {
		name := tech.Name()
		if _, ok := w.Weight(name); !ok {
			t.Errorf("embedded default missing technique %q", name)
		}
	}
	// And no extras leaked in.
	for _, name := range w.Names() {
		if _, ok := techniques.Get(name); !ok {
			t.Errorf("embedded default has unknown technique %q", name)
		}
	}
}

func TestLoadWeights_UserOverridesEmbedded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "weights.yaml")
	if err := os.WriteFile(path, []byte("weights:\n  crtsh: 0.10\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, warns, err := LoadWeights(path)
	if err != nil {
		t.Fatalf("LoadWeights: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	got, _ := w.Weight("crtsh")
	if got != 0.10 {
		t.Errorf("crtsh override: want 0.10, got %g", got)
	}
	// Untouched techniques fall through to embedded.
	if got, _ := w.Weight("censys_cert"); got != 0.90 {
		t.Errorf("censys_cert fallthrough: want 0.90, got %g", got)
	}
}

func TestLoadWeights_UnknownTechniqueWarnsButDoesNotError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "weights.yaml")
	if err := os.WriteFile(path, []byte("weights:\n  bogus: 0.5\n  crtsh: 0.42\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, warns, err := LoadWeights(path)
	if err != nil {
		t.Fatalf("LoadWeights: %v", err)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "bogus") {
		t.Fatalf("want one warning mentioning bogus, got %v", warns)
	}
	if got, _ := w.Weight("crtsh"); got != 0.42 {
		t.Errorf("crtsh override should apply: got %g", got)
	}
	if _, ok := w.Weight("bogus"); ok {
		t.Errorf("bogus should not be present in weights")
	}
}

func TestLoadWeights_OutOfRangeIsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "weights.yaml")
	if err := os.WriteFile(path, []byte("weights:\n  crtsh: 1.5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadWeights(path)
	if err == nil {
		t.Fatal("expected out-of-range error")
	}
	if !strings.Contains(err.Error(), "crtsh") {
		t.Errorf("error should name offending technique, got %v", err)
	}
}

func TestLoadWeights_NegativeIsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "weights.yaml")
	if err := os.WriteFile(path, []byte("weights:\n  crtsh: -0.01\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadWeights(path); err == nil {
		t.Fatal("expected negative-weight error")
	}
}

func TestLoadWeights_ExplicitPathMissingIsError(t *testing.T) {
	_, _, err := LoadWeights(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected error for missing explicit path")
	}
}

func TestLoadWeights_DefaultPathMissingIsOK(t *testing.T) {
	// Point XDG at an empty dir; no weights.yaml inside.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	w, warns, err := LoadWeights("")
	if err != nil {
		t.Fatalf("missing default path should be OK, got %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if _, ok := w.Weight("crtsh"); !ok {
		t.Error("embedded defaults should still be present")
	}
}

func TestLoadWeights_MalformedYAMLIsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "weights.yaml")
	if err := os.WriteFile(path, []byte("weights: not-a-map\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadWeights(path); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestWeights_ZeroValue(t *testing.T) {
	var w Weights
	if _, ok := w.Weight("anything"); ok {
		t.Error("zero Weights should never report ok=true")
	}
	if len(w.Names()) != 0 {
		t.Error("zero Weights should have no names")
	}
}

// allCredentialEnvVars is every environment variable LoadAPIKeys consults,
// across both the canonical (documented) and the legacy UNEARTH_-prefixed
// alias names. Tests clear all of them so a stray value in the real
// environment cannot leak into a case that means to assert "unset".
//
// When LoadAPIKeys gains a new envFirst call, the corresponding variable
// names MUST be added here; omitting them lets real-environment keys bleed
// into tests that intend to start from an empty-credential state, making
// assertions silently wrong.
var allCredentialEnvVars = []string{
	"CENSYS_PLATFORM_PAT", "UNEARTH_CENSYS_PAT",
	"CENSYS_API_ID", "UNEARTH_CENSYS_API_ID",
	"CENSYS_API_SECRET", "UNEARTH_CENSYS_API_SECRET",
	"SHODAN_API_KEY", "UNEARTH_SHODAN_API_KEY",
	"SECURITYTRAILS_API_KEY", "UNEARTH_SECURITYTRAILS_API_KEY",
	"VIEWDNS_API_KEY", "UNEARTH_VIEWDNS_API_KEY",
	"FOFA_EMAIL", "UNEARTH_FOFA_EMAIL",
	"FOFA_KEY", "UNEARTH_FOFA_KEY",
	"NETLAS_API_KEY", "UNEARTH_NETLAS_API_KEY",
	"CRIMINALIP_API_KEY", "UNEARTH_CRIMINALIP_API_KEY",
	"BINARYEDGE_API_KEY", "UNEARTH_BINARYEDGE_API_KEY",
	"LEAKIX_API_KEY", "UNEARTH_LEAKIX_API_KEY",
	"ONYPHE_API_KEY", "UNEARTH_ONYPHE_API_KEY",
	"FULLHUNT_API_KEY", "UNEARTH_FULLHUNT_API_KEY",
	// ZoomEye — was missing; its presence in the real env would cause
	// clearCredentialEnv calls to leave ZoomEyeKey non-empty.
	"ZOOMEYE_API_KEY", "UNEARTH_ZOOMEYE_API_KEY",
	// Chaos/ProjectDiscovery — same issue; three accepted names.
	"PDCP_API_KEY", "CHAOS_API_KEY", "UNEARTH_PDCP_API_KEY",
	// VirusTotal — same issue; three accepted names.
	"VIRUSTOTAL_API_KEY", "VT_API_KEY", "UNEARTH_VIRUSTOTAL_API_KEY",
	// URLScan — same issue.
	"URLSCAN_API_KEY", "UNEARTH_URLSCAN_API_KEY",
	// GreyNoise — same issue.
	"GREYNOISE_API_KEY", "UNEARTH_GREYNOISE_API_KEY",
	// OTX — optional key; still must be cleared so "all empty" tests are clean.
	"OTX_API_KEY", "ALIENVAULT_OTX_API_KEY", "UNEARTH_OTX_API_KEY",
}

// clearCredentialEnv unsets every credential variable for the duration of the
// test so each case starts from a known-empty environment.
func clearCredentialEnv(t *testing.T) {
	t.Helper()
	for _, name := range allCredentialEnvVars {
		t.Setenv(name, "")
	}
}

func TestLoadAPIKeys(t *testing.T) {
	clearCredentialEnv(t)
	t.Setenv("UNEARTH_CENSYS_PAT", "pat-tok")
	t.Setenv("UNEARTH_SHODAN_API_KEY", "sho")
	t.Setenv("UNEARTH_SECURITYTRAILS_API_KEY", "st")
	t.Setenv("UNEARTH_VIEWDNS_API_KEY", "vd")
	k := LoadAPIKeys()
	if k.CensysPlatformPAT != "pat-tok" {
		t.Errorf("censys PAT: %+v", k)
	}
	if k.ShodanAPIKey != "sho" || k.SecurityTrailsKey != "st" || k.ViewDNSKey != "vd" {
		t.Errorf("misc: %+v", k)
	}
}

// TestLoadAPIKeys_CanonicalNames verifies the documented, unprefixed variable
// names (the ones the README tells users to export) are honored for every
// key-bearing backend. This is the regression guard for the bug where the
// README documented CENSYS_PLATFORM_PAT, SHODAN_API_KEY, etc. but the loader
// only read the UNEARTH_-prefixed aliases, silently ignoring keys set per the
// docs.
//
// When a new backend is added to LoadAPIKeys, its canonical env-var name
// MUST be added here so the test continues to cover the full surface.
func TestLoadAPIKeys_CanonicalNames(t *testing.T) {
	clearCredentialEnv(t)
	t.Setenv("CENSYS_PLATFORM_PAT", "pat")
	t.Setenv("CENSYS_API_ID", "cid")
	t.Setenv("CENSYS_API_SECRET", "csec")
	t.Setenv("SHODAN_API_KEY", "sho")
	t.Setenv("SECURITYTRAILS_API_KEY", "st")
	t.Setenv("VIEWDNS_API_KEY", "vd")
	t.Setenv("FOFA_EMAIL", "you@example.com")
	t.Setenv("FOFA_KEY", "fk")
	t.Setenv("NETLAS_API_KEY", "nl")
	t.Setenv("CRIMINALIP_API_KEY", "cip")
	// Backends added in later packets — previously missing from this test.
	t.Setenv("BINARYEDGE_API_KEY", "be")
	t.Setenv("LEAKIX_API_KEY", "lx")
	t.Setenv("ONYPHE_API_KEY", "on")
	t.Setenv("FULLHUNT_API_KEY", "fh")
	t.Setenv("ZOOMEYE_API_KEY", "ze")
	t.Setenv("PDCP_API_KEY", "ch")
	t.Setenv("VIRUSTOTAL_API_KEY", "vt")
	t.Setenv("URLSCAN_API_KEY", "us")
	t.Setenv("GREYNOISE_API_KEY", "gn")
	t.Setenv("OTX_API_KEY", "otx")

	k := LoadAPIKeys()
	tests := []struct {
		field string
		got   string
		want  string
	}{
		{"CensysPlatformPAT", k.CensysPlatformPAT, "pat"},
		{"CensysAPIID", k.CensysAPIID, "cid"},
		{"CensysAPISecret", k.CensysAPISecret, "csec"},
		{"ShodanAPIKey", k.ShodanAPIKey, "sho"},
		{"SecurityTrailsKey", k.SecurityTrailsKey, "st"},
		{"ViewDNSKey", k.ViewDNSKey, "vd"},
		{"FOFAEmail", k.FOFAEmail, "you@example.com"},
		{"FOFAKey", k.FOFAKey, "fk"},
		{"NetlasAPIKey", k.NetlasAPIKey, "nl"},
		{"CriminalIPKey", k.CriminalIPKey, "cip"},
		{"BinaryEdgeKey", k.BinaryEdgeKey, "be"},
		{"LeakIXKey", k.LeakIXKey, "lx"},
		{"OnypheKey", k.OnypheKey, "on"},
		{"FullHuntKey", k.FullHuntKey, "fh"},
		{"ZoomEyeKey", k.ZoomEyeKey, "ze"},
		{"ChaosKey", k.ChaosKey, "ch"},
		{"VirusTotalKey", k.VirusTotalKey, "vt"},
		{"URLScanKey", k.URLScanKey, "us"},
		{"GreyNoiseKey", k.GreyNoiseKey, "gn"},
		{"OTXKey", k.OTXKey, "otx"},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s: want %q, got %q", tc.field, tc.want, tc.got)
		}
	}
}

// TestLoadAPIKeys_CanonicalWinsOverLegacy verifies the documented name takes
// precedence when both the canonical and the legacy UNEARTH_-prefixed alias
// are set.
func TestLoadAPIKeys_CanonicalWinsOverLegacy(t *testing.T) {
	clearCredentialEnv(t)
	t.Setenv("UNEARTH_SHODAN_API_KEY", "legacy")
	t.Setenv("SHODAN_API_KEY", "canonical")
	t.Setenv("UNEARTH_CENSYS_PAT", "legacy-pat")
	t.Setenv("CENSYS_PLATFORM_PAT", "canonical-pat")

	k := LoadAPIKeys()
	if k.ShodanAPIKey != "canonical" {
		t.Errorf("ShodanAPIKey: want canonical to win, got %q", k.ShodanAPIKey)
	}
	if k.CensysPlatformPAT != "canonical-pat" {
		t.Errorf("CensysPlatformPAT: want canonical to win, got %q", k.CensysPlatformPAT)
	}
}

// TestLoadAPIKeys_LegacyFallback verifies the legacy UNEARTH_-prefixed alias is
// still honored when the canonical name is unset, so existing users do not
// break.
func TestLoadAPIKeys_LegacyFallback(t *testing.T) {
	clearCredentialEnv(t)
	t.Setenv("UNEARTH_SHODAN_API_KEY", "legacy-only")
	t.Setenv("UNEARTH_NETLAS_API_KEY", "legacy-netlas")

	k := LoadAPIKeys()
	if k.ShodanAPIKey != "legacy-only" {
		t.Errorf("ShodanAPIKey: want legacy fallback, got %q", k.ShodanAPIKey)
	}
	if k.NetlasAPIKey != "legacy-netlas" {
		t.Errorf("NetlasAPIKey: want legacy fallback, got %q", k.NetlasAPIKey)
	}
}

func TestLoadAPIKeys_EmptyEnv(t *testing.T) {
	clearCredentialEnv(t)
	k := LoadAPIKeys()
	if k.CensysPlatformPAT != "" || k.ShodanAPIKey != "" {
		t.Errorf("expected empty fields, got %+v", k)
	}
}

func TestCredentialStatus(t *testing.T) {
	tests := []struct {
		name string
		set  func() (pat, sho, st, vd string)
		want map[string]bool
	}{
		{
			name: "all empty",
			set:  func() (string, string, string, string) { return "", "", "", "" },
			want: map[string]bool{"censys": false, "shodan": false, "securitytrails": false, "viewdns": false},
		},
		{
			name: "censys PAT only",
			set:  func() (string, string, string, string) { return "pat", "", "", "" },
			want: map[string]bool{"censys": true, "shodan": false, "securitytrails": false, "viewdns": false},
		},
		{
			name: "all set",
			set:  func() (string, string, string, string) { return "p", "k", "t", "v" },
			want: map[string]bool{"censys": true, "shodan": true, "securitytrails": true, "viewdns": true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearCredentialEnv(t)
			pat, sho, st, vd := tc.set()
			t.Setenv("UNEARTH_CENSYS_PAT", pat)
			t.Setenv("UNEARTH_SHODAN_API_KEY", sho)
			t.Setenv("UNEARTH_SECURITYTRAILS_API_KEY", st)
			t.Setenv("UNEARTH_VIEWDNS_API_KEY", vd)
			got := CredentialStatus(LoadAPIKeys())
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("%s: want %v, got %v", k, v, got[k])
				}
			}
		})
	}
}

func TestCredentialStatus_CriminalIP(t *testing.T) {
	clearCredentialEnv(t)
	if CredentialStatus(LoadAPIKeys())["criminalip"] {
		t.Error("criminalip should be false with no key")
	}
	t.Setenv("UNEARTH_CRIMINALIP_API_KEY", "cip-key")
	if !CredentialStatus(LoadAPIKeys())["criminalip"] {
		t.Error("criminalip should be true when key is set")
	}
}

// TestCredentialStatus_OTX confirms the OTX key is honored under all three
// accepted env-var names (canonical, AlienVault-prefixed, and UNEARTH-prefixed),
// and that the "otx" status entry tracks the key's presence — even though the
// otx_passivedns technique itself runs without a key.
func TestCredentialStatus_OTX(t *testing.T) {
	clearCredentialEnv(t)
	if CredentialStatus(LoadAPIKeys())["otx"] {
		t.Error("otx should be false with no key")
	}
	t.Setenv("OTX_API_KEY", "otx-canonical")
	if !CredentialStatus(LoadAPIKeys())["otx"] {
		t.Error("otx should be true when OTX_API_KEY is set")
	}

	clearCredentialEnv(t)
	t.Setenv("ALIENVAULT_OTX_API_KEY", "otx-av")
	if !CredentialStatus(LoadAPIKeys())["otx"] {
		t.Error("otx should be true when ALIENVAULT_OTX_API_KEY is set")
	}

	clearCredentialEnv(t)
	t.Setenv("UNEARTH_OTX_API_KEY", "otx-legacy")
	if !CredentialStatus(LoadAPIKeys())["otx"] {
		t.Error("otx should be true when UNEARTH_OTX_API_KEY is set")
	}
}

// TestCredentialStatus_NewBackends verifies that the CredentialStatus map
// correctly tracks presence/absence for the nine backends that were added
// after the initial credential coverage tests were written (BinaryEdge, LeakIX,
// Onyphe, FullHunt, ZoomEye, Chaos/PDCP, VirusTotal, URLScan, GreyNoise).
// Before the env-isolation fix, five of these (ZoomEye, Chaos, VirusTotal,
// URLScan, GreyNoise) were absent from allCredentialEnvVars, so a real
// GREYNOISE_API_KEY (for example) in the CI environment would silently bleed
// into every test that called clearCredentialEnv.
func TestCredentialStatus_NewBackends(t *testing.T) {
	tests := []struct {
		name      string // CredentialStatus map key
		envVar    string // canonical env-var name to set
		legacyVar string // UNEARTH_-prefixed alias (empty if none)
	}{
		{"binaryedge", "BINARYEDGE_API_KEY", "UNEARTH_BINARYEDGE_API_KEY"},
		{"leakix", "LEAKIX_API_KEY", "UNEARTH_LEAKIX_API_KEY"},
		{"onyphe", "ONYPHE_API_KEY", "UNEARTH_ONYPHE_API_KEY"},
		{"fullhunt", "FULLHUNT_API_KEY", "UNEARTH_FULLHUNT_API_KEY"},
		{"zoomeye", "ZOOMEYE_API_KEY", "UNEARTH_ZOOMEYE_API_KEY"},
		{"chaos", "PDCP_API_KEY", "UNEARTH_PDCP_API_KEY"},
		{"virustotal", "VIRUSTOTAL_API_KEY", "UNEARTH_VIRUSTOTAL_API_KEY"},
		{"urlscan", "URLSCAN_API_KEY", "UNEARTH_URLSCAN_API_KEY"},
		{"greynoise", "GREYNOISE_API_KEY", "UNEARTH_GREYNOISE_API_KEY"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Start from a fully-cleared environment.
			clearCredentialEnv(t)

			// With no key set the status entry must be false.
			if CredentialStatus(LoadAPIKeys())[tc.name] {
				t.Errorf("%s: should be false with no key in environment", tc.name)
			}

			// Setting the canonical name must flip the entry to true.
			t.Setenv(tc.envVar, "test-key")
			if !CredentialStatus(LoadAPIKeys())[tc.name] {
				t.Errorf("%s: should be true when %s is set", tc.name, tc.envVar)
			}

			// If a legacy alias exists, it must also work (canonical cleared).
			if tc.legacyVar != "" {
				clearCredentialEnv(t)
				t.Setenv(tc.legacyVar, "legacy-key")
				if !CredentialStatus(LoadAPIKeys())[tc.name] {
					t.Errorf("%s: should be true when legacy alias %s is set", tc.name, tc.legacyVar)
				}
			}
		})
	}
}

// TestCredentialStatus_VTAliases verifies the two accepted alternative names
// for the VirusTotal key (VT_API_KEY and UNEARTH_VIRUSTOTAL_API_KEY) in
// addition to the canonical VIRUSTOTAL_API_KEY covered above.
func TestCredentialStatus_VTAliases(t *testing.T) {
	clearCredentialEnv(t)
	t.Setenv("VT_API_KEY", "vt-alias")
	if !CredentialStatus(LoadAPIKeys())["virustotal"] {
		t.Error("virustotal should be true when VT_API_KEY is set")
	}
}

// TestCredentialStatus_ChaosAliases verifies the CHAOS_API_KEY alias for the
// Chaos/PDCP technique (three accepted names: PDCP_API_KEY, CHAOS_API_KEY,
// UNEARTH_PDCP_API_KEY).
func TestCredentialStatus_ChaosAliases(t *testing.T) {
	clearCredentialEnv(t)
	t.Setenv("CHAOS_API_KEY", "chaos-alias")
	if !CredentialStatus(LoadAPIKeys())["chaos"] {
		t.Error("chaos should be true when CHAOS_API_KEY is set")
	}
}

func TestEmbeddedAndConfigsYAMLMatch(t *testing.T) {
	// Sanity check that the canonical user-visible file in configs/ matches
	// the embedded copy. If a future contributor edits one, the test fails
	// loudly so they update the other.
	embedded := defaultWeightsYAML
	// Resolve repo root by walking up from this test file.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// wd is .../pkg/config; go up two.
	root := filepath.Join(wd, "..", "..")
	canonical, err := os.ReadFile(filepath.Join(root, "configs", "default-weights.yaml"))
	if err != nil {
		t.Skipf("configs/default-weights.yaml not readable (perhaps tested out of repo): %v", err)
	}
	if string(embedded) != string(canonical) {
		t.Fatal("configs/default-weights.yaml and embedded pkg/config/default-weights.yaml have diverged — keep them byte-identical")
	}
}

// TestKnownTechniquesMatchesRegistry verifies that every technique registered
// at init time appears in knownTechniques. If a technique is missing, users who
// try to override its weight in a weights.yaml file receive a spurious
// "unknown technique" warning, and the calibrate subcommand cannot surface
// weight suggestions for it.
//
// TestKnownTechniquesMatchesRegistry verifies that LoadWeights accepts weight
// overrides for every registered technique without emitting an "unknown technique"
// warning. Now that the validation uses the live registry (techniques.Get) instead
// of a static map, this test simply confirms that any registered technique name
// is accepted — i.e. LoadWeights warns only for names NOT in the registry.
func TestKnownTechniquesMatchesRegistry(t *testing.T) {
	dir := t.TempDir()
	for _, tech := range techniques.All() {
		name := tech.Name()
		path := dir + "/w.yaml"
		if err := os.WriteFile(path, []byte("weights:\n  "+name+": 0.5\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, warns, err := LoadWeights(path)
		if err != nil {
			t.Errorf("LoadWeights for technique %q returned error: %v", name, err)
		}
		for _, w := range warns {
			if strings.Contains(w, "unknown technique") {
				t.Errorf("registered technique %q triggered unknown-technique warning: %s", name, w)
			}
		}
	}
}
