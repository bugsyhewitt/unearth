package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	for name := range knownTechniques {
		if _, ok := w.Weight(name); !ok {
			t.Errorf("embedded default missing technique %q", name)
		}
	}
	// And no extras leaked in.
	for _, name := range w.Names() {
		if _, ok := knownTechniques[name]; !ok {
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

func TestLoadAPIKeys(t *testing.T) {
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

func TestLoadAPIKeys_EmptyEnv(t *testing.T) {
	t.Setenv("UNEARTH_CENSYS_PAT", "")
	t.Setenv("UNEARTH_SHODAN_API_KEY", "")
	t.Setenv("UNEARTH_SECURITYTRAILS_API_KEY", "")
	t.Setenv("UNEARTH_VIEWDNS_API_KEY", "")
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
			pat, sho, st, vd := tc.set()
			t.Setenv("UNEARTH_CENSYS_PAT", pat)
			t.Setenv("UNEARTH_CENSYS_API_ID", "")
			t.Setenv("UNEARTH_CENSYS_API_SECRET", "")
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
	t.Setenv("UNEARTH_CRIMINALIP_API_KEY", "")
	if CredentialStatus(LoadAPIKeys())["criminalip"] {
		t.Error("criminalip should be false with no key")
	}
	t.Setenv("UNEARTH_CRIMINALIP_API_KEY", "cip-key")
	if !CredentialStatus(LoadAPIKeys())["criminalip"] {
		t.Error("criminalip should be true when key is set")
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
