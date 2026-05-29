// Package config loads technique weight overrides and third-party API keys
// from the environment and from a user-supplied weights file. It also embeds
// the project's default weight table so the binary always has a working
// default with no external file required.
package config

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/unearth-tool/unearth/pkg/techniques"
	"gopkg.in/yaml.v3"
)

//go:embed default-weights.yaml
var defaultWeightsYAML []byte

// knownTechniques is the set of technique names recognized by v1.0. A user
// weights file that mentions a name outside this set produces a warning,
// not an error.
var knownTechniques = map[string]struct{}{
	"crtsh":            {},
	"ct_fingerprint":   {},
	"dns_history":      {},
	"spf_mx":           {},
	"subdomain_enum":   {},
	"censys_cert":      {},
	"shodan_cert":      {},
	"fofa_cert":        {},
	"netlas_cert":      {},
	"criminalip_asset": {},
	"binaryedge_cert":  {},
	"leakix_cert":      {},
	"fullhunt_asset":   {},
	"zoomeye_asset":    {},
	"host_header":      {},
	"banner_grab":      {},
	"error_page":       {},
	"ipv6_probe":       {},
}

// Weights maps technique name to its configured reliability weight in [0,1].
// The zero value is usable: it simply has no overrides and Weight always
// returns ok=false.
type Weights struct {
	values map[string]float64
}

// Weight returns the configured weight for a technique name. The second
// return value reports whether an override existed; when false the caller
// should fall back to the technique's DefaultWeight().
func (w Weights) Weight(technique string) (float64, bool) {
	if w.values == nil {
		return 0, false
	}
	v, ok := w.values[technique]
	return v, ok
}

// Names returns the sorted list of techniques that have a configured weight.
// Useful for introspection and tests.
func (w Weights) Names() []string {
	names := make([]string, 0, len(w.values))
	for k := range w.values {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// weightsFile is the YAML schema for both the embedded defaults and a user
// override file.
type weightsFile struct {
	Weights map[string]float64 `yaml:"weights"`
}

// LoadWeights resolves weights from, in priority order:
//
//  1. an explicit path passed by the caller (e.g. the --weights CLI flag).
//  2. $XDG_CONFIG_HOME/unearth/weights.yaml, falling back to
//     ~/.config/unearth/weights.yaml.
//  3. the embedded default.
//
// A user file need only specify the techniques it wants to override; missing
// techniques fall through to the embedded default, and missing-from-both
// falls back later to the technique's DefaultWeight().
//
// The returned warnings slice lists non-fatal issues (e.g. unknown technique
// names in the user file). Validation errors (e.g. weights outside [0,1])
// are returned as the error value.
func LoadWeights(explicitPath string) (Weights, []string, error) {
	defaults, err := parseWeights(defaultWeightsYAML)
	if err != nil {
		return Weights{}, nil, fmt.Errorf("config: parsing embedded default weights: %w", err)
	}
	for name, v := range defaults {
		if v < 0 || v > 1 {
			return Weights{}, nil, fmt.Errorf("config: embedded default for %q is out of range [0,1]: %g", name, v)
		}
	}

	merged := make(map[string]float64, len(defaults))
	for k, v := range defaults {
		merged[k] = v
	}

	path, err := resolveUserPath(explicitPath)
	if err != nil {
		return Weights{}, nil, err
	}

	var warnings []string
	if path != "" {
		data, readErr := os.ReadFile(path)
		switch {
		case readErr == nil:
			user, perr := parseWeights(data)
			if perr != nil {
				return Weights{}, nil, fmt.Errorf("config: parsing %s: %w", path, perr)
			}
			for name, v := range user {
				if v < 0 || v > 1 {
					return Weights{}, nil, fmt.Errorf("config: weight for %q in %s is out of range [0,1]: %g", name, path, v)
				}
				if _, ok := knownTechniques[name]; !ok {
					warnings = append(warnings, fmt.Sprintf("unknown technique %q in %s (ignored)", name, path))
					continue
				}
				merged[name] = v
			}
		case errors.Is(readErr, os.ErrNotExist):
			if explicitPath != "" {
				return Weights{}, nil, fmt.Errorf("config: weights file not found: %s", explicitPath)
			}
			// Default path doesn't exist; silently fall through to embedded.
		default:
			return Weights{}, nil, fmt.Errorf("config: reading %s: %w", path, readErr)
		}
	}

	return Weights{values: merged}, warnings, nil
}

func parseWeights(data []byte) (map[string]float64, error) {
	var f weightsFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	if f.Weights == nil {
		return map[string]float64{}, nil
	}
	return f.Weights, nil
}

// resolveUserPath returns the path to consult for a user weights file. An
// explicit path always wins. Otherwise the XDG-style default is returned;
// the caller decides whether to treat ErrNotExist as fatal.
func resolveUserPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			// No home and no XDG var — caller will get embedded defaults only.
			return "", nil
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "unearth", "weights.yaml"), nil
}

// envFirst returns the value of the first non-empty environment variable in
// names, in order. It exists so a credential can be read from its documented,
// canonical name first and still fall back to a legacy alias for backward
// compatibility.
func envFirst(names ...string) string {
	for _, name := range names {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	return ""
}

// LoadAPIKeys reads third-party credentials from the environment and returns
// a techniques.APIKeys. Missing variables yield empty fields, which the
// engine treats as "skip that technique" rather than as an error.
//
// Each credential is read from its documented, canonical name first (e.g.
// CENSYS_PLATFORM_PAT, SHODAN_API_KEY — the names shown in the README) and,
// when that is unset, falls back to the historical UNEARTH_-prefixed alias
// (e.g. UNEARTH_CENSYS_PAT). The canonical name wins when both are set. The
// README documented the unprefixed names but earlier builds only read the
// prefixed ones, so a user following the docs had their keys silently ignored;
// honoring both names fixes that without breaking anyone already using the
// prefixed form.
func LoadAPIKeys() techniques.APIKeys {
	return techniques.APIKeys{
		CensysPlatformPAT: envFirst("CENSYS_PLATFORM_PAT", "UNEARTH_CENSYS_PAT"),
		CensysAPIID:       envFirst("CENSYS_API_ID", "UNEARTH_CENSYS_API_ID"),
		CensysAPISecret:   envFirst("CENSYS_API_SECRET", "UNEARTH_CENSYS_API_SECRET"),
		ShodanAPIKey:      envFirst("SHODAN_API_KEY", "UNEARTH_SHODAN_API_KEY"),
		SecurityTrailsKey: envFirst("SECURITYTRAILS_API_KEY", "UNEARTH_SECURITYTRAILS_API_KEY"),
		ViewDNSKey:        envFirst("VIEWDNS_API_KEY", "UNEARTH_VIEWDNS_API_KEY"),
		FOFAEmail:         envFirst("FOFA_EMAIL", "UNEARTH_FOFA_EMAIL"),
		FOFAKey:           envFirst("FOFA_KEY", "UNEARTH_FOFA_KEY"),
		NetlasAPIKey:      envFirst("NETLAS_API_KEY", "UNEARTH_NETLAS_API_KEY"),
		CriminalIPKey:     envFirst("CRIMINALIP_API_KEY", "UNEARTH_CRIMINALIP_API_KEY"),
		BinaryEdgeKey:     envFirst("BINARYEDGE_API_KEY", "UNEARTH_BINARYEDGE_API_KEY"),
		LeakIXKey:         envFirst("LEAKIX_API_KEY", "UNEARTH_LEAKIX_API_KEY"),
		FullHuntKey:       envFirst("FULLHUNT_API_KEY", "UNEARTH_FULLHUNT_API_KEY"),
		ZoomEyeKey:        envFirst("ZOOMEYE_API_KEY", "UNEARTH_ZOOMEYE_API_KEY"),
	}
}

// CredentialStatus reports, per service, whether usable credentials are set.
// Keys: "censys", "shodan", "securitytrails", "viewdns", "fofa", "netlas",
// "criminalip", "binaryedge", "leakix", "fullhunt", "zoomeye". The "zoomeye"
// entry is true when a ZoomEye API key is present. The "censys" entry is true when a Censys
// Platform PAT is present; the "fofa" entry is true only when both the FOFA email
// and key are present; the "netlas" entry is true when a Netlas API key is
// present; the "criminalip" entry is true when a Criminal IP API key is present;
// the "binaryedge" entry is true when a BinaryEdge API key is present; the
// "leakix" entry is true when a LeakIX API key is present; the "fullhunt"
// entry is true when a FullHunt API key is present. The legacy ID/secret
// pair is no longer consulted: the Censys Search v2 API it authenticates is
// disabled for Free accounts and is sunsetting in 2026.
func CredentialStatus(k techniques.APIKeys) map[string]bool {
	return map[string]bool{
		"censys":         k.CensysPlatformPAT != "",
		"shodan":         k.ShodanAPIKey != "",
		"securitytrails": k.SecurityTrailsKey != "",
		"viewdns":        k.ViewDNSKey != "",
		"fofa":           k.FOFAEmail != "" && k.FOFAKey != "",
		"netlas":         k.NetlasAPIKey != "",
		"criminalip":     k.CriminalIPKey != "",
		"binaryedge":     k.BinaryEdgeKey != "",
		"leakix":         k.LeakIXKey != "",
		"fullhunt":       k.FullHuntKey != "",
		"zoomeye":        k.ZoomEyeKey != "",
	}
}
