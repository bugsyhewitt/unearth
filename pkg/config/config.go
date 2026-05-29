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
	"crtsh":          {},
	"ct_fingerprint": {},
	"dns_history":    {},
	"spf_mx":         {},
	"subdomain_enum": {},
	"censys_cert":    {},
	"shodan_cert":    {},
	"fofa_cert":      {},
	"host_header":    {},
	"banner_grab":    {},
	"error_page":     {},
	"ipv6_probe":     {},
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

// LoadAPIKeys reads third-party credentials from the environment and returns
// a techniques.APIKeys. Missing variables yield empty fields, which the
// engine treats as "skip that technique" rather than as an error.
func LoadAPIKeys() techniques.APIKeys {
	return techniques.APIKeys{
		CensysPlatformPAT: os.Getenv("UNEARTH_CENSYS_PAT"),
		CensysAPIID:       os.Getenv("UNEARTH_CENSYS_API_ID"),
		CensysAPISecret:   os.Getenv("UNEARTH_CENSYS_API_SECRET"),
		ShodanAPIKey:      os.Getenv("UNEARTH_SHODAN_API_KEY"),
		SecurityTrailsKey: os.Getenv("UNEARTH_SECURITYTRAILS_API_KEY"),
		ViewDNSKey:        os.Getenv("UNEARTH_VIEWDNS_API_KEY"),
		FOFAEmail:         os.Getenv("UNEARTH_FOFA_EMAIL"),
		FOFAKey:           os.Getenv("UNEARTH_FOFA_KEY"),
	}
}

// CredentialStatus reports, per service, whether usable credentials are set.
// Keys: "censys", "shodan", "securitytrails", "viewdns", "fofa". The "censys"
// entry is true when a Censys Platform PAT is present; the "fofa" entry is
// true only when both the FOFA email and key are present. The legacy ID/secret pair
// is no longer consulted: the Censys Search v2 API it authenticates is
// disabled for Free accounts and is sunsetting in 2026.
func CredentialStatus(k techniques.APIKeys) map[string]bool {
	return map[string]bool{
		"censys":         k.CensysPlatformPAT != "",
		"shodan":         k.ShodanAPIKey != "",
		"securitytrails": k.SecurityTrailsKey != "",
		"viewdns":        k.ViewDNSKey != "",
		"fofa":           k.FOFAEmail != "" && k.FOFAKey != "",
	}
}
