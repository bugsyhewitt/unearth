package rank

// Sample is the minimal per-technique evidence the calibrator needs: how many
// candidates the technique contributed across recorded runs (Total) and how
// many of those were corroborated by another technique (Corroborated). It
// mirrors cache.TechniqueStat but is defined here so the rank package stays
// dependency-free (no import of the cache package) and remains a pure,
// table-testable unit.
type Sample struct {
	Technique    string
	Total        int
	Corroborated int
	// Default is the technique's baseline DefaultWeight(), used as the prior
	// the suggestion is blended toward when the sample is small.
	Default float64
}

// Suggestion is a calibrated weight recommendation for one technique.
type Suggestion struct {
	Technique string
	// Current is the weight the engine uses today (the technique default or a
	// configured override the caller passed in as Sample.Default).
	Current float64
	// Suggested is the calibrated weight in [0,1].
	Suggested float64
	// Precision is the observed corroboration rate, Corroborated/Total.
	Precision float64
	// Samples is the number of observations backing the suggestion.
	Samples int
	// LowConfidence is true when Samples is below MinSamples; the suggestion
	// is still emitted but flagged so operators treat it cautiously.
	LowConfidence bool
}

// MinSamples is the observation count below which a suggestion is flagged
// LowConfidence. Smaller samples are dominated by noise, so the suggestion is
// pulled hard toward the prior (the technique default).
const MinSamples = 20

// priorStrength is the pseudo-count weight given to the prior in the shrinkage
// blend. With priorStrength=20, a technique needs ~20 real observations before
// the empirical precision contributes as much as the prior. This keeps a
// technique that fired three times and got corroborated once from being
// slammed to weight 0.33.
const priorStrength = 20.0

// Calibrate turns accumulated per-technique samples into weight suggestions.
//
// The calibrated weight is a shrinkage estimate: the observed corroboration
// rate blended toward the technique's existing weight (the prior) by a
// pseudo-count. With p = Corroborated, n = Total, and w0 = Default:
//
//	suggested = (p + priorStrength*w0) / (n + priorStrength)
//
// This is a Beta-prior posterior mean. When n is large the empirical rate
// dominates; when n is small the prior dominates, so a technique with few
// observations keeps its default weight. The result is always in [0,1].
//
// Techniques with zero observations are skipped entirely — there is nothing to
// calibrate, so the engine should keep their defaults. The output is ordered
// to match the input slice's order; the caller (the cache layer) already sorts
// by technique name.
func Calibrate(samples []Sample) []Suggestion {
	out := make([]Suggestion, 0, len(samples))
	for _, s := range samples {
		if s.Total <= 0 {
			continue
		}
		w0 := clamp01(s.Default)
		precision := float64(s.Corroborated) / float64(s.Total)
		suggested := (float64(s.Corroborated) + priorStrength*w0) /
			(float64(s.Total) + priorStrength)
		out = append(out, Suggestion{
			Technique:     s.Technique,
			Current:       w0,
			Suggested:     clamp01(suggested),
			Precision:     precision,
			Samples:       s.Total,
			LowConfidence: s.Total < MinSamples,
		})
	}
	return out
}
