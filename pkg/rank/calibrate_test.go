package rank

import "testing"

func TestCalibrateSkipsZeroTotal(t *testing.T) {
	got := Calibrate([]Sample{
		{Technique: "crtsh", Total: 0, Corroborated: 0, Default: 0.7},
	})
	if len(got) != 0 {
		t.Fatalf("zero-total sample should be skipped, got %d suggestions", len(got))
	}
}

func TestCalibrateShrinksTowardPriorWhenSmallSample(t *testing.T) {
	// A technique that fired 3 times with 1 corroboration: raw precision is
	// 0.33, but with priorStrength=20 the suggestion stays near the 0.70 prior.
	got := Calibrate([]Sample{
		{Technique: "host_header", Total: 3, Corroborated: 1, Default: 0.70},
	})
	if len(got) != 1 {
		t.Fatalf("want 1 suggestion, got %d", len(got))
	}
	s := got[0]
	// (1 + 20*0.70) / (3 + 20) = 15 / 23 = 0.652...
	if !approx(s.Suggested, 15.0/23.0) {
		t.Fatalf("Suggested = %v, want %v", s.Suggested, 15.0/23.0)
	}
	if !approx(s.Precision, 1.0/3.0) {
		t.Fatalf("Precision = %v, want %v", s.Precision, 1.0/3.0)
	}
	if !s.LowConfidence {
		t.Fatal("3 samples should be flagged low-confidence")
	}
	if s.Suggested < 0.60 {
		t.Fatalf("small sample should stay near prior, got %v", s.Suggested)
	}
}

func TestCalibrateEmpiricalDominatesLargeSample(t *testing.T) {
	// 1000 observations, 900 corroborated: precision 0.90 should dominate the
	// 0.50 prior and pull the suggestion close to 0.90.
	got := Calibrate([]Sample{
		{Technique: "favicon_hash", Total: 1000, Corroborated: 900, Default: 0.50},
	})
	if len(got) != 1 {
		t.Fatalf("want 1 suggestion, got %d", len(got))
	}
	s := got[0]
	if s.LowConfidence {
		t.Fatal("1000 samples should not be low-confidence")
	}
	// (900 + 20*0.5) / (1000 + 20) = 910 / 1020 = 0.892...
	if !approx(s.Suggested, 910.0/1020.0) {
		t.Fatalf("Suggested = %v, want %v", s.Suggested, 910.0/1020.0)
	}
	if s.Suggested < 0.85 {
		t.Fatalf("large high-precision sample should pull weight up, got %v", s.Suggested)
	}
}

func TestCalibrateClampsResultRange(t *testing.T) {
	// A Default outside [0,1] is clamped before blending; the suggestion must
	// stay within [0,1] regardless.
	got := Calibrate([]Sample{
		{Technique: "weird", Total: 5, Corroborated: 5, Default: 9.0},
		{Technique: "neg", Total: 5, Corroborated: 0, Default: -3.0},
	})
	for _, s := range got {
		if s.Suggested < 0 || s.Suggested > 1 {
			t.Fatalf("%s: Suggested %v out of [0,1]", s.Technique, s.Suggested)
		}
		if s.Current < 0 || s.Current > 1 {
			t.Fatalf("%s: Current %v out of [0,1]", s.Technique, s.Current)
		}
	}
}

func TestCalibrateLowConfidenceBoundary(t *testing.T) {
	// MinSamples is the threshold: exactly MinSamples is NOT low-confidence;
	// one below is.
	atThreshold := Calibrate([]Sample{{Technique: "a", Total: MinSamples, Corroborated: 10, Default: 0.5}})
	if atThreshold[0].LowConfidence {
		t.Fatalf("Total == MinSamples (%d) should not be low-confidence", MinSamples)
	}
	below := Calibrate([]Sample{{Technique: "b", Total: MinSamples - 1, Corroborated: 10, Default: 0.5}})
	if !below[0].LowConfidence {
		t.Fatalf("Total < MinSamples should be low-confidence")
	}
}
