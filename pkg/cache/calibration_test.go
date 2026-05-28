package cache

import "testing"

func TestRecordObservationsEmptyIsNoop(t *testing.T) {
	c := openTemp(t)
	if err := c.RecordObservations(nil); err != nil {
		t.Fatalf("RecordObservations(nil): %v", err)
	}
	n, err := c.ObservationCount()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("want 0 observations, got %d", n)
	}
}

func TestRecordAndAggregate(t *testing.T) {
	c := openTemp(t)
	// crtsh: 3 contributions, 2 corroborated.
	// host_header: 2 contributions, 0 corroborated.
	obs := []Observation{
		{Technique: "crtsh", Corroborated: true},
		{Technique: "crtsh", Corroborated: true},
		{Technique: "crtsh", Corroborated: false},
		{Technique: "host_header", Corroborated: false},
		{Technique: "host_header", Corroborated: false},
	}
	if err := c.RecordObservations(obs); err != nil {
		t.Fatalf("RecordObservations: %v", err)
	}

	count, err := c.ObservationCount()
	if err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Fatalf("ObservationCount = %d, want 5", count)
	}

	stats, err := c.CalibrationStats()
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 2 {
		t.Fatalf("want 2 technique stats, got %d", len(stats))
	}
	// Sorted by technique name: crtsh then host_header.
	if stats[0].Technique != "crtsh" || stats[1].Technique != "host_header" {
		t.Fatalf("stats not sorted by name: %+v", stats)
	}
	if stats[0].Total != 3 || stats[0].Corroborated != 2 {
		t.Fatalf("crtsh stats wrong: %+v", stats[0])
	}
	if !approxF(stats[0].Precision, 2.0/3.0) {
		t.Fatalf("crtsh precision = %v, want %v", stats[0].Precision, 2.0/3.0)
	}
	if stats[1].Total != 2 || stats[1].Corroborated != 0 {
		t.Fatalf("host_header stats wrong: %+v", stats[1])
	}
	if stats[1].Precision != 0 {
		t.Fatalf("host_header precision = %v, want 0", stats[1].Precision)
	}
}

func TestObservationsAccumulateAcrossRuns(t *testing.T) {
	c := openTemp(t)
	for i := 0; i < 3; i++ {
		if err := c.RecordObservations([]Observation{
			{Technique: "crtsh", Corroborated: true},
		}); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	stats, err := c.CalibrationStats()
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 1 || stats[0].Total != 3 || stats[0].Corroborated != 3 {
		t.Fatalf("accumulation wrong: %+v", stats)
	}
}

func TestResetObservations(t *testing.T) {
	c := openTemp(t)
	if err := c.RecordObservations([]Observation{
		{Technique: "crtsh", Corroborated: true},
		{Technique: "crtsh", Corroborated: false},
	}); err != nil {
		t.Fatal(err)
	}
	n, err := c.ResetObservations()
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("ResetObservations returned %d, want 2", n)
	}
	count, err := c.ObservationCount()
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("after reset want 0, got %d", count)
	}
}

func TestCalibrationStatsEmpty(t *testing.T) {
	c := openTemp(t)
	stats, err := c.CalibrationStats()
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 0 {
		t.Fatalf("want no stats on fresh cache, got %d", len(stats))
	}
}

func approxF(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 1e-9
}
