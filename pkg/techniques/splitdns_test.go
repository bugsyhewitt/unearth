package techniques

import (
	"context"
	"strings"
	"testing"
)

// A known Cloudflare IP (inside 104.16.0.0/13) used across these tests as the
// CDN-fronted "front door"; 203.0.113.x / 198.51.100.x are TEST-NET ranges that
// are never CDN.
const cdnFrontIP = "104.16.0.5"

func TestSplitDNS_ApexDirectWhileWWWFronted(t *testing.T) {
	fr := newFakeResolver()
	fr.A = map[string][]string{
		"example.test":     {"203.0.113.10"}, // apex direct → origin
		"www.example.test": {cdnFrontIP},     // www behind CDN
	}
	withFakeResolver(t, fr)

	out, err := splitDNSTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 candidate, got %d: %+v", len(out), out)
	}
	if out[0].IP != "203.0.113.10" {
		t.Errorf("want apex origin 203.0.113.10, got %s", out[0].IP)
	}
	if !strings.Contains(out[0].Evidence, "split-DNS") ||
		!strings.Contains(out[0].Evidence, "www.example.test") {
		t.Errorf("evidence: %q", out[0].Evidence)
	}
}

func TestSplitDNS_NoSignalWhenNothingFronted(t *testing.T) {
	fr := newFakeResolver()
	fr.A = map[string][]string{
		"example.test":     {"203.0.113.10"},
		"www.example.test": {"203.0.113.11"},
	}
	withFakeResolver(t, fr)

	out, _ := splitDNSTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if len(out) != 0 {
		t.Errorf("no CDN front door means no split-DNS signal, got %+v", out)
	}
}

func TestSplitDNS_NoCandidateWhenApexAlsoFronted(t *testing.T) {
	fr := newFakeResolver()
	fr.A = map[string][]string{
		"example.test":     {cdnFrontIP},
		"www.example.test": {cdnFrontIP},
	}
	withFakeResolver(t, fr)

	out, _ := splitDNSTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if len(out) != 0 {
		t.Errorf("fully-fronted target yields no origin candidate, got %+v", out)
	}
}

func TestSplitDNS_ProbeLabelLeaksOrigin(t *testing.T) {
	fr := newFakeResolver()
	fr.A = map[string][]string{
		"example.test":      {cdnFrontIP}, // apex fronted
		"www.example.test":  {cdnFrontIP}, // www fronted
		"mail.example.test": {"198.51.100.20"},
	}
	withFakeResolver(t, fr)

	out, _ := splitDNSTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if len(out) != 1 {
		t.Fatalf("want 1 candidate from mail sibling, got %d: %+v", len(out), out)
	}
	if out[0].IP != "198.51.100.20" {
		t.Errorf("want mail origin 198.51.100.20, got %s", out[0].IP)
	}
	if !strings.Contains(out[0].Evidence, "mail.example.test") {
		t.Errorf("evidence should name the mail sibling: %q", out[0].Evidence)
	}
}

func TestSplitDNS_FiltersCDNSiblings(t *testing.T) {
	fr := newFakeResolver()
	fr.A = map[string][]string{
		"example.test":        {"203.0.113.10"}, // apex direct
		"www.example.test":    {cdnFrontIP},     // www fronted
		"direct.example.test": {cdnFrontIP},     // sibling also fronted → filtered
	}
	withFakeResolver(t, fr)

	out, _ := splitDNSTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	for _, c := range out {
		if c.IP == cdnFrontIP {
			t.Errorf("CDN sibling IP must be filtered, got %+v", c)
		}
	}
	// Only the apex origin should remain.
	if len(out) != 1 || out[0].IP != "203.0.113.10" {
		t.Errorf("want only apex origin, got %+v", out)
	}
}

func TestSplitDNS_ApexFrontedWWWAbsent(t *testing.T) {
	// When www does not resolve but the apex is CDN-fronted, a non-CDN sibling
	// is still a valid signal against the apex front door.
	fr := newFakeResolver()
	fr.A = map[string][]string{
		"example.test":        {cdnFrontIP},
		"origin.example.test": {"203.0.113.55"},
	}
	withFakeResolver(t, fr)

	out, _ := splitDNSTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if len(out) != 1 || out[0].IP != "203.0.113.55" {
		t.Fatalf("want origin sibling 203.0.113.55, got %+v", out)
	}
	if !strings.Contains(out[0].Evidence, "example.test is CDN-fronted") {
		t.Errorf("evidence should reference apex front door: %q", out[0].Evidence)
	}
}

func TestSplitDNS_DedupsSiblings(t *testing.T) {
	fr := newFakeResolver()
	fr.A = map[string][]string{
		"example.test":      {cdnFrontIP},
		"mail.example.test": {"198.51.100.20"},
		"smtp.example.test": {"198.51.100.20"}, // same IP as mail
	}
	withFakeResolver(t, fr)

	out, _ := splitDNSTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if len(out) != 1 {
		t.Errorf("duplicate sibling IP should appear once, got %+v", out)
	}
}

func TestSplitDNSTechnique_Metadata(t *testing.T) {
	s := splitDNSTechnique{}
	if s.Name() != "split_dns" || s.Tier() != TierPassive || s.RequiresAPIKey() || s.DefaultWeight() != 0.80 {
		t.Errorf("metadata wrong: %+v", s)
	}
}

func TestSplitDNS_EmptyTarget(t *testing.T) {
	out, err := splitDNSTechnique{}.Run(context.Background(), "  ", RunOptions{})
	if err != nil || len(out) != 0 {
		t.Errorf("empty target: out=%+v err=%v", out, err)
	}
}
