package techniques

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeEML writes body to a temp .eml file and returns its path.
func writeEML(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "msg.eml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write eml: %v", err)
	}
	return path
}

func TestEmailHeader_Metadata(t *testing.T) {
	e := emailHeaderTechnique{}
	if e.Name() != "email_header" {
		t.Errorf("name: %q", e.Name())
	}
	if e.Tier() != TierPassive {
		t.Errorf("tier: %v", e.Tier())
	}
	if e.RequiresAPIKey() {
		t.Error("should not require API key")
	}
	if e.DefaultWeight() != 0.85 {
		t.Errorf("weight: %v", e.DefaultWeight())
	}
}

func TestEmailHeader_NoFileSkips(t *testing.T) {
	out, err := emailHeaderTechnique{}.Run(context.Background(), "example.test", RunOptions{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("no email file should yield no candidates, got %+v", out)
	}
}

func TestEmailHeader_ExtractsPublicIPs(t *testing.T) {
	eml := strings.Join([]string{
		"Received: from mx1.example.test (mx1.example.test [203.0.113.10])",
		"\tby mail.recipient.test with ESMTP id abc123",
		"\tfor <victim@recipient.test>; Tue, 27 May 2026 10:00:00 +0000",
		"Received: from origin.internal (origin.internal [198.51.100.7])",
		"\tby mx1.example.test with ESMTP id def456; Tue, 27 May 2026 09:59:58 +0000",
		"From: news@example.test",
		"To: victim@recipient.test",
		"Subject: hello",
		"",
		"body text",
		"",
	}, "\r\n")
	path := writeEML(t, eml)

	out, err := emailHeaderTechnique{}.Run(context.Background(), "example.test", RunOptions{EmailFile: path})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := map[string]bool{}
	for _, c := range out {
		got[c.IP] = true
	}
	for _, want := range []string{"203.0.113.10", "198.51.100.7"} {
		if !got[want] {
			t.Errorf("missing IP %s in %v", want, got)
		}
	}
}

func TestEmailHeader_FiltersPrivateAndLoopback(t *testing.T) {
	eml := strings.Join([]string{
		"Received: from internal (internal [10.0.0.5])",
		"Received: from box (box [192.168.1.1])",
		"Received: from lan (lan [172.16.0.9])",
		"Received: from local (local [127.0.0.1])",
		"Received: from real (real [203.0.113.99])",
		"",
		"body",
		"",
	}, "\r\n")
	path := writeEML(t, eml)

	out, err := emailHeaderTechnique{}.Run(context.Background(), "example.test", RunOptions{EmailFile: path})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 || out[0].IP != "203.0.113.99" {
		t.Errorf("want only the public IP 203.0.113.99, got %+v", out)
	}
}

func TestEmailHeader_FiltersCDN(t *testing.T) {
	eml := strings.Join([]string{
		"Received: from edge (edge [104.16.0.5])", // Cloudflare range
		"Received: from origin (origin [203.0.113.42])",
		"",
		"body",
		"",
	}, "\r\n")
	path := writeEML(t, eml)

	out, err := emailHeaderTechnique{}.Run(context.Background(), "example.test", RunOptions{EmailFile: path})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, c := range out {
		if c.IP == "104.16.0.5" {
			t.Errorf("Cloudflare IP should be filtered: %+v", c)
		}
	}
	if len(out) != 1 || out[0].IP != "203.0.113.42" {
		t.Errorf("want only non-CDN IP, got %+v", out)
	}
}

func TestEmailHeader_DedupAndSorted(t *testing.T) {
	eml := strings.Join([]string{
		"Received: from a (a [198.51.100.20])",
		"Received: from b (b [203.0.113.5])",
		"Received: from a-again (a-again [198.51.100.20])", // duplicate
		"",
		"body",
		"",
	}, "\r\n")
	path := writeEML(t, eml)

	out, err := emailHeaderTechnique{}.Run(context.Background(), "example.test", RunOptions{EmailFile: path})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 unique candidates, got %d: %+v", len(out), out)
	}
	if out[0].IP != "198.51.100.20" || out[1].IP != "203.0.113.5" {
		t.Errorf("candidates not sorted ascending: %+v", out)
	}
}

func TestEmailHeader_IPv6(t *testing.T) {
	eml := strings.Join([]string{
		"Received: from v6 (v6 [2001:db8::1234])",
		"",
		"body",
		"",
	}, "\r\n")
	path := writeEML(t, eml)

	out, err := emailHeaderTechnique{}.Run(context.Background(), "example.test", RunOptions{EmailFile: path})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 || out[0].IP != "2001:db8::1234" {
		t.Errorf("want IPv6 candidate, got %+v", out)
	}
}

func TestEmailHeader_MissingFileErrors(t *testing.T) {
	_, err := emailHeaderTechnique{}.Run(context.Background(), "example.test",
		RunOptions{EmailFile: filepath.Join(t.TempDir(), "does-not-exist.eml")})
	if err == nil {
		t.Error("missing file should return an error")
	}
}

func TestEmailHeader_Evidence(t *testing.T) {
	eml := "Received: from mx (mx [203.0.113.7])\r\n\r\nbody\r\n"
	path := writeEML(t, eml)
	out, err := emailHeaderTechnique{}.Run(context.Background(), "example.test", RunOptions{EmailFile: path})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(out))
	}
	if !strings.Contains(out[0].Evidence, "Received") || !strings.Contains(out[0].Evidence, "203.0.113.7") {
		t.Errorf("evidence: %q", out[0].Evidence)
	}
}
