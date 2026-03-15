package main

import (
	"net"
	"strings"
	"testing"

	"breachpilot/internal/models"
)

func TestFormatCLISummaryCounts(t *testing.T) {
	job := &models.Job{Target: "example.com", Mode: "full", FindingsCount: 5, ExploitFindingsCount: 3, FilteredCount: 2}
	lines := formatCLISummary(job, "full")
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "Nuclei findings: 5") {
		t.Fatalf("missing nuclei count: %s", joined)
	}
	if !strings.Contains(joined, "Exploit-module findings: 3") {
		t.Fatalf("missing exploit count: %s", joined)
	}
	if !strings.Contains(joined, "Total findings: 8") {
		t.Fatalf("missing total count: %s", joined)
	}
	if !strings.Contains(joined, "Filtered findings: 2") {
		t.Fatalf("missing filtered count: %s", joined)
	}
}

func TestCheckWebhookReachableHonorsExplicitPort(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("socket unavailable: %v", err)
	}
	defer ln.Close()

	if err := checkWebhookReachable("http://" + ln.Addr().String()); err != nil {
		t.Fatalf("expected explicit port to succeed, got %v", err)
	}
}

func TestSplitCommandRejectsEmpty(t *testing.T) {
	if _, err := splitCommand("   "); err == nil {
		t.Fatal("expected empty command error")
	}
}
