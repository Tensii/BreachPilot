package main

import (
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
