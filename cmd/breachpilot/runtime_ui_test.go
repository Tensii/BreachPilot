package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"breachpilot/internal/models"
)

func TestCLIRuntimeTrackerRendersProgressAndCounts(t *testing.T) {
	var buf bytes.Buffer
	tracker := newCLIRuntimeTracker(&buf)
	tracker.startedAt = time.Now().Add(-3 * time.Second)

	tracker.Handle(models.RuntimeEvent{
		Kind:   "module",
		Stage:  "exploit.module",
		Status: "planned",
		Module: "idorplaybook",
		Counts: map[string]int{"planned": 4},
		Progress: &models.RuntimeProgress{
			Label:     "modules",
			Unit:      "modules",
			Completed: 0,
			Total:     4,
			Percent:   0,
		},
	})
	tracker.Handle(models.RuntimeEvent{
		Kind:    "log",
		Stage:   "exploit.log",
		Status:  "info",
		Message: "exploit.log Requests: 25/100 (25%)",
		Progress: &models.RuntimeProgress{
			Label:     "targets",
			Unit:      "targets",
			Completed: 25,
			Total:     100,
			Percent:   25,
		},
	})
	tracker.Handle(models.RuntimeEvent{
		Kind:  "finding",
		Stage: "exploit.finding",
		Finding: &models.FindingPreview{
			Module:     "idorplaybook",
			Severity:   "critical",
			Validation: "confirmed",
			Title:      "Privilege escalation",
			Target:     "https://example.com/admin",
		},
	})
	tracker.Handle(models.RuntimeEvent{
		Kind:    "stage",
		Stage:   "exploit.errors",
		Status:  "warning",
		Message: "exploit.errors total=12 timeout=5 tls=3",
		Counts:  map[string]int{"total": 12, "timeout": 5, "tls": 3},
	})

	out := buf.String()
	if !strings.Contains(out, "[PROGRESS]") {
		t.Fatalf("expected progress line in output, got:\n%s", out)
	}
	if !strings.Contains(out, "25/100 (25%)") {
		t.Fatalf("expected target progress in output, got:\n%s", out)
	}
	if !strings.Contains(out, "findings=1") {
		t.Fatalf("expected live finding count in output, got:\n%s", out)
	}
	if !strings.Contains(out, "C/H/M=1/0/0") {
		t.Fatalf("expected severity counts in output, got:\n%s", out)
	}
	if !strings.Contains(out, "nerr=total=12 timeout=5 tls=3") {
		t.Fatalf("expected nuclei error summary in snapshot, got:\n%s", out)
	}
}
