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
	if !strings.Contains(joined, "Findings: nuclei=5 exploit=3 total=8 filtered=2") {
		t.Fatalf("missing nuclei count: %s", joined)
	}
	if !strings.Contains(joined, "Runtime: recon=0.0s exploit=0.0s total=0.0s") {
		t.Fatalf("missing runtime line: %s", joined)
	}
}

func TestFormatCLISummaryTopModules(t *testing.T) {
	job := &models.Job{
		Target:               "example.com",
		Mode:                 "full",
		ExploitFindingsCount: 5,
		ModuleTelemetry: []models.ExploitModuleTelemetry{
			{Module: "idorplaybook", FindingsCount: 3},
			{Module: "authbypass", FindingsCount: 2},
			{Module: "headers", FindingsCount: 1},
		},
	}
	lines := formatCLISummary(job, "full")
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "Top exploit modules: idorplaybook=3, authbypass=2, headers=1") {
		t.Fatalf("missing top module summary: %s", joined)
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
