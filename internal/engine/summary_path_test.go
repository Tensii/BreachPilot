package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExistingReconSummaryPathPrefersRunSummaryOverReportsCopy(t *testing.T) {
	reconDir := filepath.Join(t.TempDir(), "recon")
	runDir := filepath.Join(reconDir, "run")
	reportsDir := filepath.Join(runDir, "reports")
	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "workspace_meta.json"), []byte(`{"target":"example.com"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	runSummary := filepath.Join(runDir, "summary.json")
	if err := os.WriteFile(runSummary, []byte(`{"workdir":"run"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	reportSummary := filepath.Join(reportsDir, "summary.json")
	if err := os.WriteFile(reportSummary, []byte(`{"workdir":"run"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := existingReconSummaryPath(reconDir); got != runSummary {
		t.Fatalf("expected canonical run summary %q, got %q", runSummary, got)
	}
}
