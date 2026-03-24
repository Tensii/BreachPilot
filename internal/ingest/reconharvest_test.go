package ingest

import (
	"os"
	"path/filepath"
	"testing"

	"breachpilot/internal/models"
)

func TestNormalizeReconSummaryPathsPreservesExistingRepoRelativePaths(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(wd)
	})

	reconDir := filepath.Join("artifacts", "example.com", "4", "recon")
	if err := os.MkdirAll(filepath.Join(reconDir, "intel"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reconDir, "summary.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reconDir, "live_hosts.txt"), []byte("https://example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reconDir, "intel", "params_ranked.json"), []byte("[]"), 0o644); err != nil {
		t.Fatal(err)
	}

	rs := models.ReconSummary{
		Workdir: "artifacts/example.com/4/recon",
		Live:    "artifacts/example.com/4/recon/live_hosts.txt",
	}
	rs.Intel.ParamsRankedJSON = "artifacts/example.com/4/recon/intel/params_ranked.json"

	NormalizeReconSummaryPaths(filepath.Join(reconDir, "summary.json"), &rs)

	if got := filepath.ToSlash(rs.Workdir); got != "artifacts/example.com/4/recon" {
		t.Fatalf("expected workdir to remain repo-relative, got %q", got)
	}
	if got := filepath.ToSlash(rs.Live); got != "artifacts/example.com/4/recon/live_hosts.txt" {
		t.Fatalf("expected live_hosts path to remain repo-relative, got %q", got)
	}
	if got := filepath.ToSlash(rs.Intel.ParamsRankedJSON); got != "artifacts/example.com/4/recon/intel/params_ranked.json" {
		t.Fatalf("expected intel path to remain repo-relative, got %q", got)
	}
}

func TestNormalizeReconSummaryPathsHandlesCopiedReportSummary(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(wd)
	})

	reconRunDir := filepath.Join("artifacts", "example.com", "4", "recon", "run")
	reportsDir := filepath.Join(reconRunDir, "reports")
	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reconRunDir, "live_hosts.txt"), []byte("https://example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rs := models.ReconSummary{
		Workdir: "run",
		Live:    "run/live_hosts.txt",
	}

	NormalizeReconSummaryPaths(filepath.Join(reportsDir, "summary.json"), &rs)

	if got := filepath.ToSlash(rs.Workdir); got != "artifacts/example.com/4/recon/run" {
		t.Fatalf("expected workdir to resolve to canonical run dir, got %q", got)
	}
	if got := filepath.ToSlash(rs.Live); got != "artifacts/example.com/4/recon/run/live_hosts.txt" {
		t.Fatalf("expected live_hosts to resolve to canonical run file, got %q", got)
	}
}
