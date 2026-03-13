package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"breachpilot/internal/models"
)

func TestProcessReconTimeout(t *testing.T) {
	dir := t.TempDir()
	job := &models.Job{ID: "j1", Target: "example.com", Mode: "full", SafeMode: true}
	opt := Options{
		ReconHarvestCmd: "bash -lc 'sleep 2'",
		ReconTimeoutSec: 1,
		NucleiBin:       "true",
		ArtifactsRoot:   dir,
	}
	if err := Process(context.Background(), job, opt); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if job.Status != models.JobFailed {
		t.Fatalf("want failed got %s", job.Status)
	}
	if job.Error == "" {
		t.Fatal("expected timeout error")
	}
}

func TestProcessFileModeWritesReport(t *testing.T) {
	dir := t.TempDir()
	reconDir := filepath.Join(dir, "recon")
	_ = os.MkdirAll(reconDir, 0o755)
	summary := filepath.Join(reconDir, "summary.json")
	live := filepath.Join(reconDir, "live_hosts.txt")
	_ = os.WriteFile(live, []byte("https://example.com\n"), 0o644)
	_ = os.WriteFile(summary, []byte(`{"workdir":"`+reconDir+`","live_hosts":"`+live+`","urls":{"all":""},"intel":{"endpoints_ranked_json":"","params_ranked_json":""}}`), 0o644)

	job := &models.Job{ID: "j2", Target: "example.com", Mode: "ingest", SafeMode: true, ReconPath: summary}
	opt := Options{NucleiBin: "true", ArtifactsRoot: dir}
	if err := Process(context.Background(), job, opt); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if job.ReportPath == "" {
		t.Fatal("expected report path")
	}
	if _, err := os.Stat(job.ReportPath); err != nil {
		t.Fatalf("report missing: %v", err)
	}
}
