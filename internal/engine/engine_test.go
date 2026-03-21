package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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
	b, _ := os.ReadFile(job.ReportPath)
	if !strings.Contains(string(b), "\"schema_version\": \"1\"") {
		t.Fatalf("schema version missing in job report")
	}
}

func TestProcessFailsWhenExploitFindingsWriteFails(t *testing.T) {
	dir := t.TempDir()
	reconDir := filepath.Join(dir, "recon")
	_ = os.MkdirAll(reconDir, 0o755)
	summary := filepath.Join(reconDir, "summary.json")
	live := filepath.Join(reconDir, "live_hosts.txt")
	cors := filepath.Join(reconDir, "cors.json")
	_ = os.WriteFile(live, []byte("https://example.com\n"), 0o644)
	_ = os.WriteFile(cors, []byte(`[{"host":"https://example.com","severity":"HIGH","acao":"*","acac":"true"}]`), 0o644)
	_ = os.WriteFile(summary, []byte(`{"workdir":"`+reconDir+`","live_hosts":"`+live+`","urls":{"all":""},"intel":{"endpoints_ranked_json":"","params_ranked_json":"","cors_findings_json":"`+cors+`"}}`), 0o644)

	nucleiScript := filepath.Join(dir, "fake_nuclei.sh")
	script := "#!/usr/bin/env bash\nset -e\nout=\"\"\nfor ((i=1;i<=$#;i++)); do if [[ \"${!i}\" == '-o' ]]; then j=$((i+1)); out=\"${!j}\"; fi; done\nmkdir -p \"$(dirname \"$out\")\"\necho '{\"template-id\":\"x\",\"info\":{\"name\":\"x\",\"severity\":\"high\"},\"matched-at\":\"https://example.com\"}' > \"$out\"\nchmod 500 \"$(dirname \"$out\")\"\n"
	_ = os.WriteFile(nucleiScript, []byte(script), 0o755)

	job := &models.Job{ID: "j3", Target: "example.com", Mode: "ingest", SafeMode: true, ReconPath: summary}
	opt := Options{NucleiBin: nucleiScript, ArtifactsRoot: dir}
	err := Process(context.Background(), job, opt)
	_ = os.Chmod(filepath.Join(dir, job.ID), 0o755)
	if err == nil {
		t.Fatal("expected error")
	}
	if job.Status != models.JobFailed {
		t.Fatalf("want failed got %s", job.Status)
	}
	if job.ExploitFindingsPath != "" {
		t.Fatalf("expected empty exploit findings path on failure")
	}
	if job.ExploitReportPath != "" || job.ExploitHTMLReportPath != "" {
		t.Fatalf("expected no exploit report paths on failure")
	}
}

func TestValidateReconSummarySchemaMismatch(t *testing.T) {
	dir := t.TempDir()
	summary := filepath.Join(dir, "summary.json")
	live := filepath.Join(dir, "live_hosts.txt")
	_ = os.WriteFile(live, []byte("https://example.com\n"), 0o644)
	_ = os.WriteFile(summary, []byte(`{"schema_version":"999","workdir":"`+dir+`","live_hosts":"`+live+`","urls":{"all":""},"intel":{"endpoints_ranked_json":"","params_ranked_json":""}}`), 0o644)
	_, err := validateReconSummary(summary, "example.com")
	if err == nil {
		t.Fatal("expected schema mismatch error")
	}
}

func TestFileAndFullProduceCompatibleCounts(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live_hosts.txt")
	_ = os.WriteFile(live, []byte("http://127.0.0.1:9\n"), 0o644)
	summary := filepath.Join(dir, "summary.json")
	_ = os.WriteFile(summary, []byte(`{"workdir":"`+dir+`","live_hosts":"`+live+`","urls":{"all":""},"intel":{"endpoints_ranked_json":"","params_ranked_json":""}}`), 0o644)

	jobFile := &models.Job{ID: "c1", Target: "example.com", Mode: "ingest", SafeMode: true, ReconPath: summary}
	opt := Options{NucleiBin: "true", ArtifactsRoot: dir}
	if err := Process(context.Background(), jobFile, opt); err != nil {
		t.Fatalf("ingest failed: %v", err)
	}

	reconScript := filepath.Join(dir, "fake_recon.sh")
	script := "#!/usr/bin/env bash\nset -e\nout=\"\"\nfor ((i=1;i<=$#;i++)); do if [[ \"${!i}\" == '-o' ]]; then j=$((i+1)); out=\"${!j}\"; fi; done\nmkdir -p \"$out\"\ncp \"" + summary + "\" \"$out/summary.json\"\n"
	_ = os.WriteFile(reconScript, []byte(script), 0o755)
	jobFull := &models.Job{ID: "c2", Target: "example.com", Mode: "full", SafeMode: true}
	opt2 := Options{NucleiBin: "true", ReconHarvestCmd: reconScript, ArtifactsRoot: dir}
	if err := Process(context.Background(), jobFull, opt2); err != nil {
		t.Fatalf("full failed: %v", err)
	}
	if jobFile.ExploitFindingsCount != jobFull.ExploitFindingsCount {
		t.Fatalf("incompatible exploit counts: %d vs %d", jobFile.ExploitFindingsCount, jobFull.ExploitFindingsCount)
	}
}

func TestAnnotateModuleTelemetryYield(t *testing.T) {
	in := []models.ExploitModuleTelemetry{
		{Module: "ssrf-prober", FindingsCount: 3},
		{Module: "cookie-security", FindingsCount: 2},
		{Module: "planner-only", Skipped: true},
	}
	raw := []models.ExploitFinding{
		{Module: "ssrf-prober"},
		{Module: "ssrf-prober"},
		{Module: "ssrf-prober"},
		{Module: "cookie-security"},
		{Module: "cookie-security"},
	}
	accepted := []models.ExploitFinding{
		{Module: "ssrf-prober"},
	}

	out := annotateModuleTelemetryYield(in, raw, accepted)
	if out[0].AcceptedCount != 1 || out[0].FilteredCount != 2 {
		t.Fatalf("expected ssrf-prober yield 1 accepted / 2 filtered, got %+v", out[0])
	}
	if out[1].AcceptedCount != 0 || out[1].FilteredCount != 2 {
		t.Fatalf("expected cookie-security to be fully filtered, got %+v", out[1])
	}
	if out[2].AcceptedCount != 0 || out[2].FilteredCount != 0 {
		t.Fatalf("expected skipped planner entry to remain zero-yield, got %+v", out[2])
	}
}
