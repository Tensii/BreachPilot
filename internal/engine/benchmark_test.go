package engine

import (
	"path/filepath"
	"testing"

	"breachpilot/internal/exploit"
	"breachpilot/internal/models"
)

func TestEvaluateBenchmarkCase(t *testing.T) {
	tpFinding := models.ExploitFinding{
		Module:   "ssrf-prober",
		Severity: "HIGH",
		Target:   "https://target.example/api/render?url=https://x",
		Title:    "Blind SSRF confirmed via OOB header callback",
	}
	fpFinding := models.ExploitFinding{
		Module:   "api-surface",
		Severity: "LOW",
		Target:   "https://target.example/wp-json/",
		Title:    "WordPress REST API index exposed",
	}
	tpKey := exploit.FindingFingerprint(tpFinding)

	metrics := EvaluateBenchmarkCase(BenchmarkCase{
		Name:         "sample-case",
		Findings:     []models.ExploitFinding{tpFinding, fpFinding},
		TruePositive: []string{tpKey},
	})
	if metrics.TP != 1 || metrics.FP != 1 || metrics.FN != 0 {
		t.Fatalf("unexpected benchmark counts: %+v", metrics)
	}
	if metrics.Precision <= 0 || metrics.Recall <= 0 {
		t.Fatalf("expected non-zero precision/recall, got %+v", metrics)
	}
}

func TestWriteBenchmarkMetrics(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteBenchmarkMetrics(dir, []BenchmarkMetrics{{CaseName: "x", Precision: 1.0}})
	if err != nil {
		t.Fatalf("write benchmark metrics: %v", err)
	}
	if got := filepath.Base(path); got != "benchmark_metrics.json" {
		t.Fatalf("unexpected output file %s", got)
	}
}
