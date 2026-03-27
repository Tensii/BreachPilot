package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"breachpilot/internal/exploit"
	"breachpilot/internal/models"
)

type BenchmarkCase struct {
	Name         string                  `json:"name"`
	Findings     []models.ExploitFinding `json:"findings"`
	TruePositive []string                `json:"true_positive"`
}

type BenchmarkMetrics struct {
	CaseName    string  `json:"case_name"`
	Precision   float64 `json:"precision"`
	Recall      float64 `json:"recall"`
	F1          float64 `json:"f1"`
	TP          int     `json:"tp"`
	FP          int     `json:"fp"`
	FN          int     `json:"fn"`
	GeneratedAt string  `json:"generated_at"`
}

func EvaluateBenchmarkCase(c BenchmarkCase) BenchmarkMetrics {
	labelSet := map[string]struct{}{}
	for _, k := range c.TruePositive {
		k = strings.TrimSpace(strings.ToLower(k))
		if k != "" {
			labelSet[k] = struct{}{}
		}
	}

	tp, fp := 0, 0
	seen := map[string]struct{}{}
	for _, finding := range c.Findings {
		key := strings.ToLower(strings.TrimSpace(exploit.FindingFingerprint(finding)))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if _, ok := labelSet[key]; ok {
			tp++
		} else {
			fp++
		}
	}
	fn := 0
	for key := range labelSet {
		if _, ok := seen[key]; !ok {
			fn++
		}
	}
	precision := ratio(tp, tp+fp)
	recall := ratio(tp, tp+fn)
	f1 := 0.0
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}
	return BenchmarkMetrics{
		CaseName:    c.Name,
		Precision:   precision,
		Recall:      recall,
		F1:          f1,
		TP:          tp,
		FP:          fp,
		FN:          fn,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func WriteBenchmarkMetrics(artDir string, metrics []BenchmarkMetrics) (string, error) {
	if strings.TrimSpace(artDir) == "" {
		return "", fmt.Errorf("empty benchmark output directory")
	}
	payload := map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"metrics":      metrics,
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(artDir, "benchmark_metrics.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func ratio(num, den int) float64 {
	if den <= 0 {
		return 0
	}
	return float64(num) / float64(den)
}
