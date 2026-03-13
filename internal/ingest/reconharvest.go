package ingest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"breachpilot/internal/models"
)

func LoadReconSummary(path string) (models.ReconSummary, error) {
	var rs models.ReconSummary
	b, err := os.ReadFile(path)
	if err != nil {
		return rs, fmt.Errorf("read summary: %w", err)
	}
	if err := json.Unmarshal(b, &rs); err != nil {
		return rs, fmt.Errorf("parse summary json: %w", err)
	}
	return rs, nil
}

func GuessTargetFromSummary(path string) string {
	dir := filepath.Dir(strings.TrimSpace(path))
	if dir == "." || dir == "" {
		return ""
	}
	base := filepath.Base(dir)
	if base == "reports" || base == "recon" {
		base = filepath.Base(filepath.Dir(dir))
	}
	if base == "outputs" || base == "" {
		return ""
	}
	return base
}
