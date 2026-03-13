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

func TargetFromWorkdir(workdir string) string {
	wd := filepath.Clean(strings.TrimSpace(workdir))
	if wd == "" || wd == "." {
		return ""
	}
	parent := filepath.Dir(wd)
	if parent == "." || parent == "" {
		return ""
	}
	target := filepath.Base(parent)
	if target == "." || target == "" || target == "outputs" {
		return ""
	}
	return target
}
