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

	parts := strings.Split(filepath.ToSlash(wd), "/")
	for i := 0; i < len(parts); i++ {
		if parts[i] != "artifacts" && parts[i] != "outputs" {
			continue
		}
		// Expected shapes:
		// - artifacts/<target>/<run>/recon
		// - outputs/<target>/<run>
		if i+1 < len(parts) {
			target := strings.TrimSpace(parts[i+1])
			if target != "" && target != "." {
				return target
			}
		}
	}

	// Fallback to legacy behavior
	parent := filepath.Dir(wd)
	if parent == "." || parent == "" {
		return ""
	}
	target := filepath.Base(parent)
	if target == "." || target == "" || target == "outputs" || target == "artifacts" {
		return ""
	}
	return target
}
