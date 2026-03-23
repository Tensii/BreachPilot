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
	NormalizeReconSummaryPaths(path, &rs)
	return rs, nil
}

func NormalizeReconSummaryPaths(summaryPath string, rs *models.ReconSummary) {
	if rs == nil {
		return
	}

	summaryDir := filepath.Dir(filepath.Clean(summaryPath))
	rs.Workdir = resolveReconSummaryPath(summaryDir, "", rs.Workdir, false)
	rs.Live = resolveReconSummaryPath(summaryDir, rs.Workdir, rs.Live, true)
	rs.URLs.All = resolveReconSummaryPath(summaryDir, rs.Workdir, rs.URLs.All, true)
	rs.Nuclei.Phase1JSONL = resolveReconSummaryPath(summaryDir, rs.Workdir, rs.Nuclei.Phase1JSONL, true)
	rs.Intel.EndpointsRankedJSON = resolveReconSummaryPath(summaryDir, rs.Workdir, rs.Intel.EndpointsRankedJSON, true)
	rs.Intel.ParamsRankedJSON = resolveReconSummaryPath(summaryDir, rs.Workdir, rs.Intel.ParamsRankedJSON, true)
	rs.Intel.SecretsJSON = resolveReconSummaryPath(summaryDir, rs.Workdir, rs.Intel.SecretsJSON, true)
	rs.Intel.CORSJSON = resolveReconSummaryPath(summaryDir, rs.Workdir, rs.Intel.CORSJSON, true)
	rs.Intel.BypassJSON = resolveReconSummaryPath(summaryDir, rs.Workdir, rs.Intel.BypassJSON, true)
	rs.Intel.PortScanJSON = resolveReconSummaryPath(summaryDir, rs.Workdir, rs.Intel.PortScanJSON, true)
	rs.Intel.NucleiPhase1JSONL = resolveReconSummaryPath(summaryDir, rs.Workdir, rs.Intel.NucleiPhase1JSONL, true)
	rs.Intel.SubdomainTakeoverJSON = resolveReconSummaryPath(summaryDir, rs.Workdir, rs.Intel.SubdomainTakeoverJSON, true)
	rs.Intel.JSEndpointsJSON = resolveReconSummaryPath(summaryDir, rs.Workdir, rs.Intel.JSEndpointsJSON, true)
}

func resolveReconSummaryPath(summaryDir, workdir, candidate string, requireExisting bool) string {
	p := strings.TrimSpace(candidate)
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}

	clean := filepath.Clean(p)
	if st, err := os.Stat(clean); err == nil {
		if !requireExisting || !st.IsDir() {
			return clean
		}
	}
	if clean == "." {
		return summaryDir
	}
	if filepath.Base(summaryDir) == clean {
		return summaryDir
	}

	tryPaths := make([]string, 0, 5)
	if workdir != "" {
		tryPaths = append(tryPaths, filepath.Join(workdir, clean))
		if prefix := filepath.Base(workdir) + string(filepath.Separator); strings.HasPrefix(clean, prefix) {
			tryPaths = append(tryPaths, filepath.Join(workdir, strings.TrimPrefix(clean, prefix)))
		}
	}
	tryPaths = append(tryPaths, filepath.Join(summaryDir, clean))
	if prefix := filepath.Base(summaryDir) + string(filepath.Separator); strings.HasPrefix(clean, prefix) {
		tryPaths = append(tryPaths, filepath.Join(summaryDir, strings.TrimPrefix(clean, prefix)))
	}
	parentDir := filepath.Dir(summaryDir)
	if parentDir != "" && parentDir != "." {
		tryPaths = append(tryPaths, filepath.Join(parentDir, clean))
	}

	for _, candidatePath := range tryPaths {
		if !requireExisting {
			if _, err := os.Stat(candidatePath); err == nil {
				return candidatePath
			}
			continue
		}
		if st, err := os.Stat(candidatePath); err == nil && !st.IsDir() {
			return candidatePath
		}
	}

	if workdir != "" {
		return filepath.Join(workdir, clean)
	}
	return filepath.Join(summaryDir, clean)
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
