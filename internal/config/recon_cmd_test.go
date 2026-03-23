package config

import "testing"

func TestParseReconHarvestHelpCapturesSupportedFlags(t *testing.T) {
	help := `usage: reconHarvest.py [-h] [--run] [--resume RESUME] [-o OUTPUT] [--skip-nuclei] [--overwrite] [target]`
	caps := parseReconHarvestHelp(help)
	if !caps.SupportsCoreExecution() {
		t.Fatalf("expected core execution support, got %+v", caps)
	}
	if !caps.Supports("--skip-nuclei") || !caps.Supports("--overwrite") {
		t.Fatalf("expected optional flags to be detected, got %+v", caps)
	}
	if caps.Supports("--arjun-threads") || caps.Supports("--vhost-threads") {
		t.Fatalf("did not expect unsupported performance flags, got %+v", caps)
	}
}
