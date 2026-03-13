package config

import (
	"os"
	"testing"
)

func TestValidateInvalidTimeout(t *testing.T) {
	cfg := Config{NucleiBin: "echo", WebhookRetries: 1, ReconTimeoutSec: 0, ReconRetries: 0, NucleiTimeoutSec: 1}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidationOnlyEnvTrue(t *testing.T) {
	_ = os.Setenv("BREACHPILOT_VALIDATION_ONLY", "true")
	defer os.Unsetenv("BREACHPILOT_VALIDATION_ONLY")
	cfg := Load()
	if !cfg.ValidationOnly {
		t.Fatal("expected validation only true")
	}
}

func TestValidationOnlyDefaultFalse(t *testing.T) {
	os.Unsetenv("BREACHPILOT_VALIDATION_ONLY")
	cfg := Load()
	if cfg.ValidationOnly {
		t.Fatal("expected validation only false by default")
	}
}
