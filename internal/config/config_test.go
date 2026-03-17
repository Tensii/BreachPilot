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

func TestWebhookModuleProgressDefaultFalse(t *testing.T) {
	os.Unsetenv("BREACHPILOT_WEBHOOK_MODULE_PROGRESS")
	cfg := Load()
	if cfg.WebhookModuleProgress {
		t.Fatal("expected webhook module progress false by default")
	}
}

func TestValidateProofModeNoAllowlistIsValid(t *testing.T) {
	// Proof mode without an allowlist is now valid — empty allowlist means "allow all targets".
	// This removes the friction of listing every domain for internal security teams.
	cfg := Config{
		NucleiBin:        "echo",
		WebhookRetries:   1,
		ReconTimeoutSec:  1,
		ReconRetries:     0,
		NucleiTimeoutSec: 1,
		ModuleTimeoutSec: 1,
		ProofMode:        true,
		// ProofTargetAllowlist intentionally empty
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected no validation error when allowlist is empty, got: %v", err)
	}
}
