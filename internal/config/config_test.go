package config

import (
	"os"
	"strings"
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

func TestWebhookFindingsCapDefaultTwenty(t *testing.T) {
	os.Unsetenv("BREACHPILOT_WEBHOOK_FINDINGS_CAP")
	cfg := Load()
	if cfg.WebhookFindingsCap != 20 {
		t.Fatalf("expected webhook findings cap 20 by default, got %d", cfg.WebhookFindingsCap)
	}
}

func TestLoadMaxParallel(t *testing.T) {
	_ = os.Setenv("BREACHPILOT_MAX_PARALLEL", "6")
	defer os.Unsetenv("BREACHPILOT_MAX_PARALLEL")

	cfg := Load()
	if cfg.MaxParallel != 6 {
		t.Fatalf("expected max parallel 6, got %d", cfg.MaxParallel)
	}
}

func TestLoadHTTPTransportOptions(t *testing.T) {
	_ = os.Setenv("BREACHPILOT_HTTP_JITTER_MS", "125")
	_ = os.Setenv("BREACHPILOT_HTTP_CIRCUIT_BREAKER_THRESHOLD", "4")
	_ = os.Setenv("BREACHPILOT_HTTP_CIRCUIT_BREAKER_COOLDOWN_MS", "2200")
	_ = os.Setenv("BREACHPILOT_HTTP_CIRCUIT_BREAKER_WAIT", "true")
	defer os.Unsetenv("BREACHPILOT_HTTP_JITTER_MS")
	defer os.Unsetenv("BREACHPILOT_HTTP_CIRCUIT_BREAKER_THRESHOLD")
	defer os.Unsetenv("BREACHPILOT_HTTP_CIRCUIT_BREAKER_COOLDOWN_MS")
	defer os.Unsetenv("BREACHPILOT_HTTP_CIRCUIT_BREAKER_WAIT")

	cfg := Load()
	if cfg.HTTPJitterMS != 125 || cfg.HTTPCircuitBreakerThreshold != 4 || cfg.HTTPCircuitBreakerCooldownMS != 2200 || !cfg.HTTPCircuitBreakerWait {
		t.Fatalf("http transport options did not load correctly: %+v", cfg)
	}
}

func TestLoadOOBHTTPOptions(t *testing.T) {
	_ = os.Setenv("BREACHPILOT_OOB_HTTP_LISTEN_ADDR", "127.0.0.1:9091")
	_ = os.Setenv("BREACHPILOT_OOB_HTTP_PUBLIC_BASE_URL", "https://oob.example.com/callback")
	defer os.Unsetenv("BREACHPILOT_OOB_HTTP_LISTEN_ADDR")
	defer os.Unsetenv("BREACHPILOT_OOB_HTTP_PUBLIC_BASE_URL")

	cfg := Load()
	if cfg.OOBHTTPListenAddr != "127.0.0.1:9091" || cfg.OOBHTTPPublicBaseURL != "https://oob.example.com/callback" {
		t.Fatalf("oob http options did not load correctly: %+v", cfg)
	}
}

func TestValidateRejectsNegativeMaxParallel(t *testing.T) {
	cfg := Config{
		NucleiBin:        "echo",
		WebhookRetries:   1,
		ReconTimeoutSec:  1,
		ReconRetries:     0,
		NucleiTimeoutSec: 1,
		ModuleTimeoutSec: 1,
		MaxParallel:      -1,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for negative max parallel")
	}
}

func TestValidateRejectsNegativeHTTPJitter(t *testing.T) {
	cfg := Config{
		NucleiBin:        "echo",
		WebhookRetries:   1,
		ReconTimeoutSec:  1,
		ReconRetries:     0,
		NucleiTimeoutSec: 1,
		ModuleTimeoutSec: 1,
		HTTPJitterMS:     -1,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for negative http jitter")
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

func TestValidateRejectsInvalidOOBHTTPPublicBaseURL(t *testing.T) {
	cfg := Config{
		NucleiBin:            "echo",
		WebhookRetries:       1,
		ReconTimeoutSec:      1,
		ReconRetries:         0,
		NucleiTimeoutSec:     1,
		ModuleTimeoutSec:     1,
		OOBHTTPPublicBaseURL: "://bad-url",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for invalid OOB public base URL")
	}
}

func TestLoadBrowserCaptureOptions(t *testing.T) {
	_ = os.Setenv("BREACHPILOT_BROWSER_CAPTURE", "true")
	_ = os.Setenv("BREACHPILOT_BROWSER_CAPTURE_MAX_PAGES", "9")
	_ = os.Setenv("BREACHPILOT_BROWSER_CAPTURE_PER_PAGE_WAIT_MS", "5000")
	_ = os.Setenv("BREACHPILOT_BROWSER_CAPTURE_SETTLE_WAIT_MS", "2000")
	_ = os.Setenv("BREACHPILOT_BROWSER_CAPTURE_SCROLL_STEPS", "5")
	_ = os.Setenv("BREACHPILOT_BROWSER_CAPTURE_MAX_ROUTES_PER_PAGE", "14")
	defer os.Unsetenv("BREACHPILOT_BROWSER_CAPTURE")
	defer os.Unsetenv("BREACHPILOT_BROWSER_CAPTURE_MAX_PAGES")
	defer os.Unsetenv("BREACHPILOT_BROWSER_CAPTURE_PER_PAGE_WAIT_MS")
	defer os.Unsetenv("BREACHPILOT_BROWSER_CAPTURE_SETTLE_WAIT_MS")
	defer os.Unsetenv("BREACHPILOT_BROWSER_CAPTURE_SCROLL_STEPS")
	defer os.Unsetenv("BREACHPILOT_BROWSER_CAPTURE_MAX_ROUTES_PER_PAGE")

	cfg := Load()
	if !cfg.BrowserCaptureEnabled || cfg.BrowserCaptureMaxPages != 9 || cfg.BrowserCapturePerPageWaitMs != 5000 || cfg.BrowserCaptureSettleWaitMs != 2000 || cfg.BrowserCaptureScrollSteps != 5 || cfg.BrowserCaptureMaxRoutesPerPage != 14 {
		t.Fatalf("browser capture options did not load correctly: %+v", cfg)
	}
}

func TestLoadWebhookReliabilityOptions(t *testing.T) {
	_ = os.Setenv("BREACHPILOT_WEBHOOK_RELIABLE_MODE", "true")
	_ = os.Setenv("BREACHPILOT_WEBHOOK_QUEUE_BLOCK_TIMEOUT_MS", "3500")
	_ = os.Setenv("BREACHPILOT_WEBHOOK_SPOOL_PATH", "/tmp/bp-webhook-spool.jsonl")
	defer os.Unsetenv("BREACHPILOT_WEBHOOK_RELIABLE_MODE")
	defer os.Unsetenv("BREACHPILOT_WEBHOOK_QUEUE_BLOCK_TIMEOUT_MS")
	defer os.Unsetenv("BREACHPILOT_WEBHOOK_SPOOL_PATH")

	cfg := Load()
	if !cfg.WebhookReliableMode || cfg.WebhookQueueBlockTimeoutMS != 3500 || cfg.WebhookSpoolPath != "/tmp/bp-webhook-spool.jsonl" {
		t.Fatalf("webhook reliability options did not load correctly: %+v", cfg)
	}
}

func TestValidateWebhookReliableModeRequiresPositiveQueueTimeout(t *testing.T) {
	cfg := Config{
		NucleiBin:                  "echo",
		WebhookRetries:             1,
		WebhookReliableMode:        true,
		WebhookQueueBlockTimeoutMS: 0,
		ReconTimeoutSec:            1,
		ReconRetries:               0,
		NucleiTimeoutSec:           1,
		ModuleTimeoutSec:           1,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error when reliable mode is enabled with zero queue timeout")
	}
}

func TestNormalizeReportFormatsAlwaysIncludesPDF(t *testing.T) {
	got := normalizeReportFormats("json,md,html")
	if !strings.Contains(got, "bbmd") || !strings.Contains(got, "bbpdf") {
		t.Fatalf("expected bbmd and bbpdf in normalized formats, got %q", got)
	}
}

func TestLoadReportFormatsAutoEnforcesPDF(t *testing.T) {
	_ = os.Setenv("BREACHPILOT_REPORT_FORMATS", "json,md,html")
	defer os.Unsetenv("BREACHPILOT_REPORT_FORMATS")

	cfg := Load()
	if !strings.Contains(cfg.ReportFormats, "bbmd") || !strings.Contains(cfg.ReportFormats, "bbpdf") {
		t.Fatalf("expected report formats to include bbmd/bbpdf, got %q", cfg.ReportFormats)
	}
}
