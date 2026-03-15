package config

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type Config struct {
	WebhookURL                 string
	ReconWebhookURL            string
	ExploitWebhookURL          string
	WebhookSecret              string
	WebhookRetries             int
	NucleiBin                  string
	ReconHarvestCmd            string
	ReconTimeoutSec            int
	ReconRetries               int
	NucleiTimeoutSec           int
	ArtifactsRoot              string
	MinSeverity                string
	SkipModules                string
	OnlyModules                string
	ValidationOnly             bool
	ConfigPath                 string
	PreviousReportPath         string
	ReportFormats              string
	ScanProfile                string
	RateLimitRPS               int
	WebhookFindings            bool
	WebhookModuleProgress      bool
	WebhookFindingsMinSeverity string
	ModuleTimeoutSec           int
	ModuleRetries              int
	AggressiveMode             bool
	ProofMode                  bool
	ProofTargetAllowlist       string
	AuthUserCookie             string
	AuthAdminCookie            string
	AuthAnonHeaders            string
	AuthUserHeaders            string
	AuthAdminHeaders           string
}

func Load() Config {
	configPath := getEnv("BREACHPILOT_CONFIG", "./breachpilot.env")
	_ = loadEnvFile(configPath)

	reconWH := os.Getenv("BREACHPILOT_WEBHOOK_RECON")
	exploitWH := os.Getenv("BREACHPILOT_WEBHOOK_EXPLOIT")
	legacyWH := os.Getenv("BREACHPILOT_WEBHOOK")
	if reconWH == "" {
		reconWH = legacyWH
	}
	if exploitWH == "" {
		exploitWH = legacyWH
	}

	return Config{
		WebhookURL:                 legacyWH,
		ReconWebhookURL:            reconWH,
		ExploitWebhookURL:          exploitWH,
		WebhookSecret:              os.Getenv("BREACHPILOT_WEBHOOK_SECRET"),
		WebhookRetries:             getEnvInt("BREACHPILOT_WEBHOOK_RETRIES", 3),
		NucleiBin:                  getEnv("BREACHPILOT_NUCLEI_BIN", "nuclei"),
		ReconHarvestCmd:            getEnv("BREACHPILOT_RECONHARVEST_CMD", ""),
		ReconTimeoutSec:            getEnvInt("BREACHPILOT_RECON_TIMEOUT_SEC", 7200),
		ReconRetries:               getEnvInt("BREACHPILOT_RECON_RETRIES", 1),
		NucleiTimeoutSec:           getEnvInt("BREACHPILOT_NUCLEI_TIMEOUT_SEC", 1800),
		ArtifactsRoot:              getEnv("BREACHPILOT_ARTIFACTS", "./artifacts"),
		MinSeverity:                getEnv("BREACHPILOT_MIN_SEVERITY", ""),
		SkipModules:                getEnv("BREACHPILOT_SKIP_MODULES", ""),
		OnlyModules:                getEnv("BREACHPILOT_ONLY_MODULES", ""),
		ValidationOnly:             getEnvBool("BREACHPILOT_VALIDATION_ONLY", false),
		ConfigPath:                 configPath,
		PreviousReportPath:         getEnv("BREACHPILOT_PREVIOUS_REPORT", ""),
		ReportFormats:              getEnv("BREACHPILOT_REPORT_FORMATS", "json,md,html"),
		ScanProfile:                getEnv("BREACHPILOT_SCAN_PROFILE", ""),
		RateLimitRPS:               getEnvInt("BREACHPILOT_RATE_LIMIT_RPS", 0),
		WebhookFindings:            getEnvBool("BREACHPILOT_WEBHOOK_FINDINGS", true),
		WebhookModuleProgress:      getEnvBool("BREACHPILOT_WEBHOOK_MODULE_PROGRESS", false),
		WebhookFindingsMinSeverity: getEnv("BREACHPILOT_WEBHOOK_FINDINGS_MIN_SEVERITY", ""),
		ModuleTimeoutSec:           getEnvInt("BREACHPILOT_MODULE_TIMEOUT_SEC", 120),
		ModuleRetries:              getEnvInt("BREACHPILOT_MODULE_RETRIES", 1),
		AggressiveMode:             getEnvBool("BREACHPILOT_AGGRESSIVE", false),
		ProofMode:                  getEnvBool("BREACHPILOT_PROOF_MODE", false),
		ProofTargetAllowlist:       getEnv("BREACHPILOT_PROOF_TARGET_ALLOWLIST", ""),
		AuthUserCookie:             getEnv("BREACHPILOT_AUTH_USER_COOKIE", ""),
		AuthAdminCookie:            getEnv("BREACHPILOT_AUTH_ADMIN_COOKIE", ""),
		AuthAnonHeaders:            getEnv("BREACHPILOT_AUTH_ANON_HEADERS", ""),
		AuthUserHeaders:            getEnv("BREACHPILOT_AUTH_USER_HEADERS", ""),
		AuthAdminHeaders:           getEnv("BREACHPILOT_AUTH_ADMIN_HEADERS", ""),
	}
}

func getEnv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func getEnvBool(k string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func getEnvInt(k string, fallback int) int {
	v := os.Getenv(k)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func (c Config) Validate() error {
	if c.WebhookRetries < 0 {
		return fmt.Errorf("invalid BREACHPILOT_WEBHOOK_RETRIES: must be >= 0")
	}
	if c.ReconTimeoutSec <= 0 {
		return fmt.Errorf("invalid BREACHPILOT_RECON_TIMEOUT_SEC: must be > 0")
	}
	if c.ReconRetries < 0 {
		return fmt.Errorf("invalid BREACHPILOT_RECON_RETRIES: must be >= 0")
	}
	if c.NucleiTimeoutSec <= 0 {
		return fmt.Errorf("invalid BREACHPILOT_NUCLEI_TIMEOUT_SEC: must be > 0")
	}
	if c.ModuleTimeoutSec <= 0 {
		return fmt.Errorf("invalid BREACHPILOT_MODULE_TIMEOUT_SEC: must be > 0")
	}
	if c.ModuleRetries < 0 {
		return fmt.Errorf("invalid BREACHPILOT_MODULE_RETRIES: must be >= 0")
	}
	if c.ProofMode && strings.TrimSpace(c.ProofTargetAllowlist) == "" {
		return fmt.Errorf("invalid BREACHPILOT_PROOF_TARGET_ALLOWLIST: required when BREACHPILOT_PROOF_MODE is enabled")
	}
	if strings.TrimSpace(c.NucleiBin) != "" {
		if _, err := exec.LookPath(c.NucleiBin); err != nil {
			return fmt.Errorf("invalid BREACHPILOT_NUCLEI_BIN: %w", err)
		}
	}
	validSevs := map[string]bool{"": true, "INFO": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}
	if !validSevs[strings.ToUpper(strings.TrimSpace(c.MinSeverity))] {
		return fmt.Errorf("invalid BREACHPILOT_MIN_SEVERITY: %q (valid: INFO LOW MEDIUM HIGH CRITICAL)", c.MinSeverity)
	}
	if !validSevs[strings.ToUpper(strings.TrimSpace(c.WebhookFindingsMinSeverity))] {
		return fmt.Errorf("invalid BREACHPILOT_WEBHOOK_FINDINGS_MIN_SEVERITY: %q (valid: INFO LOW MEDIUM HIGH CRITICAL)", c.WebhookFindingsMinSeverity)
	}
	return nil
}

func (c Config) RedactedSummary() string {
	redact := func(v string) string {
		v = strings.TrimSpace(v)
		if v == "" {
			return "<empty>"
		}
		if len(v) <= 12 {
			return "<set>"
		}
		return v[:8] + "...<redacted>"
	}
	minSev := strings.TrimSpace(c.MinSeverity)
	if minSev == "" {
		minSev = "<none>"
	}
	skipMods := strings.TrimSpace(c.SkipModules)
	if skipMods == "" {
		skipMods = "<none>"
	}
	onlyMods := strings.TrimSpace(c.OnlyModules)
	if onlyMods == "" {
		onlyMods = "<none>"
	}
	prevReport := strings.TrimSpace(c.PreviousReportPath)
	if prevReport == "" {
		prevReport = "<empty>"
	}
	reportFormats := strings.TrimSpace(c.ReportFormats)
	if reportFormats == "" {
		reportFormats = "json,md,html"
	}
	ctxCount := 0
	if strings.TrimSpace(c.AuthUserCookie) != "" || strings.TrimSpace(c.AuthUserHeaders) != "" {
		ctxCount++
	}
	if strings.TrimSpace(c.AuthAdminCookie) != "" || strings.TrimSpace(c.AuthAdminHeaders) != "" {
		ctxCount++
	}
	return fmt.Sprintf("config: reconWebhook=%s exploitWebhook=%s retries=%d nucleiBin=%s reconTimeout=%ds nucleiTimeout=%ds artifacts=%s minSeverity=%s skipModules=%s onlyModules=%s validationOnly=%t aggressive=%t proofMode=%t proofAllowlist=%s authContexts=%d previousReport=%s reportFormats=%s scanProfile=%s rateLimitRPS=%d",
		redact(c.ReconWebhookURL), redact(c.ExploitWebhookURL), c.WebhookRetries, c.NucleiBin, c.ReconTimeoutSec, c.NucleiTimeoutSec, c.ArtifactsRoot, minSev, skipMods, onlyMods, c.ValidationOnly, c.AggressiveMode, c.ProofMode, redact(c.ProofTargetAllowlist), ctxCount, prevReport, reportFormats, c.ScanProfile, c.RateLimitRPS)
}

func loadEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"`)
		if k == "" {
			continue
		}
		if os.Getenv(k) == "" {
			_ = os.Setenv(k, v)
		}
	}
	return s.Err()
}
