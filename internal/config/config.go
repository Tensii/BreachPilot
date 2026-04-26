package config

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type Config struct {
	WebhookURL                     string
	ReconWebhookURL                string
	ExploitWebhookURL              string
	InteractshWebhookURL           string
	WebhookSecret                  string
	WebhookRetries                 int
	WebhookReliableMode            bool
	WebhookQueueBlockTimeoutMS     int
	WebhookSpoolPath               string
	NucleiBin                      string
	ReconHarvestCmd                string
	ReconTimeoutSec                int
	ReconRetries                   int
	NucleiTimeoutSec               int
	ArtifactsRoot                  string
	MinSeverity                    string
	SkipModules                    string
	OnlyModules                    string
	ValidationOnly                 bool
	ConfigPath                     string
	PreviousReportPath             string
	ReportFormats                  string
	ScanProfile                    string
	MaxParallel                    int
	RateLimitRPS                   int
	HTTPJitterMS                   int
	HTTPCircuitBreakerThreshold    int
	HTTPCircuitBreakerCooldownMS   int
	HTTPCircuitBreakerWait         bool
	WebhookFindings                bool
	WebhookModuleProgress          bool
	WebhookFindingsMinSeverity     string
	WebhookFindingsCap             int
	ModuleTimeoutSec               int
	ModuleRetries                  int
	AggressiveMode                 bool
	BoundlessMode                  bool
	ProofMode                      bool
	ProofTargetAllowlist           string
	OOBHTTPListenAddr              string
	OOBHTTPPublicBaseURL           string
	OOBPollWaitSec                 int
	AuthUserCookie                 string
	AuthAdminCookie                string
	AuthAnonHeaders                string
	AuthUserHeaders                string
	AuthAdminHeaders               string
	SSRFCanaryHost                 string
	SSRFCanarySupportsRedirect     bool
	OpenRedirectCanaryHost         string
	SkipNuclei                     bool
	ScoringEnabled                 bool
	ChainAnalysisEnabled           bool
	ExposureOverride               string
	CriticalityOverride            string
	BrowserCaptureEnabled          bool
	BrowserCaptureMaxPages         int
	BrowserCapturePerPageWaitMs    int
	BrowserCaptureSettleWaitMs     int
	BrowserCaptureScrollSteps      int
	BrowserCaptureMaxRoutesPerPage int
	BrowserCapturePath             string
}

func Load() Config {
	configPath := getEnv("BREACHPILOT_CONFIG", "./breachpilot.env")
	_ = loadEnvFile(configPath)

	reconWH := os.Getenv("BREACHPILOT_WEBHOOK_RECON")
	exploitWH := os.Getenv("BREACHPILOT_WEBHOOK_EXPLOIT")
	interactshWH := os.Getenv("BREACHPILOT_WEBHOOK_INTERACTSH")
	legacyWH := os.Getenv("BREACHPILOT_WEBHOOK")
	if reconWH == "" {
		reconWH = legacyWH
	}
	if exploitWH == "" {
		exploitWH = legacyWH
	}
	if interactshWH == "" {
		interactshWH = legacyWH
	}

	cfg := Config{
		WebhookURL:                     legacyWH,
		ReconWebhookURL:                reconWH,
		ExploitWebhookURL:              exploitWH,
		InteractshWebhookURL:           interactshWH,
		WebhookSecret:                  os.Getenv("BREACHPILOT_WEBHOOK_SECRET"),
		WebhookRetries:                 getEnvInt("BREACHPILOT_WEBHOOK_RETRIES", 3),
		WebhookReliableMode:            getEnvBool("BREACHPILOT_WEBHOOK_RELIABLE_MODE", false),
		WebhookQueueBlockTimeoutMS:     getEnvInt("BREACHPILOT_WEBHOOK_QUEUE_BLOCK_TIMEOUT_MS", 2000),
		WebhookSpoolPath:               getEnv("BREACHPILOT_WEBHOOK_SPOOL_PATH", ""),
		NucleiBin:                      getEnv("BREACHPILOT_NUCLEI_BIN", "nuclei"),
		ReconHarvestCmd:                getEnv("BREACHPILOT_RECONHARVEST_CMD", ""),
		ReconTimeoutSec:                getEnvInt("BREACHPILOT_RECON_TIMEOUT_SEC", 7200),
		ReconRetries:                   getEnvInt("BREACHPILOT_RECON_RETRIES", 1),
		NucleiTimeoutSec:               getEnvInt("BREACHPILOT_NUCLEI_TIMEOUT_SEC", 1800),
		ArtifactsRoot:                  getEnv("BREACHPILOT_ARTIFACTS", "./artifacts"),
		MinSeverity:                    getEnv("BREACHPILOT_MIN_SEVERITY", ""),
		SkipModules:                    getEnv("BREACHPILOT_SKIP_MODULES", ""),
		OnlyModules:                    getEnv("BREACHPILOT_ONLY_MODULES", ""),
		ValidationOnly:                 getEnvBool("BREACHPILOT_VALIDATION_ONLY", false),
		ConfigPath:                     configPath,
		PreviousReportPath:             getEnv("BREACHPILOT_PREVIOUS_REPORT", ""),
		ReportFormats:                  getEnv("BREACHPILOT_REPORT_FORMATS", "json,md,bbmd,bbpdf,html"),
		ScanProfile:                    getEnv("BREACHPILOT_SCAN_PROFILE", ""),
		MaxParallel:                    getEnvInt("BREACHPILOT_MAX_PARALLEL", 0),
		RateLimitRPS:                   getEnvInt("BREACHPILOT_RATE_LIMIT_RPS", 0),
		HTTPJitterMS:                   getEnvInt("BREACHPILOT_HTTP_JITTER_MS", 0),
		HTTPCircuitBreakerThreshold:    getEnvInt("BREACHPILOT_HTTP_CIRCUIT_BREAKER_THRESHOLD", 0),
		HTTPCircuitBreakerCooldownMS:   getEnvInt("BREACHPILOT_HTTP_CIRCUIT_BREAKER_COOLDOWN_MS", 15000),
		HTTPCircuitBreakerWait:         getEnvBool("BREACHPILOT_HTTP_CIRCUIT_BREAKER_WAIT", false),
		WebhookFindings:                getEnvBool("BREACHPILOT_WEBHOOK_FINDINGS", true),
		WebhookModuleProgress:          getEnvBool("BREACHPILOT_WEBHOOK_MODULE_PROGRESS", false),
		WebhookFindingsMinSeverity:     getEnv("BREACHPILOT_WEBHOOK_FINDINGS_MIN_SEVERITY", ""),
		WebhookFindingsCap:             getEnvInt("BREACHPILOT_WEBHOOK_FINDINGS_CAP", 20),
		ModuleTimeoutSec:               getEnvInt("BREACHPILOT_MODULE_TIMEOUT_SEC", 900),
		ModuleRetries:                  getEnvInt("BREACHPILOT_MODULE_RETRIES", 1),
		AggressiveMode:                 getEnvBool("BREACHPILOT_AGGRESSIVE", false),
		BoundlessMode:                  getEnvBool("BREACHPILOT_BOUNDLESS", false),
		ProofMode:                      getEnvBool("BREACHPILOT_PROOF_MODE", false),
		ProofTargetAllowlist:           getEnv("BREACHPILOT_PROOF_TARGET_ALLOWLIST", ""),
		OOBHTTPListenAddr:              getEnv("BREACHPILOT_OOB_HTTP_LISTEN_ADDR", ""),
		OOBHTTPPublicBaseURL:           getEnv("BREACHPILOT_OOB_HTTP_PUBLIC_BASE_URL", ""),
		OOBPollWaitSec:                 getEnvInt("BREACHPILOT_OOB_POLL_WAIT_SEC", 10),
		AuthUserCookie:                 getEnv("BREACHPILOT_AUTH_USER_COOKIE", ""),
		AuthAdminCookie:                getEnv("BREACHPILOT_AUTH_ADMIN_COOKIE", ""),
		AuthAnonHeaders:                getEnv("BREACHPILOT_AUTH_ANON_HEADERS", ""),
		AuthUserHeaders:                getEnv("BREACHPILOT_AUTH_USER_HEADERS", ""),
		AuthAdminHeaders:               getEnv("BREACHPILOT_AUTH_ADMIN_HEADERS", ""),
		SSRFCanaryHost:                 getEnv("BREACHPILOT_SSRF_CANARY_HOST", "ssrf.breachpilot.internal"),
		SSRFCanarySupportsRedirect:     getEnvBool("BREACHPILOT_SSRF_CANARY_REDIRECT", false),
		OpenRedirectCanaryHost:         getEnv("BREACHPILOT_REDIRECT_CANARY_HOST", "evil.breachpilot.internal"),
		SkipNuclei:                     getEnvBool("BREACHPILOT_SKIP_NUCLEI", false),
		ScoringEnabled:                 getEnvBool("BREACHPILOT_SCORING_ENABLED", true),
		ChainAnalysisEnabled:           getEnvBool("BREACHPILOT_CHAIN_ANALYSIS_ENABLED", true),
		ExposureOverride:               getEnv("BREACHPILOT_EXPOSURE_OVERRIDE", ""),
		CriticalityOverride:            getEnv("BREACHPILOT_CRITICALITY_OVERRIDE", ""),
		BrowserCaptureEnabled:          getEnvBool("BREACHPILOT_BROWSER_CAPTURE", false),
		BrowserCaptureMaxPages:         getEnvInt("BREACHPILOT_BROWSER_CAPTURE_MAX_PAGES", 6),
		BrowserCapturePerPageWaitMs:    getEnvInt("BREACHPILOT_BROWSER_CAPTURE_PER_PAGE_WAIT_MS", 4000),
		BrowserCaptureSettleWaitMs:     getEnvInt("BREACHPILOT_BROWSER_CAPTURE_SETTLE_WAIT_MS", 1500),
		BrowserCaptureScrollSteps:      getEnvInt("BREACHPILOT_BROWSER_CAPTURE_SCROLL_STEPS", 3),
		BrowserCaptureMaxRoutesPerPage: getEnvInt("BREACHPILOT_BROWSER_CAPTURE_MAX_ROUTES_PER_PAGE", 10),
		BrowserCapturePath:             getEnv("BREACHPILOT_BROWSER_PATH", ""),
	}
	cfg.ReportFormats = normalizeReportFormats(cfg.ReportFormats)
	return cfg
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
	if c.WebhookQueueBlockTimeoutMS < 0 {
		return fmt.Errorf("invalid BREACHPILOT_WEBHOOK_QUEUE_BLOCK_TIMEOUT_MS: must be >= 0")
	}
	if c.WebhookReliableMode && c.WebhookQueueBlockTimeoutMS == 0 {
		return fmt.Errorf("invalid BREACHPILOT_WEBHOOK_QUEUE_BLOCK_TIMEOUT_MS: must be > 0 when BREACHPILOT_WEBHOOK_RELIABLE_MODE=true")
	}
	if !c.BoundlessMode && c.ReconTimeoutSec <= 0 {
		return fmt.Errorf("invalid BREACHPILOT_RECON_TIMEOUT_SEC: must be > 0 (or enable BREACHPILOT_BOUNDLESS to disable timeouts)")
	}
	if c.ReconRetries < 0 {
		return fmt.Errorf("invalid BREACHPILOT_RECON_RETRIES: must be >= 0")
	}
	if !c.BoundlessMode && c.NucleiTimeoutSec <= 0 {
		return fmt.Errorf("invalid BREACHPILOT_NUCLEI_TIMEOUT_SEC: must be > 0 (or enable BREACHPILOT_BOUNDLESS to disable timeouts)")
	}
	if !c.BoundlessMode && c.ModuleTimeoutSec <= 0 {
		return fmt.Errorf("invalid BREACHPILOT_MODULE_TIMEOUT_SEC: must be > 0 (or enable BREACHPILOT_BOUNDLESS to disable timeouts)")
	}
	if c.ModuleRetries < 0 {
		return fmt.Errorf("invalid BREACHPILOT_MODULE_RETRIES: must be >= 0")
	}
	if c.WebhookFindingsCap < 0 {
		return fmt.Errorf("invalid BREACHPILOT_WEBHOOK_FINDINGS_CAP: must be >= 0")
	}
	if c.MaxParallel < 0 {
		return fmt.Errorf("invalid BREACHPILOT_MAX_PARALLEL: must be >= 0")
	}
	if c.RateLimitRPS < 0 {
		return fmt.Errorf("invalid BREACHPILOT_RATE_LIMIT_RPS: must be >= 0")
	}
	if c.HTTPJitterMS < 0 {
		return fmt.Errorf("invalid BREACHPILOT_HTTP_JITTER_MS: must be >= 0")
	}
	if c.HTTPCircuitBreakerThreshold < 0 {
		return fmt.Errorf("invalid BREACHPILOT_HTTP_CIRCUIT_BREAKER_THRESHOLD: must be >= 0")
	}
	if c.HTTPCircuitBreakerCooldownMS < 0 {
		return fmt.Errorf("invalid BREACHPILOT_HTTP_CIRCUIT_BREAKER_COOLDOWN_MS: must be >= 0")
	}
	if c.BrowserCaptureEnabled {
		if c.BrowserCaptureMaxPages <= 0 {
			return fmt.Errorf("invalid BREACHPILOT_BROWSER_CAPTURE_MAX_PAGES: must be > 0")
		}
		if c.BrowserCapturePerPageWaitMs <= 0 {
			return fmt.Errorf("invalid BREACHPILOT_BROWSER_CAPTURE_PER_PAGE_WAIT_MS: must be > 0")
		}
		if c.BrowserCaptureSettleWaitMs <= 0 {
			return fmt.Errorf("invalid BREACHPILOT_BROWSER_CAPTURE_SETTLE_WAIT_MS: must be > 0")
		}
		if c.BrowserCaptureScrollSteps <= 0 {
			return fmt.Errorf("invalid BREACHPILOT_BROWSER_CAPTURE_SCROLL_STEPS: must be > 0")
		}
		if c.BrowserCaptureMaxRoutesPerPage <= 0 {
			return fmt.Errorf("invalid BREACHPILOT_BROWSER_CAPTURE_MAX_ROUTES_PER_PAGE: must be > 0")
		}
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
	if base := strings.TrimSpace(c.OOBHTTPPublicBaseURL); base != "" {
		parsed, err := url.Parse(base)
		if err != nil {
			return fmt.Errorf("invalid BREACHPILOT_OOB_HTTP_PUBLIC_BASE_URL: %w", err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("invalid BREACHPILOT_OOB_HTTP_PUBLIC_BASE_URL: scheme must be http or https")
		}
		if strings.TrimSpace(parsed.Host) == "" {
			return fmt.Errorf("invalid BREACHPILOT_OOB_HTTP_PUBLIC_BASE_URL: host is required")
		}
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
	reportFormats := normalizeReportFormats(c.ReportFormats)
	ctxCount := 0
	if strings.TrimSpace(c.AuthUserCookie) != "" || strings.TrimSpace(c.AuthUserHeaders) != "" {
		ctxCount++
	}
	if strings.TrimSpace(c.AuthAdminCookie) != "" || strings.TrimSpace(c.AuthAdminHeaders) != "" {
		ctxCount++
	}
	return fmt.Sprintf("config: reconWebhook=%s exploitWebhook=%s interactshWebhook=%s retries=%d webhookReliableMode=%t webhookQueueBlockTimeoutMs=%d webhookSpoolPath=%s nucleiBin=%s reconTimeout=%ds nucleiTimeout=%ds artifacts=%s minSeverity=%s skipModules=%s onlyModules=%s validationOnly=%t aggressive=%t boundless=%t proofMode=%t proofAllowlist=%s oobHttpPublicBase=%s authContexts=%d previousReport=%s reportFormats=%s scanProfile=%s maxParallel=%d rateLimitRPS=%d httpJitterMs=%d httpCircuitBreakerThreshold=%d httpCircuitBreakerCooldownMs=%d httpCircuitBreakerWait=%t moduleTimeout=%ds webhookFindingsCap=%d scoring=%t chains=%t exposureOverride=%s criticalityOverride=%s",
		redact(c.ReconWebhookURL), redact(c.ExploitWebhookURL), redact(c.InteractshWebhookURL), c.WebhookRetries, c.WebhookReliableMode, c.WebhookQueueBlockTimeoutMS, redact(c.WebhookSpoolPath), c.NucleiBin, c.ReconTimeoutSec, c.NucleiTimeoutSec, c.ArtifactsRoot, minSev, skipMods, onlyMods, c.ValidationOnly, c.AggressiveMode, c.BoundlessMode, c.ProofMode, redact(c.ProofTargetAllowlist), redact(c.OOBHTTPPublicBaseURL), ctxCount, prevReport, reportFormats, c.ScanProfile, c.MaxParallel, c.RateLimitRPS, c.HTTPJitterMS, c.HTTPCircuitBreakerThreshold, c.HTTPCircuitBreakerCooldownMS, c.HTTPCircuitBreakerWait, c.ModuleTimeoutSec, c.WebhookFindingsCap, c.ScoringEnabled, c.ChainAnalysisEnabled, c.ExposureOverride, c.CriticalityOverride)
}

func normalizeReportFormats(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "json,md,bbmd,bbpdf,html"
	}

	formats := map[string]bool{}
	add := func(token string) {
		switch strings.ToLower(strings.TrimSpace(token)) {
		case "json", "md", "bbmd", "bbpdf", "html", "sarif":
			formats[strings.ToLower(strings.TrimSpace(token))] = true
		case "bugbounty":
			formats["bbmd"] = true
		case "pdf":
			formats["bbpdf"] = true
		}
	}

	for _, token := range strings.Split(raw, ",") {
		add(token)
	}

	if len(formats) == 0 {
		formats["json"] = true
		formats["md"] = true
		formats["html"] = true
	}

	// Always emit bug bounty markdown + per-finding PDFs.
	formats["bbmd"] = true
	formats["bbpdf"] = true

	order := []string{"json", "md", "bbmd", "bbpdf", "html", "sarif"}
	out := make([]string, 0, len(order))
	for _, name := range order {
		if formats[name] {
			out = append(out, name)
		}
	}
	return strings.Join(out, ",")
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
