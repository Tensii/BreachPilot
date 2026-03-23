package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"breachpilot/internal/config"
	"breachpilot/internal/engine"
	"breachpilot/internal/ingest"
	"breachpilot/internal/models"
	"breachpilot/internal/notify"
	"breachpilot/internal/scope"
	"github.com/google/shlex"
)

func main() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}
	args := os.Args[1:]
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	firstArg := strings.ToLower(strings.TrimSpace(args[0]))
	if firstArg == "help" || firstArg == "--help" || firstArg == "-h" {
		printUsage()
		return
	}

	if len(args) == 1 && args[0] == "setup" {
		printStartupBanner(cfg)
		engOpt := buildEngineOptions(cfg)
		if err := runSetup(engOpt); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(args) == 1 && args[0] == "list-modules" {
		printStartupBanner(cfg)
		engOpt := buildEngineOptions(cfg)
		listModules(engOpt)
		return
	}
	if len(args) == 1 && args[0] == "doctor" {
		printStartupBanner(cfg)
		engOpt := buildEngineOptions(cfg)
		if err := runDoctor(cfg, engOpt); err != nil {
			log.Fatal(err)
		}
		return
	}

	jsonOut := false
	aggressiveFlag := false
	boundlessFlag := false
	skipNucleiFlag := false
	if cfg.BrowserCaptureEnabled {
		_ = os.Setenv("BREACHPILOT_BROWSER_CAPTURE", "1")
		_ = os.Setenv("BREACHPILOT_BROWSER_CAPTURE_MAX_PAGES", fmt.Sprintf("%d", cfg.BrowserCaptureMaxPages))
		_ = os.Setenv("BREACHPILOT_BROWSER_CAPTURE_PER_PAGE_WAIT_MS", fmt.Sprintf("%d", cfg.BrowserCapturePerPageWaitMs))
		_ = os.Setenv("BREACHPILOT_BROWSER_CAPTURE_SETTLE_WAIT_MS", fmt.Sprintf("%d", cfg.BrowserCaptureSettleWaitMs))
		_ = os.Setenv("BREACHPILOT_BROWSER_CAPTURE_SCROLL_STEPS", fmt.Sprintf("%d", cfg.BrowserCaptureScrollSteps))
		_ = os.Setenv("BREACHPILOT_BROWSER_CAPTURE_MAX_ROUTES_PER_PAGE", fmt.Sprintf("%d", cfg.BrowserCaptureMaxRoutesPerPage))
		_ = os.Setenv("BREACHPILOT_BROWSER_PATH", cfg.BrowserCapturePath)
		_ = os.Setenv("BREACHPILOT_ARTIFACTS_ROOT", cfg.ArtifactsRoot)
	}
	filtered := make([]string, 0, len(args))
	for _, a := range args {
		n := strings.ToLower(strings.TrimSpace(a))
		if n == "--json" || n == "json" {
			jsonOut = true
			continue
		}
		if n == "--aggressive" || n == "aggressive" {
			aggressiveFlag = true
			continue
		}
		if n == "--boundless" || n == "boundless" {
			boundlessFlag = true
			continue
		}
		if n == "--skip-nuclei" {
			skipNucleiFlag = true
			continue
		}
		filtered = append(filtered, a)
	}
	if aggressiveFlag {
		cfg.AggressiveMode = true
	}
	if boundlessFlag {
		cfg.BoundlessMode = true
	}
	if skipNucleiFlag {
		cfg.SkipNuclei = true
	}
	printStartupBanner(cfg)

	engOpt := buildEngineOptions(cfg)
	nf := &notify.Webhook{URL: cfg.ExploitWebhookURL, Secret: cfg.WebhookSecret, Retries: cfg.WebhookRetries, DebugLogPath: filepath.Join(cfg.ArtifactsRoot, "webhook_exploit_debug.jsonl"), FindingsCap: cfg.WebhookFindingsCap}
	nf.Start()
	defer nf.Stop()
	rf := &notify.Webhook{URL: cfg.ReconWebhookURL, Secret: cfg.WebhookSecret, Retries: cfg.WebhookRetries, DebugLogPath: filepath.Join(cfg.ArtifactsRoot, "webhook_recon_debug.jsonl"), FindingsCap: cfg.WebhookFindingsCap}
	rf.Start()
	defer rf.Stop()
	engOpt.Notifier = nf

	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n[!] Interrupt received, safely stopping... Waiting for active tasks and webhooks to finish.")
		cancel()
		// We purposefully do not call os.Exit(1) here.
		// Canceling the context will cause the engine to unroll safely and return models.JobCancelled.
		// The main routine will then hit the switch job.Status case to send the job.cancelled webhook,
		// and the application will naturally exit cleanly.
	}()

	if len(filtered) > 0 && filtered[0] == "resume" {
		if err := resumeJob(ctx, filtered[1:], engOpt, nf, rf, jsonOut); err != nil {
			log.Fatal(err)
		}
		return
	}

	if err := runCLIMode(ctx, filtered, engOpt, nf, rf, jsonOut); err != nil {
		log.Fatal(err)
	}
}

func buildEngineOptions(cfg config.Config) engine.Options {
	return engine.Options{
		NucleiBin:                      cfg.NucleiBin,
		ReconHarvestCmd:                config.ResolveReconHarvestCmd(cfg.ReconHarvestCmd),
		ReconWebhookURL:                cfg.ReconWebhookURL,
		ReconTimeoutSec:                cfg.ReconTimeoutSec,
		ReconRetries:                   cfg.ReconRetries,
		NucleiTimeoutSec:               cfg.NucleiTimeoutSec,
		ArtifactsRoot:                  cfg.ArtifactsRoot,
		MinSeverity:                    cfg.MinSeverity,
		SkipModules:                    cfg.SkipModules,
		OnlyModules:                    cfg.OnlyModules,
		ValidationOnly:                 cfg.ValidationOnly,
		PreviousReportPath:             cfg.PreviousReportPath,
		ReportFormats:                  cfg.ReportFormats,
		ScanProfile:                    cfg.ScanProfile,
		MaxParallel:                    cfg.MaxParallel,
		RateLimitRPS:                   cfg.RateLimitRPS,
		HTTPJitterMS:                   cfg.HTTPJitterMS,
		HTTPCircuitBreakerThreshold:    cfg.HTTPCircuitBreakerThreshold,
		HTTPCircuitBreakerCooldownMS:   cfg.HTTPCircuitBreakerCooldownMS,
		HTTPCircuitBreakerWait:         cfg.HTTPCircuitBreakerWait,
		WebhookFindings:                cfg.WebhookFindings,
		WebhookModuleProgress:          cfg.WebhookModuleProgress,
		WebhookFindingsMinSeverity:     cfg.WebhookFindingsMinSeverity,
		ModuleTimeoutSec:               cfg.ModuleTimeoutSec,
		ModuleRetries:                  cfg.ModuleRetries,
		AggressiveMode:                 cfg.AggressiveMode,
		BoundlessMode:                  cfg.BoundlessMode,
		ProofMode:                      cfg.ProofMode,
		ProofTargetAllowlist:           cfg.ProofTargetAllowlist,
		AuthUserCookie:                 cfg.AuthUserCookie,
		AuthAdminCookie:                cfg.AuthAdminCookie,
		AuthAnonHeaders:                cfg.AuthAnonHeaders,
		AuthUserHeaders:                cfg.AuthUserHeaders,
		AuthAdminHeaders:               cfg.AuthAdminHeaders,
		SSRFCanaryHost:                 cfg.SSRFCanaryHost,
		SSRFCanaryRedirect:             cfg.SSRFCanarySupportsRedirect,
		OpenRedirectCanaryHost:         cfg.OpenRedirectCanaryHost,
		SkipNuclei:                     cfg.SkipNuclei,
		ScoringEnabled:                 cfg.ScoringEnabled,
		ChainAnalysisEnabled:           cfg.ChainAnalysisEnabled,
		ExposureOverride:               cfg.ExposureOverride,
		CriticalityOverride:            cfg.CriticalityOverride,
		BrowserCaptureEnabled:          cfg.BrowserCaptureEnabled,
		BrowserCaptureMaxPages:         cfg.BrowserCaptureMaxPages,
		BrowserCapturePerPageWaitMs:    cfg.BrowserCapturePerPageWaitMs,
		BrowserCaptureSettleWaitMs:     cfg.BrowserCaptureSettleWaitMs,
		BrowserCaptureScrollSteps:      cfg.BrowserCaptureScrollSteps,
		BrowserCaptureMaxRoutesPerPage: cfg.BrowserCaptureMaxRoutesPerPage,
		BrowserCapturePath:             cfg.BrowserCapturePath,
	}
}

func runCLIMode(ctx context.Context, args []string, opt engine.Options, nf *notify.Webhook, rf *notify.Webhook, jsonOut bool) error {
	if len(args) == 0 {
		return fmt.Errorf("missing mode. Use: full <target> OR file <summary.json>")
	}
	mode := strings.ToLower(strings.TrimSpace(args[0]))
	if mode != "full" && mode != "file" {
		return fmt.Errorf("unknown mode %q. Use: full <target> OR file <summary.json>", mode)
	}
	if len(args) < 2 {
		if mode == "file" {
			return fmt.Errorf("missing summary path. Use: breachpilot file <summary.json>")
		}
		return fmt.Errorf("missing target. Use: breachpilot full <target>")
	}

	target := ""
	if mode == "full" {
		target = strings.TrimSpace(args[1])
	}

	var reconPath string
	if mode == "file" {
		reconPath = strings.TrimSpace(args[1])
		if reconPath == "" {
			return fmt.Errorf("file mode requires summary path: breachpilot file <summary.json>")
		}
		if strings.Contains(filepath.ToSlash(reconPath), "/recon/reports/summary.json") {
			return fmt.Errorf("invalid summary path for file mode: %s (use recon/summary.json, not recon/reports/summary.json)", reconPath)
		}
		if _, err := os.Stat(reconPath); err != nil {
			return fmt.Errorf("summary path not accessible: %w", err)
		}
		if filepath.Base(reconPath) == ".breachpilot.state" {
			return fmt.Errorf("invalid summary path: file is a state checkpoint. Use: breachpilot resume %s", reconPath)
		}
		if err := validateArtifactManifestEntryForPath(reconPath); err != nil {
			return fmt.Errorf("artifact integrity validation failed: %w", err)
		}
		// Derive target from summary for directory naming
		if target == "" {
			if rs, err := ingest.LoadReconSummary(reconPath); err == nil {
				if guessed := ingest.TargetFromWorkdir(rs.Workdir); guessed != "" {
					target = guessed
				}
			}
			if target == "" {
				target = "from-summary"
			}
		}
		mode = "ingest"
	}

	jobID := nextRunID(opt.ArtifactsRoot, target)
	job := &models.Job{
		ID:        jobID,
		Target:    target,
		Mode:      mode,
		ReconPath: reconPath,
		SafeMode:  !opt.AggressiveMode,
		Status:    models.JobQueued,
		CreatedAt: time.Now().UTC(),
	}

	cliOpt := opt
	cliOpt.Progress = nil
	cliOpt.Events = buildCLIEventHandler(job, opt, nf, jsonOut)

	if mode != "full" {
		nf.Send("job.started", job)
	}
	if err := engine.Process(ctx, job, cliOpt); err != nil {
		job.Status = models.JobFailed
		job.Error = err.Error()
		nf.Send("job.failed", job)
		return err
	}

	switch job.Status {
	case models.JobRejected:
		nf.Send("job.rejected", job)
		if jsonOut {
			return printJobJSON(job)
		}
		fmt.Printf("\x1b[31m[✗] JOB REJECTED\x1b[0m %s\n", job.Error)
		return nil
	case models.JobCancelled:
		nf.Send("job.cancelled", job)
		if strings.EqualFold(job.Mode, "full") {
			rf.Send("job.cancelled", job)
		}
		if jsonOut {
			return printJobJSON(job)
		}
		fmt.Printf("\x1b[31m[!] JOB INTERRUPTED\x1b[0m\n")
		return nil
	case models.JobFailed:
		nf.Send("job.failed", job)
		if jsonOut {
			return printJobJSON(job)
		}
		fmt.Printf("\x1b[31m[✗] JOB FAILED\x1b[0m %s\n", job.Error)
		return nil
	default:
		nf.Send("job.completed", job)
	}

	if jsonOut {
		return printJobJSON(job)
	}
	for _, ln := range formatCLISummary(job, mode) {
		fmt.Println(ln)
	}
	return nil
}

func formatCLISummary(job *models.Job, mode string) []string {
	if job == nil {
		return nil
	}
	lines := []string{
		fmt.Sprintf("Done. target=%s mode=%s evidence=%s", job.Target, job.Mode, job.EvidencePath),
		fmt.Sprintf("Findings: nuclei=%d exploit=%d total=%d filtered=%d", job.FindingsCount, job.ExploitFindingsCount, job.FindingsCount+job.ExploitFindingsCount, job.FilteredCount),
		fmt.Sprintf("Runtime: recon=%.1fs exploit=%.1fs total=%.1fs", job.ReconDurationSec, job.ExploitDurationSec, job.ReconDurationSec+job.ExploitDurationSec),
	}
	if job.ReportPath != "" {
		lines = append(lines, fmt.Sprintf("Job report: %s", job.ReportPath))
	}
	if job.ExploitReportPath != "" {
		lines = append(lines, fmt.Sprintf("Exploit report: %s", job.ExploitReportPath))
	}
	if job.ExploitHTMLReportPath != "" {
		lines = append(lines, fmt.Sprintf("Exploit HTML report: %s", job.ExploitHTMLReportPath))
	}
	if job.RiskScore > 0 {
		lines = append(lines, fmt.Sprintf("Risk score: %.1f/10", job.RiskScore))
	}
	if topModules := summarizeTopModules(job); topModules != "" {
		lines = append(lines, fmt.Sprintf("Top exploit modules: %s", topModules))
	}
	if job.ExploitFindingsCount > 0 {
		lines = append(lines, fmt.Sprintf("Exploit findings: %d (JSONL: %s)", job.ExploitFindingsCount, job.ExploitFindingsPath))
	}
	if mode == "full" {
		lines = append(lines, fmt.Sprintf("Recon summary used: %s", job.ReconPath))
	}
	return lines
}

func buildCLIEventHandler(job *models.Job, opt engine.Options, nf *notify.Webhook, jsonOut bool) func(models.RuntimeEvent) {
	var tracker *cliRuntimeTracker
	if !jsonOut {
		tracker = newCLIRuntimeTracker(os.Stdout)
	}
	return func(ev models.RuntimeEvent) {
		if tracker != nil {
			tracker.Handle(ev)
		}
		if ev.Kind == "stage" && ev.Stage == "exploit" && ev.Status == "started" {
			nf.SendGeneric("exploit.started", map[string]any{
				"job_id": job.ID,
				"target": job.Target,
				"mode":   job.Mode,
			})
		}
		if opt.WebhookModuleProgress && ev.Kind == "module" {
			payload := map[string]any{
				"job_id": job.ID,
				"target": job.Target,
				"stage":  ev.Stage,
				"module": ev.Module,
				"status": ev.Status,
			}
			if strings.TrimSpace(ev.Message) != "" {
				payload["detail"] = ev.Message
			}
			if len(ev.Counts) > 0 {
				payload["counts"] = ev.Counts
			}
			nf.SendGeneric("exploit.module.progress", payload)
		}
	}
}

func printJobJSON(job *models.Job) error {
	b, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func runDoctor(cfg config.Config, opt engine.Options) error {
	fmt.Println("[doctor] running checks...")
	ok := true
	check := func(name string, err error) {
		if err != nil {
			ok = false
			fmt.Printf("[doctor] FAIL %-24s %v\n", name+":", err)
		} else {
			fmt.Printf("[doctor] OK   %-24s\n", name)
		}
	}

	_, e1 := exec.LookPath("python3")
	check("python3 in PATH", e1)
	_, e2 := exec.LookPath(opt.NucleiBin)
	check("nuclei in PATH", e2)
	if strings.TrimSpace(opt.ReconHarvestCmd) == "" {
		check("recon command configured", fmt.Errorf("BREACHPILOT_RECONHARVEST_CMD is empty"))
	} else {
		check("recon command executable", probeCommand(opt.ReconHarvestCmd, "--help"))
	}
	check("artifacts writable", ensureWritableDir(opt.ArtifactsRoot))
	check("recon webhook reachable", checkWebhookReachable(cfg.ReconWebhookURL))
	check("exploit webhook reachable", checkWebhookReachable(cfg.ExploitWebhookURL))

	if !ok {
		return fmt.Errorf("doctor failed: fix issues above")
	}
	fmt.Println("[doctor] all checks passed")
	return nil
}

func ensureWritableDir(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("empty path")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	p := filepath.Join(dir, ".writecheck.tmp")
	if err := os.WriteFile(p, []byte("ok"), 0o644); err != nil {
		return err
	}
	_ = os.Remove(p)
	return nil
}

func checkWebhookReachable(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("webhook URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("invalid URL")
	}

	port := u.Port()
	if port == "" {
		switch strings.ToLower(strings.TrimSpace(u.Scheme)) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return fmt.Errorf("unsupported URL scheme %q", u.Scheme)
		}
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(u.Hostname(), port), 3*time.Second)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func validateArtifactManifestForPath(anyPath string) error {
	p := filepath.Clean(strings.TrimSpace(anyPath))
	if p == "" {
		return nil
	}
	// walk up to find artifact_manifest.json in current/parent directories
	d := p
	if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
		d = filepath.Dir(p)
	}
	for i := 0; i < 4; i++ {
		mf := filepath.Join(d, "artifact_manifest.json")
		if _, err := os.Stat(mf); err == nil {
			return verifyManifest(mf)
		}
		next := filepath.Dir(d)
		if next == d || next == "." {
			break
		}
		d = next
	}
	return nil
}

func validateArtifactManifestEntryForPath(anyPath string) error {
	p := filepath.Clean(strings.TrimSpace(anyPath))
	if p == "" {
		return nil
	}
	d := p
	if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
		d = filepath.Dir(p)
	}
	for i := 0; i < 4; i++ {
		mf := filepath.Join(d, "artifact_manifest.json")
		if _, err := os.Stat(mf); err == nil {
			return verifyManifestEntry(mf, p)
		}
		next := filepath.Dir(d)
		if next == d || next == "." {
			break
		}
		d = next
	}
	return nil
}

func verifyManifest(manifestPath string) error {
	m, err := loadManifest(manifestPath)
	if err != nil {
		return err
	}
	for _, f := range m.Files {
		if strings.TrimSpace(f.Path) == "" || strings.TrimSpace(f.SHA256) == "" {
			continue
		}
		raw, err := os.ReadFile(f.Path)
		if err != nil {
			return fmt.Errorf("missing file in manifest: %s", f.Path)
		}
		h := sha256.Sum256(raw)
		if hex.EncodeToString(h[:]) != f.SHA256 {
			return fmt.Errorf("hash mismatch for %s", f.Path)
		}
	}
	return nil
}

func verifyManifestEntry(manifestPath, targetPath string) error {
	m, err := loadManifest(manifestPath)
	if err != nil {
		return err
	}
	targetPath = filepath.Clean(strings.TrimSpace(targetPath))
	for _, f := range m.Files {
		if filepath.Clean(strings.TrimSpace(f.Path)) != targetPath {
			continue
		}
		raw, err := os.ReadFile(f.Path)
		if err != nil {
			return fmt.Errorf("missing file in manifest: %s", f.Path)
		}
		h := sha256.Sum256(raw)
		if hex.EncodeToString(h[:]) != f.SHA256 {
			return fmt.Errorf("hash mismatch for %s", f.Path)
		}
		return nil
	}
	return fmt.Errorf("path not present in manifest: %s", targetPath)
}

func loadManifest(manifestPath string) (struct {
	Files []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"files"`
}, error) {
	var m struct {
		Files []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	return m, nil
}

func runSetup(opt engine.Options) error {
	fmt.Println("\x1b[36m[SETUP] initializing breachpilot runtime checks...\x1b[0m")
	checks := []struct {
		name string
		cmd  []string
	}{
		{"python3", []string{"python3", "--version"}},
		{"nuclei", []string{opt.NucleiBin, "-version"}},
	}
	for _, c := range checks {
		out, err := exec.Command(c.cmd[0], c.cmd[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("[setup] missing or broken %s: %v", c.name, err)
		}
		fmt.Printf("\x1b[32m[SETUP ✓]\x1b[0m %s: %s\n", c.name, strings.TrimSpace(string(out)))
	}

	reconCmd := strings.TrimSpace(opt.ReconHarvestCmd)
	if reconCmd == "" {
		return fmt.Errorf("[setup] recon command is empty")
	}
	if err := probeCommand(reconCmd, "--help"); err != nil {
		return fmt.Errorf("[setup] recon command not executable: %w", err)
	}
	fmt.Printf("\x1b[32m[SETUP ✓]\x1b[0m recon command: %s\n", reconCmd)
	if err := os.MkdirAll(opt.ArtifactsRoot, 0o755); err != nil {
		return fmt.Errorf("[setup] artifacts dir failed: %w", err)
	}
	fmt.Printf("\x1b[32m[SETUP ✓]\x1b[0m artifacts dir ready: %s\n", opt.ArtifactsRoot)
	fmt.Println("\x1b[36m[SETUP] done. system armed.\x1b[0m")
	return nil
}

// nextRunID creates a human-friendly job ID: "<domain>/<N>" with auto-incrementing run number.
func nextRunID(artifactsRoot, target string) string {
	safeDomain := scope.NormalizeTargetForDir(target)
	domainDir := filepath.Join(artifactsRoot, safeDomain)
	_ = os.MkdirAll(domainDir, 0o755)
	run := 1
	for {
		candidate := filepath.Join(domainDir, fmt.Sprintf("%d", run))
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			break
		}
		run++
	}
	return fmt.Sprintf("%s/%d", safeDomain, run)
}

func probeCommand(raw string, extraArgs ...string) error {
	argv, err := splitCommand(raw)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	args := append(append([]string{}, argv[1:]...), extraArgs...)
	cmd := exec.CommandContext(ctx, argv[0], args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("command timed out")
		}
		return err
	}
	return nil
}

func splitCommand(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty command")
	}

	argv, err := shlex.Split(raw)
	if err != nil || len(argv) == 0 {
		return nil, fmt.Errorf("invalid command: %q", raw)
	}
	if _, err := exec.LookPath(argv[0]); err != nil {
		return nil, fmt.Errorf("executable not found: %w", err)
	}
	return argv, nil
}

func listModules(opt engine.Options) {
	_ = opt
	for _, mi := range engine.RegisteredModuleInfos() {
		safety := "read-only"
		if !mi.SafeReadOnly {
			safety = "active"
		}
		fmt.Printf("%s\t%s\t%s\t%s\n", mi.Name, mi.Description, safety, mi.Group)
	}
}

func printStartupBanner(cfg config.Config) {
	cyan := "\x1b[36m"
	green := "\x1b[32m"
	yellow := "\x1b[33m"
	gray := "\x1b[90m"
	reset := "\x1b[0m"

	redact := func(v string) string {
		v = strings.TrimSpace(v)
		if v == "" {
			return "<empty>"
		}
		return "<set>"
	}
	minSev := strings.TrimSpace(cfg.MinSeverity)
	if minSev == "" {
		minSev = "none"
	}

	fmt.Println(cyan + "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓" + reset)
	fmt.Println(cyan + "┃  ☠️🔥  BREACHPILOT // OFFENSIVE RUNTIME ONLINE                           ┃" + reset)
	fmt.Println(cyan + "┃  [ RECON ] -> [ TRIAGE ] -> [ VERIFY ] -> [ EXPLOIT ] -> [ REPORT ]    ┃" + reset)
	fmt.Println(cyan + "┃  \"quiet in logs, loud in findings\"                                    ┃" + reset)
	fmt.Println(cyan + "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛" + reset)
	fmt.Printf("%s[WEBHOOKS]%s recon=%s exploit=%s retries=%d\n", green, reset, redact(cfg.ReconWebhookURL), redact(cfg.ExploitWebhookURL), cfg.WebhookRetries)
	fmt.Printf("%s[RUNTIME ]%s nuclei=%s recon_timeout=%ds nuclei_timeout=%ds\n", green, reset, cfg.NucleiBin, cfg.ReconTimeoutSec, cfg.NucleiTimeoutSec)
	fmt.Printf("%s[PROFILE ]%s scan_profile=%s min_severity=%s rate_limit_rps=%d\n", yellow, reset, emptyAs(cfg.ScanProfile, "none"), minSev, cfg.RateLimitRPS)
	fmt.Printf("%s[REPORT  ]%s formats=%s artifacts=%s\n", yellow, reset, emptyAs(cfg.ReportFormats, "json,md,html"), cfg.ArtifactsRoot)
	fmt.Printf("%s[FLAGS   ]%s validation_only=%t aggressive=%t boundless=%t proof_mode=%t skip_nuclei=%t only_modules=%s skip_modules=%s\n", gray, reset, cfg.ValidationOnly, cfg.AggressiveMode, cfg.BoundlessMode, cfg.ProofMode, cfg.SkipNuclei, emptyAs(cfg.OnlyModules, "none"), emptyAs(cfg.SkipModules, "none"))
	fmt.Printf("%s[ENGINE  ]%s default exploit lane=exploit-core context_modules=explicit-only|validation_only|deep\n", gray, reset)
	if cfg.ProofMode {
		liveAuth := (strings.TrimSpace(cfg.AuthUserCookie) != "" || strings.TrimSpace(cfg.AuthUserHeaders) != "") &&
			(strings.TrimSpace(cfg.AuthAdminCookie) != "" || strings.TrimSpace(cfg.AuthAdminHeaders) != "")
		fmt.Printf("\x1b[31m[PROOF   ]\x1b[0m allowlist=%s live auth contexts=%t\n", emptyAs(cfg.ProofTargetAllowlist, "all (no restriction)"), liveAuth)
	}
	if cfg.AggressiveMode {
		fmt.Printf("\x1b[31m[MODE    ]\x1b[0m ☠️ AGGRESSIVE MODE ENABLED — active verification probes ON\n")
	}
	if cfg.BoundlessMode {
		fmt.Printf("\x1b[31m[MODE    ]\x1b[0m ∞ BOUNDLESS MODE ENABLED — module limits and timeouts relaxed for this run\n")
	}
}

func emptyAs(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func renderStage(stage string) string {
	reset := "\x1b[0m"
	gray := "\x1b[90m"
	cyan := "\x1b[36m"
	green := "\x1b[32m"
	yellow := "\x1b[33m"
	red := "\x1b[31m"

	s := strings.TrimSpace(stage)
	switch {
	case strings.Contains(s, "exploit.log"):
		return fmt.Sprintf("%s[~]%s %s", yellow, reset, s)
	case strings.Contains(s, ".start") || strings.HasSuffix(s, "started"):
		return fmt.Sprintf("%s[⚡]%s %s", cyan, reset, s)
	case strings.Contains(s, ".done") || strings.HasSuffix(s, "completed"):
		return fmt.Sprintf("%s[✓]%s %s", green, reset, s)
	case strings.Contains(s, "warning") || strings.Contains(s, "retry"):
		return fmt.Sprintf("%s[~]%s %s", yellow, reset, s)
	case strings.Contains(s, "error") || strings.Contains(s, "failed") || strings.Contains(s, "cancel"):
		return fmt.Sprintf("%s[✗]%s %s", red, reset, s)
	default:
		return fmt.Sprintf("%s[•]%s %s", gray, reset, s)
	}
}

func printUsage() {
	fmt.Println(`Usage:
	  breachpilot setup
		  breachpilot full <target> [json] [aggressive] [boundless]
		  breachpilot file <summary.json> [json] [aggressive] [boundless]
		  breachpilot resume <path/to/.breachpilot.state> [json] [aggressive] [boundless]
	  breachpilot list-modules
	  breachpilot doctor

	Examples:
		  breachpilot full example.com aggressive
		  breachpilot full example.com aggressive boundless
		  breachpilot aggressive full example.com
		  breachpilot file recon/summary.json aggressive boundless
		  breachpilot resume artifacts/example.com/1/.breachpilot.state aggressive boundless
		  (CLI args override breachpilot.env settings)
		`)
}

func resumeJob(ctx context.Context, args []string, opt engine.Options, nf *notify.Webhook, rf *notify.Webhook, jsonOut bool) error {
	if len(args) == 0 {
		return fmt.Errorf("missing state file path. Use: breachpilot resume <path/to/.breachpilot.state>")
	}
	statePath := strings.TrimSpace(args[0])
	if statePath == "" {
		return fmt.Errorf("empty resume path")
	}
	if filepath.Base(statePath) != ".breachpilot.state" {
		return fmt.Errorf("invalid resume file: expected .breachpilot.state, got %s", filepath.Base(statePath))
	}
	if _, err := os.Stat(statePath); err != nil {
		return fmt.Errorf("resume state file not accessible: %w", err)
	}
	if err := validateArtifactManifestForPath(statePath); err != nil {
		return fmt.Errorf("artifact integrity validation failed: %w", err)
	}

	// Load state from the .breachpilot.state file
	sm, err := engine.NewStateManagerFromPath(statePath)
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}
	st := sm.State()

	// Reconstruct job from state
	jobDir := filepath.Dir(statePath)
	job := &models.Job{
		ID:        st.JobID,
		Target:    st.Target,
		Mode:      st.Mode,
		ReconPath: st.ReconPath,
		SafeMode:  !opt.AggressiveMode,
		Status:    models.JobRunning,
		CreatedAt: time.Now().UTC(),
	}

	if !jsonOut {
		fmt.Printf("\n[BREACHPILOT] Resuming: %s (target=%s)\n", job.ID, job.Target)
		fmt.Printf("[BREACHPILOT] State: recon=%v nuclei=%v modules=%d\n",
			st.ReconCompleted, st.NucleiCompleted, len(st.ModulesFinished))
	}
	nf.SendGeneric("job.resumed", map[string]any{
		"job_id":               job.ID,
		"target":               job.Target,
		"recon_completed":      st.ReconCompleted,
		"nuclei_completed":     st.NucleiCompleted,
		"modules_finished":     len(st.ModulesFinished),
		"modules_finished_ids": st.ModulesFinished,
	})

	// Derive artifacts root from job dir path
	// jobDir = artifactsRoot/domain/N → artifactsRoot = jobDir minus the last 2 path components
	cliOpt := opt
	cliOpt.ArtifactsRoot = filepath.Dir(filepath.Dir(jobDir))
	cliOpt.Progress = nil
	cliOpt.Events = buildCLIEventHandler(job, opt, nf, jsonOut)

	nf.Send("job.started", job)
	if err := engine.Process(ctx, job, cliOpt); err != nil {
		job.Status = models.JobFailed
		job.Error = err.Error()
		nf.Send("job.failed", job)
		return err
	}

	switch job.Status {
	case models.JobRejected:
		nf.Send("job.rejected", job)
		if jsonOut {
			return printJobJSON(job)
		}
		fmt.Printf("\x1b[31m[✗] JOB REJECTED\x1b[0m %s\n", job.Error)
		return nil
	case models.JobCancelled:
		nf.Send("job.cancelled", job)
		if strings.EqualFold(job.Mode, "full") {
			rf.Send("job.cancelled", job)
		}
		if jsonOut {
			return printJobJSON(job)
		}
		fmt.Printf("\x1b[31m[!] JOB INTERRUPTED\x1b[0m\n")
		return nil
	case models.JobFailed:
		nf.Send("job.failed", job)
		if jsonOut {
			return printJobJSON(job)
		}
		fmt.Printf("\x1b[31m[✗] JOB FAILED\x1b[0m %s\n", job.Error)
		return nil
	default:
		nf.Send("job.completed", job)
	}

	if jsonOut {
		return printJobJSON(job)
	}
	for _, ln := range formatCLISummary(job, job.Mode) {
		fmt.Println(ln)
	}
	return nil
}
