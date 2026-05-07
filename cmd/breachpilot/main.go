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
	browsercapture "breachpilot/internal/exploit/browsercapture"
	"breachpilot/internal/ingest"
	"breachpilot/internal/models"
	"breachpilot/internal/notify"
	"breachpilot/internal/scope"
	"github.com/google/shlex"
)

func main() {
	config.BootstrapEnvironment()
	cfg := config.Load()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n[!] Interrupt received, safely stopping...")
		cancel()

		go func() {
			<-c
			fmt.Println("\n[!] Second interrupt received, forcing immediate exit!")
			os.Exit(130)
		}()
	}()

	args := os.Args[1:]
	firstArg := ""
	if len(args) > 0 {
		firstArg = strings.ToLower(strings.TrimSpace(args[0]))
	}

	// Dependency verification is intentionally skipped for scan commands (full, file, resume).
	// It only runs during: setup (via runSetup), doctor (via runDoctor), update-tools (via runUpdateTools).
	// This prevents the full --doctor output from printing before every scan.

	if err := cfg.Validate(); err != nil {
		// Only fatal-fail if it's not a setup command (setup should try to fix things)
		if firstArg != "setup" && firstArg != "doctor" {
			log.Fatal(err)
		}
	}

	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	if firstArg == "help" || firstArg == "--help" || firstArg == "-h" {
		printUsage()
		return
	}

	if len(args) == 1 && args[0] == "setup" {
		engOpt := buildEngineOptions(cfg)
		if err := runSetup(ctx, engOpt); err != nil {
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
	if len(args) == 1 && args[0] == "browser-check" {
		path, status := browsercapture.EnsureBrowserPathWithStatus("")
		if p := strings.TrimSpace(os.Getenv("BREACHPILOT_BROWSER_PATH")); p != "" {
			path = p
		}
		fmt.Printf("Browser path: %s\n", path)
		if strings.TrimSpace(path) == "" {
			fmt.Fprintf(os.Stderr, "FAIL: %s\n", status)
			os.Exit(1)
		}
		if err := browsercapture.BrowserHealthCheck(path); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("OK: browser launched and navigated successfully")
		return
	}
	if len(args) == 1 && args[0] == "doctor" {
		engOpt := buildEngineOptions(cfg)
		if err := runDoctor(ctx, cfg, engOpt); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(args) == 1 && args[0] == "update-tools" {
		engOpt := buildEngineOptions(cfg)
		if err := runUpdateTools(ctx, engOpt); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(args) == 1 && args[0] == "fireprox-cleanup" {
		if err := runFireProxCleanup(ctx, cfg); err != nil {
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
		if p := strings.TrimSpace(cfg.BrowserCapturePath); p != "" {
			_ = os.Setenv("BREACHPILOT_BROWSER_PATH", p)
		}
		if r := strings.TrimSpace(cfg.ArtifactsRoot); r != "" {
			_ = os.Setenv("BREACHPILOT_ARTIFACTS_ROOT", r)
		}
	}
	listFile := ""
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
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
		if n == "--browser-capture" {
			cfg.BrowserCaptureEnabled = true
			continue
		}
		if n == "--only-modules" {
			if i+1 < len(args) {
				cfg.OnlyModules = args[i+1]
				i++
				continue
			} else {
				log.Fatal("missing module list for --only-modules flag")
			}
		}
		if n == "--skip-modules" {
			if i+1 < len(args) {
				cfg.SkipModules = args[i+1]
				i++
				continue
			} else {
				log.Fatal("missing module list for --skip-modules flag")
			}
		}
		if n == "-l" || n == "--list" {
			if i+1 < len(args) {
				listFile = args[i+1]
				i++
				continue
			} else {
				log.Fatal("missing file path for -l/--list flag")
			}
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
	nf := &notify.Webhook{
		URL:          cfg.ExploitWebhookURL,
		Secret:       cfg.WebhookSecret,
		Retries:      cfg.WebhookRetries,
		DebugLogPath: filepath.Join(cfg.ArtifactsRoot, "webhook_exploit_debug.jsonl"),
		FindingsCap:  cfg.WebhookFindingsCap,
		ReliableMode: cfg.WebhookReliableMode,
		QueueTimeout: time.Duration(cfg.WebhookQueueBlockTimeoutMS) * time.Millisecond,
		SpoolPath:    webhookSpoolPath(cfg.WebhookSpoolPath, "exploit"),
	}
	nf.Start()
	defer nf.Stop()
	rf := &notify.Webhook{
		URL:          cfg.ReconWebhookURL,
		Secret:       cfg.WebhookSecret,
		Retries:      cfg.WebhookRetries,
		DebugLogPath: filepath.Join(cfg.ArtifactsRoot, "webhook_recon_debug.jsonl"),
		FindingsCap:  cfg.WebhookFindingsCap,
		ReliableMode: cfg.WebhookReliableMode,
		QueueTimeout: time.Duration(cfg.WebhookQueueBlockTimeoutMS) * time.Millisecond,
		SpoolPath:    webhookSpoolPath(cfg.WebhookSpoolPath, "recon"),
	}
	rf.Start()
	defer rf.Stop()

	isf := &notify.Webhook{
		URL:          cfg.InteractshWebhookURL,
		Secret:       cfg.WebhookSecret,
		Retries:      cfg.WebhookRetries,
		DebugLogPath: filepath.Join(cfg.ArtifactsRoot, "webhook_interactsh_debug.jsonl"),
		FindingsCap:  cfg.WebhookFindingsCap,
		ReliableMode: cfg.WebhookReliableMode,
		QueueTimeout: time.Duration(cfg.WebhookQueueBlockTimeoutMS) * time.Millisecond,
		SpoolPath:    webhookSpoolPath(cfg.WebhookSpoolPath, "interactsh"),
	}
	isf.Start()
	defer isf.Stop()

	engOpt.Notifier = nf
	engOpt.ReconNotifier = rf
	engOpt.InteractshNotifier = isf

	if len(filtered) > 0 && filtered[0] == "resume" {
		if err := resumeJob(ctx, filtered[1:], engOpt, nf, rf, isf, jsonOut); err != nil {
			log.Fatal(err)
		}
		return
	}

	if err := runCLIMode(ctx, filtered, engOpt, nf, rf, isf, jsonOut, listFile); err != nil {
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
		SafeMode:                       !cfg.AggressiveMode,
		AggressiveMode:                 cfg.AggressiveMode,
		BoundlessMode:                  cfg.BoundlessMode,
		ProofMode:                      cfg.ProofMode,
		ProofTargetAllowlist:           cfg.ProofTargetAllowlist,
		OOBHTTPListenAddr:              cfg.OOBHTTPListenAddr,
		OOBHTTPPublicBaseURL:           cfg.OOBHTTPPublicBaseURL,
		OOBPollWaitSec:                 cfg.OOBPollWaitSec,
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
		FireProxEnabled:                cfg.FireProxEnabled,
		FireProxURL:                    cfg.FireProxURL,
		AWSRegion:                      cfg.AWSRegion,
	}
}

func runCLIMode(ctx context.Context, args []string, opt engine.Options, nf *notify.Webhook, rf *notify.Webhook, isf *notify.Webhook, jsonOut bool, listFile string) error {
	if len(args) == 0 && listFile == "" {
		return fmt.Errorf("missing mode. Use: full <target> OR file <summary.json>")
	}

	mode := ""
	if len(args) > 0 {
		mode = strings.ToLower(strings.TrimSpace(args[0]))
	}

	targets := []string{}
	if listFile != "" {
		if mode != "full" && mode != "" {
			return fmt.Errorf("-l/--list is only supported in 'full' mode")
		}
		if mode == "" {
			mode = "full" // Default to full mode if only -l is present
		}
		var err error
		targets, err = parseTargetsFile(listFile)
		if err != nil {
			return err
		}
	} else {
		if mode != "full" && mode != "file" {
			return fmt.Errorf("unknown mode %q. Use: full <target> OR file <summary.json>", mode)
		}
		if len(args) < 2 {
			if mode == "file" {
				return fmt.Errorf("missing summary path. Use: breachpilot file <summary.json>")
			}
			return fmt.Errorf("missing target. Use: breachpilot full <target>")
		}
		targets = append(targets, strings.TrimSpace(args[1]))
	}

	return runJobsInBatch(ctx, mode, targets, opt, nf, rf, isf, jsonOut)
}

func runJobsInBatch(ctx context.Context, mode string, targets []string, opt engine.Options, nf *notify.Webhook, rf *notify.Webhook, isf *notify.Webhook, jsonOut bool) error {
	for _, target := range targets {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var reconPath string
		currentMode := mode
		if currentMode == "file" {
			reconPath = target
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

			derivedTarget := ""
			if rs, err := ingest.LoadReconSummary(reconPath); err == nil {
				if rs.Target != "" {
					derivedTarget = rs.Target
				} else if guessed := ingest.TargetFromWorkdir(rs.Workdir); guessed != "" {
					derivedTarget = guessed
				}
			}
			if derivedTarget == "" {
				derivedTarget = "from-summary"
			}
			target = derivedTarget
			currentMode = "ingest"
		}

		jobID := nextRunID(opt.ArtifactsRoot, target)
		job := &models.Job{
			ID:        jobID,
			Target:    target,
			Mode:      currentMode,
			ReconPath: reconPath,
			SafeMode:  !opt.AggressiveMode,
			Status:    models.JobQueued,
			CreatedAt: time.Now().UTC(),
		}

		cliOpt := opt
		cliOpt.Progress = nil
		cliOpt.Events = buildCLIEventHandler(job, opt, nf, rf, isf, jsonOut)

		nf.Send("job.started", job)
		if strings.EqualFold(job.Mode, "full") {
			rf.Send("job.started", job)
		}

		if len(targets) > 1 && !jsonOut {
			fmt.Printf("\x1b[34m[BATCH] Processing target: %s (%s)\x1b[0m\n", target, jobID)
		}

		if err := engine.Process(ctx, job, cliOpt); err != nil {
			job.Status = models.JobFailed
			job.Error = err.Error()
			nf.Send("job.failed", job)
			if len(targets) > 1 {
				fmt.Printf("\x1b[31m[BATCH] Target %s failed: %v\x1b[0m\n", target, err)
				continue
			}
			return err
		}

		cancelled := false
		switch job.Status {
		case models.JobRejected:
			nf.Send("job.rejected", job)
		case models.JobCancelled:
			nf.Send("job.cancelled", job)
			if strings.EqualFold(job.Mode, "full") {
				rf.Send("job.cancelled", job)
			}
			cancelled = true
		case models.JobFailed:
			nf.Send("job.failed", job)
		default:
			nf.Send("job.completed", job)
		}

		applyWebhookDeliveryMetrics(job, nf, rf, isf)
		if job.WebhookDroppedEvents > 0 {
			log.Printf("[webhook] %d non-critical events were dropped due to queue saturation", job.WebhookDroppedEvents)
		}
		if job.WebhookSpooledEvents > 0 {
			log.Printf("[webhook] %d events were durably spooled due to queue backpressure", job.WebhookSpooledEvents)
		}
		if err := persistJobReport(job); err != nil {
			log.Printf("[report] failed to persist webhook metrics to job report: %v", err)
		}
		if cancelled {
			if jsonOut {
				_ = printJobJSON(job)
			} else {
				fmt.Printf("\x1b[31m[!] JOB INTERRUPTED\x1b[0m\n")
			}
			return nil
		}

		if jsonOut {
			_ = printJobJSON(job)
		} else {
			for _, ln := range formatCLISummary(job, currentMode) {
				fmt.Println(ln)
			}
			fmt.Println(strings.Repeat("-", 80))
		}
	}

	return nil
}

func parseTargetsFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read targets file: %w", err)
	}

	targets := []string{}
	// Replacer for common separators
	replacer := strings.NewReplacer(",", " ", ";", " ")

	for _, line := range strings.Split(string(data), "\n") {
		// Strip comments first
		lineBeforeComment, _, _ := strings.Cut(line, "#")

		// Ignore empty lines
		trimmedLine := strings.TrimSpace(lineBeforeComment)
		if trimmedLine == "" {
			continue
		}

		// Replace separators with spaces, then split by any whitespace
		lineWithSpaces := replacer.Replace(trimmedLine)
		for _, item := range strings.Fields(lineWithSpaces) {
			t := strings.TrimSpace(item)
			if t == "" {
				continue
			}
			if err := scope.ValidateTarget(t); err != nil {
				return nil, fmt.Errorf("invalid target %q in %s: %w", t, path, err)
			}
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets found in %s", path)
	}
	return targets, nil
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

func buildCLIEventHandler(job *models.Job, opt engine.Options, nf *notify.Webhook, rf *notify.Webhook, isf *notify.Webhook, jsonOut bool) func(models.RuntimeEvent) {
	var tracker *cliRuntimeTracker
	if !jsonOut {
		tracker = newCLIRuntimeTracker(os.Stdout)
	}
	return func(ev models.RuntimeEvent) {
		if tracker != nil {
			tracker.Handle(ev)
		}

		// Route events to the correct notifier based on stage/kind
		targetNotifier := nf
		if strings.HasPrefix(ev.Stage, "recon") {
			targetNotifier = rf
		} else if strings.Contains(ev.Stage, "oob") || strings.Contains(ev.Stage, "interactsh") {
			targetNotifier = isf
		}

		if ev.Kind == "stage" && (ev.Stage == "exploit" || ev.Stage == "recon") && ev.Status == "started" {
			targetNotifier.SendGeneric(ev.Stage+".started", map[string]any{
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
			if ev.Progress != nil {
				payload["progress"] = ev.Progress
			}
			targetNotifier.SendGeneric("exploit.module.progress", payload)
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

func applyWebhookDeliveryMetrics(job *models.Job, hooks ...*notify.Webhook) {
	if job == nil {
		return
	}
	var dropped int64
	var spooled int64
	for _, h := range hooks {
		if h == nil {
			continue
		}
		dropped += h.DroppedEvents()
		spooled += h.SpooledEvents()
	}
	job.WebhookDroppedEvents = dropped
	job.WebhookSpooledEvents = spooled
}

func persistJobReport(job *models.Job) error {
	if job == nil || strings.TrimSpace(job.ReportPath) == "" {
		return nil
	}
	payload := map[string]any{
		"schema_version": models.SchemaVersion,
		"job":            job,
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	tmp := job.ReportPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, job.ReportPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func runDoctor(ctx context.Context, cfg config.Config, opt engine.Options) error {
	red := "\x1b[31m"
	green := "\x1b[32m"
	reset := "\x1b[0m"
	fmt.Printf("[*] Starting BreachPilot doctor checks...\n")
	ok := true
	check := func(name string, err error) {
		if err != nil {
			ok = false
			fmt.Printf("[doctor] FAIL %-24s %v\n", name+":", err)
		} else {
			fmt.Printf("[doctor] OK   %-24s\n", name)
		}
	}

	_, e1 := exec.CommandContext(ctx, "python3", "--version").Output()
	check("python3 in PATH", e1)
	_, e2 := exec.CommandContext(ctx, opt.NucleiBin, "-version").Output()
	check("nuclei in PATH", e2)
	if strings.TrimSpace(opt.ReconHarvestCmd) == "" {
		check("recon command configured", fmt.Errorf("BREACHPILOT_RECONHARVEST_CMD is empty"))
	} else {
		resolved := config.ResolveReconHarvestCmd(opt.ReconHarvestCmd)
		check("recon command executable", probeCommand(resolved, "--help"))
		check("recon command compatible", checkReconCommandCompatibility(resolved))
		fmt.Printf("[doctor] INFO recon cmd resolved to: %s\n", resolved)
	}
	check("artifacts writable", ensureWritableDir(opt.ArtifactsRoot))
	check("recon webhook reachable", checkWebhookReachable(cfg.ReconWebhookURL))
	check("exploit webhook reachable", checkWebhookReachable(cfg.ExploitWebhookURL))
	if strings.TrimSpace(cfg.InteractshWebhookURL) != "" {
		check("interactsh webhook reachable", checkWebhookReachable(cfg.InteractshWebhookURL))
	}

	if cfg.FireProxEnabled {
		if _, err := exec.LookPath("aws"); err != nil {
			fmt.Printf("%s[FAIL]%s 'aws' CLI not found in PATH (required for FireProx)\n", red, reset)
			ok = false
		} else {
			fmt.Printf("%s[PASS]%s 'aws' CLI found\n", green, reset)
			// Check credentials
			credsCmd := exec.CommandContext(ctx, "aws", "sts", "get-caller-identity", "--region", cfg.AWSRegion)
			if err := credsCmd.Run(); err != nil {
				fmt.Printf("%s[FAIL]%s AWS credentials invalid or not configured for region %s\n", red, reset, cfg.AWSRegion)
				ok = false
			} else {
				fmt.Printf("%s[PASS]%s AWS credentials verified for region %s\n", green, reset, cfg.AWSRegion)
			}
		}
	}

	if !ok {
		return fmt.Errorf("doctor failed: fix issues above")
	}
	fmt.Println("[doctor] all checks passed")
	return nil
}

func runUpdateTools(ctx context.Context, opt engine.Options) error {
	fmt.Println("\x1b[36m[UPDATE] forcing update of all reconHarvest tools...\x1b[0m")
	reconCmd := strings.TrimSpace(opt.ReconHarvestCmd)
	if reconCmd == "" {
		return fmt.Errorf("[update] recon command is empty")
	}
	args, err := config.SplitReconHarvestCommand(opt.ReconHarvestCmd)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, args[0], append(args[1:], "--update-tools")...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("[update] failed: %w", err)
	}
	fmt.Println("\x1b[32m[UPDATE ✓]\x1b[0m tools updated successfully")
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
	targetPath, _ = filepath.Abs(filepath.Clean(strings.TrimSpace(targetPath)))
	for _, f := range m.Files {
		fPath, _ := filepath.Abs(filepath.Clean(strings.TrimSpace(f.Path)))
		if fPath != targetPath {
			continue
		}
		raw, err := os.ReadFile(fPath)
		if err != nil {
			return fmt.Errorf("missing file in manifest: %s", fPath)
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

func runSetup(ctx context.Context, opt engine.Options) error {
	fmt.Println("\x1b[36m[SETUP] initializing breachpilot runtime checks...\x1b[0m")

	// Attempt to fix missing dependencies first.
	if err := config.EnsureDependenciesWithContext(ctx, opt.NucleiBin, opt.ReconHarvestCmd); err != nil {
		fmt.Printf("\x1b[33m[SETUP !]\x1b[0m auto-bootstrap encountered issues: %v\n", err)
	}

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

	if path, status := browsercapture.EnsureBrowserPathWithStatus(strings.TrimSpace(opt.BrowserCapturePath)); strings.TrimSpace(path) != "" {
		fmt.Printf("\x1b[32m[SETUP ✓]\x1b[0m browser ready: %s\n", path)
	} else {
		fmt.Printf("\x1b[33m[SETUP !]\x1b[0m browser not ready: %s\n", status)
	}
	fmt.Println("\x1b[36m[SETUP] done. system armed.\x1b[0m")
	return nil
}

// nextRunID creates a human-friendly job ID: "<domain>/<N>" with auto-incrementing run number.
func nextRunID(artifactsRoot, target string) string {
	safeDomain := scope.NormalizeTargetForDir(target)
	domainDir := filepath.Join(artifactsRoot, safeDomain)
	_ = os.MkdirAll(domainDir, 0o755)
	for run := 1; ; run++ {
		candidate := filepath.Join(domainDir, fmt.Sprintf("%d", run))
		// os.Mkdir is atomic on POSIX: only one caller succeeds for a given path.
		if err := os.Mkdir(candidate, 0o755); err == nil {
			return fmt.Sprintf("%s/%d", safeDomain, run)
		}
	}
}

func probeCommand(raw string, extraArgs ...string) error {
	argv, err := splitCommand(raw)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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

func checkReconCommandCompatibility(raw string) error {
	caps, err := config.ProbeReconHarvestCapabilities(raw)
	if err != nil {
		return err
	}
	if !caps.SupportsCoreExecution() {
		return fmt.Errorf("missing required reconHarvest flags; expected support for --run, -o/--output, and --resume")
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
	red := "\x1b[31m"
	magenta := "\x1b[35m"
	white := "\x1b[97m"
	bold := "\x1b[1m"
	reset := "\x1b[0m"

	minSev := strings.TrimSpace(cfg.MinSeverity)
	if minSev == "" {
		minSev = "none"
	}
	modes := make([]string, 0, 4)
	if cfg.AggressiveMode {
		modes = append(modes, "aggressive")
	}
	if cfg.BoundlessMode {
		modes = append(modes, "boundless")
	}
	if cfg.ProofMode {
		modes = append(modes, "proof")
	}
	if len(modes) == 0 {
		modes = append(modes, "standard")
	}

	fmt.Println(magenta + "╔══════════════════════════════════════════════════════════════════════════╗" + reset)
	fmt.Println(magenta + "║" + bold + "  BREACHPILOT // RED-TEAM TERMINAL                                  " + reset + magenta + "║" + reset)
	fmt.Println(magenta + "║  " + green + "◉ RECON" + magenta + "  ➜  " + yellow + "◉ TRIAGE" + magenta + "  ➜  " + cyan + "◉ VERIFY" + magenta + "  ➜  " + red + "◉ EXPLOIT" + magenta + "  ➜  " + white + "◉ REPORT" + magenta + "  ║" + reset)
	fmt.Println(magenta + "╚══════════════════════════════════════════════════════════════════════════╝" + reset)
	fmt.Printf("%s┌─ SESSION ───────────────────────────────────────────────────────────────┐%s\n", gray, reset)
	fmt.Printf("%s│%s mode=%s  profile=%s  min_severity=%s\n", gray, reset, strings.Join(modes, ","), emptyAs(cfg.ScanProfile, "none"), minSev)
	fmt.Printf("%s│%s skip_nuclei=%t  browser_capture=%t  only=%s  skip=%s\n", gray, reset, cfg.SkipNuclei, cfg.BrowserCaptureEnabled, emptyAs(cfg.OnlyModules, "none"), emptyAs(cfg.SkipModules, "none"))
	fmt.Printf("%s└─────────────────────────────────────────────────────────────────────────┘%s\n", gray, reset)
	// Removed RUNTIME box to declutter startup output as requested.

	if cfg.ProofMode {
		liveAuth := (strings.TrimSpace(cfg.AuthUserCookie) != "" || strings.TrimSpace(cfg.AuthUserHeaders) != "") &&
			(strings.TrimSpace(cfg.AuthAdminCookie) != "" || strings.TrimSpace(cfg.AuthAdminHeaders) != "")
		fmt.Printf("%s[PROOF]%s allowlist=%s live_auth_contexts=%t\n", red, reset, emptyAs(cfg.ProofTargetAllowlist, "all (no restriction)"), liveAuth)
	}
	if cfg.AggressiveMode {
		fmt.Printf("%s[MODE ]%s ☠️ aggressive verification probes are enabled\n", red, reset)
	}
	if cfg.BoundlessMode {
		fmt.Printf("%s[MODE ]%s ∞ boundless run: limits and timeouts are relaxed\n", red, reset)
	}
}

func emptyAs(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func webhookSpoolPath(raw, kind string) string {
	base := strings.TrimSpace(raw)
	if base == "" {
		return ""
	}
	ext := filepath.Ext(base)
	if ext == "" {
		return base + "." + kind + ".jsonl"
	}
	return strings.TrimSuffix(base, ext) + "." + kind + ext
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
	  breachpilot update-tools
		  breachpilot full <target> [json] [aggressive] [boundless]
		  breachpilot -l <targets.txt> full [json] [aggressive] [boundless]
		  breachpilot file <summary.json> [json] [aggressive] [boundless]
		  breachpilot resume <path/to/.breachpilot.state> [json] [aggressive] [boundless]
	  breachpilot list-modules
	  breachpilot doctor
	  breachpilot fireprox-cleanup

	Examples:
		  breachpilot full example.com aggressive
		  breachpilot -l domains.txt full aggressive
		  breachpilot full example.com aggressive boundless
		  breachpilot aggressive full example.com
		  breachpilot file recon/summary.json aggressive boundless
		  breachpilot resume artifacts/example.com/1/.breachpilot.state aggressive boundless
		  (CLI args override breachpilot.env settings)
		`)
}

func resumeJob(ctx context.Context, args []string, opt engine.Options, nf *notify.Webhook, rf *notify.Webhook, isf *notify.Webhook, jsonOut bool) error {
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
	cliOpt.Events = buildCLIEventHandler(job, opt, nf, rf, isf, jsonOut)

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

func runFireProxCleanup(ctx context.Context, cfg config.Config) error {
	fmt.Printf("[*] Starting FireProx cleanup in region: %s\n", cfg.AWSRegion)
	cmd := exec.CommandContext(ctx, "aws", "apigateway", "get-rest-apis", "--region", cfg.AWSRegion)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to list APIs: %w (output: %s)", err, string(out))
	}

	var apis struct {
		Items []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := json.Unmarshal(out, &apis); err != nil {
		return fmt.Errorf("failed to parse APIs JSON: %w", err)
	}

	found := 0
	for _, api := range apis.Items {
		if strings.HasPrefix(api.Name, "fireprox-") {
			fmt.Printf("[!] Deleting orphaned gateway: %s (%s)\n", api.Name, api.ID)
			delCmd := exec.CommandContext(ctx, "aws", "apigateway", "delete-rest-api", "--rest-api-id", api.ID, "--region", cfg.AWSRegion)
			if delOut, delErr := delCmd.CombinedOutput(); delErr != nil {
				fmt.Printf("[?] Error deleting %s: %v (output: %s)\n", api.ID, delErr, string(delOut))
			} else {
				found++
			}
		}
	}

	if found == 0 {
		fmt.Println("[+] No orphaned gateways found.")
	} else {
		fmt.Printf("[+] Cleaned up %d gateway(s).\n", found)
	}
	return nil
}
