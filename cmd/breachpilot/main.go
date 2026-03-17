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
	skipNucleiFlag := false
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
		if n == "--skip-nuclei" {
			skipNucleiFlag = true
			continue
		}
		filtered = append(filtered, a)
	}
	if aggressiveFlag {
		cfg.AggressiveMode = true
	}
	if skipNucleiFlag {
		cfg.SkipNuclei = true
	}
	printStartupBanner(cfg)

	engOpt := buildEngineOptions(cfg)
	nf := &notify.Webhook{URL: cfg.ExploitWebhookURL, Secret: cfg.WebhookSecret, Retries: cfg.WebhookRetries, DebugLogPath: filepath.Join(cfg.ArtifactsRoot, "webhook_exploit_debug.jsonl")}
	nf.Start()
	defer nf.Stop()
	rf := &notify.Webhook{URL: cfg.ReconWebhookURL, Secret: cfg.WebhookSecret, Retries: cfg.WebhookRetries, DebugLogPath: filepath.Join(cfg.ArtifactsRoot, "webhook_recon_debug.jsonl")}
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
		NucleiBin:                  cfg.NucleiBin,
		ReconHarvestCmd:            config.ResolveReconHarvestCmd(cfg.ReconHarvestCmd),
		ReconWebhookURL:            cfg.ReconWebhookURL,
		ReconTimeoutSec:            cfg.ReconTimeoutSec,
		ReconRetries:               cfg.ReconRetries,
		NucleiTimeoutSec:           cfg.NucleiTimeoutSec,
		ArtifactsRoot:              cfg.ArtifactsRoot,
		MinSeverity:                cfg.MinSeverity,
		SkipModules:                cfg.SkipModules,
		OnlyModules:                cfg.OnlyModules,
		ValidationOnly:             cfg.ValidationOnly,
		PreviousReportPath:         cfg.PreviousReportPath,
		ReportFormats:              cfg.ReportFormats,
		ScanProfile:                cfg.ScanProfile,
		RateLimitRPS:               cfg.RateLimitRPS,
		WebhookFindings:            cfg.WebhookFindings,
		WebhookModuleProgress:      cfg.WebhookModuleProgress,
		WebhookFindingsMinSeverity: cfg.WebhookFindingsMinSeverity,
		ModuleTimeoutSec:           cfg.ModuleTimeoutSec,
		ModuleRetries:              cfg.ModuleRetries,
		AggressiveMode:             cfg.AggressiveMode,
		ProofMode:                  cfg.ProofMode,
		ProofTargetAllowlist:       cfg.ProofTargetAllowlist,
		AuthUserCookie:             cfg.AuthUserCookie,
		AuthAdminCookie:            cfg.AuthAdminCookie,
		AuthAnonHeaders:            cfg.AuthAnonHeaders,
		AuthUserHeaders:            cfg.AuthUserHeaders,
		AuthAdminHeaders:           cfg.AuthAdminHeaders,
		SkipNuclei:                 cfg.SkipNuclei,
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
	cliOpt.Progress = func(stage string) {
		if !jsonOut {
			fmt.Println(renderStage(stage))
		}
		if stage == "exploit.started" {
			nf.SendGeneric("exploit.started", map[string]any{
				"job_id": job.ID,
				"target": job.Target,
				"mode":   job.Mode,
			})
		}
		// Forward exploit module progress to webhook for per-module visibility.
		if opt.WebhookModuleProgress && strings.HasPrefix(stage, "exploit.module.") {
			parts := strings.Fields(stage)
			if len(parts) >= 2 {
				payload := map[string]any{
					"job_id": job.ID,
					"target": job.Target,
					"stage":  parts[0],
					"module": parts[1],
				}
				if len(parts) >= 3 {
					payload["detail"] = strings.Join(parts[2:], " ")
				}
				nf.SendGeneric("exploit.module.progress", payload)
			}
		}
	}

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
		fmt.Sprintf("Nuclei findings: %d", job.FindingsCount),
		fmt.Sprintf("Exploit-module findings: %d", job.ExploitFindingsCount),
		fmt.Sprintf("Total findings: %d", job.FindingsCount+job.ExploitFindingsCount),
		fmt.Sprintf("Durations: recon=%.1fs exploit=%.1fs", job.ReconDurationSec, job.ExploitDurationSec),
	}
	if job.FilteredCount > 0 {
		lines = append(lines, fmt.Sprintf("Filtered findings: %d", job.FilteredCount))
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
	if job.ExploitFindingsCount > 0 {
		lines = append(lines, fmt.Sprintf("Exploit findings: %d (JSONL: %s)", job.ExploitFindingsCount, job.ExploitFindingsPath))
	}
	if mode == "full" {
		lines = append(lines, fmt.Sprintf("Recon summary used: %s", job.ReconPath))
	}
	return lines
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
	safeDomain := safeDirName(target)
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

// safeDirName sanitises a target into a safe directory name.
func safeDirName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	// Remove protocol prefix if present
	for _, pfx := range []string{"https://", "http://"} {
		s = strings.TrimPrefix(s, pfx)
	}
	// Remove trailing slashes
	s = strings.TrimRight(s, "/")
	// Replace disallowed characters
	var out strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			out.WriteRune(r)
		default:
			out.WriteRune('_')
		}
	}
	result := out.String()
	if result == "" {
		return "unknown"
	}
	return result
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
		fmt.Printf("%s\t%s\t%s\n", mi.Name, mi.Description, safety)
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
	fmt.Printf("%s[FLAGS   ]%s validation_only=%t aggressive=%t proof_mode=%t skip_nuclei=%t only_modules=%s skip_modules=%s\n", gray, reset, cfg.ValidationOnly, cfg.AggressiveMode, cfg.ProofMode, cfg.SkipNuclei, emptyAs(cfg.OnlyModules, "none"), emptyAs(cfg.SkipModules, "none"))
	if cfg.ProofMode {
		liveAuth := (strings.TrimSpace(cfg.AuthUserCookie) != "" || strings.TrimSpace(cfg.AuthUserHeaders) != "") &&
			(strings.TrimSpace(cfg.AuthAdminCookie) != "" || strings.TrimSpace(cfg.AuthAdminHeaders) != "")
		fmt.Printf("\x1b[31m[PROOF   ]\x1b[0m allowlist=%s live auth contexts=%t\n", emptyAs(cfg.ProofTargetAllowlist, "all (no restriction)"), liveAuth)
	}
	if cfg.AggressiveMode {
		fmt.Printf("\x1b[31m[MODE    ]\x1b[0m ☠️ AGGRESSIVE MODE ENABLED — active verification probes ON\n")
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
	  breachpilot full <target> [json] [aggressive]
	  breachpilot file <summary.json> [json] [aggressive]
	  breachpilot resume <path/to/.breachpilot.state> [json] [aggressive]
	  breachpilot list-modules
	  breachpilot doctor

	Examples:
	  breachpilot full example.com aggressive
	  breachpilot aggressive full example.com
	  breachpilot file recon/summary.json aggressive
	  breachpilot resume artifacts/example.com/1/.breachpilot.state aggressive
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
	cliOpt.Progress = func(stage string) {
		if !jsonOut {
			fmt.Println(renderStage(stage))
		}
		// Forward exploit module progress to webhook for per-module visibility.
		if opt.WebhookModuleProgress && strings.HasPrefix(stage, "exploit.module.") {
			parts := strings.Fields(stage)
			if len(parts) >= 2 {
				payload := map[string]any{
					"job_id": job.ID,
					"target": job.Target,
					"stage":  parts[0],
					"module": parts[1],
				}
				if len(parts) >= 3 {
					payload["detail"] = strings.Join(parts[2:], " ")
				}
				nf.SendGeneric("exploit.module.progress", payload)
			}
		}
	}

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
