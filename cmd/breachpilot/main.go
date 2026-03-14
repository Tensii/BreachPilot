package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
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
)

func main() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}
	log.Println(cfg.RedactedSummary())
	engOpt := engine.Options{
		NucleiBin:          cfg.NucleiBin,
		ReconHarvestCmd:    config.ResolveReconHarvestCmd(cfg.ReconHarvestCmd),
		ReconWebhookURL:    cfg.ReconWebhookURL,
		ReconTimeoutSec:    cfg.ReconTimeoutSec,
		ReconRetries:       cfg.ReconRetries,
		NucleiTimeoutSec:   cfg.NucleiTimeoutSec,
		ArtifactsRoot:      cfg.ArtifactsRoot,
		MinSeverity:        cfg.MinSeverity,
		SkipModules:        cfg.SkipModules,
		OnlyModules:        cfg.OnlyModules,
		ValidationOnly:     cfg.ValidationOnly,
		PreviousReportPath: cfg.PreviousReportPath,
		ReportFormats:      cfg.ReportFormats,
		ScanProfile:        cfg.ScanProfile,
		RateLimitRPS:       cfg.RateLimitRPS,
	}
	nf := &notify.Webhook{URL: cfg.ExploitWebhookURL, Secret: cfg.WebhookSecret, Retries: cfg.WebhookRetries}
	nf.Start()
	defer nf.Stop()
	engOpt.Notifier = nf

	args := os.Args[1:]
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	if len(args) == 1 && args[0] == "setup" {
		if err := runSetup(engOpt); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(args) == 1 && args[0] == "list-modules" {
		listModules(engOpt)
		return
	}

	jsonOut := false
	filtered := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--json" {
			jsonOut = true
			continue
		}
		filtered = append(filtered, a)
	}

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
		if err := resumeJob(ctx, filtered[1:], engOpt, nf, jsonOut); err != nil {
			log.Fatal(err)
		}
		return
	}

	if err := runCLIMode(ctx, filtered, engOpt, nf, jsonOut); err != nil {
		log.Fatal(err)
	}
}

func runCLIMode(ctx context.Context, args []string, opt engine.Options, nf *notify.Webhook, jsonOut bool) error {
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
		SafeMode:  true,
		Status:    models.JobQueued,
		CreatedAt: time.Now().UTC(),
	}

	cliOpt := opt
	cliOpt.Progress = func(stage string) {
		if !jsonOut {
			fmt.Printf("[stage] %s\n", stage)
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
		fmt.Printf("Job rejected: %s\n", job.Error)
		return nil
	case models.JobCancelled:
		nf.Send("job.cancelled", job)
		if jsonOut {
			return printJobJSON(job)
		}
		fmt.Printf("Job cancelled\n")
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

func runSetup(opt engine.Options) error {
	fmt.Println("[setup] checking runtime dependencies...")
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
		fmt.Printf("[setup] ok %s: %s\n", c.name, strings.TrimSpace(string(out)))
	}

	reconCmd := strings.TrimSpace(opt.ReconHarvestCmd)
	if reconCmd == "" {
		return fmt.Errorf("[setup] recon command is empty")
	}
	probe := exec.Command("/bin/bash", "-lc", reconCmd+" --help >/dev/null 2>&1")
	if err := probe.Run(); err != nil {
		return fmt.Errorf("[setup] recon command not executable: %s", reconCmd)
	}
	fmt.Printf("[setup] ok recon command: %s\n", reconCmd)
	if err := os.MkdirAll(opt.ArtifactsRoot, 0o755); err != nil {
		return fmt.Errorf("[setup] artifacts dir failed: %w", err)
	}
	fmt.Printf("[setup] artifacts dir ready: %s\n", opt.ArtifactsRoot)
	fmt.Println("[setup] done")
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

func printUsage() {
	fmt.Println(`Usage:
	  breachpilot setup
	  breachpilot full <target> [--json]
	  breachpilot file <summary.json> [--json]
	  breachpilot resume <path/to/.breachpilot.state> [--json]
	  breachpilot list-modules

	Examples:
	  breachpilot full example.com
	  breachpilot file recon/summary.json --json
	  breachpilot resume artifacts/example.com/1/.breachpilot.state
	`)
}

func resumeJob(ctx context.Context, args []string, opt engine.Options, nf *notify.Webhook, jsonOut bool) error {
	if len(args) == 0 {
		return fmt.Errorf("missing state file path. Use: breachpilot resume <path/to/.breachpilot.state>")
	}
	statePath := strings.TrimSpace(args[0])

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
		SafeMode:  true,
		Status:    models.JobRunning,
		CreatedAt: time.Now().UTC(),
	}

	if !jsonOut {
		fmt.Printf("\n[BREACHPILOT] Resuming: %s (target=%s)\n", job.ID, job.Target)
		fmt.Printf("[BREACHPILOT] State: recon=%v nuclei=%v modules=%d\n",
			st.ReconCompleted, st.NucleiCompleted, len(st.ModulesFinished))
	}

	// Derive artifacts root from job dir path
	// jobDir = artifactsRoot/domain/N → artifactsRoot = jobDir minus the last 2 path components
	cliOpt := opt
	cliOpt.ArtifactsRoot = filepath.Dir(filepath.Dir(jobDir))
	cliOpt.Progress = func(stage string) {
		if !jsonOut {
			fmt.Printf("[stage] %s\n", stage)
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
		fmt.Printf("Job rejected: %s\n", job.Error)
		return nil
	case models.JobCancelled:
		nf.Send("job.cancelled", job)
		if jsonOut {
			return printJobJSON(job)
		}
		fmt.Printf("Job cancelled\n")
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
