package main

import (
	"context"
	"crypto/rand"
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
		fmt.Println("\n[!] Interrupt received, safely stopping (waiting 1s for state flush)...")
		cancel()
		time.Sleep(1 * time.Second)
		os.Exit(1)
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
	job := &models.Job{
		ID:        newJobID(),
		Target:    target,
		Mode:      mode,
		SafeMode:  true,
		Status:    models.JobQueued,
		CreatedAt: time.Now().UTC(),
	}

	if mode == "file" {
		job.ReconPath = strings.TrimSpace(args[1])
		job.Mode = "ingest"
		if job.ReconPath == "" {
			return fmt.Errorf("file mode requires summary path: breachpilot file <summary.json>")
		}
		if job.Target == "" {
			if rs, err := ingest.LoadReconSummary(job.ReconPath); err == nil {
				if guessed := ingest.TargetFromWorkdir(rs.Workdir); guessed != "" {
					job.Target = guessed
				}
			}
			if job.Target == "" {
				job.Target = "from-summary"
			}
		}
	}

	cliOpt := opt
	cliOpt.Progress = func(stage string) {
		if !jsonOut {
			fmt.Printf("[stage] %s\n", stage)
		}
	}

	// Persist job config so `resume` can reload it later
	if err := saveJobConfig(job, cliOpt.ArtifactsRoot); err != nil {
		log.Printf("warning: could not save job.json: %v", err)
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

func newJobID() string {
	b := make([]byte, 2)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s_%04x", time.Now().UTC().Format("20060102T150405"), int(b[0])<<8|int(b[1]))
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
	  breachpilot resume <job_id> [--json]
	  breachpilot list-modules

	Examples:
	  breachpilot setup
	  breachpilot full example.com
	  breachpilot file recon/summary.json --json
	  breachpilot resume 20260314T032654_48b3
	`)
}

func resumeJob(ctx context.Context, args []string, opt engine.Options, nf *notify.Webhook, jsonOut bool) error {
	if len(args) == 0 {
		return fmt.Errorf("missing job_id. Use: breachpilot resume <job_id>")
	}
	jobID := strings.TrimSpace(args[0])

	// Try job.json first, then fall back to job_report.json (embedded job object)
	job, err := loadJobForResume(opt.ArtifactsRoot, jobID)
	if err != nil {
		return err
	}

	statePath := filepath.Join(opt.ArtifactsRoot, jobID, ".breachpilot_state.json")
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		return fmt.Errorf("no state found for job %q. Job cannot be resumed from %s", jobID, statePath)
	}

	if !jsonOut {
		fmt.Printf("\n[BREACHPILOT] Engine Resuming Job: %s\n", job.ID)
	}

	job.Status = models.JobRunning

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
	for _, ln := range formatCLISummary(job, job.Mode) {
		fmt.Println(ln)
	}
	return nil
}

// loadJobForResume tries job.json first, then extracts from job_report.json.
func loadJobForResume(artifactsRoot, jobID string) (*models.Job, error) {
	jobDir := filepath.Join(artifactsRoot, jobID)
	// Try standalone job.json
	jobPath := filepath.Join(jobDir, "job.json")
	if data, err := os.ReadFile(jobPath); err == nil {
		var job models.Job
		if err := json.Unmarshal(data, &job); err == nil {
			return &job, nil
		}
	}
	// Fallback: extract from job_report.json
	reportPath := filepath.Join(jobDir, "job_report.json")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("no job.json or job_report.json found in %s", jobDir)
	}
	var wrapper struct {
		Job models.Job `json:"job"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to parse job_report.json: %w", err)
	}
	return &wrapper.Job, nil
}

// saveJobConfig persists the job config to job.json for later resumption.
func saveJobConfig(job *models.Job, artifactsRoot string) error {
	dir := filepath.Join(artifactsRoot, job.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "job.json"), b, 0o644)
}
