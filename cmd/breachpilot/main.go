package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"time"

	"breachpilot/internal/config"
	"breachpilot/internal/engine"
	"breachpilot/internal/ingest"
	"breachpilot/internal/models"
	"breachpilot/internal/notify"
)

func main() {
	rand.Seed(time.Now().UnixNano())
	cfg := config.Load()
	engOpt := engine.Options{
		NucleiBin:        cfg.NucleiBin,
		ReconHarvestCmd:  config.ResolveReconHarvestCmd(cfg.ReconHarvestCmd),
		ReconWebhookURL:  cfg.ReconWebhookURL,
		ReconTimeoutSec:  cfg.ReconTimeoutSec,
		ReconRetries:     cfg.ReconRetries,
		NucleiTimeoutSec: cfg.NucleiTimeoutSec,
		ArtifactsRoot:    cfg.ArtifactsRoot,
	}
	nf := &notify.Webhook{URL: cfg.ExploitWebhookURL, Secret: cfg.WebhookSecret, Retries: cfg.WebhookRetries}
	nf.Start()

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

	jsonOut := false
	filtered := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--json" {
			jsonOut = true
			continue
		}
		filtered = append(filtered, a)
	}

	if err := runCLIMode(filtered, engOpt, nf, jsonOut); err != nil {
		log.Fatal(err)
	}
}

func runCLIMode(args []string, opt engine.Options, nf *notify.Webhook, jsonOut bool) error {
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

	nf.Send("job.started", job)
	if err := engine.Process(context.Background(), job, cliOpt); err != nil {
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
	fmt.Printf("Done. target=%s mode=%s findings=%d evidence=%s\n", job.Target, job.Mode, job.FindingsCount, job.EvidencePath)
	fmt.Printf("Durations: recon=%.1fs exploit=%.1fs\n", job.ReconDurationSec, job.ExploitDurationSec)
	if job.ReportPath != "" {
		fmt.Printf("Job report: %s\n", job.ReportPath)
	}
	if mode == "full" {
		fmt.Printf("Recon summary used: %s\n", job.ReconPath)
	}
	return nil
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
	return fmt.Sprintf("%s_%04x", time.Now().UTC().Format("20060102T150405"), rand.Intn(0x10000))
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  breachpilot setup")
	fmt.Println("  breachpilot full <target> [--json]")
	fmt.Println("  breachpilot file <summary.json> [--json]")
}
