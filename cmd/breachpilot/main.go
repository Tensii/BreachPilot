package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"breachpilot/internal/api"
	"breachpilot/internal/config"
	"breachpilot/internal/engine"
	"breachpilot/internal/ingest"
	"breachpilot/internal/models"
	"breachpilot/internal/notify"
	"breachpilot/internal/queue"
	"breachpilot/internal/store"
)

func main() {
	cfg := config.Load()
	engOpt := engine.Options{
		NucleiBin:        cfg.NucleiBin,
		ReconHarvestCmd:  cfg.ReconHarvestCmd,
		ReconTimeoutSec:  cfg.ReconTimeoutSec,
		ReconRetries:     cfg.ReconRetries,
		NucleiTimeoutSec: cfg.NucleiTimeoutSec,
		ArtifactsRoot:    cfg.ArtifactsRoot,
	}
	nf := &notify.Webhook{URL: cfg.WebhookURL, Secret: cfg.WebhookSecret, Retries: cfg.WebhookRetries}
	nf.Start()

	// Simple CLI mode:
	//   breachpilot full <target> [--json]
	//   breachpilot file <summary.json> [--json]
	args := flag.Args()
	if len(args) > 0 {
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
		return
	}

	st, err := store.OpenSQLite(cfg.DBPath)
	if err != nil {
		log.Fatalf("open sqlite store: %v", err)
	}
	defer st.Close()

	q := queue.New(cfg.QueueSize, engOpt, nf, st)
	q.StartWorkers(cfg.Workers)

	srv := &api.Server{Q: q, Token: cfg.RequireToken, TriggerSecret: cfg.TriggerSecret}
	log.Printf("breachpilot listening on %s workers=%d queue=%d", cfg.Listen, cfg.Workers, cfg.QueueSize)
	if err := http.ListenAndServe(cfg.Listen, srv.Router()); err != nil {
		log.Fatal(err)
	}
}

func runCLIMode(args []string, opt engine.Options, nf *notify.Webhook, jsonOut bool) error {
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
		ID:        time.Now().UTC().Format("20060102T150405"),
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
			if guessed := ingest.GuessTargetFromSummary(job.ReconPath); guessed != "" {
				job.Target = guessed
			} else {
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

func init() {
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		fmt.Println("Usage:")
		fmt.Println("  breachpilot                 # run API server")
		fmt.Println("  breachpilot full <target> [--json]   # run reconHarvest then exploit stage")
		fmt.Println("  breachpilot file <summary.json> [--json]  # use existing ReconHarvest summary")
	}
}
