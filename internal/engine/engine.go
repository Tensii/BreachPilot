package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"breachpilot/internal/ingest"
	"breachpilot/internal/models"
	"breachpilot/internal/policy"
)

type Options struct {
	NucleiBin        string
	ReconHarvestCmd  string
	ReconWebhookURL  string
	ReconTimeoutSec  int
	ReconRetries     int
	NucleiTimeoutSec int
	ArtifactsRoot    string
	Progress         func(string)
}

// Process executes safe planning and optional nuclei validation with approval gates.
func Process(ctx context.Context, job *models.Job, opt Options) error {
	job.StartedAt = time.Now().UTC()
	job.Status = models.JobRunning

	notify := func(s string) {
		if opt.Progress != nil {
			opt.Progress(s)
		}
	}

	if strings.EqualFold(strings.TrimSpace(job.Mode), "full") {
		notify("recon.started")
		reconStart := time.Now()
		summaryPath, err := runReconHarvest(ctx, job, opt)
		job.ReconDurationSec = time.Since(reconStart).Seconds()
		if err != nil {
			_ = writeJobReport(job, opt.ArtifactsRoot)
			return err
		}
		if job.Status == models.JobCancelled || job.Status == models.JobFailed {
			_ = writeJobReport(job, opt.ArtifactsRoot)
			return nil
		}
		job.ReconPath = summaryPath
		notify("recon.completed")
	}

	rs, err := ingest.LoadReconSummary(job.ReconPath)
	if err != nil {
		_ = writeJobReport(job, opt.ArtifactsRoot)
		return err
	}
	if strings.TrimSpace(job.Target) == "" || strings.TrimSpace(job.Target) == "from-summary" {
		if guessed := ingest.GuessTargetFromSummary(job.ReconPath); guessed != "" {
			job.Target = guessed
		}
	}

	plan := []string{
		fmt.Sprintf("Load live hosts from: %s", rs.Live),
		fmt.Sprintf("Load ranked endpoints: %s", rs.Intel.EndpointsRankedJSON),
		"Filter candidates by confidence/severity",
		"Map candidates to safe verification checks",
	}
	if job.SafeMode {
		plan = append(plan, "Safe mode ON: run verification-only nuclei profile")
		if policy.HasIntrusive(job.Templates) {
			job.Status = models.JobRejected
			job.FinishedAt = time.Now().UTC()
			job.Error = "intrusive templates are blocked in safe_mode"
			job.PlanPreview = plan
			_ = writeJobReport(job, opt.ArtifactsRoot)
			return nil
		}
	} else {
		if !job.ApproveIntrusive {
			job.Status = models.JobRejected
			job.FinishedAt = time.Now().UTC()
			job.Error = "intrusive mode requested without approve_intrusive=true"
			job.PlanPreview = plan
			_ = writeJobReport(job, opt.ArtifactsRoot)
			return nil
		}
		if strings.TrimSpace(job.ApprovalTicket) == "" {
			job.Status = models.JobRejected
			job.FinishedAt = time.Now().UTC()
			job.Error = "approval_ticket missing for intrusive mode"
			job.PlanPreview = plan
			_ = writeJobReport(job, opt.ArtifactsRoot)
			return nil
		}
		plan = append(plan, "Approved intrusive mode: broader nuclei templates allowed")
	}
	job.PlanPreview = plan

	hostsPath := strings.TrimSpace(rs.Live)
	if hostsPath == "" {
		hostsPath = filepath.Join(rs.Workdir, "live_hosts.txt")
	}
	if _, err := os.Stat(hostsPath); err != nil {
		_ = writeJobReport(job, opt.ArtifactsRoot)
		return fmt.Errorf("live hosts file not accessible: %w", err)
	}

	artDir := filepath.Join(opt.ArtifactsRoot, job.ID)
	if err := os.MkdirAll(artDir, 0o755); err != nil {
		return err
	}
	outJSONL := filepath.Join(artDir, "nuclei_findings.jsonl")
	outLog := filepath.Join(artDir, "nuclei.log")
	job.EvidencePath = artDir

	args := []string{"-l", hostsPath, "-jsonl", "-o", outJSONL, "-silent", "-no-color", "-stats"}
	if len(job.Templates) > 0 {
		args = append(args, "-t", strings.Join(job.Templates, ","))
	} else if job.SafeMode {
		args = append(args, "-tags", "misconfig,exposure,tech")
	} else {
		args = append(args, "-severity", "medium,high,critical")
	}

	notify("exploit.started")
	exploitStart := time.Now()
	nucleiCtx := ctx
	cancelNuclei := func() {}
	if opt.NucleiTimeoutSec > 0 {
		nucleiCtx, cancelNuclei = context.WithTimeout(ctx, time.Duration(opt.NucleiTimeoutSec)*time.Second)
	}
	defer cancelNuclei()

	cmd := exec.CommandContext(nucleiCtx, opt.NucleiBin, args...)
	logFile, err := os.Create(outLog)
	if err != nil {
		return err
	}
	defer logFile.Close()
	mw := io.MultiWriter(logFile, &progressWriter{stage: "exploit.log", cb: opt.Progress})
	cmd.Stdout = mw
	cmd.Stderr = mw

	if err := cmd.Run(); err != nil {
		job.ExploitDurationSec = time.Since(exploitStart).Seconds()
		if ctx.Err() == context.Canceled {
			job.Status = models.JobCancelled
			job.FinishedAt = time.Now().UTC()
			job.Error = "job cancelled"
			_ = writeJobReport(job, opt.ArtifactsRoot)
			return nil
		}
		if nucleiCtx.Err() == context.DeadlineExceeded {
			job.Status = models.JobFailed
			job.FinishedAt = time.Now().UTC()
			job.Error = "nuclei timeout exceeded"
			_ = writeJobReport(job, opt.ArtifactsRoot)
			return nil
		}
		_ = writeJobReport(job, opt.ArtifactsRoot)
		return fmt.Errorf("nuclei execution failed: %w", err)
	}

	count, err := countLines(outJSONL)
	if err != nil {
		_ = writeJobReport(job, opt.ArtifactsRoot)
		return err
	}
	job.ExploitDurationSec = time.Since(exploitStart).Seconds()
	job.FindingsCount = count
	job.Status = models.JobDone
	job.FinishedAt = time.Now().UTC()
	notify("exploit.completed")
	_ = writeJobReport(job, opt.ArtifactsRoot)
	return nil
}

func runReconHarvest(ctx context.Context, job *models.Job, opt Options) (string, error) {
	if strings.TrimSpace(opt.ReconHarvestCmd) == "" {
		return "", fmt.Errorf("recon harvest command is not configured")
	}
	reconDir := filepath.Join(opt.ArtifactsRoot, job.ID, "recon")
	if err := os.MkdirAll(reconDir, 0o755); err != nil {
		return "", err
	}
	summaryPath := filepath.Join(reconDir, "summary.json")
	if st, err := os.Stat(summaryPath); err == nil && st.Size() > 0 {
		if opt.Progress != nil {
			opt.Progress("recon.resume existing summary found; skipping recon rerun")
		}
		job.EvidencePath = filepath.Join(opt.ArtifactsRoot, job.ID)
		return summaryPath, nil
	}
	logPath := filepath.Join(reconDir, "reconharvest.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return "", err
	}
	defer logFile.Close()

	cmdline := fmt.Sprintf("%s %q --run -o %q", opt.ReconHarvestCmd, job.Target, reconDir)
	attempts := opt.ReconRetries + 1
	if attempts < 1 {
		attempts = 1
	}
	for attempt := 1; attempt <= attempts; attempt++ {
		reconCtx := ctx
		cancelRecon := func() {}
		if opt.ReconTimeoutSec > 0 {
			reconCtx, cancelRecon = context.WithTimeout(ctx, time.Duration(opt.ReconTimeoutSec)*time.Second)
		}
		cmd := exec.CommandContext(reconCtx, "/bin/bash", "-lc", cmdline)
		if opt.ReconWebhookURL != "" {
			cmd.Env = append(os.Environ(), "RECONHARVEST_WEBHOOK="+opt.ReconWebhookURL)
		}
		mw := io.MultiWriter(logFile, &progressWriter{stage: "recon.log", cb: opt.Progress})
		cmd.Stdout = mw
		cmd.Stderr = mw
		err := cmd.Run()
		cancelRecon()
		if err == nil {
			if _, statErr := os.Stat(summaryPath); statErr == nil {
				job.EvidencePath = filepath.Join(opt.ArtifactsRoot, job.ID)
				return summaryPath, nil
			}
			return "", fmt.Errorf("recon summary missing after successful run")
		}
		if ctx.Err() == context.Canceled {
			job.Status = models.JobCancelled
			job.FinishedAt = time.Now().UTC()
			job.Error = "job cancelled during recon phase"
			return "", nil
		}
		if reconCtx.Err() == context.DeadlineExceeded {
			job.Status = models.JobFailed
			job.FinishedAt = time.Now().UTC()
			job.Error = "recon timeout exceeded"
			return "", nil
		}
		if opt.Progress != nil {
			opt.Progress(fmt.Sprintf("recon.retry attempt=%d/%d", attempt, attempts))
		}
		if attempt == attempts {
			return "", fmt.Errorf("reconHarvest failed after retries: %w", err)
		}
		time.Sleep(time.Duration(attempt) * time.Second)
	}
	return "", fmt.Errorf("reconHarvest failed")
}

func writeJobReport(job *models.Job, artifactsRoot string) error {
	if job == nil {
		return nil
	}
	dir := filepath.Join(artifactsRoot, job.ID)
	if job.EvidencePath != "" {
		dir = job.EvidencePath
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	report := filepath.Join(dir, "job_report.json")
	job.ReportPath = report
	b, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(report, b, 0o644); err != nil {
		return err
	}
	return nil
}

type progressWriter struct {
	stage string
	cb    func(string)
	buf   []byte
}

func (w *progressWriter) Write(p []byte) (int, error) {
	if w.cb == nil {
		return len(p), nil
	}
	w.buf = append(w.buf, p...)
	for {
		i := -1
		for idx, b := range w.buf {
			if b == '\n' {
				i = idx
				break
			}
		}
		if i < 0 {
			break
		}
		line := strings.TrimSpace(string(w.buf[:i]))
		w.buf = w.buf[i+1:]
		if line != "" {
			w.cb(fmt.Sprintf("%s %s", w.stage, line))
		}
	}
	return len(p), nil
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	n := 0
	for s.Scan() {
		if strings.TrimSpace(s.Text()) != "" {
			n++
		}
	}
	return n, s.Err()
}
