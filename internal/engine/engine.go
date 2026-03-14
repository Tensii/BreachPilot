package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"breachpilot/internal/exploit"
	"breachpilot/internal/exploit/filter"
	adminsurface "breachpilot/internal/exploit/modules/adminsurface"
	apisurface "breachpilot/internal/exploit/modules/apisurface"
	bypasspoc "breachpilot/internal/exploit/modules/bypasspoc"
	cookiesecurity "breachpilot/internal/exploit/modules/cookiesecurity"
	cors "breachpilot/internal/exploit/modules/cors"
	cspaudit "breachpilot/internal/exploit/modules/cspaudit"
	dnscheck "breachpilot/internal/exploit/modules/dnscheck"
	exposedfiles "breachpilot/internal/exploit/modules/exposedfiles"
	headers "breachpilot/internal/exploit/modules/headers"
	httpresponse "breachpilot/internal/exploit/modules/httpresponse"
	httpmethods "breachpilot/internal/exploit/modules/httpmethods"
	infodisclosure "breachpilot/internal/exploit/modules/infodisclosure"
	jsendpoints "breachpilot/internal/exploit/modules/jsendpoints"
	nucleitriage "breachpilot/internal/exploit/modules/nucleitriage"
	openredirect "breachpilot/internal/exploit/modules/openredirect"
	portservice "breachpilot/internal/exploit/modules/portservice"
	secretsvalidator "breachpilot/internal/exploit/modules/secretsvalidator"
	subt "breachpilot/internal/exploit/modules/subt"
	tlsaudit "breachpilot/internal/exploit/modules/tlsaudit"
	"breachpilot/internal/ingest"
	"breachpilot/internal/models"
	"breachpilot/internal/policy"
	"breachpilot/internal/scope"
	"github.com/google/shlex"
)

type Options struct {
	NucleiBin          string
	ReconHarvestCmd    string
	ReconWebhookURL    string
	ReconTimeoutSec    int
	ReconRetries       int
	NucleiTimeoutSec   int
	ArtifactsRoot      string
	MinSeverity        string
	SkipModules        string
	OnlyModules        string
	ValidationOnly     bool
	Progress           func(string)
	Notifier           Notifier
	PreviousReportPath string
	ReportFormats      string
	ScanProfile        string
	RateLimitRPS       int
}

// Notifier sends structured events.
type Notifier interface {
	SendGeneric(eventType string, payload any)
}

// Process executes safe planning and optional nuclei validation with approval gates.
func Process(ctx context.Context, job *models.Job, opt Options) error {
	// Resolve scan profile if set
	if opt.ScanProfile != "" {
		if p, ok := GetProfile(opt.ScanProfile); ok {
			if opt.OnlyModules == "" {
				opt.OnlyModules = p.OnlyModules
			}
			if opt.SkipModules == "" {
				opt.SkipModules = p.SkipModules
			}
		}
	}
	job.StartedAt = time.Now().UTC()
	job.Status = models.JobRunning

	artDir := filepath.Join(opt.ArtifactsRoot, job.ID)
	sm, err := NewStateManager(artDir, job)
	if err != nil {
		job.Status = models.JobFailed
		job.FinishedAt = time.Now().UTC()
		job.Error = fmt.Sprintf("state manager init failed: %v", err)
		_ = writeJobReport(job, opt.ArtifactsRoot)
		return err
	}
	if t := strings.TrimSpace(job.Target); t != "" && t != "from-summary" {
		if err := scope.ValidateTarget(t); err != nil {
			job.Status = models.JobFailed
			job.FinishedAt = time.Now().UTC()
			job.Error = fmt.Sprintf("target validation failed: %v", err)
			_ = writeJobReport(job, opt.ArtifactsRoot)
			return nil
		}
	}

	notify := func(s string) {
		if opt.Progress != nil {
			opt.Progress(s)
		}
	}

	if strings.EqualFold(strings.TrimSpace(job.Mode), "full") {
		if sm.IsReconCompleted() {
			notify("recon.resumed")
			job.ReconPath = filepath.Join(opt.ArtifactsRoot, job.ID, "summary.json")
		} else {
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
			_ = sm.MarkReconCompleted()
		}
	}

	rs, err := validateReconSummary(job.ReconPath, job.Target)
	if err != nil {
		_ = writeJobReport(job, opt.ArtifactsRoot)
		return err
	}
	if strings.TrimSpace(job.Target) == "" || strings.TrimSpace(job.Target) == "from-summary" {
		if guessed := ingest.TargetFromWorkdir(rs.Workdir); guessed != "" {
			job.Target = guessed
		}
	}
	if t := strings.TrimSpace(job.Target); t != "" && t != "from-summary" {
		if err := scope.ValidateTarget(t); err != nil {
			job.Status = models.JobFailed
			job.FinishedAt = time.Now().UTC()
			job.Error = fmt.Sprintf("target validation failed: %v", err)
			_ = writeJobReport(job, opt.ArtifactsRoot)
			return nil
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

	artDir = filepath.Join(opt.ArtifactsRoot, job.ID)
	if err := os.MkdirAll(artDir, 0o755); err != nil {
		return err
	}
	outJSONL := filepath.Join(artDir, "nuclei_findings.jsonl")
	outLog := filepath.Join(artDir, "nuclei.log")
	job.EvidencePath = artDir

	nucleiInput := hostsPath
	if rankedInput, rankedCount := buildRankedNucleiInput(rs.Intel.EndpointsRankedJSON, artDir); rankedCount > 0 {
		nucleiInput = rankedInput
		if opt.Progress != nil {
			opt.Progress(fmt.Sprintf("exploit.targeting using ranked endpoints: %d", rankedCount))
		}
	}

	args := []string{"-l", nucleiInput, "-jsonl", "-o", outJSONL, "-silent", "-no-color", "-stats"}
	if len(job.Templates) > 0 {
		args = append(args, "-t", strings.Join(job.Templates, ","))
	} else if job.SafeMode {
		args = append(args, "-tags", "misconfig,exposure,tech")
	} else {
		args = append(args, "-severity", "medium,high,critical")
	}

	stOut, errOut := os.Stat(outJSONL)
	if sm.IsNucleiCompleted() && errOut == nil && stOut.Size() > 0 {
		notify("exploit.nuclei.resumed")
	} else {
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
		nucleiPW := &progressWriter{stage: "exploit.log", cb: opt.Progress}
		mw := io.MultiWriter(logFile, nucleiPW)
		cmd.Stdout = mw
		cmd.Stderr = mw

		nucleiErr := cmd.Run()
		nucleiPW.Flush()
		if nucleiErr != nil {
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
			st, statErr := os.Stat(outJSONL)
			if statErr != nil || st.Size() == 0 {
				_ = writeJobReport(job, opt.ArtifactsRoot)
				return fmt.Errorf("nuclei execution failed: %w", nucleiErr)
			}
			if opt.Progress != nil {
				opt.Progress("exploit.warning nuclei exited non-zero with partial results; continuing")
			}
			job.Error = fmt.Sprintf("nuclei exited non-zero; partial results accepted: %v", nucleiErr)
		}

		job.ExploitDurationSec = time.Since(exploitStart).Seconds()
		_ = sm.MarkNucleiCompleted()
	}

	count, err := countLines(outJSONL)
	if err != nil {
		_ = writeJobReport(job, opt.ArtifactsRoot)
		return err
	}
	job.FindingsCount = count
	notify("exploit.completed")

	// --- exploit module phase ---
	exploitModules := filterModules(registeredModuleInstances(), opt.OnlyModules, opt.SkipModules)
	if opt.ValidationOnly {
		exploitModules = filterValidationOnly(exploitModules)
	}
	exploitFindings, telemetry := exploit.RunModules(ctx, job, &rs, exploit.Options{
		ArtifactsRoot: opt.ArtifactsRoot,
		Progress:      opt.Progress,
		SafeMode:      job.SafeMode,
		MaxParallel:   0,
		StateManager:  sm,
	}, exploitModules)
	job.ModuleTelemetry = telemetry
	preFilterCount := len(exploitFindings)
	exploitFindings = filter.BySeverity(exploitFindings, opt.MinSeverity)
	job.FilteredCount = preFilterCount - len(exploitFindings)

	// Send exploit.modules.completed webhook
	if opt.Notifier != nil {
		opt.Notifier.SendGeneric("exploit.modules.completed", map[string]any{
			"job_id":         job.ID,
			"target":         job.Target,
			"findings_count": len(exploitFindings),
			"filtered_count": job.FilteredCount,
			"risk_score":     job.RiskScore,
			"module_count":   len(exploitModules),
			"duration_sec":   job.ExploitDurationSec,
		})
	}

	if err := writeExploitFindingsJSONL(exploitFindings, artDir, job); err != nil {
		job.Status = models.JobFailed
		job.FinishedAt = time.Now().UTC()
		job.Error = err.Error()
		_ = writeJobReport(job, opt.ArtifactsRoot)
		return err
	}
	rptOpts := exploit.ReportOptions{
		Formats:            opt.ReportFormats,
		PreviousReportPath: opt.PreviousReportPath,
		Secrets:            loadSecretsIntel(rs.Intel.SecretsJSON),
		CORS:               loadCORSIntel(rs.Intel.CORSJSON),
	}
	if reportPath, rpErr := exploit.WriteExploitReport(exploitFindings, job, artDir, rptOpts); rpErr != nil {
		job.Status = models.JobFailed
		job.FinishedAt = time.Now().UTC()
		job.Error = fmt.Sprintf("write exploit report: %v", rpErr)
		_ = writeJobReport(job, opt.ArtifactsRoot)
		return rpErr
	} else {
		job.ExploitReportPath = reportPath
	}

	job.Status = models.JobDone
	job.FinishedAt = time.Now().UTC()
	if err := writeJobReport(job, opt.ArtifactsRoot); err != nil {
		job.Status = models.JobFailed
		job.FinishedAt = time.Now().UTC()
		job.Error = fmt.Sprintf("write job report: %v", err)
		return err
	}
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
		if _, vErr := validateReconSummary(summaryPath, job.Target); vErr != nil {
			return "", fmt.Errorf("resume validation failed: %w", vErr)
		}
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

	baseArgv, err := shlex.Split(strings.TrimSpace(opt.ReconHarvestCmd))
	if err != nil || len(baseArgv) == 0 {
		return "", fmt.Errorf("invalid recon command: %q", opt.ReconHarvestCmd)
	}
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
		argv := append([]string{}, baseArgv...)
		// If the recon dir already has partial work (e.g. from a previous interrupted run),
		// pass --resume so reconHarvest picks up where it left off.
		// On a fresh run the dir was just created empty, so --overwrite is safe.
		if hasPartialRecon(reconDir) {
			argv = append(argv, job.Target, "--run", "-o", reconDir, "--resume", filepath.Join(reconDir, "run.log"), "--skip-nuclei", "--arjun-threads", "20", "--vhost-threads", "80")
		} else {
			argv = append(argv, job.Target, "--run", "-o", reconDir, "--overwrite", "--skip-nuclei", "--arjun-threads", "20", "--vhost-threads", "80")
		}
		cmd := exec.CommandContext(reconCtx, argv[0], argv[1:]...)
		if opt.ReconWebhookURL != "" {
			cmd.Env = append(os.Environ(), "RECONHARVEST_WEBHOOK="+opt.ReconWebhookURL)
		}
		pw := &progressWriter{stage: "recon.log", cb: opt.Progress}
		mw := io.MultiWriter(logFile, pw)
		cmd.Stdout = mw
		cmd.Stderr = mw
		err := cmd.Run()
		pw.Flush() // Flush any partial output left in the progress writer buffer
		cancelRecon()
		if err == nil {
			if _, statErr := os.Stat(summaryPath); statErr == nil {
				job.EvidencePath = filepath.Join(opt.ArtifactsRoot, job.ID)
				return summaryPath, nil
			}
			// Fallback: search for summary.json inside recon subdirectories
			if alt := findSummaryJSON(reconDir); alt != "" {
				job.EvidencePath = filepath.Join(opt.ArtifactsRoot, job.ID)
				return alt, nil
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

// hasPartialRecon returns true if the recon dir already has work files from a
// previous (interrupted) run. This determines whether we pass --resume vs
// --overwrite to reconHarvest.py.
func hasPartialRecon(reconDir string) bool {
	markers := []string{"run.log", "workspace_meta.json", "live_hosts.txt", "run_commands.sh"}
	for _, m := range markers {
		if st, err := os.Stat(filepath.Join(reconDir, m)); err == nil && st.Size() > 0 {
			return true
		}
	}
	return false
}

// findSummaryJSON walks reconDir looking for any summary.json file.
func findSummaryJSON(reconDir string) string {
	var found string
	_ = filepath.Walk(reconDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && info.Name() == "summary.json" && info.Size() > 0 {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func buildRankedNucleiInput(path string, artDir string) (string, int) {
	p := strings.TrimSpace(path)
	if p == "" {
		return "", 0
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", 0
	}
	var data any
	if err := json.Unmarshal(b, &data); err != nil {
		return "", 0
	}
	items := make([]string, 0, 256)
	seen := make(map[string]struct{})
	appendURL := func(v string) {
		u := strings.TrimSpace(v)
		if u == "" {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		items = append(items, u)
	}

	switch t := data.(type) {
	case []any:
		for _, row := range t {
			m, ok := row.(map[string]any)
			if !ok {
				continue
			}
			if u, ok := m["url"].(string); ok {
				appendURL(u)
			}
			if len(items) >= 500 {
				break
			}
		}
	case map[string]any:
		if arr, ok := t["items"].([]any); ok {
			for _, row := range arr {
				m, ok := row.(map[string]any)
				if !ok {
					continue
				}
				if u, ok := m["url"].(string); ok {
					appendURL(u)
				}
				if len(items) >= 500 {
					break
				}
			}
		}
	}
	if len(items) == 0 {
		return "", 0
	}
	out := filepath.Join(artDir, "nuclei_targets_ranked.txt")
	_ = os.WriteFile(out, []byte(strings.Join(items, "\n")+"\n"), 0o644)
	return out, len(items)
}

func writeExploitFindingsJSONL(findings []models.ExploitFinding, artDir string, job *models.Job) error {
	if job == nil {
		return nil
	}
	if len(findings) == 0 {
		job.ExploitFindingsCount = 0
		job.ExploitFindingsPath = ""
		return nil
	}
	path := filepath.Join(artDir, "exploit_findings.jsonl")
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		job.ExploitFindingsPath = ""
		return fmt.Errorf("write exploit findings jsonl: %w", err)
	}
	enc := json.NewEncoder(f)
	for _, it := range findings {
		if err := enc.Encode(it); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			job.ExploitFindingsPath = ""
			return fmt.Errorf("encode exploit finding: %w", err)
		}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		job.ExploitFindingsPath = ""
		return fmt.Errorf("close exploit findings jsonl: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		job.ExploitFindingsPath = ""
		return fmt.Errorf("rename temp exploit findings file: %w", err)
	}
	job.ExploitFindingsCount = len(findings)
	job.ExploitFindingsPath = path
	return nil
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
	payload := map[string]any{"schema_version": models.SchemaVersion, "job": job}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWriteFile(report, b, 0o644); err != nil {
		return fmt.Errorf("write job report: %w", err)
	}
	job.ReportPath = report
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

// Flush emits any remaining partial line still in the buffer.
func (w *progressWriter) Flush() {
	if w.cb == nil || len(w.buf) == 0 {
		return
	}
	line := strings.TrimSpace(string(w.buf))
	w.buf = nil
	if line != "" {
		w.cb(fmt.Sprintf("%s %s", w.stage, line))
	}
}

func validateReconSummary(summaryPath, requestedTarget string) (models.ReconSummary, error) {
	var rs models.ReconSummary
	st, err := os.Stat(summaryPath)
	if err != nil {
		return rs, fmt.Errorf("resume summary missing: %w", err)
	}
	if st.Size() == 0 {
		return rs, fmt.Errorf("resume summary empty")
	}
	b, err := os.ReadFile(summaryPath)
	if err != nil {
		return rs, fmt.Errorf("read summary: %w", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return rs, fmt.Errorf("parse summary json: %w", err)
	}
	if sv, ok := raw["schema_version"].(string); ok && sv != "" && sv != models.SchemaVersion {
		return rs, fmt.Errorf("incompatible schema_version: %s", sv)
	}
	if err := json.Unmarshal(b, &rs); err != nil {
		return rs, fmt.Errorf("decode summary struct: %w", err)
	}
	live := strings.TrimSpace(rs.Live)
	if live == "" {
		live = filepath.Join(rs.Workdir, "live_hosts.txt")
	}
	if lst, lerr := os.Stat(live); lerr != nil || lst.Size() == 0 {
		return rs, fmt.Errorf("resume live hosts invalid: %s", live)
	}
	if rt := strings.TrimSpace(requestedTarget); rt != "" && rt != "from-summary" {
		if tgt := ingest.TargetFromWorkdir(rs.Workdir); tgt != "" && strings.Contains(tgt, ".") && !strings.EqualFold(tgt, rt) {
			return rs, fmt.Errorf("resume target mismatch: summary=%s requested=%s", tgt, rt)
		}
	}
	return rs, nil
}

func loadSecretsIntel(path string) []models.SecretsFinding {
	p := strings.TrimSpace(path)
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		log.Printf("warning: secrets intel not loaded: %v", err)
		return nil
	}
	var out []models.SecretsFinding
	if err := json.Unmarshal(b, &out); err != nil {
		log.Printf("warning: secrets intel JSON parse failed: %v", err)
		return nil
	}
	return out
}

func loadCORSIntel(path string) []models.CORSFinding {
	p := strings.TrimSpace(path)
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		log.Printf("warning: CORS intel not loaded: %v", err)
		return nil
	}
	var out []models.CORSFinding
	if err := json.Unmarshal(b, &out); err != nil {
		log.Printf("warning: CORS intel JSON parse failed: %v", err)
		return nil
	}
	return out
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

type ModuleInfo struct {
	Name         string
	Description  string
	SafeReadOnly bool
}

func registeredModuleInfos() []ModuleInfo {
	return []ModuleInfo{
		{"security-headers", "Detects missing/weak security headers", true},
		{"open-redirect", "Detects potential open redirect vectors", true},
		{"info-disclosure", "Probes common exposed files/endpoints", true},
		{"cors-poc", "Validates risky CORS findings", true},
		{"secrets-validator", "Validates leaked key/JWT patterns", true},
		{"bypass-poc", "Builds PoC from discovered 403 bypasses", true},
		{"port-service", "Classifies risky exposed network services", true},
		{"nuclei-triage", "Triages nuclei phase1 results", true},
		{"subdomain-takeover", "Checks takeover signatures", true},
		{"api-surface", "Finds exposed API specs/graphql endpoints", true},
		{"cookie-security", "Checks cookie flag hardening", true},
		{"http-method-tampering", "Checks dangerous HTTP methods", true},
		{"js-endpoints", "Scores JS-discovered endpoint risk", true},
		{"admin-surface", "Finds exposed admin/debug surfaces", true},
		{"exposed-files", "Finds exposed sensitive files/config", true},
		{"tls-audit", "Validates TLS certificate and handshake security", true},
		{"dns-check", "Validates DNS/email security configuration", true},
		{"csp-audit", "Validates Content Security Policy headers", true},
		{"http-response", "Detects HTTP response anomalies and information leaks", true},
	}
}

func RegisteredModuleInfos() []ModuleInfo {
	infos := registeredModuleInfos()
	out := make([]ModuleInfo, len(infos))
	copy(out, infos)
	return out
}

func registeredModuleInstances() []exploit.Module {
	return []exploit.Module{
		headers.New(),
		openredirect.New(),
		infodisclosure.New(),
		cors.New(),
		secretsvalidator.New(),
		bypasspoc.New(),
		portservice.New(),
		nucleitriage.New(),
		subt.New(),
		apisurface.New(),
		cookiesecurity.New(),
		httpmethods.New(),
		jsendpoints.New(),
		adminsurface.New(),
		exposedfiles.New(),
		tlsaudit.New(),
		dnscheck.New(),
		cspaudit.New(),
		httpresponse.New(),
	}
}

// RegisteredModules returns the names of all exploit modules in registration order.
func RegisteredModules() []string {
	infos := registeredModuleInfos()
	out := make([]string, 0, len(infos))
	for _, m := range infos {
		out = append(out, m.Name)
	}
	return out
}

func filterModules(modules []exploit.Module, onlyModules string, skipList string) []exploit.Module {
	if strings.TrimSpace(onlyModules) != "" {
		only := make(map[string]struct{})
		for _, s := range strings.Split(onlyModules, ",") {
			s = strings.ToLower(strings.TrimSpace(s))
			if s != "" {
				only[s] = struct{}{}
			}
		}
		out := make([]exploit.Module, 0, len(modules))
		for _, m := range modules {
			if _, ok := only[strings.ToLower(m.Name())]; ok {
				out = append(out, m)
			}
		}
		return out
	}
	return filterModulesBySkipList(modules, skipList)
}

func filterValidationOnly(modules []exploit.Module) []exploit.Module {
	infos := registeredModuleInfos()
	safe := map[string]bool{}
	for _, i := range infos {
		safe[strings.ToLower(i.Name)] = i.SafeReadOnly
	}
	out := make([]exploit.Module, 0, len(modules))
	for _, m := range modules {
		if safe[strings.ToLower(m.Name())] {
			out = append(out, m)
		}
	}
	return out
}

func filterModulesBySkipList(modules []exploit.Module, skipList string) []exploit.Module {
	if strings.TrimSpace(skipList) == "" {
		return modules
	}
	skip := make(map[string]struct{})
	for _, s := range strings.Split(skipList, ",") {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			skip[s] = struct{}{}
		}
	}
	out := make([]exploit.Module, 0, len(modules))
	for _, m := range modules {
		if _, blocked := skip[strings.ToLower(m.Name())]; !blocked {
			out = append(out, m)
		}
	}
	return out
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
