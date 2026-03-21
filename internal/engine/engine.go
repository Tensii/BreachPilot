package engine

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"breachpilot/internal/exploit"
	"breachpilot/internal/exploit/filter"
	adminsurface "breachpilot/internal/exploit/modules/adminsurface"
	advancedinjection "breachpilot/internal/exploit/modules/advancedinjection"
	apisurface "breachpilot/internal/exploit/modules/apisurface"
	authbypass "breachpilot/internal/exploit/modules/authbypass"
	bypasspoc "breachpilot/internal/exploit/modules/bypasspoc"
	cookiesecurity "breachpilot/internal/exploit/modules/cookiesecurity"
	cors "breachpilot/internal/exploit/modules/cors"
	crlfinjection "breachpilot/internal/exploit/modules/crlfinjection"
	cspaudit "breachpilot/internal/exploit/modules/cspaudit"
	dnscheck "breachpilot/internal/exploit/modules/dnscheck"
	exposedfiles "breachpilot/internal/exploit/modules/exposedfiles"
	graphqlabuse "breachpilot/internal/exploit/modules/graphqlabuse"
	headers "breachpilot/internal/exploit/modules/headers"
	httpmethods "breachpilot/internal/exploit/modules/httpmethods"
	httpresponse "breachpilot/internal/exploit/modules/httpresponse"
	idorplaybook "breachpilot/internal/exploit/modules/idorplaybook"
	idorsize "breachpilot/internal/exploit/modules/idorsize"
	infodisclosure "breachpilot/internal/exploit/modules/infodisclosure"
	jsendpoints "breachpilot/internal/exploit/modules/jsendpoints"
	jwtaccess "breachpilot/internal/exploit/modules/jwtaccess"
	mutationengine "breachpilot/internal/exploit/modules/mutationengine"
	nucleitriage "breachpilot/internal/exploit/modules/nucleitriage"
	openredirect "breachpilot/internal/exploit/modules/openredirect"
	portservice "breachpilot/internal/exploit/modules/portservice"
	privpath "breachpilot/internal/exploit/modules/privpath"
	rsqlinjection "breachpilot/internal/exploit/modules/rsqlinjection"
	samlprobe "breachpilot/internal/exploit/modules/samlprobe"
	secretsvalidator "breachpilot/internal/exploit/modules/secretsvalidator"
	sessionabuse "breachpilot/internal/exploit/modules/sessionabuse"
	ssrfprober "breachpilot/internal/exploit/modules/ssrfprober"
	statechange "breachpilot/internal/exploit/modules/statechange"
	subt "breachpilot/internal/exploit/modules/subt"
	tlsaudit "breachpilot/internal/exploit/modules/tlsaudit"
	uploadabuse "breachpilot/internal/exploit/modules/uploadabuse"
	"breachpilot/internal/ingest"
	"breachpilot/internal/models"
	"breachpilot/internal/policy"
	"breachpilot/internal/scope"
	riskscoring "breachpilot/internal/scoring"
	"github.com/google/shlex"
)

const (
	ErrTimeout      = "timeout"
	ErrInvalidInput = "invalid-input"
	ErrToolMissing  = "tool-missing"
	ErrNetwork      = "network-blocked"
	ErrParse        = "parse-failed"
	ErrExecution    = "execution-failed"
)

type Options struct {
	NucleiBin                  string
	ReconHarvestCmd            string
	ReconWebhookURL            string
	ReconTimeoutSec            int
	ReconRetries               int
	NucleiTimeoutSec           int
	ArtifactsRoot              string
	MinSeverity                string
	SkipModules                string
	OnlyModules                string
	ValidationOnly             bool
	Progress                   func(string)
	Events                     func(models.RuntimeEvent)
	Notifier                   Notifier
	PreviousReportPath         string
	ReportFormats              string
	ScanProfile                string
	RateLimitRPS               int
	WebhookFindings            bool
	WebhookModuleProgress      bool
	WebhookFindingsMinSeverity string
	ModuleTimeoutSec           int
	ModuleRetries              int
	AggressiveMode             bool
	ProofMode                  bool
	ProofTargetAllowlist       string
	AuthUserCookie             string
	AuthAdminCookie            string
	AuthAnonHeaders            string
	AuthUserHeaders            string
	AuthAdminHeaders           string
	SSRFCanaryHost             string
	SSRFCanaryRedirect         bool
	OpenRedirectCanaryHost     string
	SkipNuclei                 bool
	ScoringEnabled             bool
	ChainAnalysisEnabled       bool
	ExposureOverride           string
	CriticalityOverride        string
	BrowserCaptureEnabled      bool
	BrowserCaptureMaxPages     int
	BrowserCapturePath         string
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
			if !opt.SkipNuclei {
				opt.SkipNuclei = p.SkipNuclei
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
		setJobError(job, ErrExecution, fmt.Sprintf("state manager init failed: %v", err))
		_ = writeJobReport(job, opt.ArtifactsRoot)
		return err
	}
	if t := strings.TrimSpace(job.Target); t != "" && t != "from-summary" {
		if err := scope.ValidateTarget(t); err != nil {
			job.Status = models.JobFailed
			job.FinishedAt = time.Now().UTC()
			setJobError(job, ErrInvalidInput, fmt.Sprintf("target validation failed: %v", err))
			_ = writeJobReport(job, opt.ArtifactsRoot)
			return nil
		}
	}

	emit := func(ev models.RuntimeEvent) {
		ev.Timestamp = time.Now().UTC()
		if opt.Events != nil {
			opt.Events(ev)
		}
		if opt.Progress != nil && strings.TrimSpace(ev.Message) != "" {
			opt.Progress(ev.Message)
		}
	}
	notify := func(s string) {
		stage, status := classifyProgressMessage(s)
		emit(models.RuntimeEvent{
			Kind:    "stage",
			Stage:   stage,
			Status:  status,
			Message: s,
			Target:  job.Target,
		})
	}

	if strings.EqualFold(strings.TrimSpace(job.Mode), "full") {
		if sm.IsReconCompleted() {
			notify("recon.resumed")
			st := sm.State()
			if st.ReconPath != "" {
				job.ReconPath = st.ReconPath
			} else {
				// Fallback if not persisted (for older states)
				job.ReconPath = filepath.Join(opt.ArtifactsRoot, job.ID, "recon", "summary.json")
				if _, err := os.Stat(job.ReconPath); err != nil {
					job.ReconPath = filepath.Join(opt.ArtifactsRoot, job.ID, "summary.json")
				}
			}
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
			_ = sm.MarkReconCompleted(summaryPath)
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
			setJobError(job, ErrInvalidInput, fmt.Sprintf("target validation failed: %v", err))
			_ = writeJobReport(job, opt.ArtifactsRoot)
			return nil
		}
	}

	_ = writeRuntimeConfigSnapshot(job, opt)

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
			setJobError(job, ErrInvalidInput, "intrusive templates are blocked in safe_mode")
			job.PlanPreview = plan
			_ = writeJobReport(job, opt.ArtifactsRoot)
			return nil
		}
	} else {
		// When aggressive mode is active (passed via CLI), auto-approve intrusive mode.
		// This removes the friction of setting approve_intrusive=true and approval_ticket manually.
		if opt.AggressiveMode {
			job.ApproveIntrusive = true
		}
		if !job.ApproveIntrusive {
			job.Status = models.JobRejected
			job.FinishedAt = time.Now().UTC()
			setJobError(job, ErrInvalidInput, "intrusive mode requested without approve_intrusive=true")
			job.PlanPreview = plan
			_ = writeJobReport(job, opt.ArtifactsRoot)
			return nil
		}
		if !opt.AggressiveMode && strings.TrimSpace(job.ApprovalTicket) == "" {
			job.Status = models.JobRejected
			job.FinishedAt = time.Now().UTC()
			setJobError(job, ErrInvalidInput, "approval_ticket missing for intrusive mode")
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
		emit(models.RuntimeEvent{
			Kind:    "stage",
			Stage:   "exploit.targeting",
			Status:  "info",
			Message: fmt.Sprintf("exploit.targeting using ranked endpoints: %d", rankedCount),
			Target:  job.Target,
			Counts:  map[string]int{"ranked_endpoints": rankedCount},
		})
	}

	args := []string{"-l", nucleiInput, "-jsonl", "-o", outJSONL, "-silent", "-no-color", "-stats", "-timeout", "5"}
	if strings.Contains(job.Target, "localhost") || strings.Contains(job.Target, "127.0.0.1") {
		args = append(args, "-concurrency", "10")
	}
	if len(job.Templates) > 0 {
		args = append(args, "-t", strings.Join(job.Templates, ","))
	} else if job.SafeMode {
		args = append(args, "-tags", "misconfig,exposure,tech")
	} else {
		args = append(args, "-severity", "medium,high,critical")
	}

	stOut, errOut := os.Stat(outJSONL)
	if opt.SkipNuclei {
		notify("exploit.nuclei.skipped")
	} else if sm.IsNucleiCompleted() && errOut == nil && stOut.Size() > 0 {
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
		nucleiPW := &progressWriter{stage: "exploit.log", target: job.Target, cb: opt.Progress, eventCB: opt.Events}
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
				setJobError(job, "cancelled", "job cancelled")
				_ = writeJobReport(job, opt.ArtifactsRoot)
				return nil
			}
			if nucleiCtx.Err() == context.DeadlineExceeded {
				job.Status = models.JobFailed
				job.FinishedAt = time.Now().UTC()
				setJobError(job, ErrTimeout, "nuclei timeout exceeded")
				_ = writeJobReport(job, opt.ArtifactsRoot)
				return nil
			}
			st, statErr := os.Stat(outJSONL)
			if statErr != nil || st.Size() == 0 {
				_ = writeJobReport(job, opt.ArtifactsRoot)
				return fmt.Errorf("nuclei execution failed: %w", nucleiErr)
			}
			emit(models.RuntimeEvent{
				Kind:    "stage",
				Stage:   "exploit",
				Status:  "warning",
				Message: "exploit.warning nuclei exited non-zero with partial results; continuing",
				Target:  job.Target,
			})
			setJobError(job, ErrExecution, fmt.Sprintf("nuclei exited non-zero; partial results accepted: %v", nucleiErr))
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
	exploitModules = prioritizeModules(exploitModules, rs)
	names := make([]string, 0, len(exploitModules))
	for _, m := range exploitModules {
		names = append(names, m.Name())
	}
	emit(models.RuntimeEvent{
		Kind:    "module",
		Stage:   "exploit.module",
		Status:  "planned",
		Message: "exploit.module.order " + strings.Join(names, ","),
		Target:  job.Target,
		Counts:  map[string]int{"planned": len(names)},
	})
	exploitFindings, telemetry := exploit.RunModules(ctx, job, &rs, exploit.Options{
		ArtifactsRoot:          opt.ArtifactsRoot,
		Progress:               opt.Progress,
		Events:                 opt.Events,
		SafeMode:               job.SafeMode,
		MaxParallel:            0,
		StateManager:           sm,
		ModuleTimeoutSec:       opt.ModuleTimeoutSec,
		ModuleRetries:          opt.ModuleRetries,
		Aggressive:             opt.AggressiveMode,
		ProofMode:              opt.ProofMode,
		ProofTargetAllowlist:   opt.ProofTargetAllowlist,
		AuthUserCookie:         opt.AuthUserCookie,
		AuthAdminCookie:        opt.AuthAdminCookie,
		AuthAnonHeaders:        opt.AuthAnonHeaders,
		AuthUserHeaders:        opt.AuthUserHeaders,
		AuthAdminHeaders:       opt.AuthAdminHeaders,
		SSRFCanaryHost:         opt.SSRFCanaryHost,
		SSRFCanaryRedirect:     opt.SSRFCanaryRedirect,
		OpenRedirectCanaryHost: opt.OpenRedirectCanaryHost,
		ScoringEnabled:         opt.ScoringEnabled,
		ChainAnalysisEnabled:   opt.ChainAnalysisEnabled,
		ExposureOverride:       opt.ExposureOverride,
		CriticalityOverride:    opt.CriticalityOverride,
		BrowserCaptureEnabled:  opt.BrowserCaptureEnabled,
		BrowserCaptureMaxPages: opt.BrowserCaptureMaxPages,
		BrowserCapturePath:     opt.BrowserCapturePath,
	}, exploitModules)
	job.ModuleTelemetry = telemetry
	if ctx.Err() == context.Canceled {
		job.Status = models.JobCancelled
		job.FinishedAt = time.Now().UTC()
		setJobError(job, "cancelled", "job cancelled")
		_ = writeJobReport(job, opt.ArtifactsRoot)
		return nil
	}
	preFilterCount := len(exploitFindings)
	exploitFindings = filter.BySeverity(exploitFindings, opt.MinSeverity)
	job.FilteredCount = preFilterCount - len(exploitFindings)

	// --- scoring pass ---
	if opt.ScoringEnabled {
		// 1. Infer target-level exposure and criticality
		meta := riskscoring.TargetMeta{
			Hostname:         job.Target,
			ResolvedIP:       "", // Would need to resolve or get from rs
			IsInternetFacing: true,
			BehindCDN:        false,
		}

		exposure := riskscoring.InferExposure(meta)
		if opt.ExposureOverride != "" {
			exposure = riskscoring.ExposureLevel(opt.ExposureOverride)
		}

		criticality := riskscoring.InferCriticality(meta)
		if opt.CriticalityOverride != "" {
			criticality = riskscoring.CriticalityLevel(opt.CriticalityOverride)
		}

		// 2. Build FindingMeta slice for chain analysis
		findingMetas := make([]riskscoring.FindingMeta, len(exploitFindings))
		for i, f := range exploitFindings {
			findingMetas[i] = riskscoring.FindingMeta{
				ID:     fmt.Sprintf("%s-%d", f.Module, i),
				Module: f.Module,
				URL:    f.Target,
			}
		}

		// 3. Run chain analysis
		chainBonusMap := make(map[string]float64)
		chainRefsMap := make(map[string][]riskscoring.ChainRef)
		var allChains []riskscoring.ChainRef

		if opt.ChainAnalysisEnabled {
			chainAnalysis := riskscoring.AnalyzeChains(findingMetas)
			for id, ca := range chainAnalysis {
				chainBonusMap[id] = ca.Bonus
				chainRefsMap[id] = ca.Chains
				allChains = append(allChains, ca.Chains...)
			}
		}

		// 4. Score each finding
		var scoredFindings []riskscoring.ScoredFinding
		for i := range exploitFindings {
			f := &exploitFindings[i]
			id := findingMetas[i].ID
			bonus := chainBonusMap[id]
			chains := chainRefsMap[id]

			input := riskscoring.ScoreInput{
				FindingID:   id,
				Module:      f.Module,
				URL:         f.Target,
				RawSeverity: f.Severity,
				Exposure:    exposure,
				Criticality: criticality,
				ChainBonus:  bonus,
			}
			input = riskscoring.ApplyFindingOverrides(input, f.Title, f.Validation)

			rsScore := riskscoring.Score(input)
			rsScore.Chains = chains
			f.RiskScore = rsScore

			scoredFindings = append(scoredFindings, riskscoring.ScoredFinding{
				ID:     id,
				Title:  f.Title,
				Module: f.Module,
				URL:    f.Target,
				Score:  rsScore,
			})
		}

		// 5. Build scan-level summary
		job.RiskSummary = riskscoring.BuildSummary(scoredFindings, exposure, criticality, allChains)
		job.RiskScore = job.RiskSummary.OverallScore
	}

	reliableFindings, reliabilityFiltered := exploit.FilterReliableFindings(exploitFindings)
	exploitFindings = reliableFindings
	job.FilteredCount += reliabilityFiltered

	if opt.ScoringEnabled {
		meta := riskscoring.TargetMeta{
			Hostname:         job.Target,
			ResolvedIP:       "",
			IsInternetFacing: true,
			BehindCDN:        false,
		}
		exposure := riskscoring.InferExposure(meta)
		if opt.ExposureOverride != "" {
			exposure = riskscoring.ExposureLevel(opt.ExposureOverride)
		}
		criticality := riskscoring.InferCriticality(meta)
		if opt.CriticalityOverride != "" {
			criticality = riskscoring.CriticalityLevel(opt.CriticalityOverride)
		}

		scoredFindings := make([]riskscoring.ScoredFinding, 0, len(exploitFindings))
		var allChains []riskscoring.ChainRef
		for i, f := range exploitFindings {
			id := fmt.Sprintf("%s-%d", f.Module, i)
			scoredFindings = append(scoredFindings, riskscoring.ScoredFinding{
				ID:     id,
				Title:  f.Title,
				Module: f.Module,
				URL:    f.Target,
				Score:  f.RiskScore,
			})
			allChains = append(allChains, f.RiskScore.Chains...)
		}
		job.RiskSummary = riskscoring.BuildSummary(scoredFindings, exposure, criticality, allChains)
		job.RiskScore = job.RiskSummary.OverallScore
	}

	emit(models.RuntimeEvent{
		Kind:    "summary",
		Stage:   "exploit",
		Status:  "completed",
		Message: fmt.Sprintf("exploit.summary nuclei=%d exploit=%d filtered=%d", job.FindingsCount, len(exploitFindings), job.FilteredCount),
		Target:  job.Target,
		Counts: map[string]int{
			"nuclei":   job.FindingsCount,
			"exploit":  len(exploitFindings),
			"filtered": job.FilteredCount,
		},
	})

	if opt.Notifier != nil {
		severityCounts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
		topFindings := make([]map[string]any, 0, 5)
		for _, f := range exploitFindings {
			sev := strings.ToUpper(strings.TrimSpace(f.Severity))
			if band := strings.ToUpper(strings.TrimSpace(string(f.RiskScore.Band))); band != "" {
				sev = band
			}
			if _, ok := severityCounts[sev]; ok {
				severityCounts[sev]++
			}
			if len(topFindings) < 5 && (sev == "CRITICAL" || sev == "HIGH") {
				topFindings = append(topFindings, map[string]any{"severity": sev, "title": f.Title, "module": f.Module, "target": f.Target})
			}
		}

		opt.Notifier.SendGeneric("exploit.modules.completed", map[string]any{
			"job_id":          job.ID,
			"target":          job.Target,
			"findings_count":  len(exploitFindings),
			"filtered_count":  job.FilteredCount,
			"risk_score":      job.RiskScore,
			"module_count":    len(exploitModules),
			"duration_sec":    job.ExploitDurationSec,
			"severity_counts": severityCounts,
			"top_findings":    topFindings,
		})

		if opt.WebhookFindings {
			batchCounts := map[string]int{"INFO": 0, "LOW": 0, "MEDIUM": 0}
			batchSample := make([]map[string]any, 0, 5)
			for _, f := range exploitFindings {
				sevForFilter := f.Severity
				if band := strings.ToUpper(strings.TrimSpace(string(f.RiskScore.Band))); band != "" {
					sevForFilter = band
				}
				if !severityAtLeast(sevForFilter, opt.WebhookFindingsMinSeverity) {
					continue
				}
				sev := strings.ToUpper(strings.TrimSpace(sevForFilter))
				if sev == "CRITICAL" || sev == "HIGH" {
					opt.Notifier.SendGeneric("exploit.finding", map[string]any{
						"job_id":      job.ID,
						"target":      f.Target,
						"module":      f.Module,
						"severity":    sev,
						"title":       f.Title,
						"confidence":  f.Confidence,
						"validation":  f.Validation,
						"evidence":    f.Evidence,
						"report_path": job.ExploitReportPath,
					})
					continue
				}
				if _, ok := batchCounts[sev]; ok {
					batchCounts[sev]++
					if len(batchSample) < 5 {
						batchSample = append(batchSample, map[string]any{"severity": sev, "title": f.Title, "module": f.Module, "target": f.Target})
					}
				}
			}
			if batchCounts["INFO"]+batchCounts["LOW"]+batchCounts["MEDIUM"] > 0 {
				opt.Notifier.SendGeneric("exploit.findings.batch", map[string]any{
					"job_id":  job.ID,
					"target":  job.Target,
					"counts":  batchCounts,
					"sample":  batchSample,
					"min_sev": opt.WebhookFindingsMinSeverity,
					"note":    "low-priority findings aggregated",
				})
			}
		}
	}

	if err := writeExploitFindingsJSONL(exploitFindings, artDir, job); err != nil {
		job.Status = models.JobFailed
		job.FinishedAt = time.Now().UTC()
		setJobError(job, ErrExecution, err.Error())
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
		setJobError(job, ErrExecution, fmt.Sprintf("write exploit report: %v", rpErr))
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
		setJobError(job, ErrExecution, fmt.Sprintf("write job report: %v", err))
		return err
	}
	_ = writeArtifactManifest(job, opt.ArtifactsRoot)
	_ = writePerformanceBaseline(job, opt.ArtifactsRoot)
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
		if opt.Events != nil {
			opt.Events(models.RuntimeEvent{
				Kind:      "stage",
				Stage:     "recon",
				Status:    "resumed",
				Message:   "recon.resume existing summary found; skipping recon rerun",
				Target:    job.Target,
				Timestamp: time.Now().UTC(),
			})
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
			// Pass --resume <workdir> so reconHarvest picks up its existing state.
			// Do NOT pass -o or the target positional arg; reconHarvest derives both
			// from workspace_meta.json when --resume is used.
			argv = append(argv, "--run", "--resume", reconDir,
				"--skip-nuclei", "--arjun-threads", "20", "--vhost-threads", "80")
		} else {
			argv = append(argv, job.Target, "--run", "-o", reconDir, "--overwrite",
				"--skip-nuclei", "--arjun-threads", "20", "--vhost-threads", "80")
		}
		cmd := exec.CommandContext(reconCtx, argv[0], argv[1:]...)
		if opt.ReconWebhookURL != "" {
			cmd.Env = append(os.Environ(), "RECONHARVEST_WEBHOOK="+opt.ReconWebhookURL)
		}
		pw := &progressWriter{stage: "recon.log", target: job.Target, cb: opt.Progress, eventCB: opt.Events}
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
			setJobError(job, "cancelled", "job cancelled during recon phase")
			return "", nil
		}
		if reconCtx.Err() == context.DeadlineExceeded {
			job.Status = models.JobFailed
			job.FinishedAt = time.Now().UTC()
			setJobError(job, ErrTimeout, "recon timeout exceeded")
			return "", nil
		}
		msg := fmt.Sprintf("recon.retry attempt=%d/%d", attempt, attempts)
		if opt.Events != nil {
			opt.Events(models.RuntimeEvent{
				Kind:      "stage",
				Stage:     "recon",
				Status:    "warning",
				Message:   msg,
				Target:    job.Target,
				Timestamp: time.Now().UTC(),
				Counts:    map[string]int{"attempt": attempt, "attempts": attempts},
			})
		}
		if opt.Progress != nil {
			opt.Progress(msg)
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
	stage   string
	target  string
	cb      func(string)
	eventCB func(models.RuntimeEvent)
	buf     []byte
}

func (w *progressWriter) Write(p []byte) (int, error) {
	if w.cb == nil && w.eventCB == nil {
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
			msg := fmt.Sprintf("%s %s", w.stage, line)
			if w.cb != nil {
				w.cb(msg)
			}
			if w.eventCB != nil {
				w.eventCB(models.RuntimeEvent{
					Kind:      "log",
					Stage:     w.stage,
					Status:    "info",
					Message:   msg,
					Target:    w.target,
					Timestamp: time.Now().UTC(),
				})
			}
		}
	}
	return len(p), nil
}

// Flush emits any remaining partial line still in the buffer.
func (w *progressWriter) Flush() {
	if (w.cb == nil && w.eventCB == nil) || len(w.buf) == 0 {
		return
	}
	line := strings.TrimSpace(string(w.buf))
	w.buf = nil
	if line != "" {
		msg := fmt.Sprintf("%s %s", w.stage, line)
		if w.cb != nil {
			w.cb(msg)
		}
		if w.eventCB != nil {
			w.eventCB(models.RuntimeEvent{
				Kind:      "log",
				Stage:     w.stage,
				Status:    "info",
				Message:   msg,
				Target:    w.target,
				Timestamp: time.Now().UTC(),
			})
		}
	}
}

func classifyProgressMessage(s string) (string, string) {
	s = strings.TrimSpace(s)
	stage := s
	if idx := strings.IndexAny(s, " :"); idx > 0 {
		stage = strings.TrimSpace(s[:idx])
	}
	status := "info"
	switch {
	case strings.Contains(s, ".start") || strings.HasSuffix(s, "started"):
		status = "started"
	case strings.Contains(s, ".done") || strings.HasSuffix(s, "completed"):
		status = "completed"
	case strings.Contains(s, "warning") || strings.Contains(s, "retry"):
		status = "warning"
	case strings.Contains(s, "error") || strings.Contains(s, "failed") || strings.Contains(s, "cancel"):
		status = "error"
	case strings.Contains(s, "resume"):
		status = "resumed"
	}
	return stage, status
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
	// Basic validation to ensure this is a recon summary and not a state file
	if _, ok := raw["workdir"]; !ok {
		if _, isState := raw["job_id"]; isState {
			return rs, fmt.Errorf("invalid recon summary: file appears to be a .breachpilot.state file (expected summary.json)")
		}
		return rs, fmt.Errorf("invalid recon summary: missing 'workdir' field")
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
		normalizedRT := scope.NormalizeTargetForDir(rt)
		if tgt := ingest.TargetFromWorkdir(rs.Workdir); tgt != "" && strings.Contains(tgt, ".") && !strings.EqualFold(tgt, normalizedRT) {
			return rs, fmt.Errorf("resume target mismatch: summary=%s requested=%s (normalized=%s)", tgt, rt, normalizedRT)
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
		{"session-abuse", "Detects risky session/token handling surfaces", true},
		{"privilege-path", "Maps probable privilege escalation endpoint paths", true},
		{"graphql-abuse", "Detects GraphQL abuse opportunities and exposed consoles", true},
		{"state-change", "Detects risky state-changing endpoint patterns", true},
		{"upload-abuse", "Detects upload attack surface and retrieval risks", true},
		{"auth-bypass", "Executes auth bypass chain checks across risky surfaces", true},
		{"mutation-engine", "Runs aggressive mutation probes (method/header/param/content-type)", true},
		{"idor-playbook", "Runs deterministic IDOR privilege hopping playbook", true},
		{"jwt-access", "Detects JWT-specific vulnerabilities (none alg, header injection)", true},
		{"ssrf-prober", "Detects SSRF via parameters, headers, and bodies", true},
		{"crlf-injection", "Detects CRLF injection in headers/params", true},
		{"saml-probe", "Detects SAML/SSO vulnerabilities and misconfigurations", true},
		{"rsql-injection", "Detects RSQL/FIQL-style injection in parameters", true},
		{"idor-size", "Response size-based IDOR detection", true},
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
		sessionabuse.New(),
		privpath.New(),
		graphqlabuse.New(),
		statechange.New(),
		uploadabuse.New(),
		authbypass.New(),
		mutationengine.New(),
		idorplaybook.New(),
		jwtaccess.New(),
		advancedinjection.New(),
		ssrfprober.New(),
		crlfinjection.New(),
		samlprobe.New(),
		rsqlinjection.New(),
		idorsize.New(),
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

func prioritizeModules(mods []exploit.Module, rs models.ReconSummary) []exploit.Module {
	if len(mods) <= 1 {
		return mods
	}
	// Lower score executes earlier.
	score := map[string]int{}
	for _, m := range mods {
		score[strings.ToLower(m.Name())] = 100
	}
	// Push high-value Phase 13 modules earlier when relevant intel exists.
	if strings.TrimSpace(rs.Intel.EndpointsRankedJSON) != "" {
		score["privilege-path"] = 20
		score["session-abuse"] = 25
		score["open-redirect"] = 23
	}
	if strings.TrimSpace(rs.URLs.All) != "" {
		score["graphql-abuse"] = 22
		score["auth-bypass"] = 26
		score["crlf-injection"] = 30
		score["ssrf-prober"] = 35
		score["rsql-injection"] = 40
	}
	if strings.Contains(strings.ToLower(rs.Live), "saml") || strings.Contains(strings.ToLower(rs.Live), "sso") {
		score["saml-probe"] = 15
	}
	// keep broad context modules early too.
	score["api-surface"] = 18
	score["admin-surface"] = 24

	out := make([]exploit.Module, len(mods))
	copy(out, mods)
	sort.SliceStable(out, func(i, j int) bool {
		a := score[strings.ToLower(out[i].Name())]
		b := score[strings.ToLower(out[j].Name())]
		if a != b {
			return a < b
		}
		return out[i].Name() < out[j].Name()
	})
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

func writeRuntimeConfigSnapshot(job *models.Job, opt Options) error {
	if job == nil || strings.TrimSpace(opt.ArtifactsRoot) == "" {
		return nil
	}
	path := filepath.Join(opt.ArtifactsRoot, job.ID, "runtime_config.json")
	payload := map[string]any{
		"schema_version": models.SchemaVersion,
		"saved_at":       time.Now().UTC().Format(time.RFC3339),
		"job_id":         job.ID,
		"target":         job.Target,
		"mode":           job.Mode,
		"config": map[string]any{
			"scan_profile":                  opt.ScanProfile,
			"min_severity":                  opt.MinSeverity,
			"skip_modules":                  opt.SkipModules,
			"only_modules":                  opt.OnlyModules,
			"validation_only":               opt.ValidationOnly,
			"report_formats":                opt.ReportFormats,
			"rate_limit_rps":                opt.RateLimitRPS,
			"webhook_findings":              opt.WebhookFindings,
			"webhook_module_progress":       opt.WebhookModuleProgress,
			"webhook_findings_min_severity": opt.WebhookFindingsMinSeverity,
		},
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, b, 0o644)
}

func setJobError(job *models.Job, code string, msg string) {
	if job == nil {
		return
	}
	job.ErrorCode = strings.TrimSpace(code)
	job.Error = strings.TrimSpace(msg)
}

func writeArtifactManifest(job *models.Job, artifactsRoot string) error {
	if job == nil {
		return nil
	}
	base := filepath.Join(artifactsRoot, job.ID)
	files := []string{job.ReconPath, job.ExploitFindingsPath, job.ExploitReportPath, job.ExploitHTMLReportPath, job.ReportPath, filepath.Join(base, "nuclei_findings.jsonl")}
	entries := make([]map[string]any, 0, len(files))
	for _, f := range files {
		p := strings.TrimSpace(f)
		if p == "" {
			continue
		}
		h, sz, err := fileHash(p)
		if err != nil {
			continue
		}
		entries = append(entries, map[string]any{"path": p, "sha256": h, "size": sz})
	}
	payload := map[string]any{"job_id": job.ID, "created_at": time.Now().UTC().Format(time.RFC3339), "files": entries}
	b, _ := json.MarshalIndent(payload, "", "  ")
	return atomicWriteFile(filepath.Join(base, "artifact_manifest.json"), b, 0o644)
}

func writePerformanceBaseline(job *models.Job, artifactsRoot string) error {
	if job == nil {
		return nil
	}
	payload := map[string]any{
		"job_id":               job.ID,
		"target":               job.Target,
		"created_at":           time.Now().UTC().Format(time.RFC3339),
		"recon_duration_sec":   job.ReconDurationSec,
		"exploit_duration_sec": job.ExploitDurationSec,
		"module_telemetry":     job.ModuleTelemetry,
	}
	b, _ := json.MarshalIndent(payload, "", "  ")
	return atomicWriteFile(filepath.Join(artifactsRoot, job.ID, "performance_baseline.json"), b, 0o644)
}

func fileHash(path string) (string, int64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", 0, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), st.Size(), nil
}

func severityAtLeast(sev, min string) bool {
	rank := map[string]int{"": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
	s := strings.ToUpper(strings.TrimSpace(sev))
	m := strings.ToUpper(strings.TrimSpace(min))
	return rank[s] >= rank[m]
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
