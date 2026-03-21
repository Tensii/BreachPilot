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
	massassign "breachpilot/internal/exploit/modules/massassign"
	mutationengine "breachpilot/internal/exploit/modules/mutationengine"
	nucleitriage "breachpilot/internal/exploit/modules/nucleitriage"
	openredirect "breachpilot/internal/exploit/modules/openredirect"
	portservice "breachpilot/internal/exploit/modules/portservice"
	privpath "breachpilot/internal/exploit/modules/privpath"
	racecondition "breachpilot/internal/exploit/modules/racecondition"
	rsqlinjection "breachpilot/internal/exploit/modules/rsqlinjection"
	samlprobe "breachpilot/internal/exploit/modules/samlprobe"
	schemaprobe "breachpilot/internal/exploit/modules/schemaprobe"
	secretsvalidator "breachpilot/internal/exploit/modules/secretsvalidator"
	sessionabuse "breachpilot/internal/exploit/modules/sessionabuse"
	ssrfprober "breachpilot/internal/exploit/modules/ssrfprober"
	statechange "breachpilot/internal/exploit/modules/statechange"
	subt "breachpilot/internal/exploit/modules/subt"
	tlsaudit "breachpilot/internal/exploit/modules/tlsaudit"
	uploadabuse "breachpilot/internal/exploit/modules/uploadabuse"
	oob "breachpilot/internal/exploit/oob"
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
	NucleiBin                      string
	ReconHarvestCmd                string
	ReconWebhookURL                string
	ReconTimeoutSec                int
	ReconRetries                   int
	NucleiTimeoutSec               int
	ArtifactsRoot                  string
	MinSeverity                    string
	SkipModules                    string
	OnlyModules                    string
	ValidationOnly                 bool
	Progress                       func(string)
	Events                         func(models.RuntimeEvent)
	Notifier                       Notifier
	PreviousReportPath             string
	ReportFormats                  string
	ScanProfile                    string
	RateLimitRPS                   int
	WebhookFindings                bool
	WebhookModuleProgress          bool
	WebhookFindingsMinSeverity     string
	ModuleTimeoutSec               int
	ModuleRetries                  int
	AggressiveMode                 bool
	ProofMode                      bool
	ProofTargetAllowlist           string
	AuthUserCookie                 string
	AuthAdminCookie                string
	AuthAnonHeaders                string
	AuthUserHeaders                string
	AuthAdminHeaders               string
	SSRFCanaryHost                 string
	SSRFCanaryRedirect             bool
	OpenRedirectCanaryHost         string
	SkipNuclei                     bool
	ScoringEnabled                 bool
	ChainAnalysisEnabled           bool
	ExposureOverride               string
	CriticalityOverride            string
	BrowserCaptureEnabled          bool
	BrowserCaptureMaxPages         int
	BrowserCapturePerPageWaitMs    int
	BrowserCaptureSettleWaitMs     int
	BrowserCaptureScrollSteps      int
	BrowserCaptureMaxRoutesPerPage int
	BrowserCapturePath             string
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
	exploitModules := filterModules(selectedModuleInstances(opt), opt.OnlyModules, opt.SkipModules)
	if opt.ValidationOnly {
		exploitModules = filterValidationOnly(exploitModules)
	}
	exploitModules, plannerSkipped, plannerPreview := planExploitModules(exploitModules, rs, opt)
	job.PlanPreview = append(job.PlanPreview, plannerPreview...)
	scoutModules, proofModules := splitModulesByPlannerStage(exploitModules)
	persistedSignals := loadCorrelationSignalsArtifact(artDir)
	scoutModules = prioritizeModules(scoutModules, rs)
	scoutNames := moduleNames(scoutModules)
	emit(models.RuntimeEvent{
		Kind:    "module",
		Stage:   "exploit.module",
		Status:  "planned",
		Message: "exploit.module.wave1 " + strings.Join(scoutNames, ","),
		Target:  job.Target,
		Counts:  map[string]int{"planned": len(scoutModules)},
	})

	// Initialize OOB Provider
	var oobProvider oob.Provider
	if opt.AggressiveMode {
		if p, err := oob.NewInteractshProvider(); err == nil {
			oobProvider = p
			defer p.Close()
		}
	}

	sharedState := exploit.NewSharedState()
	exploitOpt := exploit.Options{
		ArtifactsRoot:                  opt.ArtifactsRoot,
		Progress:                       opt.Progress,
		Events:                         opt.Events,
		SafeMode:                       job.SafeMode,
		MaxParallel:                    0,
		StateManager:                   sm,
		ModuleTimeoutSec:               opt.ModuleTimeoutSec,
		ModuleRetries:                  opt.ModuleRetries,
		Aggressive:                     opt.AggressiveMode,
		ProofMode:                      opt.ProofMode,
		ProofTargetAllowlist:           opt.ProofTargetAllowlist,
		AuthUserCookie:                 opt.AuthUserCookie,
		AuthAdminCookie:                opt.AuthAdminCookie,
		AuthAnonHeaders:                opt.AuthAnonHeaders,
		AuthUserHeaders:                opt.AuthUserHeaders,
		AuthAdminHeaders:               opt.AuthAdminHeaders,
		SSRFCanaryHost:                 opt.SSRFCanaryHost,
		SSRFCanaryRedirect:             opt.SSRFCanaryRedirect,
		OpenRedirectCanaryHost:         opt.OpenRedirectCanaryHost,
		ScoringEnabled:                 opt.ScoringEnabled,
		ChainAnalysisEnabled:           opt.ChainAnalysisEnabled,
		ExposureOverride:               opt.ExposureOverride,
		CriticalityOverride:            opt.CriticalityOverride,
		BrowserCaptureEnabled:          opt.BrowserCaptureEnabled,
		BrowserCaptureMaxPages:         opt.BrowserCaptureMaxPages,
		BrowserCapturePerPageWaitMs:    opt.BrowserCapturePerPageWaitMs,
		BrowserCaptureSettleWaitMs:     opt.BrowserCaptureSettleWaitMs,
		BrowserCaptureScrollSteps:      opt.BrowserCaptureScrollSteps,
		BrowserCaptureMaxRoutesPerPage: opt.BrowserCaptureMaxRoutesPerPage,
		BrowserCapturePath:             opt.BrowserCapturePath,
		SharedState:                    sharedState,
		OOBProvider:                    oobProvider,
	}
	scoutFindings, scoutTelemetry := exploit.RunModules(ctx, job, &rs, exploitOpt, scoutModules)
	scoutSignals := buildCorrelationSignals(scoutFindings)
	mergedSignals := mergeCorrelationSignals(persistedSignals, scoutSignals)
	_ = saveCorrelationSignalsArtifact(artDir, mergedSignals)
	correlatedProofModules, correlationSkipped, correlationPreview := correlateProofModules(proofModules, mergedSignals, rs, opt)
	job.PlanPreview = append(job.PlanPreview, correlationPreview...)
	correlatedProofModules = prioritizeProofModules(correlatedProofModules, mergedSignals, rs)
	proofNames := moduleNames(correlatedProofModules)
	if len(proofNames) > 0 {
		emit(models.RuntimeEvent{
			Kind:    "module",
			Stage:   "exploit.module",
			Status:  "planned",
			Message: "exploit.module.wave2 " + strings.Join(proofNames, ","),
			Target:  job.Target,
			Counts:  map[string]int{"planned": len(correlatedProofModules)},
		})
	}
	proofFindings, proofTelemetry := exploit.RunModules(ctx, job, &rs, exploitOpt, correlatedProofModules)
	exploitFindings := append(scoutFindings, proofFindings...)
	telemetry := append(scoutTelemetry, proofTelemetry...)
	job.ModuleTelemetry = append(append(telemetry, plannerSkipped...), correlationSkipped...)
	if ctx.Err() == context.Canceled {
		job.Status = models.JobCancelled
		job.FinishedAt = time.Now().UTC()
		setJobError(job, "cancelled", "job cancelled")
		_ = writeJobReport(job, opt.ArtifactsRoot)
		return nil
	}
	rawExploitFindings := append([]models.ExploitFinding(nil), exploitFindings...)

	// --- OOB Verification Phase ---
	if oobProvider != nil && ctx.Err() == nil {
		emit(models.RuntimeEvent{
			Kind:    "oob",
			Stage:   "exploit.oob.verify",
			Status:  "polling",
			Message: "Waiting up to 10s for asynchronous OOB callbacks...",
			Target:  job.Target,
		})
		
		// Wait to allow asynchronous payloads (like Blind XSS / Blind RCE) to fire
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
		}

		if hits, err := oobProvider.Poll(ctx); err == nil && len(hits) > 0 {
			emit(models.RuntimeEvent{
				Kind:    "oob",
				Stage:   "exploit.oob.verify",
				Status:  "hits",
				Message: fmt.Sprintf("Received %d OOB interaction(s)", len(hits)),
				Target:  job.Target,
				Counts:  map[string]int{"oob_hits": len(hits)},
			})

			for _, hit := range hits {
				// We expect correlation metadata to be formatted as: module-uuid
				parts := strings.SplitN(hit.CorrelationMeta, "-", 2)
				moduleName := "oob-listener"
				if len(parts) == 2 {
					moduleName = parts[0]
				}

				title := fmt.Sprintf("Out-Of-Band %s Interaction Received", strings.ToUpper(hit.Protocol))
				evidence := fmt.Sprintf("protocol=%s source_ip=%s correlation_id=%s timestamp=%s", 
					hit.Protocol, hit.SourceIP, hit.CorrelationMeta, hit.Timestamp.Format(time.RFC3339))
				
				// Create an artifact for the raw request
				artifactPath := ""
				if hit.RawRequest != "" && job != nil {
					ap, err := exploit.SaveValidationArtifact(opt.ArtifactsRoot, job.ID, moduleName,
						"oob_"+exploit.SafeArtifactName(hit.CorrelationMeta),
						job.Target, "confirmed", title,
						nil, nil, "raw_oob_interaction", hit.RawRequest, 0)
					if err == nil {
						artifactPath = ap
					}
				}

				oobFinding := models.ExploitFinding{
					Module:       moduleName,
					Severity:     "CRITICAL",
					Confidence:   100,
					Validation:   "confirmed",
					Target:       job.Target, // We might not know the exact path without more correlation state, but the module knows
					Title:        title,
					Evidence:     evidence,
					ArtifactPath: artifactPath,
					PoCHint:      "Review OOB interaction payload for execution proof",
					Tags:         []string{"oob", "blind-execution", strings.ToLower(hit.Protocol)},
					Timestamp:    exploit.NowISO(),
				}
				
				exploitFindings = append(exploitFindings, oobFinding)
				rawExploitFindings = append(rawExploitFindings, oobFinding)
			}
		}
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
	job.ModuleTelemetry = annotateModuleTelemetryYield(job.ModuleTelemetry, rawExploitFindings, exploitFindings)

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

func annotateModuleTelemetryYield(in []models.ExploitModuleTelemetry, rawFindings []models.ExploitFinding, acceptedFindings []models.ExploitFinding) []models.ExploitModuleTelemetry {
	if len(in) == 0 {
		return in
	}
	rawByModule := countFindingsByModule(rawFindings)
	acceptedByModule := countFindingsByModule(acceptedFindings)
	out := make([]models.ExploitModuleTelemetry, len(in))
	for i, item := range in {
		key := strings.ToLower(strings.TrimSpace(item.Module))
		raw := item.FindingsCount
		if counted := rawByModule[key]; counted > raw {
			raw = counted
		}
		item.FindingsCount = raw
		item.AcceptedCount = acceptedByModule[key]
		if item.AcceptedCount > item.FindingsCount {
			item.AcceptedCount = item.FindingsCount
		}
		item.FilteredCount = item.FindingsCount - item.AcceptedCount
		if item.FilteredCount < 0 {
			item.FilteredCount = 0
		}
		out[i] = item
	}
	return out
}

func countFindingsByModule(findings []models.ExploitFinding) map[string]int {
	out := make(map[string]int, len(findings))
	for _, finding := range findings {
		module := strings.ToLower(strings.TrimSpace(finding.Module))
		if module == "" {
			continue
		}
		out[module]++
	}
	return out
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
	Group        string
}

func registeredModuleInfos() []ModuleInfo {
	return []ModuleInfo{
		{"security-headers", "Detects missing/weak security headers", true, "context"},
		{"open-redirect", "Detects potential open redirect vectors", true, "exploit-core"},
		{"info-disclosure", "Probes common exposed files/endpoints", true, "exploit-core"},
		{"cors-poc", "Validates risky CORS findings", true, "exploit-core"},
		{"secrets-validator", "Validates leaked key/JWT patterns", true, "exploit-core"},
		{"bypass-poc", "Builds PoC from discovered 403 bypasses", true, "exploit-core"},
		{"port-service", "Classifies risky exposed network services", true, "context"},
		{"nuclei-triage", "Triages nuclei phase1 results", true, "exploit-core"},
		{"subdomain-takeover", "Checks takeover signatures", true, "exploit-core"},
		{"api-surface", "Finds exposed API specs/graphql endpoints", true, "context"},
		{"cookie-security", "Checks cookie flag hardening", true, "context"},
		{"http-method-tampering", "Checks dangerous HTTP methods", true, "exploit-core"},
		{"js-endpoints", "Scores JS-discovered endpoint risk", true, "exploit-core"},
		{"admin-surface", "Finds exposed admin/debug surfaces", true, "context"},
		{"exposed-files", "Finds exposed sensitive files/config", true, "exploit-core"},
		{"tls-audit", "Validates TLS certificate and handshake security", true, "context"},
		{"dns-check", "Validates DNS/email security configuration", true, "context"},
		{"csp-audit", "Validates Content Security Policy headers", true, "context"},
		{"http-response", "Detects HTTP response anomalies and information leaks", true, "context"},
		{"session-abuse", "Detects risky session/token handling surfaces", true, "exploit-core"},
		{"privilege-path", "Maps probable privilege escalation endpoint paths", true, "exploit-core"},
		{"graphql-abuse", "Detects GraphQL abuse opportunities and exposed consoles", true, "exploit-core"},
		{"state-change", "Detects risky state-changing endpoint patterns", true, "exploit-core"},
		{"upload-abuse", "Detects upload attack surface and retrieval risks", true, "exploit-core"},
		{"auth-bypass", "Executes auth bypass chain checks across risky surfaces", true, "exploit-core"},
		{"mutation-engine", "Runs aggressive mutation probes (method/header/param/content-type)", true, "exploit-core"},
		{"idor-playbook", "Runs deterministic IDOR privilege hopping playbook", true, "exploit-core"},
		{"jwt-access", "Detects JWT-specific vulnerabilities (none alg, header injection)", true, "exploit-core"},
		{"ssrf-prober", "Detects SSRF via parameters, headers, and bodies", true, "exploit-core"},
		{"crlf-injection", "Detects CRLF injection in headers/params", true, "exploit-core"},
		{"saml-probe", "Detects SAML/SSO vulnerabilities and misconfigurations", true, "exploit-core"},
		{"rsql-injection", "Detects RSQL/FIQL-style injection in parameters", true, "exploit-core"},
		{"idor-size", "Response size-based IDOR detection", true, "exploit-core"},
	}
}

func RegisteredModuleInfos() []ModuleInfo {
	infos := registeredModuleInfos()
	out := make([]ModuleInfo, len(infos))
	copy(out, infos)
	return out
}

func registeredExploitCoreModuleInstances() []exploit.Module {
	return []exploit.Module{
		openredirect.New(),
		infodisclosure.New(),
		cors.New(),
		secretsvalidator.New(),
		bypasspoc.New(),
		nucleitriage.New(),
		subt.New(),
		httpmethods.New(),
		jsendpoints.New(),
		exposedfiles.New(),
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
		massassign.New(),
		schemaprobe.New(),
		racecondition.New(),
	}
}

func registeredContextModuleInstances() []exploit.Module {
	return []exploit.Module{
		headers.New(),
		portservice.New(),
		apisurface.New(),
		cookiesecurity.New(),
		adminsurface.New(),
		tlsaudit.New(),
		dnscheck.New(),
		cspaudit.New(),
		httpresponse.New(),
	}
}

func registeredAllModuleInstances() []exploit.Module {
	all := make([]exploit.Module, 0, len(registeredExploitCoreModuleInstances())+len(registeredContextModuleInstances()))
	all = append(all, registeredContextModuleInstances()...)
	all = append(all, registeredExploitCoreModuleInstances()...)
	return all
}

func selectedModuleInstances(opt Options) []exploit.Module {
	includeContext := opt.ValidationOnly || strings.EqualFold(strings.TrimSpace(opt.ScanProfile), "deep")
	if strings.TrimSpace(opt.OnlyModules) != "" {
		includeContext = true
	}
	if includeContext {
		return registeredAllModuleInstances()
	}
	return registeredExploitCoreModuleInstances()
}

func planExploitModules(mods []exploit.Module, rs models.ReconSummary, opt Options) ([]exploit.Module, []models.ExploitModuleTelemetry, []string) {
	if len(mods) == 0 {
		return nil, nil, nil
	}
	planned := make([]exploit.Module, 0, len(mods))
	skipped := make([]models.ExploitModuleTelemetry, 0, len(mods))
	preview := make([]string, 0, len(mods)+1)
	preview = append(preview, fmt.Sprintf("Exploit planner evaluating %d module(s) against recon/auth prerequisites", len(mods)))
	now := time.Now().UTC().Format(time.RFC3339)
	for _, m := range mods {
		ready, reason := moduleReadyForExecution(strings.ToLower(strings.TrimSpace(m.Name())), rs, opt)
		if ready {
			planned = append(planned, m)
			preview = append(preview, fmt.Sprintf("Planner selected %s: %s", m.Name(), reason))
			continue
		}
		skipped = append(skipped, models.ExploitModuleTelemetry{
			Module:        m.Name(),
			StartedAt:     now,
			FinishedAt:    now,
			DurationMs:    0,
			FindingsCount: 0,
			ErrorCount:    0,
			Skipped:       true,
			SkippedReason: "planner: " + reason,
		})
		preview = append(preview, fmt.Sprintf("Planner skipped %s: %s", m.Name(), reason))
	}
	if len(preview) > 12 {
		preview = append(preview[:12], fmt.Sprintf("Planner omitted %d additional module decision(s) from preview", len(preview)-12))
	}
	return planned, skipped, preview
}

func moduleReadyForExecution(name string, rs models.ReconSummary, opt Options) (bool, string) {
	hasURLs := strings.TrimSpace(rs.URLs.All) != ""
	hasRankedEndpoints := strings.TrimSpace(rs.Intel.EndpointsRankedJSON) != ""
	hasLiveHosts := strings.TrimSpace(rs.Live) != ""
	hasCORS := strings.TrimSpace(rs.Intel.CORSJSON) != ""
	hasSecrets := strings.TrimSpace(rs.Intel.SecretsJSON) != ""
	hasBypass := strings.TrimSpace(rs.Intel.BypassJSON) != ""
	hasNuclei := strings.TrimSpace(rs.Intel.NucleiPhase1JSONL) != ""
	hasSubT := strings.TrimSpace(rs.Intel.SubdomainTakeoverJSON) != ""
	hasJS := strings.TrimSpace(rs.Intel.JSEndpointsJSON) != ""
	hasUserAuth := strings.TrimSpace(opt.AuthUserCookie) != "" || strings.TrimSpace(opt.AuthUserHeaders) != ""
	hasAdminAuth := strings.TrimSpace(opt.AuthAdminCookie) != "" || strings.TrimSpace(opt.AuthAdminHeaders) != ""
	hasRealAuth := hasUserAuth && hasAdminAuth

	switch name {
	case "open-redirect":
		return hasRankedEndpoints || hasLiveHosts, "redirect candidates available"
	case "info-disclosure", "exposed-files", "http-method-tampering":
		return hasLiveHosts, "live host inventory available"
	case "cors-poc":
		return hasCORS, "CORS intel available"
	case "secrets-validator":
		return hasSecrets, "secret findings available"
	case "bypass-poc":
		return hasBypass, "bypass intel available"
	case "nuclei-triage":
		return hasNuclei, "nuclei phase1 results available"
	case "subdomain-takeover":
		return hasSubT, "subdomain takeover intel available"
	case "js-endpoints":
		return hasJS, "JS endpoint intel available"
	case "session-abuse":
		return hasURLs || hasRankedEndpoints, "session/auth candidates available"
	case "privilege-path", "rsql-injection":
		return hasRankedEndpoints, "ranked endpoint candidates available"
	case "graphql-abuse":
		return hasURLs || hasRankedEndpoints, "GraphQL candidate collection available"
	case "state-change", "upload-abuse", "crlf-injection", "jwt-access":
		return hasURLs, "URL corpus available"
	case "auth-bypass":
		if !opt.AggressiveMode {
			return false, "requires aggressive mode"
		}
		if !hasURLs {
			return false, "requires URL corpus"
		}
		if !hasCORS && !hasRealAuth {
			return false, "requires CORS intel or real auth contexts"
		}
		return true, "auth chain prerequisites available"
	case "mutation-engine", "advanced-injection", "ssrf-prober", "idor-size", "mass-assign":
		if !opt.AggressiveMode {
			return false, "requires aggressive mode"
		}
		if !hasURLs && !hasRankedEndpoints {
			return false, "requires URL or ranked endpoint corpus"
		}
		return true, "aggressive probe corpus available"
	case "schema-probe":
		// Schema probing is passive discovery — only requires live hosts or URL corpus
		if !hasURLs && !hasLiveHosts {
			return false, "requires live hosts or URL corpus"
		}
		return true, "host corpus available for schema discovery"
	case "race-condition":
		if !opt.AggressiveMode {
			return false, "requires aggressive mode"
		}
		if !opt.ProofMode {
			return false, "requires proof mode"
		}
		if !hasRealAuth {
			return false, "requires real auth contexts"
		}
		if !hasURLs && !hasRankedEndpoints {
			return false, "requires URL or ranked endpoint corpus"
		}
		return true, "race condition prerequisites available"
	case "idor-playbook":
		if !opt.AggressiveMode {
			return false, "requires aggressive mode"
		}
		if !opt.ProofMode {
			return false, "requires proof mode"
		}
		if !hasURLs {
			return false, "requires URL corpus"
		}
		if !hasRealAuth {
			return false, "requires real user/admin auth contexts"
		}
		return true, "proof and auth prerequisites available"
	case "saml-probe":
		if hasURLs {
			return true, "URL corpus available"
		}
		if strings.Contains(strings.ToLower(rs.Live), "saml") || strings.Contains(strings.ToLower(rs.Live), "sso") {
			return true, "SSO hints in live host inventory"
		}
		return false, "requires SSO hints or URL corpus"
	default:
		return true, "no planner constraint"
	}
}

func splitModulesByPlannerStage(mods []exploit.Module) ([]exploit.Module, []exploit.Module) {
	scout := make([]exploit.Module, 0, len(mods))
	proof := make([]exploit.Module, 0, len(mods))
	for _, m := range mods {
		if modulePlannerStage(strings.ToLower(strings.TrimSpace(m.Name()))) == "proof" {
			proof = append(proof, m)
			continue
		}
		scout = append(scout, m)
	}
	return scout, proof
}

func modulePlannerStage(name string) string {
	switch name {
	case "auth-bypass", "idor-playbook", "state-change", "upload-abuse", "mutation-engine", "jwt-access", "ssrf-prober", "crlf-injection", "advanced-injection", "rsql-injection", "idor-size", "saml-probe":
		return "proof"
	default:
		return "scout"
	}
}

type correlationSignals struct {
	modules map[string]int
}

func correlateProofModules(mods []exploit.Module, signals correlationSignals, rs models.ReconSummary, opt Options) ([]exploit.Module, []models.ExploitModuleTelemetry, []string) {
	if len(mods) == 0 {
		return nil, nil, nil
	}
	planned := make([]exploit.Module, 0, len(mods))
	skipped := make([]models.ExploitModuleTelemetry, 0, len(mods))
	preview := make([]string, 0, len(mods)+1)
	preview = append(preview, fmt.Sprintf("Correlation planner evaluating %d proof module(s) from scout findings/signals", len(mods)))
	now := time.Now().UTC().Format(time.RFC3339)
	for _, m := range mods {
		ready, reason := moduleReadyByCorrelation(strings.ToLower(strings.TrimSpace(m.Name())), signals, rs, opt)
		if ready {
			planned = append(planned, m)
			preview = append(preview, fmt.Sprintf("Correlation selected %s: %s", m.Name(), reason))
			continue
		}
		skipped = append(skipped, models.ExploitModuleTelemetry{
			Module:        m.Name(),
			StartedAt:     now,
			FinishedAt:    now,
			DurationMs:    0,
			FindingsCount: 0,
			ErrorCount:    0,
			Skipped:       true,
			SkippedReason: "correlation: " + reason,
		})
		preview = append(preview, fmt.Sprintf("Correlation skipped %s: %s", m.Name(), reason))
	}
	if len(preview) > 12 {
		preview = append(preview[:12], fmt.Sprintf("Correlation planner omitted %d additional module decision(s) from preview", len(preview)-12))
	}
	return planned, skipped, preview
}

func buildCorrelationSignals(findings []models.ExploitFinding) correlationSignals {
	s := correlationSignals{modules: make(map[string]int, len(findings))}
	for _, f := range findings {
		name := strings.ToLower(strings.TrimSpace(f.Module))
		if name == "" {
			continue
		}
		strength := findingCorrelationStrength(f)
		if strength > s.modules[name] {
			s.modules[name] = strength
		}
	}
	return s
}

func mergeCorrelationSignals(parts ...correlationSignals) correlationSignals {
	merged := correlationSignals{modules: map[string]int{}}
	for _, part := range parts {
		for name, strength := range part.modules {
			if strength > merged.modules[name] {
				merged.modules[name] = strength
			}
		}
	}
	return merged
}

func (s correlationSignals) hasModule(name string) bool {
	return s.strength(name) > 0
}

func (s correlationSignals) strength(name string) int {
	return s.modules[strings.ToLower(strings.TrimSpace(name))]
}

func (s correlationSignals) hasModuleAtLeast(name string, min int) bool {
	return s.strength(name) >= min
}

func findingCorrelationStrength(f models.ExploitFinding) int {
	strength := validationStrength(f.Validation)
	sev := strings.ToUpper(strings.TrimSpace(f.Severity))
	if band := strings.ToUpper(strings.TrimSpace(string(f.RiskScore.Band))); band != "" {
		sev = band
	}
	switch sev {
	case "CRITICAL", "HIGH":
		strength++
	}
	if strength > 5 {
		strength = 5
	}
	return strength
}

func validationStrength(v string) int {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "weaponized":
		return 4
	case "confirmed":
		return 3
	case "verified":
		return 2
	case "signal":
		return 1
	default:
		return 0
	}
}

func saveCorrelationSignalsArtifact(artDir string, signals correlationSignals) error {
	if strings.TrimSpace(artDir) == "" {
		return nil
	}
	names := make([]string, 0, len(signals.modules))
	modules := make(map[string]int, len(signals.modules))
	for name, strength := range signals.modules {
		if strength <= 0 {
			continue
		}
		names = append(names, name)
		modules[name] = strength
	}
	sort.Strings(names)
	payload := map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"modules":      modules,
		"ordered":      names,
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(artDir, "correlation_signals.json"), b, 0o644)
}

func loadCorrelationSignalsArtifact(artDir string) correlationSignals {
	signals := correlationSignals{modules: map[string]int{}}
	if strings.TrimSpace(artDir) == "" {
		return signals
	}
	b, err := os.ReadFile(filepath.Join(artDir, "correlation_signals.json"))
	if err != nil || len(b) == 0 {
		return signals
	}
	var payload struct {
		Modules json.RawMessage `json:"modules"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {
		return signals
	}
	var oldFormat []string
	if err := json.Unmarshal(payload.Modules, &oldFormat); err == nil {
		for _, name := range oldFormat {
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "" {
				signals.modules[name] = 1
			}
		}
		return signals
	}
	var newFormat map[string]int
	if err := json.Unmarshal(payload.Modules, &newFormat); err == nil {
		for name, strength := range newFormat {
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "" && strength > 0 {
				signals.modules[name] = strength
			}
		}
	}
	return signals
}

func moduleReadyByCorrelation(name string, signals correlationSignals, rs models.ReconSummary, opt Options) (bool, string) {
	_ = opt
	switch name {
	case "auth-bypass":
		if signals.hasModuleAtLeast("cors-poc", 2) || signals.hasModuleAtLeast("open-redirect", 2) || signals.hasModuleAtLeast("session-abuse", 2) || signals.hasModuleAtLeast("privilege-path", 2) {
			return true, fmt.Sprintf("strong redirect/session/CORS scout lead available (strength=%d)", maxCorrelationStrength(signals, "cors-poc", "open-redirect", "session-abuse", "privilege-path"))
		}
		if strings.TrimSpace(rs.Intel.CORSJSON) != "" {
			return true, "CORS intel available without scout confirmation"
		}
		return false, "needs strong redirect/session/CORS lead from scouts"
	case "idor-playbook":
		if signals.hasModuleAtLeast("privilege-path", 2) || signals.hasModuleAtLeast("session-abuse", 2) || signals.hasModuleAtLeast("graphql-abuse", 2) || signals.hasModuleAtLeast("js-endpoints", 1) {
			return true, fmt.Sprintf("authorization/object-access scout lead available (strength=%d)", maxCorrelationStrength(signals, "privilege-path", "session-abuse", "graphql-abuse", "js-endpoints"))
		}
		return false, "needs strong privilege/session/graphql/object lead from scouts"
	case "state-change":
		if signals.hasModuleAtLeast("session-abuse", 2) || signals.hasModuleAtLeast("cors-poc", 2) || signals.hasModuleAtLeast("graphql-abuse", 2) || signals.hasModuleAtLeast("js-endpoints", 1) {
			return true, fmt.Sprintf("state-change lead available from scouts (strength=%d)", maxCorrelationStrength(signals, "session-abuse", "cors-poc", "graphql-abuse", "js-endpoints"))
		}
		if matches := reconCorpusMatchCount(rs.URLs.All, []string{"post", "put", "patch", "delete", "update", "settings", "profile", "account", "password", "billing"}); matches >= 2 {
			return true, fmt.Sprintf("multiple state-changing URL patterns detected in recon corpus (%d)", matches)
		}
		return false, "needs state-change lead from scouts or URL corpus"
	case "upload-abuse":
		if matches := reconCorpusMatchCount(rs.URLs.All, []string{"upload", "file", "attachment", "import", "avatar", "image"}); matches >= 2 {
			return true, fmt.Sprintf("multiple upload-oriented URL patterns detected (%d)", matches)
		}
		return false, "needs upload-oriented URLs"
	case "mutation-engine":
		if signals.hasModuleAtLeast("bypass-poc", 2) || signals.hasModuleAtLeast("nuclei-triage", 1) || signals.hasModuleAtLeast("http-method-tampering", 1) {
			return true, fmt.Sprintf("mutation/bypass lead available from scouts (strength=%d)", maxCorrelationStrength(signals, "bypass-poc", "nuclei-triage", "http-method-tampering"))
		}
		return false, "needs bypass or method tampering scout lead"
	case "jwt-access":
		if signals.hasModuleAtLeast("session-abuse", 2) || signals.hasModuleAtLeast("secrets-validator", 2) {
			return true, fmt.Sprintf("auth token lead available from scouts (strength=%d)", maxCorrelationStrength(signals, "session-abuse", "secrets-validator"))
		}
		if matches := reconCorpusMatchCount(rs.URLs.All, []string{"jwt", "token", "oauth", "authorize", "login", "auth"}); matches >= 2 {
			return true, fmt.Sprintf("multiple token-oriented URL patterns detected (%d)", matches)
		}
		return false, "needs token/auth lead from scouts or URL corpus"
	case "ssrf-prober":
		if signals.hasModuleAtLeast("open-redirect", 2) {
			return true, fmt.Sprintf("URL-forwarding lead available from open-redirect scout (strength=%d)", signals.strength("open-redirect"))
		}
		urlMatches := reconCorpusMatchCount(rs.URLs.All, []string{"url=", "uri=", "dest=", "redirect=", "next=", "/render", "/proxy", "/fetch", "/preview", "/image"})
		endpointMatches := reconCorpusMatchCount(rs.Intel.EndpointsRankedJSON, []string{"render", "proxy", "fetch", "url", "preview", "image"})
		if urlMatches+endpointMatches >= 2 {
			return true, fmt.Sprintf("stacked SSRF-oriented URL/endpoint patterns detected (%d)", urlMatches+endpointMatches)
		}
		return false, "needs SSRF-style forwarding lead"
	case "crlf-injection":
		if signals.hasModuleAtLeast("open-redirect", 1) || signals.hasModuleAtLeast("http-method-tampering", 1) {
			return true, fmt.Sprintf("header/redirect manipulation lead available from scouts (strength=%d)", maxCorrelationStrength(signals, "open-redirect", "http-method-tampering"))
		}
		return false, "needs redirect or header manipulation scout lead"
	case "advanced-injection", "rsql-injection":
		if signals.hasModuleAtLeast("graphql-abuse", 2) || signals.hasModuleAtLeast("js-endpoints", 1) || signals.hasModuleAtLeast("nuclei-triage", 1) {
			return true, fmt.Sprintf("query/injection lead available from scouts (strength=%d)", maxCorrelationStrength(signals, "graphql-abuse", "js-endpoints", "nuclei-triage"))
		}
		paramMatches := reconCorpusMatchCount(rs.Intel.ParamsRankedJSON, []string{"id", "query", "search", "filter", "where", "sort"})
		endpointMatches := reconCorpusMatchCount(rs.Intel.EndpointsRankedJSON, []string{"search", "query", "filter", "graphql", "api"})
		if paramMatches+endpointMatches >= 2 {
			return true, fmt.Sprintf("stacked query-oriented parameter or endpoint patterns detected (%d)", paramMatches+endpointMatches)
		}
		return false, "needs query/injection lead from scouts or ranked params"
	case "idor-size":
		if signals.hasModuleAtLeast("privilege-path", 2) || signals.hasModuleAtLeast("session-abuse", 2) || signals.hasModuleAtLeast("graphql-abuse", 2) || signals.hasModuleAtLeast("js-endpoints", 1) {
			return true, fmt.Sprintf("object-access lead available from scouts (strength=%d)", maxCorrelationStrength(signals, "privilege-path", "session-abuse", "graphql-abuse", "js-endpoints"))
		}
		return false, "needs object-access lead from scouts"
	case "saml-probe":
		if signals.hasModuleAtLeast("session-abuse", 2) {
			return true, fmt.Sprintf("session/auth scout lead available (strength=%d)", signals.strength("session-abuse"))
		}
		if matches := reconCorpusMatchCount(rs.URLs.All, []string{"saml", "sso", "assertion", "acs", "metadata"}); matches >= 2 {
			return true, fmt.Sprintf("multiple SAML/SSO URL patterns detected (%d)", matches)
		}
		return false, "needs SAML/SSO lead from scouts or URL corpus"
	default:
		return true, "no correlation constraint"
	}
}

func maxCorrelationStrength(signals correlationSignals, names ...string) int {
	best := 0
	for _, name := range names {
		if strength := signals.strength(name); strength > best {
			best = strength
		}
	}
	return best
}

func prioritizeProofModules(mods []exploit.Module, signals correlationSignals, rs models.ReconSummary) []exploit.Module {
	if len(mods) <= 1 {
		return mods
	}
	base := prioritizeModules(mods, rs)
	order := make(map[string]int, len(base))
	for i, m := range base {
		order[strings.ToLower(strings.TrimSpace(m.Name()))] = i
	}
	out := make([]exploit.Module, len(base))
	copy(out, base)
	sort.SliceStable(out, func(i, j int) bool {
		aName := strings.ToLower(strings.TrimSpace(out[i].Name()))
		bName := strings.ToLower(strings.TrimSpace(out[j].Name()))
		aScore := correlationPriorityScore(aName, signals, rs)
		bScore := correlationPriorityScore(bName, signals, rs)
		if aScore != bScore {
			return aScore > bScore
		}
		return order[aName] < order[bName]
	})
	return out
}

func correlationPriorityScore(name string, signals correlationSignals, rs models.ReconSummary) int {
	score := maxCorrelationStrength(signals, name) * 100
	switch name {
	case "auth-bypass":
		score += maxCorrelationStrength(signals, "cors-poc", "open-redirect", "session-abuse", "privilege-path") * 30
		if strings.TrimSpace(rs.Intel.CORSJSON) != "" {
			score += 15
		}
	case "idor-playbook":
		score += maxCorrelationStrength(signals, "privilege-path", "session-abuse", "graphql-abuse", "js-endpoints") * 30
	case "state-change":
		score += maxCorrelationStrength(signals, "session-abuse", "cors-poc", "graphql-abuse", "js-endpoints") * 30
		score += reconCorpusMatchCount(rs.URLs.All, []string{"post", "put", "patch", "delete", "update", "settings", "profile", "account", "password", "billing"}) * 5
	case "upload-abuse":
		score += reconCorpusMatchCount(rs.URLs.All, []string{"upload", "file", "attachment", "import", "avatar", "image"}) * 10
	case "mutation-engine":
		score += maxCorrelationStrength(signals, "bypass-poc", "nuclei-triage", "http-method-tampering") * 30
	case "jwt-access":
		score += maxCorrelationStrength(signals, "session-abuse", "secrets-validator") * 30
		score += reconCorpusMatchCount(rs.URLs.All, []string{"jwt", "token", "oauth", "authorize", "login", "auth"}) * 5
	case "ssrf-prober":
		score += maxCorrelationStrength(signals, "open-redirect") * 35
		score += reconCorpusMatchCount(rs.URLs.All, []string{"url=", "uri=", "dest=", "redirect=", "next=", "/render", "/proxy", "/fetch", "/preview", "/image"}) * 5
		score += reconCorpusMatchCount(rs.Intel.EndpointsRankedJSON, []string{"render", "proxy", "fetch", "url", "preview", "image"}) * 5
	case "crlf-injection":
		score += maxCorrelationStrength(signals, "open-redirect", "http-method-tampering") * 30
	case "advanced-injection", "rsql-injection":
		score += maxCorrelationStrength(signals, "graphql-abuse", "js-endpoints", "nuclei-triage") * 30
		score += reconCorpusMatchCount(rs.Intel.ParamsRankedJSON, []string{"id", "query", "search", "filter", "where", "sort"}) * 5
		score += reconCorpusMatchCount(rs.Intel.EndpointsRankedJSON, []string{"search", "query", "filter", "graphql", "api"}) * 5
	case "idor-size":
		score += maxCorrelationStrength(signals, "privilege-path", "session-abuse", "graphql-abuse", "js-endpoints") * 30
	case "saml-probe":
		score += maxCorrelationStrength(signals, "session-abuse") * 30
		score += reconCorpusMatchCount(rs.URLs.All, []string{"saml", "sso", "assertion", "acs", "metadata"}) * 5
	}
	return score
}

func reconCorpusContainsAny(path string, needles []string) bool {
	return reconCorpusMatchCount(path, needles) > 0
}

func reconCorpusMatchCount(path string, needles []string) int {
	path = strings.TrimSpace(path)
	if path == "" || len(needles) == 0 {
		return 0
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return 0
	}
	text := strings.ToLower(string(b))
	seen := map[string]struct{}{}
	for _, needle := range needles {
		needle = strings.ToLower(strings.TrimSpace(needle))
		if needle == "" {
			continue
		}
		if strings.Contains(text, needle) {
			seen[needle] = struct{}{}
		}
	}
	return len(seen)
}

func moduleNames(mods []exploit.Module) []string {
	out := make([]string, 0, len(mods))
	for _, m := range mods {
		out = append(out, m.Name())
	}
	return out
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
	// If context modules are explicitly enabled, keep them informative but secondary.
	score["api-surface"] = 48
	score["admin-surface"] = 52
	score["security-headers"] = 85
	score["cookie-security"] = 86
	score["http-response"] = 87
	score["csp-audit"] = 88
	score["tls-audit"] = 89
	score["dns-check"] = 90
	score["port-service"] = 91

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
			"scan_profile":                        opt.ScanProfile,
			"min_severity":                        opt.MinSeverity,
			"skip_modules":                        opt.SkipModules,
			"only_modules":                        opt.OnlyModules,
			"validation_only":                     opt.ValidationOnly,
			"report_formats":                      opt.ReportFormats,
			"rate_limit_rps":                      opt.RateLimitRPS,
			"webhook_findings":                    opt.WebhookFindings,
			"webhook_module_progress":             opt.WebhookModuleProgress,
			"webhook_findings_min_severity":       opt.WebhookFindingsMinSeverity,
			"browser_capture":                     opt.BrowserCaptureEnabled,
			"browser_capture_max_pages":           opt.BrowserCaptureMaxPages,
			"browser_capture_per_page_wait_ms":    opt.BrowserCapturePerPageWaitMs,
			"browser_capture_settle_wait_ms":      opt.BrowserCaptureSettleWaitMs,
			"browser_capture_scroll_steps":        opt.BrowserCaptureScrollSteps,
			"browser_capture_max_routes_per_page": opt.BrowserCaptureMaxRoutesPerPage,
			"browser_capture_path":                opt.BrowserCapturePath,
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
