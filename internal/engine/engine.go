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
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	configpkg "breachpilot/internal/config"
	"breachpilot/internal/exploit"
	"breachpilot/internal/exploit/browsercapture"
	"breachpilot/internal/exploit/filter"
	"breachpilot/internal/exploit/httppolicy"
	adminsurface "breachpilot/internal/exploit/modules/adminsurface"
	advancedinjection "breachpilot/internal/exploit/modules/advancedinjection"
	apisurface "breachpilot/internal/exploit/modules/apisurface"
	authbypass "breachpilot/internal/exploit/modules/authbypass"
	businesslogic "breachpilot/internal/exploit/modules/businesslogic"
	bypasspoc "breachpilot/internal/exploit/modules/bypasspoc"
	cmdinject "breachpilot/internal/exploit/modules/cmdinject"
	cookiesecurity "breachpilot/internal/exploit/modules/cookiesecurity"
	cors "breachpilot/internal/exploit/modules/cors"
	crlfinjection "breachpilot/internal/exploit/modules/crlfinjection"
	cspaudit "breachpilot/internal/exploit/modules/cspaudit"
	deserialization "breachpilot/internal/exploit/modules/deserialization"
	dnscheck "breachpilot/internal/exploit/modules/dnscheck"
	domxss "breachpilot/internal/exploit/modules/domxss"
	exposedfiles "breachpilot/internal/exploit/modules/exposedfiles"
	graphqlabuse "breachpilot/internal/exploit/modules/graphqlabuse"
	headers "breachpilot/internal/exploit/modules/headers"
	hostheader "breachpilot/internal/exploit/modules/hostheader"
	hpp "breachpilot/internal/exploit/modules/hpp"
	httpmethods "breachpilot/internal/exploit/modules/httpmethods"
	httpresponse "breachpilot/internal/exploit/modules/httpresponse"
	idorplaybook "breachpilot/internal/exploit/modules/idorplaybook"
	idorsize "breachpilot/internal/exploit/modules/idorsize"
	infodisclosure "breachpilot/internal/exploit/modules/infodisclosure"
	jsendpoints "breachpilot/internal/exploit/modules/jsendpoints"
	jwtaccess "breachpilot/internal/exploit/modules/jwtaccess"
	lfi "breachpilot/internal/exploit/modules/lfi"
	massassign "breachpilot/internal/exploit/modules/massassign"
	mutationengine "breachpilot/internal/exploit/modules/mutationengine"
	nucleitriage "breachpilot/internal/exploit/modules/nucleitriage"
	openredirect "breachpilot/internal/exploit/modules/openredirect"
	portservice "breachpilot/internal/exploit/modules/portservice"
	privpath "breachpilot/internal/exploit/modules/privpath"
	racecondition "breachpilot/internal/exploit/modules/racecondition"
	rsqlinjection "breachpilot/internal/exploit/modules/rsqlinjection"
	rxss "breachpilot/internal/exploit/modules/rxss"
	samlprobe "breachpilot/internal/exploit/modules/samlprobe"
	schemaprobe "breachpilot/internal/exploit/modules/schemaprobe"
	secretsvalidator "breachpilot/internal/exploit/modules/secretsvalidator"
	sessionabuse "breachpilot/internal/exploit/modules/sessionabuse"
	smuggling "breachpilot/internal/exploit/modules/smuggling"
	ssrfprober "breachpilot/internal/exploit/modules/ssrfprober"
	statechange "breachpilot/internal/exploit/modules/statechange"
	subt "breachpilot/internal/exploit/modules/subt"
	tlsaudit "breachpilot/internal/exploit/modules/tlsaudit"
	uploadabuse "breachpilot/internal/exploit/modules/uploadabuse"
	xxeinjection "breachpilot/internal/exploit/modules/xxeinjection"
	oob "breachpilot/internal/exploit/oob"
	"breachpilot/internal/ingest"
	"breachpilot/internal/models"
	notifypkg "breachpilot/internal/notify"
	"breachpilot/internal/policy"
	"breachpilot/internal/scope"
	riskscoring "breachpilot/internal/scoring"
)

const (
	ErrTimeout      = "timeout"
	ErrInvalidInput = "invalid-input"
	ErrToolMissing  = "tool-missing"
	ErrNetwork      = "network-blocked"
	ErrParse        = "parse-failed"
	ErrExecution    = "execution-failed"
)

var (
	progressFractionRE = regexp.MustCompile(`(?i)\b(\d+)\s*/\s*(\d+)\s*(?:\((\d{1,3})%\))?`)
	progressPercentRE  = regexp.MustCompile(`(?i)\b(\d{1,3})%\b`)
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
	MaxParallel                    int
	RateLimitRPS                   int
	HTTPJitterMS                   int
	HTTPCircuitBreakerThreshold    int
	HTTPCircuitBreakerCooldownMS   int
	HTTPCircuitBreakerWait         bool
	WebhookFindings                bool
	WebhookModuleProgress          bool
	WebhookFindingsMinSeverity     string
	ModuleTimeoutSec               int
	ModuleRetries                  int
	AggressiveMode                 bool
	BoundlessMode                  bool
	ProofMode                      bool
	ProofTargetAllowlist           string
	OOBHTTPListenAddr              string
	OOBHTTPPublicBaseURL           string
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
			if opt.MaxParallel <= 0 && p.MaxParallel > 0 {
				opt.MaxParallel = p.MaxParallel
			}
		}
	}
	if opt.MaxParallel <= 0 {
		opt.MaxParallel = exploit.DefaultMaxParallel
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
			reconPlan, err := prepareReconHarvestRun(job, opt)
			if err != nil {
				_ = writeJobReport(job, opt.ArtifactsRoot)
				return err
			}
			notify("recon.started")
			reconStart := time.Now()
			summaryPath, err := runReconHarvest(ctx, job, opt, reconPlan)
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
	liveHostsTotal, err := countLines(hostsPath)
	if err != nil {
		_ = writeJobReport(job, opt.ArtifactsRoot)
		return err
	}

	artDir = filepath.Join(opt.ArtifactsRoot, job.ID)
	if err := os.MkdirAll(artDir, 0o755); err != nil {
		return err
	}
	outJSONL := filepath.Join(artDir, "nuclei_findings.jsonl")
	outErrors := filepath.Join(artDir, "nuclei_errors.jsonl")
	outLog := filepath.Join(artDir, "nuclei.log")
	job.EvidencePath = artDir

	nucleiInput := hostsPath
	nucleiTargetsTotal := liveHostsTotal
	if rankedInput, rankedCount := buildRankedNucleiInput(rs.Intel.EndpointsRankedJSON, artDir); rankedCount > 0 {
		nucleiInput = rankedInput
		nucleiTargetsTotal = rankedCount
		emit(models.RuntimeEvent{
			Kind:     "stage",
			Stage:    "exploit.targeting",
			Status:   "info",
			Message:  fmt.Sprintf("exploit.targeting using ranked endpoints: %d", rankedCount),
			Target:   job.Target,
			Counts:   map[string]int{"ranked_endpoints": rankedCount},
			Progress: runtimeStageProgress("targets", "targets", 0, nucleiTargetsTotal),
		})
	}
	emit(models.RuntimeEvent{
		Kind:    "stage",
		Stage:   "exploit.targeting",
		Status:  "info",
		Message: fmt.Sprintf("exploit.targeting inventory live_hosts=%d nuclei_targets=%d", liveHostsTotal, nucleiTargetsTotal),
		Target:  job.Target,
		Counts: map[string]int{
			"live_hosts":     liveHostsTotal,
			"nuclei_targets": nucleiTargetsTotal,
		},
		Progress: runtimeStageProgress("targets", "targets", 0, nucleiTargetsTotal),
	})

	args := buildNucleiExecutionArgs(job, nucleiInput, outJSONL, outErrors, opt)

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
		nucleiTimeoutSec := effectiveNucleiTimeoutSec(opt)
		if nucleiTimeoutSec > 0 {
			nucleiCtx, cancelNuclei = context.WithTimeout(ctx, time.Duration(nucleiTimeoutSec)*time.Second)
		}
		defer cancelNuclei()

		cmd := exec.CommandContext(nucleiCtx, opt.NucleiBin, args...)
		logFile, err := os.Create(outLog)
		if err != nil {
			return err
		}
		defer logFile.Close()
		errorTracker := newNucleiErrorTracker(job.Target, opt.Events)
		stopErrorTracker := errorTracker.start(nucleiCtx, outErrors)
		defer stopErrorTracker()
		nucleiPW := &progressWriter{stage: "exploit.log", target: job.Target, cb: opt.Progress, eventCB: opt.Events}
		mw := io.MultiWriter(logFile, nucleiPW)
		cmd.Stdout = mw
		cmd.Stderr = mw

		nucleiErr := cmd.Run()
		nucleiPW.Flush()
		stopErrorTracker()
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
		Kind:     "module",
		Stage:    "exploit.module",
		Status:   "planned",
		Message:  "exploit.module.wave1 " + strings.Join(scoutNames, ","),
		Target:   job.Target,
		Counts:   map[string]int{"planned": len(scoutModules)},
		Progress: runtimeStageProgress("modules", "modules", 0, len(scoutModules)),
	})

	// Initialize OOB Provider
	var oobProvider oob.Provider
	if opt.AggressiveMode || opt.ProofMode {
		provider, providerLabel, err := newOOBProvider(opt)
		switch {
		case err == nil && provider != nil:
			oobProvider = oob.NewTrackingProvider(provider)
			defer oobProvider.Close()
			emit(models.RuntimeEvent{
				Kind:    "oob",
				Stage:   "exploit.oob",
				Status:  "ready",
				Message: fmt.Sprintf("exploit.oob provider=%s ready", providerLabel),
				Target:  job.Target,
			})
		case err != nil:
			emit(models.RuntimeEvent{
				Kind:    "oob",
				Stage:   "exploit.oob",
				Status:  "warning",
				Message: fmt.Sprintf("exploit.oob unavailable: %v", err),
				Target:  job.Target,
			})
		}
	}

	sharedState := exploit.NewSharedState()
	httpMaxInFlight := resolvedHTTPMaxInFlight(opt)
	httpRuntime := httppolicy.NewRuntime(httppolicy.Config{
		RateLimitRPS:            opt.RateLimitRPS,
		MaxInFlight:             httpMaxInFlight,
		Jitter:                  time.Duration(opt.HTTPJitterMS) * time.Millisecond,
		CircuitBreakerThreshold: opt.HTTPCircuitBreakerThreshold,
		CircuitBreakerCooldown:  time.Duration(opt.HTTPCircuitBreakerCooldownMS) * time.Millisecond,
		WaitOnCircuitOpen:       opt.HTTPCircuitBreakerWait,
		AdaptiveEvent: func(event httppolicy.AdaptiveEvent) {
			emit(models.RuntimeEvent{
				Kind:    "stage",
				Stage:   "exploit.http",
				Status:  "throttled",
				Message: fmt.Sprintf("exploit.http adaptive throttle host=%s status=%d delay=%s", event.Host, event.StatusCode, event.Delay.Round(time.Millisecond)),
				Target:  job.Target,
				Counts: map[string]int{
					"status_code":          event.StatusCode,
					"adaptive_delay_ms":    int(event.Delay / time.Millisecond),
					"previous_delay_ms":    int(event.PreviousDelay / time.Millisecond),
					"retry_after_delay_ms": int(event.RetryAfterDelay / time.Millisecond),
				},
			})
		},
	})
	defer httpRuntime.Close()
	exploitOpt := exploit.Options{
		ArtifactsRoot:                  opt.ArtifactsRoot,
		Progress:                       opt.Progress,
		Events:                         opt.Events,
		SafeMode:                       job.SafeMode,
		MaxParallel:                    opt.MaxParallel,
		StateManager:                   sm,
		ModuleTimeoutSec:               opt.ModuleTimeoutSec,
		ModuleRetries:                  opt.ModuleRetries,
		Aggressive:                     opt.AggressiveMode,
		Boundless:                      opt.BoundlessMode,
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
		HTTPRuntime:                    httpRuntime,
		SharedState:                    sharedState,
		OOBProvider:                    oobProvider,
	}
	scoutFindings, scoutTelemetry := exploit.RunModules(ctx, job, &rs, exploitOpt, scoutModules)
	enrichReconSummaryFromSharedState(artDir, &rs, sharedState)
	scoutSignals := buildCorrelationSignals(scoutFindings)
	mergedSignals := mergeCorrelationSignals(persistedSignals, scoutSignals)
	_ = saveCorrelationSignalsArtifact(artDir, mergedSignals)
	correlatedProofModules, correlationSkipped, correlationPreview := correlateProofModules(proofModules, mergedSignals, rs, opt)
	job.PlanPreview = append(job.PlanPreview, correlationPreview...)
	correlatedProofModules = prioritizeProofModules(correlatedProofModules, mergedSignals, rs)
	proofNames := moduleNames(correlatedProofModules)
	if len(proofNames) > 0 {
		emit(models.RuntimeEvent{
			Kind:     "module",
			Stage:    "exploit.module",
			Status:   "planned",
			Message:  "exploit.module.wave2 " + strings.Join(proofNames, ","),
			Target:   job.Target,
			Counts:   map[string]int{"planned": len(correlatedProofModules)},
			Progress: runtimeStageProgress("modules", "modules", 0, len(correlatedProofModules)),
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
				corr, hasCorr := oob.LookupCorrelation(oobProvider, hit.CorrelationMeta)
				moduleName := "oob-listener"
				if hasCorr && strings.TrimSpace(corr.Module) != "" {
					moduleName = corr.Module
				} else {
					parts := strings.SplitN(hit.CorrelationMeta, "-", 2)
					if len(parts) == 2 {
						moduleName = parts[0]
					}
				}

				title := fmt.Sprintf("Out-Of-Band %s Interaction Received", strings.ToUpper(hit.Protocol))
				if hasCorr && strings.TrimSpace(corr.Title) != "" {
					title = corr.Title
				}
				evidenceParts := make([]string, 0, 5)
				if hasCorr && strings.TrimSpace(corr.Evidence) != "" {
					evidenceParts = append(evidenceParts, corr.Evidence)
				}
				evidenceParts = append(evidenceParts,
					fmt.Sprintf("protocol=%s", hit.Protocol),
					fmt.Sprintf("source_ip=%s", hit.SourceIP),
					fmt.Sprintf("correlation_id=%s", hit.CorrelationMeta),
					fmt.Sprintf("timestamp=%s", hit.Timestamp.Format(time.RFC3339)),
				)
				evidence := strings.Join(evidenceParts, " ")

				// Create an artifact for the raw request
				artifactPath := ""
				if job != nil {
					probeEx := exploit.ProofExchange{}
					if hasCorr && strings.TrimSpace(corr.RequestURL) != "" {
						probeEx = exploit.GenericExchange(
							"probe",
							emptyIfBlank(corr.RequestMethod, http.MethodGet),
							corr.RequestURL,
							corr.RequestHeaders,
							corr.RequestBody,
							0,
							nil,
							"",
							"",
						)
					}
					ap, err := exploit.SaveValidationArtifact(opt.ArtifactsRoot, job.ID, moduleName,
						"oob_"+exploit.SafeArtifactName(hit.CorrelationMeta),
						emptyIfBlank(corr.Target, job.Target), emptyIfBlank(corr.Validation, "confirmed"), title,
						exploit.ProofExchange{}, probeEx, "raw_oob_interaction", hit.RawRequest, 0)
					if err == nil {
						artifactPath = ap
					}
				}

				oobFinding := models.ExploitFinding{
					Module:       moduleName,
					Severity:     emptyIfBlank(corr.Severity, "CRITICAL"),
					Confidence:   intOrDefault(corr.Confidence, 100),
					Validation:   emptyIfBlank(corr.Validation, "confirmed"),
					Target:       emptyIfBlank(corr.Target, job.Target),
					Title:        title,
					Evidence:     evidence,
					ArtifactPath: artifactPath,
					PoCHint:      emptyIfBlank(corr.PoCHint, "Review OOB interaction payload for execution proof"),
					Tags:         appendUniqueStrings(corr.Tags, []string{"oob", "blind-execution", strings.ToLower(hit.Protocol)}),
					CWE:          corr.CWE,
					Timestamp:    exploit.NowISO(),
				}

				exploitFindings = append(exploitFindings, oobFinding)
				rawExploitFindings = append(rawExploitFindings, oobFinding)
			}
		}
	}

	// --- Stored Vulnerability Verification Phase ---
	if sharedState != nil && opt.BrowserCaptureEnabled && ctx.Err() == nil {
		storedMarkers := make(map[string]string) // marker -> source URL
		for k, v := range sharedState.GetAll("stored_marker_") {
			storedMarkers[strings.TrimPrefix(k, "stored_marker_")] = v
		}

		if len(storedMarkers) > 0 {
			emit(models.RuntimeEvent{
				Kind:    "stored",
				Stage:   "exploit.stored.verify",
				Status:  "crawling",
				Message: fmt.Sprintf("Hunting for %d stored payloads reflecting in DOM...", len(storedMarkers)),
				Target:  job.Target,
			})

			bcOpt := browsercapture.Options{
				BrowserPath:      opt.BrowserCapturePath,
				MaxPages:         opt.BrowserCaptureMaxPages,
				PerPageWait:      time.Duration(opt.BrowserCapturePerPageWaitMs) * time.Millisecond,
				SettleWait:       time.Duration(opt.BrowserCaptureSettleWaitMs) * time.Millisecond,
				ScrollSteps:      opt.BrowserCaptureScrollSteps,
				MaxRoutesPerPage: opt.BrowserCaptureMaxRoutesPerPage,
			}
			var startURLs []string
			if p := strings.TrimSpace(rs.URLs.All); p != "" {
				if f, err := os.Open(p); err == nil {
					s := bufio.NewScanner(f)
					for s.Scan() && len(startURLs) < 15 {
						startURLs = append(startURLs, s.Text())
					}
					f.Close()
				}
			}

			if len(startURLs) > 0 {
				captured := browsercapture.Capture(startURLs, bcOpt)
				for _, req := range captured {
					for marker, source := range storedMarkers {
						// Here we simplify by checking if the URL itself reflected it (DOM XSS leaking to fetch)
						// In a true engine, we'd have the headless browser hook verify the exact HTML DOM,
						// but capturing network traffic triggered by the browser acts as a strong signal.
						if strings.Contains(req.URL, marker) || strings.Contains(req.PostData, marker) {
							title := "Stored Vulnerability (Second-Order) Detected"
							evidence := fmt.Sprintf("Payload injected via %s, executed and logged during cross-site crawl at %s", source, req.URL)

							finding := models.ExploitFinding{
								Module:     "stored-verification",
								Severity:   "CRITICAL",
								Confidence: 95,
								Validation: "confirmed",
								Target:     source,
								Title:      title,
								Evidence:   evidence,
								PoCHint:    "The payload injected on the target endpoint persisted and fired asynchronously on another user's session.",
								Tags:       []string{"stored-xss", "second-order", "owasp-a03"},
								CWE:        "CWE-79",
								Timestamp:  exploit.NowISO(),
							}
							exploitFindings = append(exploitFindings, finding)
							rawExploitFindings = append(rawExploitFindings, finding)

							// Remove so we don't alert multiple times for the same payload
							delete(storedMarkers, marker)
						}
					}
				}
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

	leadFindings := exploit.SignalOnlyFindings(exploitFindings)
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
			suppressedFindingWebhooks := 0
			findingCap := 0
			webhookNotifier, _ := opt.Notifier.(*notifypkg.Webhook)
			if webhookNotifier != nil {
				findingCap = webhookNotifier.FindingCap()
			}
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
					if webhookNotifier != nil && !webhookNotifier.ShouldSendFinding() {
						suppressedFindingWebhooks++
						continue
					}
					opt.Notifier.SendGeneric("exploit.finding", map[string]any{
						"_bp_finding_cap_checked": true,
						"job_id":                  job.ID,
						"target":                  f.Target,
						"module":                  f.Module,
						"severity":                sev,
						"title":                   f.Title,
						"confidence":              f.Confidence,
						"validation":              f.Validation,
						"evidence":                f.Evidence,
						"report_path":             job.ExploitReportPath,
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
			if batchCounts["INFO"]+batchCounts["LOW"]+batchCounts["MEDIUM"] > 0 || suppressedFindingWebhooks > 0 {
				payload := map[string]any{
					"job_id":  job.ID,
					"target":  job.Target,
					"counts":  batchCounts,
					"sample":  batchSample,
					"min_sev": opt.WebhookFindingsMinSeverity,
					"note":    "low-priority findings aggregated",
				}
				if suppressedFindingWebhooks > 0 && findingCap > 0 {
					payload["note"] = fmt.Sprintf("individual finding webhooks capped at %d — see batch for full list", findingCap)
					payload["suppressed_individual_findings"] = suppressedFindingWebhooks
				}
				opt.Notifier.SendGeneric("exploit.findings.batch", payload)
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
		LeadFindings:       leadFindings,
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

type reconExecutionPlan struct {
	baseArgv           []string
	caps               configpkg.ReconHarvestCapabilities
	reconDir           string
	preferredSummary   string
	resumeDir          string
	freshOutputName    string
	capabilityProbeErr error
}

func prepareReconHarvestRun(job *models.Job, opt Options) (reconExecutionPlan, error) {
	if strings.TrimSpace(opt.ReconHarvestCmd) == "" {
		return reconExecutionPlan{}, fmt.Errorf("recon harvest command is not configured")
	}

	reconDir := filepath.Join(opt.ArtifactsRoot, job.ID, "recon")
	if err := os.MkdirAll(reconDir, 0o755); err != nil {
		return reconExecutionPlan{}, err
	}

	baseArgv, err := configpkg.SplitReconHarvestCommand(opt.ReconHarvestCmd)
	if err != nil {
		return reconExecutionPlan{}, err
	}

	reconCaps, reconCapsErr := configpkg.ProbeReconHarvestCapabilities(opt.ReconHarvestCmd)
	if reconCapsErr == nil && !reconCaps.SupportsCoreExecution() {
		return reconExecutionPlan{}, fmt.Errorf("recon command is incompatible: missing required support for --run, -o/--output, and --resume")
	}

	return reconExecutionPlan{
		baseArgv:           baseArgv,
		caps:               reconCaps,
		reconDir:           reconDir,
		preferredSummary:   existingReconSummaryPath(reconDir),
		resumeDir:          findPartialReconWorkdir(reconDir),
		freshOutputName:    "run",
		capabilityProbeErr: reconCapsErr,
	}, nil
}

func runReconHarvest(ctx context.Context, job *models.Job, opt Options, plan reconExecutionPlan) (string, error) {
	if plan.preferredSummary != "" {
		if _, vErr := validateReconSummary(plan.preferredSummary, job.Target); vErr != nil {
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
		return plan.preferredSummary, nil
	}
	logPath := filepath.Join(plan.reconDir, "reconharvest.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return "", err
	}
	defer logFile.Close()

	reconCaps := plan.caps
	if plan.capabilityProbeErr != nil {
		reconCaps = configpkg.ReconHarvestCapabilities{}
		if opt.Events != nil {
			opt.Events(models.RuntimeEvent{
				Kind:      "stage",
				Stage:     "recon",
				Status:    "warning",
				Message:   fmt.Sprintf("recon.compatibility probe failed; using minimal arg set: %v", plan.capabilityProbeErr),
				Target:    job.Target,
				Timestamp: time.Now().UTC(),
			})
		}
	}
	attempts := opt.ReconRetries + 1
	if attempts < 1 {
		attempts = 1
	}
	for attempt := 1; attempt <= attempts; attempt++ {
		reconCtx := ctx
		cancelRecon := func() {}
		reconTimeoutSec := effectiveReconTimeoutSec(opt)
		if reconTimeoutSec > 0 {
			reconCtx, cancelRecon = context.WithTimeout(ctx, time.Duration(reconTimeoutSec)*time.Second)
		}
		argv := append([]string{}, plan.baseArgv...)
		resumeDir := findPartialReconWorkdir(plan.reconDir)
		if resumeDir != "" {
			// Pass --resume <workdir> so reconHarvest picks up its existing state.
			// Do NOT pass -o or the target positional arg; reconHarvest derives both
			// from workspace_meta.json when --resume is used.
			argv = append(argv, buildReconHarvestExecutionArgs(job.Target, plan.freshOutputName, resumeDir, true, reconCaps)...)
		} else {
			argv = append(argv, buildReconHarvestExecutionArgs(job.Target, plan.freshOutputName, "", false, reconCaps)...)
		}
		cmd := exec.CommandContext(reconCtx, argv[0], argv[1:]...)
		cmd.Dir = plan.reconDir
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
			summaryPath := existingReconSummaryPath(plan.reconDir)
			if summaryPath != "" {
				job.EvidencePath = filepath.Join(opt.ArtifactsRoot, job.ID)
				return summaryPath, nil
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

func hasReconMarkers(dir string) bool {
	markers := []string{"run.log", "workspace_meta.json", "live_hosts.txt", "run_commands.sh"}
	for _, m := range markers {
		if st, err := os.Stat(filepath.Join(dir, m)); err == nil && st.Size() > 0 {
			return true
		}
	}
	return false
}

func findPartialReconWorkdir(reconDir string) string {
	if hasReconMarkers(reconDir) {
		return reconDir
	}

	var newestDir string
	var newestMod time.Time
	_ = filepath.Walk(reconDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if info.Name() != "workspace_meta.json" || info.Size() == 0 {
			return nil
		}
		dir := filepath.Dir(path)
		if newestDir == "" || info.ModTime().After(newestMod) {
			newestDir = dir
			newestMod = info.ModTime()
		}
		return nil
	})
	return newestDir
}

func existingReconSummaryPath(reconDir string) string {
	summaryPath := filepath.Join(reconDir, "summary.json")
	if st, err := os.Stat(summaryPath); err == nil && st.Size() > 0 {
		return summaryPath
	}
	if workdir := findPartialReconWorkdir(reconDir); workdir != "" {
		summaryPath = filepath.Join(workdir, "summary.json")
		if st, err := os.Stat(summaryPath); err == nil && st.Size() > 0 {
			return summaryPath
		}
	}
	return findSummaryJSON(reconDir)
}

// findSummaryJSON walks reconDir looking for any summary.json file.
func findSummaryJSON(reconDir string) string {
	var preferred string
	var fallback string
	_ = filepath.Walk(reconDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && info.Name() == "summary.json" && info.Size() > 0 {
			if !strings.Contains(filepath.ToSlash(path), "/reports/") {
				preferred = path
				return filepath.SkipAll
			}
			if fallback == "" {
				fallback = path
			}
		}
		return nil
	})
	if preferred != "" {
		return preferred
	}
	return fallback
}

func buildReconHarvestExecutionArgs(target, outputName, resumeDir string, partial bool, caps configpkg.ReconHarvestCapabilities) []string {
	args := []string{}
	if !partial {
		args = append(args, target)
	}
	args = append(args, "--run")
	if partial {
		args = append(args, "--resume", resumeDir)
	} else {
		args = append(args, "-o", outputName)
		if caps.Supports("--overwrite") {
			args = append(args, "--overwrite")
		}
	}
	if caps.Supports("--skip-nuclei") {
		args = append(args, "--skip-nuclei")
	}
	if caps.Supports("--arjun-threads") {
		args = append(args, "--arjun-threads", "20")
	}
	if caps.Supports("--vhost-threads") {
		args = append(args, "--vhost-threads", "80")
	}
	return args
}

func buildNucleiExecutionArgs(job *models.Job, nucleiInput, outJSONL, outErrors string, opt Options) []string {
	args := []string{"-l", nucleiInput, "-jsonl", "-o", outJSONL, "-silent", "-no-color", "-stats", "-timeout", strconv.Itoa(defaultNucleiRequestTimeoutSec(job))}
	if strings.TrimSpace(outErrors) != "" {
		args = append(args, "-error-log", outErrors)
	}
	if job != nil && (strings.Contains(job.Target, "localhost") || strings.Contains(job.Target, "127.0.0.1")) {
		args = append(args, "-concurrency", "10", "-max-host-error", "10")
	} else {
		args = append(args, "-c", "35", "-bs", "25", "-max-host-error", "35")
	}
	if job != nil && len(job.Templates) > 0 {
		args = append(args, "-t", strings.Join(job.Templates, ","))
	} else if job != nil && job.SafeMode {
		args = append(args, "-tags", "misconfig,exposure,tech")
	} else {
		args = append(args, "-severity", "medium,high,critical")
	}

	if opt.RateLimitRPS > 0 {
		args = append(args, "-rl", strconv.Itoa(opt.RateLimitRPS))
	}
	return args
}

func defaultNucleiRequestTimeoutSec(job *models.Job) int {
	if job != nil {
		target := strings.ToLower(strings.TrimSpace(job.Target))
		if strings.Contains(target, "localhost") || strings.Contains(target, "127.0.0.1") {
			return 5
		}
	}
	return 10
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
		parsed, err := url.Parse(u)
		if err != nil || parsed == nil {
			return
		}
		if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
			return
		}
		if strings.TrimSpace(parsed.Host) == "" {
			return
		}
		normalized := parsed.Scheme + "://" + parsed.Host
		u = normalized
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
			if len(items) >= 50 {
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

func emptyIfBlank(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func intOrDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func effectiveReconTimeoutSec(opt Options) int {
	if opt.BoundlessMode {
		return 0
	}
	return opt.ReconTimeoutSec
}

func effectiveNucleiTimeoutSec(opt Options) int {
	if opt.BoundlessMode {
		return 0
	}
	return opt.NucleiTimeoutSec
}

func appendUniqueStrings(a, b []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(a)+len(b))
	for _, item := range append(append([]string{}, a...), b...) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

type nucleiErrorLogEntry struct {
	Error string         `json:"error"`
	Kind  string         `json:"kind"`
	Attrs map[string]any `json:"attrs"`
}

type nucleiErrorTracker struct {
	target      string
	eventCB     func(models.RuntimeEvent)
	mu          sync.Mutex
	offset      int64
	total       int
	counts      map[string]int
	lastEmitted string
	stopOnce    sync.Once
	stopped     chan struct{}
}

func newNucleiErrorTracker(target string, eventCB func(models.RuntimeEvent)) *nucleiErrorTracker {
	return &nucleiErrorTracker{
		target:  target,
		eventCB: eventCB,
		counts:  map[string]int{},
		stopped: make(chan struct{}),
	}
}

func (t *nucleiErrorTracker) start(ctx context.Context, path string) func() {
	if t == nil || t.eventCB == nil || strings.TrimSpace(path) == "" {
		return func() {}
	}
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				t.consume(path)
				t.emit()
				return
			case <-t.stopped:
				t.consume(path)
				t.emit()
				return
			case <-ticker.C:
				t.consume(path)
				t.emit()
			}
		}
	}()
	return func() {
		t.stopOnce.Do(func() {
			close(t.stopped)
		})
	}
}

func (t *nucleiErrorTracker) consume(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	t.mu.Lock()
	offset := t.offset
	t.mu.Unlock()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return
	}

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var consumed int64
	updates := map[string]int{}
	total := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		consumed += int64(len(scanner.Bytes())) + 1
		if line == "" {
			continue
		}
		category := classifyNucleiErrorLogLine(line)
		updates[category]++
		total++
	}
	if total == 0 {
		t.mu.Lock()
		t.offset = offset + consumed
		t.mu.Unlock()
		return
	}

	t.mu.Lock()
	t.offset = offset + consumed
	t.total += total
	for k, v := range updates {
		t.counts[k] += v
	}
	t.mu.Unlock()
}

func (t *nucleiErrorTracker) emit() {
	if t == nil || t.eventCB == nil {
		return
	}
	t.mu.Lock()
	total := t.total
	if total == 0 {
		t.mu.Unlock()
		return
	}
	counts := make(map[string]int, len(t.counts)+1)
	for k, v := range t.counts {
		counts[k] = v
	}
	counts["total"] = total
	summary := formatNucleiErrorSummary(counts)
	if summary == t.lastEmitted {
		t.mu.Unlock()
		return
	}
	t.lastEmitted = summary
	t.mu.Unlock()

	t.eventCB(models.RuntimeEvent{
		Kind:      "stage",
		Stage:     "exploit.errors",
		Status:    "warning",
		Message:   "exploit.errors " + summary,
		Target:    t.target,
		Timestamp: time.Now().UTC(),
		Counts:    counts,
	})
}

func classifyNucleiErrorLogLine(line string) string {
	var entry nucleiErrorLogEntry
	if err := json.Unmarshal([]byte(line), &entry); err == nil {
		return classifyNucleiError(entry.Error, entry.Kind, entry.Attrs)
	}
	return classifyNucleiError(line, "", nil)
}

func classifyNucleiError(errText, kind string, attrs map[string]any) string {
	combined := strings.ToLower(strings.TrimSpace(errText + " " + kind))
	if attrs != nil {
		if status, ok := attrs["status_code"]; ok {
			combined += " status_code=" + fmt.Sprint(status)
		}
	}
	switch {
	case strings.Contains(combined, "429") || strings.Contains(combined, "too many requests"):
		return "rate_429"
	case strings.Contains(combined, "403") || strings.Contains(combined, "forbidden"):
		return "blocked_403"
	case strings.Contains(combined, "timeout") || strings.Contains(combined, "deadline exceeded"):
		return "timeout"
	case strings.Contains(combined, "tls") || strings.Contains(combined, "x509") || strings.Contains(combined, "certificate") || strings.Contains(combined, "handshake"):
		return "tls"
	case strings.Contains(combined, "no such host") || strings.Contains(combined, "temporary failure in name resolution") || strings.Contains(combined, "server misbehaving") || strings.Contains(combined, "lookup "):
		return "dns"
	case strings.Contains(combined, "connection refused") || strings.Contains(combined, "port closed or filtered"):
		return "refused"
	case strings.Contains(combined, "connection reset") || strings.Contains(combined, "reset by peer") || strings.Contains(combined, "broken pipe"):
		return "reset"
	case strings.Contains(combined, " eof") || strings.HasSuffix(combined, " eof") || strings.Contains(combined, "unexpected eof"):
		return "eof"
	case strings.Contains(combined, "status code 4"):
		return "http_4xx"
	case strings.Contains(combined, "status code 5"):
		return "http_5xx"
	case strings.Contains(combined, "network"):
		return "network"
	default:
		return "other"
	}
}

func formatNucleiErrorSummary(counts map[string]int) string {
	if len(counts) == 0 {
		return "total=0"
	}
	total := counts["total"]
	type pair struct {
		key   string
		value int
	}
	items := make([]pair, 0, len(counts))
	for _, key := range []string{"timeout", "tls", "dns", "blocked_403", "rate_429", "refused", "reset", "eof", "http_4xx", "http_5xx", "network", "other"} {
		if counts[key] > 0 {
			items = append(items, pair{key: key, value: counts[key]})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].value == items[j].value {
			return items[i].key < items[j].key
		}
		return items[i].value > items[j].value
	})
	parts := []string{fmt.Sprintf("total=%d", total)}
	for i, item := range items {
		if i >= 5 {
			break
		}
		parts = append(parts, fmt.Sprintf("%s=%d", item.key, item.value))
	}
	return strings.Join(parts, " ")
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
			progress := parseRuntimeLogProgress(w.stage, line)
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
					Progress:  progress,
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
		progress := parseRuntimeLogProgress(w.stage, line)
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
				Progress:  progress,
			})
		}
	}
}

func runtimeStageProgress(label, unit string, completed, total int) *models.RuntimeProgress {
	if total <= 0 {
		return nil
	}
	if completed < 0 {
		completed = 0
	}
	if completed > total {
		completed = total
	}
	return &models.RuntimeProgress{
		Label:     strings.TrimSpace(label),
		Unit:      strings.TrimSpace(unit),
		Completed: completed,
		Total:     total,
		Percent:   completed * 100 / total,
	}
}

func parseRuntimeLogProgress(stage, line string) *models.RuntimeProgress {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	lineLower := strings.ToLower(line)
	looksLikeProgress := strings.Contains(line, "%") ||
		strings.Contains(lineLower, "progress") ||
		strings.Contains(lineLower, "target") ||
		strings.Contains(lineLower, "host") ||
		strings.Contains(lineLower, "request") ||
		strings.Contains(lineLower, "template")
	if !looksLikeProgress {
		return nil
	}
	if matches := progressFractionRE.FindStringSubmatch(line); len(matches) == 4 {
		completed, errA := strconv.Atoi(matches[1])
		total, errB := strconv.Atoi(matches[2])
		if errA == nil && errB == nil && total > 0 {
			percent := completed * 100 / total
			if matches[3] != "" {
				if parsedPercent, err := strconv.Atoi(matches[3]); err == nil {
					percent = parsedPercent
				}
			}
			if percent < 0 {
				percent = 0
			}
			if percent > 100 {
				percent = 100
			}
			return &models.RuntimeProgress{
				Label:     progressLabelForStage(stage),
				Unit:      progressUnitForStage(stage),
				Completed: completed,
				Total:     total,
				Percent:   percent,
			}
		}
	}
	if matches := progressPercentRE.FindStringSubmatch(line); len(matches) == 2 {
		percent, err := strconv.Atoi(matches[1])
		if err == nil {
			if percent < 0 {
				percent = 0
			}
			if percent > 100 {
				percent = 100
			}
			return &models.RuntimeProgress{
				Label:   progressLabelForStage(stage),
				Unit:    progressUnitForStage(stage),
				Percent: percent,
			}
		}
	}
	return nil
}

func progressLabelForStage(stage string) string {
	switch {
	case strings.HasPrefix(stage, "exploit.log"):
		return "targets"
	case strings.HasPrefix(stage, "recon.log"):
		return "recon"
	default:
		return "progress"
	}
}

func progressUnitForStage(stage string) string {
	switch {
	case strings.HasPrefix(stage, "exploit.log"):
		return "targets"
	case strings.HasPrefix(stage, "recon.log"):
		return "steps"
	default:
		return ""
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
	ingest.NormalizeReconSummaryPaths(summaryPath, &rs)
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

type browserWorkflowSignals struct {
	Available        bool
	RequestSteps     int
	WriteSteps       int
	UploadSteps      int
	QueryLikeSteps   int
	AuthLikeSteps    int
	SSRFLikeSteps    int
	RouteCount       int
	FormCount        int
	RecordedWorkflow int
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
		{"hostheader", "Detects host header injection and cache poisoning", true, "exploit-core"},
		{"hpp", "Detects HTTP parameter pollution", true, "exploit-core"},
		{"lfi", "Detects local file inclusion and path traversal", true, "exploit-core"},
		{"xxeinjection", "Detects XXE via file read and OOB probes", true, "exploit-core"},
		{"state-change", "Detects risky state-changing endpoint patterns", true, "exploit-core"},
		{"upload-abuse", "Detects upload attack surface and retrieval risks", true, "exploit-core"},
		{"auth-bypass", "Executes auth bypass chain checks across risky surfaces", true, "exploit-core"},
		{"businesslogic", "Detects business logic flaws via boundary and type probing", true, "exploit-core"},
		{"cmdinject", "Detects OS command injection (blind timing and OOB)", true, "exploit-core"},
		{"mutation-engine", "Runs aggressive mutation probes (method/header/param/content-type)", true, "exploit-core"},
		{"idor-playbook", "Runs deterministic IDOR privilege hopping playbook", true, "exploit-core"},
		{"jwt-access", "Detects JWT-specific vulnerabilities (none alg, header injection)", true, "exploit-core"},
		{"rxss", "Detects reflected XSS without browser via marker reflection", true, "exploit-core"},
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
		hostheader.New(),
		hpp.New(),
		lfi.New(),
		xxeinjection.New(),
		statechange.New(),
		uploadabuse.New(),
		authbypass.New(),
		businesslogic.New(),
		cmdinject.New(),
		mutationengine.New(),
		idorplaybook.New(),
		jwtaccess.New(),
		rxss.New(),
		advancedinjection.New(),
		ssrfprober.New(),
		crlfinjection.New(),
		samlprobe.New(),
		rsqlinjection.New(),
		idorsize.New(),
		massassign.New(),
		schemaprobe.New(),
		racecondition.New(),
		domxss.New(),
		smuggling.New(),
		deserialization.New(),
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
	wf := loadBrowserWorkflowSignals(rs)

	switch name {
	case "deserialization":
		return opt.AggressiveMode && hasURLs, "requires aggressive mode and URL corpus"
	case "smuggling":
		return opt.AggressiveMode && hasURLs, "requires aggressive mode and URL corpus"
	case "dom-xss":
		if opt.AggressiveMode && opt.BrowserCaptureEnabled && hasURLs {
			return true, "aggressive mode & browser available"
		}
		return false, "requires aggressive mode, URL corpus, and browser enabled"
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
	case "hostheader":
		return hasLiveHosts, "live host inventory available"
	case "hpp", "lfi", "rxss", "businesslogic":
		return hasURLs || hasRankedEndpoints, "URL or endpoint corpus available"
	case "xxeinjection":
		return hasURLs || hasLiveHosts, "URL or live host corpus available"
	case "state-change", "upload-abuse", "crlf-injection", "jwt-access":
		switch name {
		case "state-change":
			if wf.WriteSteps > 0 {
				return true, fmt.Sprintf("browser workflow captured %d write-like step(s)", wf.WriteSteps)
			}
		case "upload-abuse":
			if wf.UploadSteps > 0 {
				return true, fmt.Sprintf("browser workflow captured %d upload-like step(s)", wf.UploadSteps)
			}
		case "jwt-access":
			if wf.AuthLikeSteps > 0 {
				return true, fmt.Sprintf("browser workflow captured %d auth/token step(s)", wf.AuthLikeSteps)
			}
		case "crlf-injection":
			if wf.RequestSteps > 0 {
				return true, fmt.Sprintf("browser workflow captured %d replayable request step(s)", wf.RequestSteps)
			}
		}
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
	case "advanced-injection":
		if !opt.AggressiveMode {
			return false, "requires aggressive mode"
		}
		if wf.QueryLikeSteps > 0 {
			return true, fmt.Sprintf("browser workflow captured %d parameterized/query-like step(s)", wf.QueryLikeSteps)
		}
		return true, "aggressive mode enabled; correlation planner will gate injection leads"
	case "cmdinject":
		if !opt.AggressiveMode {
			return false, "requires aggressive mode"
		}
		return hasURLs || hasRankedEndpoints, "URL or endpoint corpus available"
	case "mutation-engine", "ssrf-prober", "idor-size", "mass-assign":
		if !opt.AggressiveMode {
			return false, "requires aggressive mode"
		}
		if !hasURLs && !hasRankedEndpoints {
			switch name {
			case "ssrf-prober":
				if wf.SSRFLikeSteps > 0 {
					return true, fmt.Sprintf("browser workflow captured %d SSRF-style forwarding step(s)", wf.SSRFLikeSteps)
				}
			case "mutation-engine":
				if wf.WriteSteps > 0 || wf.RequestSteps > 0 {
					return true, fmt.Sprintf("browser workflow captured %d replayable request step(s)", wf.RequestSteps)
				}
			case "mass-assign":
				if wf.WriteSteps > 0 {
					return true, fmt.Sprintf("browser workflow captured %d body-backed write step(s)", wf.WriteSteps)
				}
			case "idor-size":
				if wf.AuthLikeSteps > 0 || wf.WriteSteps > 0 {
					return true, fmt.Sprintf("browser workflow captured %d authenticated/object workflow step(s)", wf.AuthLikeSteps+wf.WriteSteps)
				}
			}
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
	wf := loadBrowserWorkflowSignals(rs)
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
		if wf.WriteSteps > 0 {
			return true, fmt.Sprintf("browser workflow retained %d write-like step(s)", wf.WriteSteps)
		}
		return false, "needs state-change lead from scouts or URL corpus"
	case "upload-abuse":
		if matches := reconCorpusMatchCount(rs.URLs.All, []string{"upload", "file", "attachment", "import", "avatar", "image"}); matches >= 2 {
			return true, fmt.Sprintf("multiple upload-oriented URL patterns detected (%d)", matches)
		}
		if wf.UploadSteps > 0 {
			return true, fmt.Sprintf("browser workflow retained %d upload-like step(s)", wf.UploadSteps)
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
		if wf.AuthLikeSteps > 0 {
			return true, fmt.Sprintf("browser workflow retained %d auth/token step(s)", wf.AuthLikeSteps)
		}
		hasURLs := strings.TrimSpace(rs.URLs.All) != ""
		if hasURLs && reconCorpusMatchCount(rs.URLs.All, []string{"api/", "auth/", "token", "session", "login", "authorize", "oauth"}) >= 1 {
			return true, "URL corpus has auth/API endpoint(s) — direct JWT probe"
		}
		return false, "needs token/auth lead from scouts or URL corpus"
	case "ssrf-prober":
		if signals.hasModuleAtLeast("open-redirect", 2) {
			return true, fmt.Sprintf("URL-forwarding lead available from open-redirect scout (strength=%d)", signals.strength("open-redirect"))
		}
		if paramCount := reconCorpusMatchCount(rs.URLs.All, []string{"url=", "uri=", "src=", "source=", "fetch=", "load=", "path=", "file=", "dest=", "destination=", "target=", "endpoint=", "proxy=", "callback=", "webhook=", "host=", "redirect=", "return=", "link=", "img=", "image="}); paramCount >= 1 {
			return true, fmt.Sprintf("URL corpus has %d SSRF-like parameter(s) — direct probe without scout confirmation", paramCount)
		}
		urlMatches := reconCorpusMatchCount(rs.URLs.All, []string{"url=", "uri=", "dest=", "redirect=", "next=", "/render", "/proxy", "/fetch", "/preview", "/image"})
		endpointMatches := reconCorpusMatchCount(rs.Intel.EndpointsRankedJSON, []string{"render", "proxy", "fetch", "url", "preview", "image"})
		if urlMatches+endpointMatches >= 2 {
			return true, fmt.Sprintf("stacked SSRF-oriented URL/endpoint patterns detected (%d)", urlMatches+endpointMatches)
		}
		if wf.SSRFLikeSteps > 0 {
			return true, fmt.Sprintf("browser workflow retained %d SSRF-style forwarding step(s)", wf.SSRFLikeSteps)
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
		if wf.QueryLikeSteps > 0 {
			return true, fmt.Sprintf("browser workflow retained %d parameterized/query-like step(s)", wf.QueryLikeSteps)
		}
		if paramCount := reconCorpusMatchCount(rs.URLs.All, []string{"id=", "q=", "search=", "filter=", "query=", "page=", "user=", "name=", "type=", "category=", "sort=", "order=", "key=", "token=", "data=", "input=", "value=", "param="}); paramCount >= 1 {
			return true, fmt.Sprintf("URL corpus has %d parameterised endpoint(s) — direct injection probe", paramCount)
		}
		return false, "needs query/injection lead from scouts or ranked params"
	case "lfi":
		return true, "no correlation constraint"
	case "hostheader":
		return true, "no correlation constraint"
	case "hpp":
		return true, "no correlation constraint"
	case "xxeinjection":
		return true, "no correlation constraint"
	case "cmdinject":
		if signals.hasModuleAtLeast("advanced-injection", 1) || signals.hasModuleAtLeast("nuclei-triage", 1) {
			return true, fmt.Sprintf("injection scout lead available (strength=%d)", maxCorrelationStrength(signals, "advanced-injection", "nuclei-triage"))
		}
		if strings.TrimSpace(rs.URLs.All) != "" {
			return true, "URL corpus available for command injection probe"
		}
		return false, "needs URL corpus or injection scout lead"
	case "rxss":
		return strings.TrimSpace(rs.URLs.All) != "", "URL corpus available for XSS probe"
	case "businesslogic":
		if signals.hasModuleAtLeast("advanced-injection", 1) || signals.hasModuleAtLeast("rxss", 1) {
			return true, "injection signal confirms input processing"
		}
		if strings.TrimSpace(rs.URLs.All) != "" {
			return true, "URL corpus available"
		}
		return false, "needs URL corpus"
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
	case "lfi":
		score += maxCorrelationStrength(signals, "info-disclosure", "exposed-files") * 40
		score += reconCorpusMatchCount(rs.URLs.All, []string{"file=", "page=", "path=", "template=", "include="}) * 10
	case "rxss":
		score += maxCorrelationStrength(signals, "open-redirect", "http-method-tampering") * 25
		score += reconCorpusMatchCount(rs.URLs.All, []string{"q=", "search=", "query=", "message=", "name=", "comment="}) * 8
	case "cmdinject":
		score += maxCorrelationStrength(signals, "advanced-injection", "nuclei-triage") * 50
		score += reconCorpusMatchCount(rs.URLs.All, []string{"cmd=", "exec=", "command=", "ping=", "host=", "ip="}) * 15
	case "hostheader":
		score += maxCorrelationStrength(signals, "open-redirect", "cors-poc") * 20
		score += reconCorpusMatchCount(rs.URLs.All, []string{"reset", "forgot", "password", "account"}) * 10
	case "hpp":
		score += maxCorrelationStrength(signals, "mutation-engine", "http-method-tampering") * 20
		score += reconCorpusMatchCount(rs.URLs.All, []string{"?"}) * 2
	case "xxeinjection":
		score += maxCorrelationStrength(signals, "advanced-injection", "info-disclosure") * 30
		score += reconCorpusMatchCount(rs.URLs.All, []string{"xml", "soap", "wsdl", "upload", "import"}) * 12
	case "businesslogic":
		score += reconCorpusMatchCount(rs.URLs.All, []string{"price=", "amount=", "qty=", "quantity=", "count=", "balance=", "credit=", "discount="}) * 15
		score += maxCorrelationStrength(signals, "session-abuse", "idor-playbook") * 15
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
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	lowered := make([]string, 0, len(needles))
	for _, needle := range needles {
		needle = strings.ToLower(strings.TrimSpace(needle))
		if needle != "" {
			lowered = append(lowered, needle)
		}
	}
	if len(lowered) == 0 {
		return 0
	}
	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(f)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		if lineCount > 100000 {
			break
		}
		line := strings.ToLower(scanner.Text())
		for _, needle := range lowered {
			if _, ok := seen[needle]; ok {
				continue
			}
			if strings.Contains(line, needle) {
				seen[needle] = struct{}{}
			}
		}
		if len(seen) == len(lowered) {
			break
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

func enrichReconSummaryFromSharedState(artDir string, rs *models.ReconSummary, state *exploit.SharedState) bool {
	if rs == nil || state == nil {
		return false
	}
	rawCount, ok := state.Get("schema.endpoint.count")
	if !ok {
		return false
	}
	count, err := strconv.Atoi(strings.TrimSpace(rawCount))
	if err != nil || count <= 0 {
		return false
	}

	urls := make([]string, 0, count)
	for i := 0; i < count; i++ {
		value, ok := state.Get(fmt.Sprintf("schema.endpoint.%d", i))
		if !ok {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(value))
		if len(fields) >= 2 {
			urls = append(urls, fields[1])
		}
	}
	if len(urls) == 0 {
		return false
	}

	targetPath := strings.TrimSpace(rs.URLs.All)
	if targetPath == "" {
		if strings.TrimSpace(artDir) == "" {
			return false
		}
		targetPath = filepath.Join(artDir, "schema_discovered_urls.txt")
	}

	existing := map[string]struct{}{}
	if f, err := os.Open(targetPath); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				existing[line] = struct{}{}
			}
		}
		_ = f.Close()
	}

	f, err := os.OpenFile(targetPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return false
	}
	defer f.Close()
	wrote := false
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if _, ok := existing[u]; ok {
			continue
		}
		if _, err := f.WriteString(u + "\n"); err == nil {
			existing[u] = struct{}{}
			wrote = true
		}
	}
	rs.URLs.All = targetPath
	return wrote || len(existing) > 0
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
		score["rxss"] = 28
		score["cmdinject"] = 30
		score["hostheader"] = 32
		score["xxeinjection"] = 33
		score["lfi"] = 35
		score["crlf-injection"] = 30
		score["ssrf-prober"] = 35
		score["rsql-injection"] = 40
		score["hpp"] = 42
		score["businesslogic"] = 43
	}
	if strings.TrimSpace(rs.URLs.All) != "" || strings.TrimSpace(rs.Intel.EndpointsRankedJSON) != "" {
		score["lfi"] = 35
		score["rxss"] = 28
		score["cmdinject"] = 30
		score["xxeinjection"] = 33
		score["hpp"] = 42
		score["businesslogic"] = 43
	}
	if strings.TrimSpace(rs.Live) != "" {
		score["hostheader"] = 32
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
			"max_parallel":                        opt.MaxParallel,
			"min_severity":                        opt.MinSeverity,
			"skip_modules":                        opt.SkipModules,
			"only_modules":                        opt.OnlyModules,
			"validation_only":                     opt.ValidationOnly,
			"report_formats":                      opt.ReportFormats,
			"rate_limit_rps":                      opt.RateLimitRPS,
			"http_max_inflight":                   resolvedHTTPMaxInFlight(opt),
			"http_jitter_ms":                      opt.HTTPJitterMS,
			"http_circuit_breaker_threshold":      opt.HTTPCircuitBreakerThreshold,
			"http_circuit_breaker_cooldown_ms":    opt.HTTPCircuitBreakerCooldownMS,
			"http_circuit_breaker_wait":           opt.HTTPCircuitBreakerWait,
			"http_adaptive_throttle":              true,
			"module_timeout_sec":                  opt.ModuleTimeoutSec,
			"module_retries":                      opt.ModuleRetries,
			"aggressive_mode":                     opt.AggressiveMode,
			"proof_mode":                          opt.ProofMode,
			"oob_http_listen_addr":                opt.OOBHTTPListenAddr,
			"oob_http_public_base_url":            opt.OOBHTTPPublicBaseURL,
			"oob_provider":                        resolvedOOBProviderLabel(opt),
			"skip_nuclei":                         opt.SkipNuclei,
			"webhook_findings":                    opt.WebhookFindings,
			"webhook_module_progress":             opt.WebhookModuleProgress,
			"webhook_findings_min_severity":       opt.WebhookFindingsMinSeverity,
			"has_auth_user_context":               strings.TrimSpace(opt.AuthUserCookie) != "" || strings.TrimSpace(opt.AuthUserHeaders) != "",
			"has_auth_admin_context":              strings.TrimSpace(opt.AuthAdminCookie) != "" || strings.TrimSpace(opt.AuthAdminHeaders) != "",
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

func loadBrowserWorkflowSignals(rs models.ReconSummary) browserWorkflowSignals {
	workdir := strings.TrimSpace(rs.Workdir)
	if workdir == "" {
		return browserWorkflowSignals{}
	}
	artifact, err := browsercapture.LoadArtifact(filepath.Join(workdir, "browser_capture_artifact.json"))
	if err != nil {
		return browserWorkflowSignals{}
	}
	signals := browserWorkflowSignals{
		Available:        len(artifact.Requests) > 0 || len(artifact.Routes) > 0 || len(artifact.Forms) > 0 || len(artifact.Workflows) > 0,
		RouteCount:       len(artifact.Routes),
		FormCount:        len(artifact.Forms),
		RecordedWorkflow: len(artifact.Workflows),
	}
	for _, wf := range artifact.Workflows {
		for _, step := range wf.Steps {
			kind := strings.ToLower(strings.TrimSpace(step.Kind))
			method := strings.ToUpper(strings.TrimSpace(step.Method))
			target := strings.ToLower(strings.TrimSpace(step.URL))
			fieldsJoined := strings.Join(step.Fields, ",")
			if kind == "request" || kind == "form" {
				signals.RequestSteps++
			}
			if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete || kind == "form" {
				signals.WriteSteps++
			}
			if strings.Contains(target, "upload") || strings.Contains(target, "import") || strings.Contains(target, "avatar") || strings.Contains(fieldsJoined, "file") || strings.Contains(fieldsJoined, "image") {
				signals.UploadSteps++
			}
			if strings.Contains(target, "query") || strings.Contains(target, "search") || strings.Contains(target, "filter") || strings.Contains(fieldsJoined, "query") || strings.Contains(fieldsJoined, "search") || strings.Contains(fieldsJoined, "filter") || strings.Contains(fieldsJoined, "id") || strings.Contains(fieldsJoined, "sort") {
				signals.QueryLikeSteps++
			}
			if strings.Contains(target, "token") || strings.Contains(target, "oauth") || strings.Contains(target, "login") || strings.Contains(target, "auth") || strings.Contains(fieldsJoined, "token") || strings.Contains(fieldsJoined, "authorization") {
				signals.AuthLikeSteps++
			}
			if strings.Contains(target, "url=") || strings.Contains(target, "uri=") || strings.Contains(target, "redirect=") || strings.Contains(target, "next=") || strings.Contains(target, "/proxy") || strings.Contains(target, "/fetch") || strings.Contains(target, "/render") || strings.Contains(fieldsJoined, "url") || strings.Contains(fieldsJoined, "uri") || strings.Contains(fieldsJoined, "callback") || strings.Contains(fieldsJoined, "dest") {
				signals.SSRFLikeSteps++
			}
		}
	}
	return signals
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

func resolvedHTTPMaxInFlight(opt Options) int {
	maxParallel := opt.MaxParallel
	if maxParallel <= 0 {
		maxParallel = exploit.DefaultMaxParallel
	}
	derived := maxParallel * 2
	if opt.RateLimitRPS > 0 && opt.RateLimitRPS < derived {
		derived = opt.RateLimitRPS
	}
	if derived < 2 {
		derived = 2
	}
	if derived > 64 {
		derived = 64
	}
	return derived
}

func newOOBProvider(opt Options) (oob.Provider, string, error) {
	if strings.TrimSpace(opt.OOBHTTPPublicBaseURL) != "" {
		p, err := oob.NewHTTPProvider(opt.OOBHTTPListenAddr, opt.OOBHTTPPublicBaseURL)
		if err != nil {
			return nil, "", err
		}
		return p, "builtin-http", nil
	}
	p, err := oob.NewInteractshProvider()
	if err != nil {
		return nil, "", err
	}
	return p, "interactsh", nil
}

func resolvedOOBProviderLabel(opt Options) string {
	if strings.TrimSpace(opt.OOBHTTPPublicBaseURL) != "" {
		return "builtin-http"
	}
	if opt.AggressiveMode || opt.ProofMode {
		return "interactsh"
	}
	return "disabled"
}
