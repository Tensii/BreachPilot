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
	"breachpilot/internal/exploit/discovery"
	"breachpilot/internal/exploit/filter"
	"breachpilot/internal/exploit/httppolicy"
	adminsurface "breachpilot/internal/exploit/modules/adminsurface"
	advancedinjection "breachpilot/internal/exploit/modules/advancedinjection"
	apisurface "breachpilot/internal/exploit/modules/apisurface"
	authbypass "breachpilot/internal/exploit/modules/authbypass"
	authpolicy "breachpilot/internal/exploit/modules/authpolicy"
	autoregister "breachpilot/internal/exploit/modules/autoregister"
	businesslogic "breachpilot/internal/exploit/modules/businesslogic"
	bypasspoc "breachpilot/internal/exploit/modules/bypasspoc"
	cmdinject "breachpilot/internal/exploit/modules/cmdinject"
	cookiesecurity "breachpilot/internal/exploit/modules/cookiesecurity"
	cors "breachpilot/internal/exploit/modules/cors"
	crlfinjection "breachpilot/internal/exploit/modules/crlfinjection"
	cryptoaudit "breachpilot/internal/exploit/modules/cryptoaudit"
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
	idor "breachpilot/internal/exploit/modules/idor"
	idorplaybook "breachpilot/internal/exploit/modules/idorplaybook"
	idorsize "breachpilot/internal/exploit/modules/idorsize"
	infodisclosure "breachpilot/internal/exploit/modules/infodisclosure"
	jsendpoints "breachpilot/internal/exploit/modules/jsendpoints"
	jwtaccess "breachpilot/internal/exploit/modules/jwtaccess"
	ldapinject "breachpilot/internal/exploit/modules/ldapinject"
	lfi "breachpilot/internal/exploit/modules/lfi"
	massassign "breachpilot/internal/exploit/modules/massassign"
	mutationengine "breachpilot/internal/exploit/modules/mutationengine"
	nucleitriage "breachpilot/internal/exploit/modules/nucleitriage"
	openredirect "breachpilot/internal/exploit/modules/openredirect"
	portservice "breachpilot/internal/exploit/modules/portservice"
	privpath "breachpilot/internal/exploit/modules/privpath"
	racecondition "breachpilot/internal/exploit/modules/racecondition"
	ratelimit "breachpilot/internal/exploit/modules/ratelimit"
	rsqlinjection "breachpilot/internal/exploit/modules/rsqlinjection"
	rxss "breachpilot/internal/exploit/modules/rxss"
	samlprobe "breachpilot/internal/exploit/modules/samlprobe"
	schemaprobe "breachpilot/internal/exploit/modules/schemaprobe"
	secretsvalidator "breachpilot/internal/exploit/modules/secretsvalidator"
	sessionabuse "breachpilot/internal/exploit/modules/sessionabuse"
	smuggling "breachpilot/internal/exploit/modules/smuggling"
	ssrfprober "breachpilot/internal/exploit/modules/ssrfprober"
	sstiprober "breachpilot/internal/exploit/modules/sstiprober"
	statechange "breachpilot/internal/exploit/modules/statechange"
	subt "breachpilot/internal/exploit/modules/subt"
	tlsaudit "breachpilot/internal/exploit/modules/tlsaudit"
	tokenleakage "breachpilot/internal/exploit/modules/tokenleakage"
	sqliprober "breachpilot/internal/exploit/modules/sqliprober"
	uploadabuse "breachpilot/internal/exploit/modules/uploadabuse"
	xxeinjection "breachpilot/internal/exploit/modules/xxeinjection"
	oob "breachpilot/internal/exploit/oob"
	sessionrt "breachpilot/internal/exploit/session"
	"breachpilot/internal/exploit/waf"
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
	progressFractionRE    = regexp.MustCompile(`(?i)\b(\d+)\s*/\s*(\d+)\s*(?:\((\d{1,3})%\))?`)
	progressPercentRE     = regexp.MustCompile(`(?i)\b(\d{1,3})%\b`)
	reconCorpusMatchMu    sync.Mutex
	reconCorpusMatchCache = map[string]int{}
	workflowSignalCacheMu sync.Mutex
	workflowSignalCache   = map[string]browserWorkflowSignals{}
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
	InteractshNotifier             Notifier
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
	SafeMode                       bool
	AggressiveMode                 bool
	BoundlessMode                  bool
	ProofMode                      bool
	ProofTargetAllowlist           string
	OOBHTTPListenAddr              string
	OOBHTTPPublicBaseURL           string
	OOBPollWaitSec                 int
	OOBSweepWaitSec                int
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
	SharedState                    *exploit.SharedState
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
		if fromSummary := strings.TrimSpace(rs.Target); fromSummary != "" {
			job.Target = fromSummary
		} else if guessed := ingest.TargetFromWorkdir(rs.Workdir); guessed != "" {
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
	rankedSeed := rs.Intel.EndpointsRankedJSON
	if strings.TrimSpace(rankedSeed) == "" {
		rankedSeed = firstNonEmptyString(rs.Intel.URLsRevalidatedJSON, rs.Intel.URLsDiscoveredJSON)
	}
	if rankedInput, rankedCount := buildRankedNucleiInput(rankedSeed, artDir); rankedCount > 0 {
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
	if filteredInput, filteredCount, droppedHosts := buildErrorAwareNucleiInput(nucleiInput, outErrors, artDir); filteredCount > 0 {
		nucleiInput = filteredInput
		nucleiTargetsTotal = filteredCount
		emit(models.RuntimeEvent{
			Kind:    "stage",
			Stage:   "exploit.targeting",
			Status:  "info",
			Message: fmt.Sprintf("exploit.targeting host-error-aware pruning applied: dropped_hosts=%d targets=%d", droppedHosts, filteredCount),
			Target:  job.Target,
			Counts: map[string]int{
				"dropped_hosts":  droppedHosts,
				"nuclei_targets": filteredCount,
			},
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
	} else if !sm.IsNucleiCompleted() && errOut == nil && stOut.Size() > 0 {
		// Partial nuclei results exist from a previous interrupted run.
		resumeCfg := sm.State().NucleiResumeCfg
		if resumeCfg != "" && fileExists(resumeCfg) {
			notify("exploit.nuclei.resumed")
			exploitStart := time.Now()
			nucleiCtx := ctx
			cancelNuclei := func() {}
			nucleiTimeoutSec := effectiveNucleiTimeoutSec(opt)
			if nucleiTimeoutSec > 0 {
				nucleiCtx, cancelNuclei = context.WithTimeout(ctx, time.Duration(nucleiTimeoutSec)*time.Second)
			}
			defer cancelNuclei()

			// Use native nuclei resume
			resumeArgs := []string{"-resume", resumeCfg}
			cmd := exec.CommandContext(nucleiCtx, opt.NucleiBin, resumeArgs...)
			logFile, err := os.OpenFile(outLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
				job.ExploitDurationSec += time.Since(exploitStart).Seconds()
				if ctx.Err() == context.Canceled || nucleiCtx.Err() == context.DeadlineExceeded {
					// Interrupted again, try to copy new resume.cfg
					newCfg := copyNucleiResumeCfg(outLog, artDir)
					if newCfg != "" {
						_ = sm.SetNucleiResumeCfg(newCfg)
					}
					if ctx.Err() == context.Canceled {
						job.Status = models.JobCancelled
						job.FinishedAt = time.Now().UTC()
						setJobError(job, "cancelled", "job cancelled")
						_ = writeJobReport(job, opt.ArtifactsRoot)
						return nil
					}
					job.Status = models.JobFailed
					job.FinishedAt = time.Now().UTC()
					setJobError(job, ErrTimeout, "nuclei timeout exceeded")
					_ = writeJobReport(job, opt.ArtifactsRoot)
					return nil
				}
				emit(models.RuntimeEvent{
					Kind:    "stage",
					Stage:   "exploit",
					Status:  "warning",
					Message: "exploit.warning nuclei exited non-zero with partial results; continuing",
					Target:  job.Target,
				})
				setJobError(job, ErrExecution, fmt.Sprintf("nuclei exited non-zero; partial results accepted: %v", nucleiErr))
			} else {
				job.ExploitDurationSec += time.Since(exploitStart).Seconds()
			}
			_ = sm.MarkNucleiCompleted()
		} else {
			// No resume.cfg available, accept partial findings
			notify("exploit.nuclei.partial-resume")
			_ = sm.MarkNucleiCompleted()
		}
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

			// Extract and save resume.cfg path
			cfgPath := copyNucleiResumeCfg(outLog, artDir)
			if cfgPath != "" {
				_ = sm.SetNucleiResumeCfg(cfgPath)
			}

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
	notify("exploit.nuclei.completed")

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

	sharedState := exploit.NewSharedState()
	opt.SharedState = sharedState
	httpMaxInFlight := resolvedHTTPMaxInFlight(opt)
	httpRuntime := httppolicy.NewRuntime(ctx, httppolicy.Config{
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
	probeRuntimeBaseline(ctx, job, rs, httpRuntime)
	populateTechSharedState(sharedState, rs.Tech, httpRuntime)
	scoutModules = injectTechDrivenScoutModules(scoutModules, sharedState, registeredAllModuleInstances())
	techHints := discovery.TechHints{
		IsWordPress: sharedState.HasPrefix("tech.cms", "wordpress"),
		IsSpring:    sharedState.HasPrefix("tech.framework", "spring"),
		IsLaravel:   sharedState.HasPrefix("tech.framework", "laravel"),
		IsDrupal:    sharedState.HasPrefix("tech.cms", "drupal"),
		HasGraphQL:  sharedState.IsSet("tech.graphql"),
		WAFDetected: sharedState.IsSet("tech.waf_detected"),
	}
	wafProfile := waf.FromSharedState(sharedState)
	var wafProfileRef *waf.Profile
	if wafProfile.Detected {
		wafProfileRef = &wafProfile
	}

	authBootstrapModules, scoutModules := splitAuthBootstrapModules(scoutModules)
	scoutStages, scoutStagePreview := buildDependencyStages(scoutModules)
	job.PlanPreview = append(job.PlanPreview, scoutStagePreview...)
	if len(authBootstrapModules) > 0 {
		bootstrapNames := moduleNames(authBootstrapModules)
		emit(models.RuntimeEvent{
			Kind:     "module",
			Stage:    "exploit.module",
			Status:   "planned",
			Message:  "exploit.module.wave0 " + strings.Join(bootstrapNames, ","),
			Target:   job.Target,
			Counts:   map[string]int{"planned": len(authBootstrapModules)},
			Progress: runtimeStageProgress("modules", "modules", 0, len(authBootstrapModules)),
		})
	}
	if len(scoutStages) > 0 {
		scoutNames := moduleNames(flattenModuleStages(scoutStages))
		emit(models.RuntimeEvent{
			Kind:     "module",
			Stage:    "exploit.module",
			Status:   "planned",
			Message:  "exploit.module.wave1 " + strings.Join(scoutNames, ","),
			Target:   job.Target,
			Counts:   map[string]int{"planned": len(scoutModules)},
			Progress: runtimeStageProgress("modules", "modules", 0, len(scoutModules)),
		})
		for idx, stage := range scoutStages {
			stageNames := moduleNames(stage)
			emit(models.RuntimeEvent{
				Kind:     "module",
				Stage:    "exploit.module",
				Status:   "planned",
				Message:  fmt.Sprintf("exploit.module.wave1.stage%d %s", idx+1, strings.Join(stageNames, ",")),
				Target:   job.Target,
				Counts:   map[string]int{"planned": len(stage)},
				Progress: runtimeStageProgress("modules", "modules", 0, len(stage)),
			})
		}
	}

	// Initialize OOB Provider
	var oobProvider oob.Provider
	if shouldInitializeOOBProvider(opt, scoutModules, proofModules) {
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
		DiscoveryHints:                 techHints,
		SharedState:                    sharedState,
		WAFProfile:                     wafProfileRef,
		OOBProvider:                    oobProvider,
		OOBSweepWaitSec:                opt.OOBSweepWaitSec,
	}

	scoutFindings := make([]models.ExploitFinding, 0, 64)
	scoutTelemetry := make([]models.ExploitModuleTelemetry, 0, len(authBootstrapModules)+len(scoutModules))

	// Bootstrap auth-producing modules first so auth-sensitive modules can consume
	// observed context generated during this run instead of relying on static config.
	if len(authBootstrapModules) > 0 {
		bootstrapOpt := exploitOpt
		bootstrapOpt.MaxParallel = 1
		bootstrapFindings, bootstrapTelemetry := exploit.RunModules(ctx, job, &rs, bootstrapOpt, authBootstrapModules)
		scoutFindings = append(scoutFindings, bootstrapFindings...)
		scoutTelemetry = append(scoutTelemetry, bootstrapTelemetry...)
	}

	authObserved := applyObservedAuthFromSharedState(&exploitOpt, sharedState)
	emit(models.RuntimeEvent{
		Kind:    "module",
		Stage:   "exploit.auth-context",
		Status:  "ready",
		Message: fmt.Sprintf("exploit.auth-context user=%t admin=%t distinct=%t quality=%d source=%s", authObserved.HasUser, authObserved.HasAdmin, authObserved.DistinctContexts, authObserved.QualityScore, authObserved.Source),
		Target:  job.Target,
		Counts: map[string]int{
			"auth_user_context":  boolToInt(authObserved.HasUser),
			"auth_admin_context": boolToInt(authObserved.HasAdmin),
			"auth_distinct":      boolToInt(authObserved.DistinctContexts),
			"auth_quality_score": authObserved.QualityScore,
		},
	})

	if len(scoutStages) > 0 {
		for idx, stage := range scoutStages {
			if len(stage) == 0 {
				continue
			}
			emit(models.RuntimeEvent{
				Kind:    "module",
				Stage:   "exploit.module",
				Status:  "started",
				Message: fmt.Sprintf("exploit.module.wave1.stage%d.start %s", idx+1, strings.Join(moduleNames(stage), ",")),
				Target:  job.Target,
			})
			waveFindings, waveTelemetry := exploit.RunModules(ctx, job, &rs, exploitOpt, stage)
			scoutFindings = append(scoutFindings, waveFindings...)
			scoutTelemetry = append(scoutTelemetry, waveTelemetry...)
		}
	}
	enrichReconSummaryFromSharedState(artDir, &rs, sharedState)
	enrichURLCorpusFromSharedState(&rs, sharedState)
	scoutSignals := buildCorrelationSignals(scoutFindings)
	mergedSignals := mergeCorrelationSignals(persistedSignals, scoutSignals)
	_ = saveCorrelationSignalsArtifact(artDir, mergedSignals)
	precisionPriors := loadModulePrecisionPriors(opt.PreviousReportPath)
	correlatedProofModules, correlationSkipped, correlationPreview := correlateProofModules(proofModules, mergedSignals, rs, opt, precisionPriors)
	job.PlanPreview = append(job.PlanPreview, correlationPreview...)
	correlatedProofModules = prioritizeProofModules(correlatedProofModules, mergedSignals, rs, precisionPriors)
	correlatedProofModules, authQualitySkipped, authQualityPreview := filterModulesByAuthContextQuality(correlatedProofModules, authObserved)
	job.PlanPreview = append(job.PlanPreview, authQualityPreview...)
	proofStages, proofStagePreview := buildDependencyStages(correlatedProofModules)
	job.PlanPreview = append(job.PlanPreview, proofStagePreview...)
	proofNames := moduleNames(flattenModuleStages(proofStages))
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
		for idx, stage := range proofStages {
			stageNames := moduleNames(stage)
			emit(models.RuntimeEvent{
				Kind:     "module",
				Stage:    "exploit.module",
				Status:   "planned",
				Message:  fmt.Sprintf("exploit.module.wave2.stage%d %s", idx+1, strings.Join(stageNames, ",")),
				Target:   job.Target,
				Counts:   map[string]int{"planned": len(stage)},
				Progress: runtimeStageProgress("modules", "modules", 0, len(stage)),
			})
		}
	}
	_ = applyObservedAuthFromSharedState(&exploitOpt, sharedState)

	// Keep a live-updated signal set that grows as proof stages complete.
	liveSignals := mergedSignals // start from merged scout signals

	// Track modules that were correlation-skipped so we can re-evaluate them.
	reEvalPool := make([]exploit.Module, 0, len(correlationSkipped))
	for _, t := range correlationSkipped {
		// Recover the module instance from the registered list.
		if m := findRegisteredModule(t.Module); m != nil {
			reEvalPool = append(reEvalPool, m)
		}
	}

	proofFindings := make([]models.ExploitFinding, 0, 64)
	proofTelemetry := make([]models.ExploitModuleTelemetry, 0, len(correlatedProofModules))
	executedProof := map[string]struct{}{}

	for idx := 0; idx < len(proofStages); idx++ {
		stage := proofStages[idx]
		if len(stage) == 0 {
			continue
		}
		emit(models.RuntimeEvent{
			Kind:    "module",
			Stage:   "exploit.module",
			Status:  "started",
			Message: fmt.Sprintf("exploit.module.wave2.stage%d.start %s", idx+1, strings.Join(moduleNames(stage), ",")),
			Target:  job.Target,
		})
		stageFindings, stageTelemetry := exploit.RunModules(ctx, job, &rs, exploitOpt, stage)
		proofFindings = append(proofFindings, stageFindings...)
		proofTelemetry = append(proofTelemetry, stageTelemetry...)
		for _, m := range stage {
			executedProof[strings.ToLower(strings.TrimSpace(m.Name()))] = struct{}{}
		}

		// Live re-correlation: grow signals with new proof findings and re-check
		// previously skipped modules.
		if len(stageFindings) > 0 && len(reEvalPool) > 0 && ctx.Err() == nil {
			newSignals := buildCorrelationSignals(stageFindings)
			liveSignals = mergeCorrelationSignals(liveSignals, newSignals)
			_ = saveCorrelationSignalsArtifact(artDir, liveSignals)

			var stillSkipped []exploit.Module
			var nowReady []exploit.Module
			for _, m := range reEvalPool {
				if m == nil {
					continue
				}
				name := strings.ToLower(strings.TrimSpace(m.Name()))
				if _, done := executedProof[name]; done {
					continue
				}
				ready, reason := moduleReadyByCorrelation(name, liveSignals, rs, opt, precisionPriors)
				if ready {
					nowReady = append(nowReady, m)
					emit(models.RuntimeEvent{
						Kind:    "module",
						Stage:   "exploit.module",
						Status:  "planned",
						Message: fmt.Sprintf("exploit.module.wave2.live-unlock %s: %s", m.Name(), reason),
						Target:  job.Target,
					})
				} else {
					stillSkipped = append(stillSkipped, m)
				}
			}
			reEvalPool = stillSkipped
			if len(nowReady) > 0 {
				// Prioritize and append as a new stage.
				nowReady = prioritizeProofModules(nowReady, liveSignals, rs, precisionPriors)
				proofStages = append(proofStages, nowReady)
			}
		}
	}
	// Persist final live signals so operators can audit module selection decisions.
	finalProofSignals := buildCorrelationSignals(proofFindings)
	finalMerged := mergeCorrelationSignals(liveSignals, finalProofSignals)
	_ = saveCorrelationSignalsArtifact(artDir, finalMerged)

	exploitFindings := append(scoutFindings, proofFindings...)
	telemetry := append(scoutTelemetry, proofTelemetry...)
	job.ModuleTelemetry = append(append(append(telemetry, plannerSkipped...), correlationSkipped...), authQualitySkipped...)
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
		_ = persistOOBCorrelationSnapshot(artDir, oobProvider)
		// Poll repeatedly to reduce missed late callbacks and persist each hit batch.
		oobWait := opt.OOBPollWaitSec
		if oobWait <= 0 {
			oobWait = 20
		}
		emit(models.RuntimeEvent{
			Kind:    "oob",
			Stage:   "exploit.oob.verify",
			Status:  "polling",
			Message: fmt.Sprintf("Polling up to %ds for asynchronous OOB callbacks...", oobWait),
			Target:  job.Target,
		})

		collectedHits := make([]oob.Hit, 0, 16)
		seenHit := map[string]struct{}{}
		startedPolling := time.Now()
		pollEvery := 5 * time.Second
		for {
			if ctx.Err() != nil {
				break
			}
			hits, err := oobProvider.Poll(ctx)
			if err == nil && len(hits) > 0 {
				for _, hit := range hits {
					key := fmt.Sprintf("%s|%s|%s", hit.CorrelationMeta, hit.Protocol, hit.Timestamp.UTC().Format(time.RFC3339Nano))
					if _, ok := seenHit[key]; ok {
						continue
					}
					seenHit[key] = struct{}{}
					collectedHits = append(collectedHits, hit)

					// Real-time webhook push for interactsh interaction
					if opt.InteractshNotifier != nil {
						payload := map[string]any{
							"job_id":           job.ID,
							"target":           job.Target,
							"correlation_meta": hit.CorrelationMeta,
							"protocol":         hit.Protocol,
							"source_ip":        hit.SourceIP,
							"timestamp":        hit.Timestamp.UTC().Format(time.RFC3339Nano),
							"q_type":           hit.QType,
							"unique_id":        hit.UniqueID,
							"full_id":          hit.FullId,
							"raw_request":      hit.RawRequest,
							"raw_response":     hit.RawResponse,
						}
						if len(hit.AsnInfo) > 0 {
							payload["asn_info"] = hit.AsnInfo
						}
						opt.InteractshNotifier.SendGeneric("interactsh.interaction", payload)
					}
				}
				_ = appendOOBHits(artDir, hits)
			}
			if time.Since(startedPolling) >= time.Duration(oobWait)*time.Second {
				break
			}
			select {
			case <-ctx.Done():
			case <-time.After(pollEvery):
			}
		}

		if len(collectedHits) > 0 {
			emit(models.RuntimeEvent{
				Kind:    "oob",
				Stage:   "exploit.oob.verify",
				Status:  "hits",
				Message: fmt.Sprintf("Received %d OOB interaction(s)", len(collectedHits)),
				Target:  job.Target,
				Counts:  map[string]int{"oob_hits": len(collectedHits)},
			})

			for _, hit := range collectedHits {
				corr, hasCorr := oob.LookupCorrelation(oobProvider, hit.CorrelationMeta)
				moduleName := moduleFromCorrelationMeta(hit.CorrelationMeta, "oob-listener")
				if hasCorr && strings.TrimSpace(corr.Module) != "" {
					moduleName = corr.Module
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

				// Real-time webhook push for correlated interactsh finding
				if opt.InteractshNotifier != nil {
					opt.InteractshNotifier.SendGeneric("interactsh.finding", map[string]any{
						"job_id":           job.ID,
						"target":           job.Target,
						"correlation_meta": hit.CorrelationMeta,
						"finding":          oobFinding,
					})
				}
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

	exploitFindings = exploit.AutoReplayConfirmedFindingsWithContext(ctx, exploitFindings, exploitOpt)
	exploitFindings = applyAuthContextMatrix(exploitFindings, exploitOpt)
	exploitFindings = exploit.ApplyHybridQualityGates(exploitFindings)
	exploitFindings = exploit.PromoteConfidenceBandsOnMultiChannel(exploitFindings)
	leadFindings := exploit.AnnotateConfidenceBands(exploit.SignalOnlyFindings(exploitFindings))
	reliableFindings, reliabilityFiltered := exploit.FilterReliableFindings(exploitFindings)
	exploitFindings = reliableFindings
	exploitFindings = exploit.PrepareEvidenceBundles(exploitFindings, artDir)
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
						"confidence_band":         f.ConfidenceBand,
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
	_ = writeCalibrationArtifacts(rawExploitFindings, exploitFindings, artDir, job)
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
	notify("exploit.completed")
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
			// Ensure resumeDir is relative to cmd.Dir (plan.reconDir) so reconHarvest can find it.
			if rel, err := filepath.Rel(plan.reconDir, resumeDir); err == nil {
				resumeDir = rel
			}
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
	maxHostErrors := adaptiveNucleiMaxHostErrors(nucleiInput, outErrors)
	if job != nil && (strings.Contains(job.Target, "localhost") || strings.Contains(job.Target, "127.0.0.1")) {
		args = append(args, "-concurrency", "10", "-max-host-error", "10")
	} else {
		args = append(args, "-c", "35", "-bs", "25", "-max-host-error", strconv.Itoa(maxHostErrors))
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

func adaptiveNucleiMaxHostErrors(nucleiInput, outErrors string) int {
	maxHostErrors := 35
	targets := countLinesSafe(nucleiInput)
	switch {
	case targets > 150:
		maxHostErrors = 10
	case targets > 80:
		maxHostErrors = 14
	case targets > 40:
		maxHostErrors = 18
	}
	noisy := collectNoisyErrorHosts(outErrors, 8)
	if len(noisy) >= 8 && maxHostErrors > 10 {
		maxHostErrors = 10
	} else if len(noisy) >= 3 && maxHostErrors > 12 {
		maxHostErrors = 12
	}
	if maxHostErrors < 8 {
		maxHostErrors = 8
	}
	return maxHostErrors
}

func buildErrorAwareNucleiInput(nucleiInput, outErrors, artDir string) (string, int, int) {
	noisy := collectNoisyErrorHosts(outErrors, 15)
	if len(noisy) == 0 {
		return "", 0, 0
	}
	raw, err := os.ReadFile(nucleiInput)
	if err != nil {
		return "", 0, 0
	}
	lines := strings.Split(string(raw), "\n")
	kept := make([]string, 0, len(lines))
	droppedHosts := map[string]struct{}{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		host := nucleiTargetHost(line)
		if host != "" {
			if _, bad := noisy[host]; bad {
				droppedHosts[host] = struct{}{}
				continue
			}
		}
		kept = append(kept, line)
	}
	if len(droppedHosts) == 0 || len(kept) == 0 {
		return "", 0, 0
	}
	filteredPath := filepath.Join(artDir, "nuclei_targets_erroraware.txt")
	if err := os.WriteFile(filteredPath, []byte(strings.Join(kept, "\n")+"\n"), 0o644); err != nil {
		return "", 0, 0
	}
	return filteredPath, len(kept), len(droppedHosts)
}

type nucleiErrorLine struct {
	Address string `json:"address"`
	Error   string `json:"error"`
	Kind    string `json:"kind"`
}

func collectNoisyErrorHosts(path string, threshold int) map[string]int {
	out := map[string]int{}
	if strings.TrimSpace(path) == "" || threshold <= 0 {
		return out
	}
	file, err := os.Open(path)
	if err != nil {
		return out
	}
	defer file.Close()
	counts := map[string]int{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry nucleiErrorLine
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		host := hostFromAddress(entry.Address)
		if host == "" {
			continue
		}
		if !isSchedulingPenaltyError(entry) {
			continue
		}
		counts[host]++
	}
	for host, n := range counts {
		if n >= threshold {
			out[host] = n
		}
	}
	return out
}

func isSchedulingPenaltyError(e nucleiErrorLine) bool {
	kind := strings.ToLower(strings.TrimSpace(e.Kind))
	errText := strings.ToLower(strings.TrimSpace(e.Error))
	if strings.Contains(kind, "temporary") || strings.Contains(kind, "unknown") {
		return true
	}
	return strings.Contains(errText, "timeout") ||
		strings.Contains(errText, "deadline exceeded") ||
		strings.Contains(errText, "connection reset") ||
		strings.Contains(errText, "readstatusline: eof")
}

func hostFromAddress(addr string) string {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, "[") {
		if idx := strings.Index(addr, "]"); idx > 1 {
			return strings.TrimSpace(addr[1:idx])
		}
	}
	if strings.Count(addr, ":") == 1 {
		parts := strings.SplitN(addr, ":", 2)
		return strings.TrimSpace(parts[0])
	}
	return addr
}

func nucleiTargetHost(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	if parsed, err := url.Parse(line); err == nil && parsed != nil && parsed.Hostname() != "" {
		return strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	}
	if !strings.Contains(line, "://") {
		if parsed, err := url.Parse("http://" + line); err == nil && parsed != nil && parsed.Hostname() != "" {
			return strings.ToLower(strings.TrimSpace(parsed.Hostname()))
		}
	}
	return ""
}

func countLinesSafe(path string) int {
	n, err := countLines(path)
	if err != nil || n < 0 {
		return 0
	}
	return n
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
		host := strings.TrimSpace(parsed.Hostname())
		if host == "" {
			return
		}
		scheme := strings.ToLower(parsed.Scheme)
		port := parsed.Port()
		defaultPort := (scheme == "http" && port == "80") || (scheme == "https" && port == "443")
		normalized := scheme + "://" + host
		if port != "" && !defaultPort {
			normalized += ":" + port
		}
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
			for _, key := range []string{"url", "normalized_url", "final_url", "route", "page_url"} {
				if u, ok := m[key].(string); ok {
					appendURL(u)
				}
			}
			for _, key := range []string{"sample_urls", "concrete_urls", "raw_urls"} {
				if arr, ok := m[key].([]any); ok {
					for _, item := range arr {
						if u, ok := item.(string); ok {
							appendURL(u)
						}
					}
				}
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
				for _, key := range []string{"url", "normalized_url", "final_url", "route", "page_url"} {
					if u, ok := m[key].(string); ok {
						appendURL(u)
					}
				}
				for _, key := range []string{"sample_urls", "concrete_urls", "raw_urls"} {
					if arr2, ok := m[key].([]any); ok {
						for _, item := range arr2 {
							if u, ok := item.(string); ok {
								appendURL(u)
							}
						}
					}
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
	items = collapseNucleiTargets(items)
	out := filepath.Join(artDir, "nuclei_targets_ranked.txt")
	if err := os.WriteFile(out, []byte(strings.Join(items, "\n")+"\n"), 0o644); err != nil {
		log.Printf("warning: failed to write ranked nuclei targets: %v", err)
		return "", 0
	}
	return out, len(items)
}

func collapseNucleiTargets(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	originsByBase := make(map[string][]string)
	order := make([]string, 0, len(items))
	for _, item := range items {
		parsed, err := url.Parse(strings.TrimSpace(item))
		if err != nil || parsed == nil {
			continue
		}
		host := strings.TrimSpace(parsed.Hostname())
		if host == "" {
			continue
		}
		base := strings.ToLower(parsed.Scheme) + "://" + host
		if _, ok := originsByBase[base]; !ok {
			order = append(order, base)
		}
		originsByBase[base] = append(originsByBase[base], item)
	}

	out := make([]string, 0, len(originsByBase))
	for _, base := range order {
		candidates := originsByBase[base]
		keepBase := false
		fallbacks := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			parsed, err := url.Parse(candidate)
			if err != nil || parsed == nil {
				continue
			}
			port := parsed.Port()
			if port == "" || (parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443") {
				keepBase = true
				break
			}
			fallbacks = append(fallbacks, candidate)
		}
		if keepBase {
			out = append(out, base)
			continue
		}
		out = append(out, fallbacks...)
	}
	return out
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

func writeCalibrationArtifacts(rawFindings, acceptedFindings []models.ExploitFinding, artDir string, job *models.Job) error {
	if strings.TrimSpace(artDir) == "" {
		return nil
	}
	accepted := make(map[string]struct{}, len(acceptedFindings))
	for _, f := range acceptedFindings {
		accepted[exploit.FindingFingerprint(f)] = struct{}{}
	}

	type moduleAgg struct {
		Raw      int `json:"raw"`
		Accepted int `json:"accepted"`
		Rejected int `json:"rejected"`
	}
	moduleStats := map[string]*moduleAgg{}

	calPath := filepath.Join(artDir, "calibration_findings.jsonl")
	f, err := os.Create(calPath)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, finding := range rawFindings {
		key := exploit.FindingFingerprint(finding)
		_, ok := accepted[key]
		mod := strings.ToLower(strings.TrimSpace(finding.Module))
		if _, exists := moduleStats[mod]; !exists {
			moduleStats[mod] = &moduleAgg{}
		}
		moduleStats[mod].Raw++
		if ok {
			moduleStats[mod].Accepted++
		} else {
			moduleStats[mod].Rejected++
		}
		record := map[string]any{
			"job_id":          job.ID,
			"target":          job.Target,
			"module":          finding.Module,
			"severity":        strings.ToUpper(strings.TrimSpace(finding.Severity)),
			"validation":      strings.ToLower(strings.TrimSpace(finding.Validation)),
			"confidence":      finding.Confidence,
			"accepted":        ok,
			"title":           finding.Title,
			"url":             finding.Target,
			"evidence":        finding.Evidence,
			"risk_score":      finding.RiskScore.Final,
			"timestamp":       finding.Timestamp,
			"artifact_source": "exploit_pipeline",
		}
		if err := enc.Encode(record); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}

	type moduleSummary struct {
		Module         string  `json:"module"`
		Raw            int     `json:"raw"`
		Accepted       int     `json:"accepted"`
		Rejected       int     `json:"rejected"`
		PrecisionProxy float64 `json:"precision_proxy"`
	}
	outModules := make([]moduleSummary, 0, len(moduleStats))
	for module, st := range moduleStats {
		precision := 0.0
		if st.Raw > 0 {
			precision = float64(st.Accepted) / float64(st.Raw)
		}
		outModules = append(outModules, moduleSummary{
			Module:         module,
			Raw:            st.Raw,
			Accepted:       st.Accepted,
			Rejected:       st.Rejected,
			PrecisionProxy: mathRound(precision, 4),
		})
	}
	sort.Slice(outModules, func(i, j int) bool {
		if outModules[i].PrecisionProxy != outModules[j].PrecisionProxy {
			return outModules[i].PrecisionProxy > outModules[j].PrecisionProxy
		}
		if outModules[i].Accepted != outModules[j].Accepted {
			return outModules[i].Accepted > outModules[j].Accepted
		}
		return outModules[i].Module < outModules[j].Module
	})

	summary := map[string]any{
		"generated_at":        time.Now().UTC().Format(time.RFC3339),
		"job_id":              job.ID,
		"target":              job.Target,
		"raw_findings":        len(rawFindings),
		"accepted_findings":   len(acceptedFindings),
		"rejected_findings":   len(rawFindings) - len(acceptedFindings),
		"calibration_dataset": filepath.Base(calPath),
		"module_metrics":      outModules,
		"notes": []string{
			"precision_proxy is accepted/raw and should be calibrated against manually labeled truth sets",
			"use this summary to tune module thresholds and profile budgets over time",
		},
	}
	b, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(artDir, "calibration_summary.json"), b, 0o644)
}

func mathRound(v float64, places int) float64 {
	if places <= 0 {
		return float64(int(v + 0.5))
	}
	pow := 1.0
	for i := 0; i < places; i++ {
		pow *= 10
	}
	return float64(int(v*pow+0.5)) / pow
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

func moduleFromCorrelationMeta(meta, fallback string) string {
	meta = strings.ToLower(strings.TrimSpace(meta))
	if meta == "" {
		return fallback
	}
	token := meta
	if idx := strings.IndexRune(meta, '-'); idx > 0 {
		token = meta[:idx]
	}
	if token == "" {
		return fallback
	}
	for _, r := range token {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return fallback
		}
	}
	return token
}

func persistOOBCorrelationSnapshot(artDir string, provider oob.Provider) error {
	if strings.TrimSpace(artDir) == "" || provider == nil {
		return nil
	}
	snapshot := oob.SnapshotCorrelations(provider)
	if len(snapshot) == 0 {
		return nil
	}
	type row struct {
		CorrelationMeta string          `json:"correlation_meta"`
		Correlation     oob.Correlation `json:"correlation"`
	}
	rows := make([]row, 0, len(snapshot))
	for k, v := range snapshot {
		rows = append(rows, row{CorrelationMeta: k, Correlation: v})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].CorrelationMeta < rows[j].CorrelationMeta })
	payload := map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"rows":         rows,
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(artDir, "oob_correlations.json"), b, 0o644)
}

func appendOOBHits(artDir string, hits []oob.Hit) error {
	if strings.TrimSpace(artDir) == "" || len(hits) == 0 {
		return nil
	}
	path := filepath.Join(artDir, "oob_hits.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, hit := range hits {
		record := map[string]any{
			"protocol":         hit.Protocol,
			"source_ip":        hit.SourceIP,
			"correlation_meta": hit.CorrelationMeta,
			"raw_request":      hit.RawRequest,
			"raw_response":     hit.RawResponse,
			"q_type":           hit.QType,
			"unique_id":        hit.UniqueID,
			"full_id":          hit.FullId,
			"timestamp":        hit.Timestamp.UTC().Format(time.RFC3339Nano),
		}
		if len(hit.AsnInfo) > 0 {
			record["asn_info"] = hit.AsnInfo
		}
		if err := enc.Encode(record); err != nil {
			return err
		}
	}
	return nil
}

func applyAuthContextMatrix(findings []models.ExploitFinding, opt exploit.Options) []models.ExploitFinding {
	if len(findings) == 0 || opt.HTTPRuntime == nil {
		return findings
	}
	roles := sessionrt.BuildRoleContexts(opt.AuthAnonHeaders, opt.AuthUserHeaders, opt.AuthAdminHeaders, opt.AuthUserCookie, opt.AuthAdminCookie)
	if len(roles) == 0 {
		return findings
	}
	engine := sessionrt.New(5*time.Second, opt.HTTPRuntime)
	for i := range findings {
		if !isAuthSensitiveFinding(findings[i]) {
			continue
		}
		artifact, ok := loadProofArtifactForMatrix(findings[i].ArtifactPath)
		if !ok || len(artifact.Exchanges) == 0 {
			continue
		}
		probe := artifact.Exchanges[len(artifact.Exchanges)-1]
		method := strings.ToUpper(strings.TrimSpace(probe.RequestMethod))
		if method == "" {
			method = http.MethodGet
		}
		targetURL := strings.TrimSpace(probe.RequestURL)
		if targetURL == "" {
			targetURL = strings.TrimSpace(findings[i].Target)
		}
		if targetURL == "" {
			continue
		}
		spec := sessionrt.ProbeSpec{
			Method:  method,
			URL:     targetURL,
			Headers: probe.RequestHeaders,
			Body:    probe.RequestBody,
		}
		snaps := engine.Probe(spec, roles)
		if len(snaps) == 0 {
			continue
		}
		analysis := sessionrt.AnalyzeAccess(snaps)
		if findings[i].DynamicMetadata == nil {
			findings[i].DynamicMetadata = map[string]any{}
		}
		findings[i].DynamicMetadata["auth_matrix_reason"] = analysis.Reason
		findings[i].DynamicMetadata["auth_matrix_has_real_roles"] = analysis.HasRealRoleContexts
		findings[i].DynamicMetadata["auth_matrix_anon_allowed"] = analysis.AnonAllowed
		findings[i].DynamicMetadata["auth_matrix_user_allowed"] = analysis.UserAllowed
		findings[i].DynamicMetadata["auth_matrix_admin_allowed"] = analysis.AdminAllowed
		findings[i].DynamicMetadata["auth_matrix_user_matches_admin"] = analysis.UserMatchesAdmin
		findings[i].DynamicMetadata["auth_matrix_protected_from_anon"] = analysis.ProtectedFromAnon

		val := strings.ToLower(strings.TrimSpace(findings[i].Validation))
		if (val == "confirmed" || val == "weaponized") && !analysis.HasRealRoleContexts {
			findings[i].Validation = "verified"
			if findings[i].Confidence > 89 {
				findings[i].Confidence = 89
			}
		}
		if analysis.LikelyWeakBoundary {
			if val == "signal" {
				findings[i].Validation = "verified"
				if findings[i].Confidence < 82 {
					findings[i].Confidence = 82
				}
			}
		}
	}
	return findings
}

func isAuthSensitiveFinding(f models.ExploitFinding) bool {
	module := strings.ToLower(strings.TrimSpace(f.Module))
	switch module {
	case "auth-bypass", "idor-playbook", "idor-size", "state-change", "session-abuse", "privilege-path", "idor":
		return true
	}
	joined := strings.ToLower(strings.TrimSpace(f.Title + " " + f.Evidence))
	return strings.Contains(joined, "idor") ||
		strings.Contains(joined, "access control") ||
		strings.Contains(joined, "privilege") ||
		strings.Contains(joined, "csrf")
}

func loadProofArtifactForMatrix(path string) (exploit.ProofArtifact, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return exploit.ProofArtifact{}, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return exploit.ProofArtifact{}, false
	}
	var artifact exploit.ProofArtifact
	if err := json.Unmarshal(b, &artifact); err != nil {
		return exploit.ProofArtifact{}, false
	}
	return artifact, true
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
			isStage := false

			// Detect stage transitions from reconHarvest output
			if strings.Contains(line, "[*] Stage:") {
				isStage = true
				stageName := strings.TrimSpace(strings.TrimPrefix(strings.Split(line, "[STARTED]")[0], "[*] Stage:"))
				stageName = strings.TrimSpace(strings.Split(stageName, "[DONE]")[0])
				if w.eventCB != nil {
					w.eventCB(models.RuntimeEvent{
						Kind:      "stage",
						Stage:     "recon." + strings.ToLower(stageName),
						Status:    "running",
						Message:   line,
						Target:    w.target,
						Timestamp: time.Now().UTC(),
					})
				}
			}

			if w.cb != nil {
				w.cb(msg)
			}
			if w.eventCB != nil && !isStage {
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
		isStage := false
		// Detect stage transitions from reconHarvest output
		if strings.Contains(line, "[*] Stage:") {
			isStage = true
			stageName := strings.TrimSpace(strings.TrimPrefix(strings.Split(line, "[STARTED]")[0], "[*] Stage:"))
			stageName = strings.TrimSpace(strings.Split(stageName, "[DONE]")[0])
			if w.eventCB != nil {
				w.eventCB(models.RuntimeEvent{
					Kind:      "stage",
					Stage:     "recon." + strings.ToLower(stageName),
					Status:    "running",
					Message:   line,
					Target:    w.target,
					Timestamp: time.Now().UTC(),
				})
			}
		}

		if w.cb != nil {
			w.cb(msg)
		}
		if w.eventCB != nil && !isStage {
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
	// Parse once into the struct, then validate field presence via the decoded struct.
	if err := json.Unmarshal(b, &rs); err != nil {
		return rs, fmt.Errorf("parse summary json: %w", err)
	}
	// Detect if the user accidentally passed a .breachpilot.state file by checking
	// for a field that only state files have (job_id) and that summary files require (workdir).
	if strings.TrimSpace(rs.Workdir) == "" {
		// Check if this might be a state file by re-probing for job_id
		var probe struct {
			JobID string `json:"job_id"`
		}
		if jerr := json.Unmarshal(b, &probe); jerr == nil && probe.JobID != "" {
			return rs, fmt.Errorf("invalid recon summary: file appears to be a .breachpilot.state file (expected summary.json)")
		}
		return rs, fmt.Errorf("invalid recon summary: missing 'workdir' field")
	}
	// Schema version check via a lightweight probe (models.ReconSummary does not have this field).
	var schemaPeek struct {
		SchemaVersion string `json:"schema_version"`
	}
	if jerr := json.Unmarshal(b, &schemaPeek); jerr == nil {
		if sv := strings.TrimSpace(schemaPeek.SchemaVersion); sv != "" && sv != models.SchemaVersion {
			return rs, fmt.Errorf("incompatible schema_version: %s", sv)
		}
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
		summaryTarget := strings.TrimSpace(rs.Target)
		if summaryTarget == "" {
			summaryTarget = ingest.TargetFromWorkdir(rs.Workdir)
		}
		if summaryTarget != "" {
			normalizedRT := scope.NormalizeTargetForDir(rt)
			normalizedSummary := scope.NormalizeTargetForDir(summaryTarget)
			if !strings.EqualFold(normalizedSummary, normalizedRT) {
				return rs, fmt.Errorf(
					"resume target mismatch: summary=%s requested=%s (normalized summary=%s requested=%s)",
					summaryTarget, rt, normalizedSummary, normalizedRT,
				)
			}
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
		{"autoregister", "Automatically registers a new user via headless browser", true, "exploit-core"},
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
		{"idor_engine", "Dual-user automated IDOR detection engine", true, "exploit-core"},
		{"sstiprober", "Detects Server-Side Template Injection via math expressions", true, "exploit-core"},
		{"token-leakage", "Detects sensitive token leakage to third-parties (e.g. Bizible) and Host Header Injection on reset paths", true, "exploit-core"},
		{"sqliprober", "Rigorous baseline, boolean, timing, and OOB SQLi testing with control groups", true, "exploit-core"},
		{"ldapinject", "Detects LDAP injection in queries via boolean and error markers", true, "exploit-core"},
		{"ratelimit", "Detects lack of rate-limits or bypassable limits on auth surfaces", true, "exploit-core"},
		{"authpolicy", "Validates password policies and discovers username enumeration", true, "exploit-core"},
		{"cryptoaudit", "Reviews sensitive data transmission and crypto/HTTP downgrade issues", true, "context"},
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
		autoregister.New(),
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
		idor.New(),
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
		sstiprober.New(),
		tokenleakage.New(),
		sqliprober.New(),
		ldapinject.New(),
		ratelimit.New(),
		authpolicy.New(),
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
		cryptoaudit.New(),
	}
}

func registeredAllModuleInstances() []exploit.Module {
	all := make([]exploit.Module, 0, len(registeredExploitCoreModuleInstances())+len(registeredContextModuleInstances()))
	all = append(all, registeredContextModuleInstances()...)
	all = append(all, registeredExploitCoreModuleInstances()...)
	return all
}

// findRegisteredModule returns the module instance with the given name
// (case-insensitive) from the full registered list, or nil if not found.
func findRegisteredModule(name string) exploit.Module {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, m := range registeredAllModuleInstances() {
		if strings.ToLower(strings.TrimSpace(m.Name())) == name {
			return m
		}
	}
	return nil
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
	urlCorpus := reconURLCorpusPath(rs)
	hasURLs := strings.TrimSpace(urlCorpus) != ""
	hasRankedEndpoints := strings.TrimSpace(rs.Intel.EndpointsRankedJSON) != ""
	hasLiveHosts := strings.TrimSpace(rs.Live) != ""
	hasCORS := strings.TrimSpace(rs.Intel.CORSJSON) != ""
	hasSecrets := strings.TrimSpace(rs.Intel.SecretsJSON) != ""
	hasBypass := strings.TrimSpace(rs.Intel.BypassJSON) != ""
	hasNuclei := strings.TrimSpace(rs.Intel.NucleiPhase1JSONL) != ""
	hasSubT := strings.TrimSpace(rs.Intel.SubdomainTakeoverJSON) != ""
	hasJS := strings.TrimSpace(rs.Intel.JSEndpointsJSON) != ""
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
		if !hasCORS {
			return true, "URL corpus available; auth context will be inferred at runtime"
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
		if !hasURLs && !hasRankedEndpoints {
			return false, "requires URL or ranked endpoint corpus"
		}
		return true, "race condition candidates available; auth context inferred at runtime"
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
		return true, "proof prerequisites available; auth context inferred at runtime"
	case "saml-probe":
		if hasURLs {
			return true, "URL corpus available"
		}
		if strings.Contains(strings.ToLower(rs.Live), "saml") || strings.Contains(strings.ToLower(rs.Live), "sso") {
			return true, "SSO hints in live host inventory"
		}
		return false, "requires SSO hints or URL corpus"
	case "sstiprober", "ldapinject":
		return opt.AggressiveMode && (hasURLs || hasRankedEndpoints), "requires aggressive mode and URL or endpoint corpus"
	case "ratelimit":
		if opt.SafeMode {
			return false, "skipped in safe mode"
		}
		return hasURLs || hasRankedEndpoints, "URL or endpoint corpus available"
	case "authpolicy":
		return hasURLs || hasRankedEndpoints, "URL or endpoint corpus available"
	case "cryptoaudit":
		return hasURLs || hasLiveHosts, "URL or host corpus available"
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

// probeRuntimeBaseline performs one lightweight baseline request and stores
// derived technology signals on the runtime.
func probeRuntimeBaseline(ctx context.Context, job *models.Job, rs models.ReconSummary, rt *httppolicy.Runtime) {
	if rt == nil {
		return
	}
	target := strings.TrimSpace(rs.Target)
	if target == "" && job != nil {
		target = strings.TrimSpace(job.Target)
	}
	if target == "" || strings.EqualFold(target, "from-summary") {
		return
	}
	lower := strings.ToLower(target)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		target = "https://" + target
	}
	req, err := httppolicy.NewRequest(ctx, http.MethodGet, target, nil)
	if err != nil {
		return
	}
	resp, err := rt.Client(httppolicy.ClientOptions{
		Timeout:           httppolicy.DefaultTimeout,
		NoFollowRedirects: true,
	}).Do(req)
	if err != nil || resp == nil {
		return
	}
	rt.TechObserved = rt.ExtractTechFromResponse(resp)
}

// populateTechSharedState writes technology fingerprint data into
// the shared state bag so that all modules can query it without
// needing a direct TechFingerprint reference.
func populateTechSharedState(ss *exploit.SharedState, tf models.TechFingerprint, rt *httppolicy.Runtime) {
	if ss == nil {
		return
	}
	if rt != nil && rt.TechObserved.Server != "" {
		tf = mergeTechFingerprints(tf, rt.TechObserved)
	}
	if tf.Server != "" {
		ss.Set("tech.server", tf.Server)
	}
	if tf.WAF != "" {
		ss.Set("tech.waf", tf.WAF)
	}
	if tf.WAFDetected {
		ss.Set("tech.waf_detected", "1")
	}
	if tf.Framework != "" {
		ss.Set("tech.framework", tf.Framework)
	}
	if tf.CMS != "" {
		ss.Set("tech.cms", tf.CMS)
	}
	if tf.GraphQLDetected {
		ss.Set("tech.graphql", "1")
	}
	for _, lang := range tf.Languages {
		lang = strings.ToLower(strings.TrimSpace(lang))
		if lang == "" {
			continue
		}
		ss.Set("tech.lang."+lang, "1")
	}
	for _, jsf := range tf.JSFrameworks {
		jsf = strings.ToLower(strings.TrimSpace(jsf))
		if jsf == "" {
			continue
		}
		ss.Set("tech.jsfw."+jsf, "1")
	}
}

// mergeTechFingerprints overlays live observations on top of recon-provided
// technology metadata and merges list-like fields.
func mergeTechFingerprints(base, live models.TechFingerprint) models.TechFingerprint {
	if live.Server != "" {
		base.Server = live.Server
	}
	if live.PoweredBy != "" {
		base.PoweredBy = live.PoweredBy
	}
	if live.Framework != "" {
		base.Framework = live.Framework
	}
	if live.WAF != "" {
		base.WAF = live.WAF
	}
	if live.WAFDetected {
		base.WAFDetected = true
	}
	if live.GraphQLDetected {
		base.GraphQLDetected = true
	}
	base.Languages = mergeStringSlices(base.Languages, live.Languages)
	base.JSFrameworks = mergeStringSlices(base.JSFrameworks, live.JSFrameworks)
	base.Technologies = mergeStringSlices(base.Technologies, live.Technologies)
	return base
}

// mergeStringSlices combines two string slices while preserving first-seen order.
func mergeStringSlices(a, b []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(a, b...) {
		k := strings.ToLower(strings.TrimSpace(s))
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, s)
	}
	return out
}

// injectTechDrivenScoutModules appends modules that should always
// run in the scout phase when a specific technology is detected,
// even if they would not otherwise be scheduled.
func injectTechDrivenScoutModules(mods []exploit.Module, ss *exploit.SharedState, allRegistered []exploit.Module) []exploit.Module {
	if ss == nil {
		return mods
	}
	alreadyScheduled := map[string]bool{}
	for _, m := range mods {
		alreadyScheduled[strings.ToLower(m.Name())] = true
	}
	// If GraphQL is detected and graphql-abuse is not already a scout, inject it.
	if ss.IsSet("tech.graphql") && !alreadyScheduled["graphql-abuse"] {
		for _, m := range allRegistered {
			if strings.ToLower(m.Name()) == "graphql-abuse" {
				mods = append(mods, m)
				break
			}
		}
	}
	return mods
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
	modules      map[string]int
	scopeByKey   map[string]struct{}
	scopeOverlap map[string]int
}

func correlateProofModules(mods []exploit.Module, signals correlationSignals, rs models.ReconSummary, opt Options, priors map[string]float64) ([]exploit.Module, []models.ExploitModuleTelemetry, []string) {
	if len(mods) == 0 {
		return nil, nil, nil
	}
	planned := make([]exploit.Module, 0, len(mods))
	skipped := make([]models.ExploitModuleTelemetry, 0, len(mods))
	preview := make([]string, 0, len(mods)+1)
	preview = append(preview, fmt.Sprintf("Correlation planner evaluating %d proof module(s) from scout findings/signals", len(mods)))
	now := time.Now().UTC().Format(time.RFC3339)
	for _, m := range mods {
		ready, reason := moduleReadyByCorrelation(strings.ToLower(strings.TrimSpace(m.Name())), signals, rs, opt, priors)
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
	s := correlationSignals{
		modules:      make(map[string]int, len(findings)),
		scopeByKey:   map[string]struct{}{},
		scopeOverlap: map[string]int{},
	}
	moduleScopes := map[string]map[string]struct{}{}
	for _, f := range findings {
		name := strings.ToLower(strings.TrimSpace(f.Module))
		if name == "" {
			continue
		}
		strength := findingCorrelationStrength(f)
		if strength > s.modules[name] {
			s.modules[name] = strength
		}
		scope := correlationScopeKey(f.Target)
		if scope == "" {
			continue
		}
		k := name + "|" + scope
		s.scopeByKey[k] = struct{}{}
		if _, ok := moduleScopes[name]; !ok {
			moduleScopes[name] = map[string]struct{}{}
		}
		moduleScopes[name][scope] = struct{}{}
	}
	for a, aScopes := range moduleScopes {
		for b, bScopes := range moduleScopes {
			if a >= b {
				continue
			}
			overlap := 0
			for scope := range aScopes {
				if _, ok := bScopes[scope]; ok {
					overlap++
				}
			}
			if overlap > 0 {
				s.scopeOverlap[a+"|"+b] = overlap
				s.scopeOverlap[b+"|"+a] = overlap
			}
		}
	}
	// Chain-confirmed: when two modules both achieved strength >= 4 on the same
	// scope, mark them as chain-confirmed (strength 7) in the overlap map.
	for a, aStrength := range s.modules {
		if aStrength < 4 {
			continue
		}
		for b, bStrength := range s.modules {
			if a >= b || bStrength < 4 {
				continue
			}
			if s.scopeOverlap[a+"|"+b] > 0 {
				s.scopeOverlap[a+"|"+b] = 7
				s.scopeOverlap[b+"|"+a] = 7
			}
		}
	}
	return s
}

func mergeCorrelationSignals(parts ...correlationSignals) correlationSignals {
	merged := correlationSignals{
		modules:      map[string]int{},
		scopeByKey:   map[string]struct{}{},
		scopeOverlap: map[string]int{},
	}
	for _, part := range parts {
		for name, strength := range part.modules {
			if strength > merged.modules[name] {
				merged.modules[name] = strength
			}
		}
		for k := range part.scopeByKey {
			merged.scopeByKey[k] = struct{}{}
		}
		for k, v := range part.scopeOverlap {
			if v > merged.scopeOverlap[k] {
				merged.scopeOverlap[k] = v
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

func (s correlationSignals) hasScopeOverlap(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if a == "" || b == "" {
		return false
	}
	if s.scopeOverlap[a+"|"+b] > 0 {
		return true
	}
	return false
}

// chainStrength returns 7 if both modules have strength >= 4 on shared scope,
// otherwise returns the max individual strength.
func (s correlationSignals) chainStrength(a, b string) int {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if v := s.scopeOverlap[a+"|"+b]; v == 7 {
		return 7
	}
	if s.strength(a) > s.strength(b) {
		return s.strength(a)
	}
	return s.strength(b)
}

func findingCorrelationStrength(f models.ExploitFinding) int {
	strength := validationStrength(f.Validation)
	sev := strings.ToUpper(strings.TrimSpace(f.Severity))
	if band := strings.ToUpper(strings.TrimSpace(string(f.RiskScore.Band))); band != "" {
		sev = band
	}
	switch sev {
	case "CRITICAL":
		strength += 2
	case "HIGH":
		strength += 1
	}
	if strength > 8 {
		strength = 8
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

func correlationScopeKey(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return strings.ToLower(raw)
	}
	if strings.TrimSpace(u.Host) == "" {
		return strings.ToLower(raw)
	}
	p := strings.TrimSpace(u.EscapedPath())
	if p == "" {
		p = "/"
	}
	if len(p) > 1 && strings.HasSuffix(p, "/") {
		p = strings.TrimSuffix(p, "/")
	}
	return strings.ToLower(strings.TrimSpace(u.Host + p))
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

// precisionThresholdPass returns (true, reason) if the module has a stored
// precision prior above 0.70 AND has at least one signal of any strength,
// meaning historical accuracy justifies a lower bar.
func precisionThresholdPass(name string, priors map[string]float64, signals correlationSignals) (bool, string) {
	if len(priors) == 0 {
		return false, ""
	}
	name = strings.ToLower(strings.TrimSpace(name))
	p, ok := priors[name]
	if !ok || p < 0.70 {
		return false, ""
	}
	if signals.hasModule(name) || signals.strength(name) > 0 {
		return true, fmt.Sprintf("precision prior %.2f >= 0.70 with any signal — threshold relaxed", p)
	}
	return false, ""
}

func moduleReadyByCorrelation(name string, signals correlationSignals, rs models.ReconSummary, opt Options, priors ...map[string]float64) (bool, string) {
	wf := loadBrowserWorkflowSignals(rs)
	urlCorpus := reconURLCorpusPath(rs)
	hasScopedSignals := len(signals.scopeByKey) > 0
	ss := opt.SharedState
	techWAF := opt.SharedState != nil && opt.SharedState.IsSet("tech.waf_detected")
	techGraphQL := opt.SharedState != nil && (opt.SharedState.IsSet("tech.graphql") || rs.Tech.GraphQLDetected)
	techWordPress := opt.SharedState != nil && opt.SharedState.HasPrefix("tech.cms", "wordpress")
	techSpring := opt.SharedState != nil && opt.SharedState.HasPrefix("tech.framework", "spring")
	techLaravel := opt.SharedState != nil && opt.SharedState.HasPrefix("tech.framework", "laravel")
	techNode := opt.SharedState != nil && opt.SharedState.IsSet("tech.lang.node.js")
	hasObjectID := ss != nil && len(ss.GetAll("object.id.")) > 0
	hasUserID := ss != nil && func() bool {
		_, ok := ss.Get("user.id")
		return ok
	}()
	hasSwagger := ss != nil && func() bool {
		v, ok := ss.Get("swagger.url")
		return ok && v != ""
	}()
	hasCSRF := ss != nil && func() bool {
		v, ok := ss.Get("csrf.token")
		return ok && v != ""
	}()
	hasDiscoveredEndpoints := ss != nil && len(ss.GetAll("discovered.endpoint.")) > 0
	var precPriors map[string]float64
	if len(priors) > 0 {
		precPriors = priors[0]
	}
	if ok, reason := precisionThresholdPass(name, precPriors, signals); ok {
		return true, reason
	}
	switch name {
	case "graphql-abuse":
		if techGraphQL {
			return true, "GraphQL detected from tech fingerprint — direct probe without scout confirmation"
		}
		return true, "no correlation constraint"
	case "auth-bypass":
		if techWordPress {
			return true, "WordPress detected — auth bypass probe for REST API and xmlrpc"
		}
		globalStrong := signals.hasModuleAtLeast("cors-poc", 2) || signals.hasModuleAtLeast("open-redirect", 2) || signals.hasModuleAtLeast("session-abuse", 2) || signals.hasModuleAtLeast("privilege-path", 2)
		scopedStrong := (signals.hasModuleAtLeast("cors-poc", 2) && signals.hasScopeOverlap("cors-poc", "session-abuse")) ||
			(signals.hasModuleAtLeast("open-redirect", 2) && signals.hasScopeOverlap("open-redirect", "session-abuse")) ||
			(signals.hasModuleAtLeast("session-abuse", 2) && signals.hasScopeOverlap("session-abuse", "privilege-path")) ||
			(signals.hasModuleAtLeast("privilege-path", 2) && signals.hasScopeOverlap("privilege-path", "session-abuse"))
		if scopedStrong || (!hasScopedSignals && globalStrong) {
			return true, fmt.Sprintf("strong redirect/session/CORS scout lead available (strength=%d)", maxCorrelationStrength(signals, "cors-poc", "open-redirect", "session-abuse", "privilege-path"))
		}
		if strings.TrimSpace(rs.Intel.CORSJSON) != "" {
			return true, "CORS intel available without scout confirmation"
		}
		if hasCSRF {
			return true, "SharedState: CSRF token captured — auth bypass probe"
		}
		return false, "needs strong redirect/session/CORS lead from scouts"
	case "idor-playbook":
		globalStrong := signals.hasModuleAtLeast("privilege-path", 2) || signals.hasModuleAtLeast("session-abuse", 2) || signals.hasModuleAtLeast("graphql-abuse", 2) || signals.hasModuleAtLeast("js-endpoints", 1)
		scopedStrong := (signals.hasModuleAtLeast("privilege-path", 2) && signals.hasScopeOverlap("privilege-path", "session-abuse")) ||
			(signals.hasModuleAtLeast("session-abuse", 2) && signals.hasScopeOverlap("session-abuse", "graphql-abuse")) ||
			(signals.hasModuleAtLeast("graphql-abuse", 2) && signals.hasScopeOverlap("graphql-abuse", "js-endpoints"))
		if scopedStrong || (!hasScopedSignals && globalStrong) {
			return true, fmt.Sprintf("authorization/object-access scout lead available (strength=%d)", maxCorrelationStrength(signals, "privilege-path", "session-abuse", "graphql-abuse", "js-endpoints"))
		}
		if hasObjectID && hasUserID {
			return true, "SharedState: object ID + user ID captured — direct IDOR playbook"
		}
		return false, "needs strong privilege/session/graphql/object lead from scouts"
	case "state-change":
		globalStrong := signals.hasModuleAtLeast("session-abuse", 2) || signals.hasModuleAtLeast("cors-poc", 2) || signals.hasModuleAtLeast("graphql-abuse", 2) || signals.hasModuleAtLeast("js-endpoints", 1)
		scopedStrong := (signals.hasModuleAtLeast("session-abuse", 2) && signals.hasScopeOverlap("session-abuse", "js-endpoints")) ||
			(signals.hasModuleAtLeast("cors-poc", 2) && signals.hasScopeOverlap("cors-poc", "session-abuse")) ||
			(signals.hasModuleAtLeast("graphql-abuse", 2) && signals.hasScopeOverlap("graphql-abuse", "session-abuse"))
		if scopedStrong || (!hasScopedSignals && globalStrong) {
			return true, fmt.Sprintf("state-change lead available from scouts (strength=%d)", maxCorrelationStrength(signals, "session-abuse", "cors-poc", "graphql-abuse", "js-endpoints"))
		}
		if matches := reconCorpusMatchCount(urlCorpus, []string{"post", "put", "patch", "delete", "update", "settings", "profile", "account", "password", "billing"}); matches >= 2 {
			return true, fmt.Sprintf("multiple state-changing URL patterns detected in recon corpus (%d)", matches)
		}
		if wf.WriteSteps > 0 {
			return true, fmt.Sprintf("browser workflow retained %d write-like step(s)", wf.WriteSteps)
		}
		if hasObjectID && hasUserID {
			return true, "SharedState: object ID + user ID captured — state-change probe"
		}
		return false, "needs state-change lead from scouts or URL corpus"
	case "upload-abuse":
		if matches := reconCorpusMatchCount(urlCorpus, []string{"upload", "file", "attachment", "import", "avatar", "image"}); matches >= 2 {
			return true, fmt.Sprintf("multiple upload-oriented URL patterns detected (%d)", matches)
		}
		if wf.UploadSteps > 0 {
			return true, fmt.Sprintf("browser workflow retained %d upload-like step(s)", wf.UploadSteps)
		}
		return false, "needs upload-oriented URLs"
	case "mutation-engine":
		if techWAF {
			return true, "WAF detected — mutation engine required to find bypass vectors"
		}
		if signals.hasModuleAtLeast("bypass-poc", 2) || signals.hasModuleAtLeast("nuclei-triage", 1) || signals.hasModuleAtLeast("http-method-tampering", 1) {
			return true, fmt.Sprintf("mutation/bypass lead available from scouts (strength=%d)", maxCorrelationStrength(signals, "bypass-poc", "nuclei-triage", "http-method-tampering"))
		}
		return false, "needs bypass or method tampering scout lead"
	case "jwt-access":
		if techNode || techLaravel || techSpring {
			return true, fmt.Sprintf("framework detected that commonly uses JWT (%s) — direct probe", readTechFramework(opt.SharedState))
		}
		if signals.hasModuleAtLeast("session-abuse", 2) || signals.hasModuleAtLeast("secrets-validator", 2) {
			return true, fmt.Sprintf("auth token lead available from scouts (strength=%d)", maxCorrelationStrength(signals, "session-abuse", "secrets-validator"))
		}
		if matches := reconCorpusMatchCount(urlCorpus, []string{"jwt", "token", "oauth", "authorize", "login", "auth"}); matches >= 2 {
			return true, fmt.Sprintf("multiple token-oriented URL patterns detected (%d)", matches)
		}
		if wf.AuthLikeSteps > 0 {
			return true, fmt.Sprintf("browser workflow retained %d auth/token step(s)", wf.AuthLikeSteps)
		}
		hasURLs := strings.TrimSpace(urlCorpus) != ""
		if hasURLs && reconCorpusMatchCount(urlCorpus, []string{"api/", "auth/", "token", "session", "login", "authorize", "oauth"}) >= 1 {
			return true, "URL corpus has auth/API endpoint(s) — direct JWT probe"
		}
		if hasSwagger {
			return true, "SharedState: Swagger/OpenAPI spec captured — JWT scope probe"
		}
		return false, "needs token/auth lead from scouts or URL corpus"
	case "ssrf-prober":
		if signals.hasModuleAtLeast("open-redirect", 2) {
			return true, fmt.Sprintf("URL-forwarding lead available from open-redirect scout (strength=%d)", signals.strength("open-redirect"))
		}
		if paramCount := reconCorpusMatchCount(urlCorpus, []string{"url=", "uri=", "src=", "source=", "fetch=", "load=", "path=", "file=", "dest=", "destination=", "target=", "endpoint=", "proxy=", "callback=", "webhook=", "host=", "redirect=", "return=", "link=", "img=", "image="}); paramCount >= 1 {
			return true, fmt.Sprintf("URL corpus has %d SSRF-like parameter(s) — direct probe without scout confirmation", paramCount)
		}
		urlMatches := reconCorpusMatchCount(urlCorpus, []string{"url=", "uri=", "dest=", "redirect=", "next=", "/render", "/proxy", "/fetch", "/preview", "/image"})
		endpointMatches := reconCorpusMatchCount(rs.Intel.EndpointsRankedJSON, []string{"render", "proxy", "fetch", "url", "preview", "image"})
		if urlMatches+endpointMatches >= 2 {
			return true, fmt.Sprintf("stacked SSRF-oriented URL/endpoint patterns detected (%d)", urlMatches+endpointMatches)
		}
		if wf.SSRFLikeSteps > 0 {
			return true, fmt.Sprintf("browser workflow retained %d SSRF-style forwarding step(s)", wf.SSRFLikeSteps)
		}
		if hasDiscoveredEndpoints {
			return true, "SharedState: new endpoints discovered — SSRF pivot probe"
		}
		return false, "needs SSRF-style forwarding lead"
	case "crlf-injection":
		if signals.hasModuleAtLeast("open-redirect", 1) || signals.hasModuleAtLeast("http-method-tampering", 1) {
			return true, fmt.Sprintf("header/redirect manipulation lead available from scouts (strength=%d)", maxCorrelationStrength(signals, "open-redirect", "http-method-tampering"))
		}
		if signals.hasScopeOverlap("hostheader", "open-redirect") {
			return true, fmt.Sprintf("co-located hostheader+redirect (chain=%d) — CRLF probe", signals.chainStrength("hostheader", "open-redirect"))
		}
		return false, "needs redirect or header manipulation scout lead"
	case "advanced-injection", "rsql-injection":
		if techLaravel {
			return true, "Laravel detected — injection probe for Eloquent ORM endpoints"
		}
		if signals.hasModuleAtLeast("graphql-abuse", 2) || signals.hasModuleAtLeast("js-endpoints", 1) || signals.hasModuleAtLeast("nuclei-triage", 1) {
			return true, fmt.Sprintf("query/injection lead available from scouts (strength=%d)", maxCorrelationStrength(signals, "graphql-abuse", "js-endpoints", "nuclei-triage"))
		}
		paramMatches := reconCorpusMatchCount(rs.Intel.ParamsRankedJSON, []string{"id", "query", "search", "filter", "where", "sort"})
		endpointMatches := reconCorpusMatchCount(rs.Intel.EndpointsRankedJSON, []string{"search", "query", "filter", "graphql", "api"})
		if paramMatches+endpointMatches >= 2 {
			return true, fmt.Sprintf("stacked query-oriented parameter or endpoint patterns detected (%d)", paramMatches+endpointMatches)
		}
		needleMatches := reconCorpusNeedleMatchCount(rs.Intel.ParamsRankedJSON, []string{"id", "query", "search", "filter", "where", "sort"})
		if needleMatches >= 2 {
			return true, fmt.Sprintf("ranked parameters contain multiple query-like hints (%d)", needleMatches)
		}
		if wf.QueryLikeSteps > 0 {
			return true, fmt.Sprintf("browser workflow retained %d parameterized/query-like step(s)", wf.QueryLikeSteps)
		}
		if paramCount := reconCorpusMatchCount(urlCorpus, []string{"id=", "q=", "search=", "filter=", "query=", "page=", "user=", "name=", "type=", "category=", "sort=", "order=", "key=", "token=", "data=", "input=", "value=", "param="}); paramCount >= 1 {
			return true, fmt.Sprintf("URL corpus has %d parameterised endpoint(s) — direct injection probe", paramCount)
		}
		if hasSwagger {
			return true, "SharedState: Swagger/OpenAPI spec URL captured — schema-guided injection"
		}
		if hasDiscoveredEndpoints {
			return true, "SharedState: new endpoints discovered at runtime — injection probe"
		}
		return false, "needs query/injection lead from scouts or ranked params"
	case "lfi":
		// Run if URL corpus has path-parameter patterns, or there is any file/path
		// signal from info-disclosure or exposed-files scouts.
		if signals.hasModuleAtLeast("info-disclosure", 1) || signals.hasModuleAtLeast("exposed-files", 1) {
			return true, fmt.Sprintf("file-exposure scout lead (strength=%d)", maxCorrelationStrength(signals, "info-disclosure", "exposed-files"))
		}
		if paramCount := reconCorpusMatchCount(urlCorpus, []string{"file=", "page=", "path=", "template=", "include=", "view=", "doc=", "read=", "load="}); paramCount >= 1 {
			return true, fmt.Sprintf("LFI-pattern parameter detected in URL corpus (%d)", paramCount)
		}
		if hasDiscoveredEndpoints {
			return true, "SharedState: new endpoints — LFI probe"
		}
		return false, "no LFI-oriented parameter or file-exposure signal"
	case "hostheader":
		// Run if the target has password-reset / account flows, or any redirect signal.
		if signals.hasModuleAtLeast("open-redirect", 1) {
			return true, "redirect lead available — host header injection probe"
		}
		if matches := reconCorpusMatchCount(urlCorpus, []string{"reset", "forgot", "password", "account", "verify", "confirm", "magic"}); matches >= 1 {
			return true, fmt.Sprintf("account-flow URL detected (%d match(es)) — host header injection", matches)
		}
		return false, "no redirect or account-flow signal for host header"
	case "hpp":
		// Run if the URL corpus has any parameterised endpoints.
		if paramCount := reconCorpusMatchCount(urlCorpus, []string{"?", "&"}); paramCount >= 2 {
			return true, fmt.Sprintf("parameterised URLs in corpus (%d) — HPP probe", paramCount)
		}
		if signals.hasModuleAtLeast("mutation-engine", 1) || signals.hasModuleAtLeast("http-method-tampering", 1) {
			return true, "parameter mutation lead available"
		}
		return false, "no parameterised URL or mutation signal"
	case "xxeinjection":
		// Run only if there is a clear XML/SOAP surface or an upload-capable endpoint.
		if matches := reconCorpusMatchCount(urlCorpus, []string{"xml", "soap", "wsdl", "import", "upload", ".xml", "rss", "feed", "sitemap"}); matches >= 1 {
			return true, fmt.Sprintf("XML/upload surface detected (%d match(es)) — XXE probe", matches)
		}
		if signals.hasModuleAtLeast("upload-abuse", 1) || signals.hasModuleAtLeast("advanced-injection", 1) {
			return true, "upload or injection lead — XXE probe"
		}
		if hasSwagger {
			return true, "Swagger spec captured — XXE probe on schema-defined upload endpoints"
		}
		return false, "no XML/upload surface or injection lead for XXE"
	case "cmdinject":
		if signals.hasModuleAtLeast("advanced-injection", 1) || signals.hasModuleAtLeast("nuclei-triage", 1) {
			return true, fmt.Sprintf("injection scout lead available (strength=%d)", maxCorrelationStrength(signals, "advanced-injection", "nuclei-triage"))
		}
		if signals.hasScopeOverlap("advanced-injection", "rxss") {
			return true, fmt.Sprintf("co-located injection+XSS signals (chain strength=%d) — cmd inject probe", signals.chainStrength("advanced-injection", "rxss"))
		}
		if strings.TrimSpace(urlCorpus) != "" {
			return true, "URL corpus available for command injection probe"
		}
		return false, "needs URL corpus or injection scout lead"
	case "rxss":
		if strings.TrimSpace(urlCorpus) != "" {
			return true, "URL corpus available for XSS probe"
		}
		if signals.hasScopeOverlap("open-redirect", "http-method-tampering") {
			return true, fmt.Sprintf("co-located redirect+method signals — reflected XSS scope expanded (chain=%d)", signals.chainStrength("open-redirect", "http-method-tampering"))
		}
		return false, "no URL corpus or co-located signal for XSS"
	case "businesslogic":
		if signals.hasModuleAtLeast("advanced-injection", 1) || signals.hasModuleAtLeast("rxss", 1) {
			return true, "injection signal confirms input processing"
		}
		if strings.TrimSpace(urlCorpus) != "" {
			return true, "URL corpus available"
		}
		return false, "needs URL corpus"
	case "idor-size":
		globalStrong := signals.hasModuleAtLeast("privilege-path", 2) || signals.hasModuleAtLeast("session-abuse", 2) || signals.hasModuleAtLeast("graphql-abuse", 2) || signals.hasModuleAtLeast("js-endpoints", 1)
		scopedStrong := (signals.hasModuleAtLeast("privilege-path", 2) && signals.hasScopeOverlap("privilege-path", "session-abuse")) ||
			(signals.hasModuleAtLeast("session-abuse", 2) && signals.hasScopeOverlap("session-abuse", "graphql-abuse"))
		if scopedStrong || (!hasScopedSignals && globalStrong) {
			return true, fmt.Sprintf("object-access lead available from scouts (strength=%d)", maxCorrelationStrength(signals, "privilege-path", "session-abuse", "graphql-abuse", "js-endpoints"))
		}
		if hasObjectID {
			return true, "SharedState: object ID captured — size-comparison IDOR probe"
		}
		return false, "needs object-access lead from scouts"
	case "saml-probe":
		if signals.hasModuleAtLeast("session-abuse", 2) {
			return true, fmt.Sprintf("session/auth scout lead available (strength=%d)", signals.strength("session-abuse"))
		}
		if matches := reconCorpusMatchCount(urlCorpus, []string{"saml", "sso", "assertion", "acs", "metadata"}); matches >= 2 {
			return true, fmt.Sprintf("multiple SAML/SSO URL patterns detected (%d)", matches)
		}
		return false, "needs SAML/SSO lead from scouts or URL corpus"
	default:
		return true, "no correlation constraint"
	}
}

// readTechFramework returns the strongest framework or CMS hint captured in shared state.
func readTechFramework(ss *exploit.SharedState) string {
	if ss == nil {
		return "unknown"
	}
	if v, ok := ss.Get("tech.framework"); ok && v != "" {
		return v
	}
	if v, ok := ss.Get("tech.cms"); ok && v != "" {
		return v
	}
	return "detected"
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

func prioritizeProofModules(mods []exploit.Module, signals correlationSignals, rs models.ReconSummary, precisionPriors map[string]float64) []exploit.Module {
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
		aScore := correlationPriorityScore(aName, signals, rs, precisionPriors)
		bScore := correlationPriorityScore(bName, signals, rs, precisionPriors)
		if aScore != bScore {
			return aScore > bScore
		}
		return order[aName] < order[bName]
	})
	return out
}

func correlationPriorityScore(name string, signals correlationSignals, rs models.ReconSummary, precisionPriors map[string]float64) int {
	score := maxCorrelationStrength(signals, name) * 100
	urlCorpus := reconURLCorpusPath(rs)
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
		score += reconCorpusMatchCount(urlCorpus, []string{"post", "put", "patch", "delete", "update", "settings", "profile", "account", "password", "billing"}) * 5
	case "upload-abuse":
		score += reconCorpusMatchCount(urlCorpus, []string{"upload", "file", "attachment", "import", "avatar", "image"}) * 10
	case "mutation-engine":
		score += maxCorrelationStrength(signals, "bypass-poc", "nuclei-triage", "http-method-tampering") * 30
	case "jwt-access":
		score += maxCorrelationStrength(signals, "session-abuse", "secrets-validator") * 30
		score += reconCorpusMatchCount(urlCorpus, []string{"jwt", "token", "oauth", "authorize", "login", "auth"}) * 5
	case "lfi":
		score += maxCorrelationStrength(signals, "info-disclosure", "exposed-files") * 40
		score += reconCorpusMatchCount(urlCorpus, []string{"file=", "page=", "path=", "template=", "include="}) * 10
		if signals.hasScopeOverlap("info-disclosure", "exposed-files") {
			score += 40
		}
	case "rxss":
		score += maxCorrelationStrength(signals, "open-redirect", "http-method-tampering") * 25
		score += reconCorpusMatchCount(urlCorpus, []string{"q=", "search=", "query=", "message=", "name=", "comment="}) * 8
		if signals.hasScopeOverlap("open-redirect", "http-method-tampering") {
			score += 40
		}
	case "cmdinject":
		score += maxCorrelationStrength(signals, "advanced-injection", "nuclei-triage") * 50
		score += reconCorpusMatchCount(urlCorpus, []string{"cmd=", "exec=", "command=", "ping=", "host=", "ip="}) * 15
		if signals.hasScopeOverlap("advanced-injection", "rxss") {
			score += 40
		}
	case "hostheader":
		score += maxCorrelationStrength(signals, "open-redirect", "cors-poc") * 20
		score += reconCorpusMatchCount(urlCorpus, []string{"reset", "forgot", "password", "account"}) * 10
		if signals.hasScopeOverlap("open-redirect", "session-abuse") {
			score += 40
		}
	case "hpp":
		score += maxCorrelationStrength(signals, "mutation-engine", "http-method-tampering") * 20
		score += reconCorpusMatchCount(urlCorpus, []string{"?"}) * 2
		if signals.hasScopeOverlap("mutation-engine", "http-method-tampering") {
			score += 40
		}
	case "xxeinjection":
		score += maxCorrelationStrength(signals, "advanced-injection", "info-disclosure") * 30
		score += reconCorpusMatchCount(urlCorpus, []string{"xml", "soap", "wsdl", "upload", "import"}) * 12
	case "businesslogic":
		score += reconCorpusMatchCount(urlCorpus, []string{"price=", "amount=", "qty=", "quantity=", "count=", "balance=", "credit=", "discount="}) * 15
		score += maxCorrelationStrength(signals, "session-abuse", "idor-playbook") * 15
	case "ssrf-prober":
		score += maxCorrelationStrength(signals, "open-redirect") * 35
		score += reconCorpusMatchCount(urlCorpus, []string{"url=", "uri=", "dest=", "redirect=", "next=", "/render", "/proxy", "/fetch", "/preview", "/image"}) * 5
		score += reconCorpusMatchCount(rs.Intel.EndpointsRankedJSON, []string{"render", "proxy", "fetch", "url", "preview", "image"}) * 5
	case "crlf-injection":
		score += maxCorrelationStrength(signals, "open-redirect", "http-method-tampering") * 30
		if signals.hasScopeOverlap("hostheader", "open-redirect") {
			score += 40
		}
	case "advanced-injection", "rsql-injection":
		score += maxCorrelationStrength(signals, "graphql-abuse", "js-endpoints", "nuclei-triage") * 30
		score += reconCorpusMatchCount(rs.Intel.ParamsRankedJSON, []string{"id", "query", "search", "filter", "where", "sort"}) * 5
		score += reconCorpusMatchCount(rs.Intel.EndpointsRankedJSON, []string{"search", "query", "filter", "graphql", "api"}) * 5
	case "idor-size":
		score += maxCorrelationStrength(signals, "privilege-path", "session-abuse", "graphql-abuse", "js-endpoints") * 30
	case "saml-probe":
		score += maxCorrelationStrength(signals, "session-abuse") * 30
		score += reconCorpusMatchCount(urlCorpus, []string{"saml", "sso", "assertion", "acs", "metadata"}) * 5
	}
	if len(precisionPriors) > 0 {
		if p, ok := precisionPriors[name]; ok {
			if p < 0 {
				p = 0
			}
			if p > 1 {
				p = 1
			}
			// Feedback loop: previous accepted/raw precision nudges future scheduling.
			// 0.50 => neutral, >0.50 boost, <0.50 slight penalty.
			score += int((p - 0.5) * 80.0)
		}
	}
	return score
}

func loadModulePrecisionPriors(previousReportPath string) map[string]float64 {
	previousReportPath = strings.TrimSpace(previousReportPath)
	if previousReportPath == "" {
		return nil
	}
	summaryPath := filepath.Join(filepath.Dir(previousReportPath), "calibration_summary.json")
	b, err := os.ReadFile(summaryPath)
	if err != nil || len(b) == 0 {
		return nil
	}
	var payload struct {
		ModuleMetrics []struct {
			Module         string  `json:"module"`
			PrecisionProxy float64 `json:"precision_proxy"`
		} `json:"module_metrics"`
	}
	if err := json.Unmarshal(b, &payload); err != nil || len(payload.ModuleMetrics) == 0 {
		return nil
	}
	out := make(map[string]float64, len(payload.ModuleMetrics))
	for _, item := range payload.ModuleMetrics {
		name := strings.ToLower(strings.TrimSpace(item.Module))
		if name == "" {
			continue
		}
		out[name] = item.PrecisionProxy
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func reconCorpusContainsAny(path string, needles []string) bool {
	return reconCorpusHasMatch(path, needles)
}

// reconCorpusHasMatch is a convenience wrapper over reconCorpusMatchCount.
func reconCorpusHasMatch(path string, needles []string) bool {
	return reconCorpusMatchCount(path, needles) > 0
}

func reconCorpusMatchCount(path string, needles []string) int {
	path = strings.TrimSpace(path)
	if path == "" {
		return 0
	}
	lowered := normalizedNeedles(needles)
	if len(lowered) == 0 {
		return 0
	}
	cacheKey := reconCorpusMatchCacheKey(path, lowered)
	if cacheKey != "" {
		reconCorpusMatchMu.Lock()
		if cached, ok := reconCorpusMatchCache[cacheKey]; ok {
			reconCorpusMatchMu.Unlock()
			return cached
		}
		reconCorpusMatchMu.Unlock()
	}
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	matchedLines := map[string]struct{}{}
	count := 0
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		if line == "" {
			continue
		}
		for _, needle := range lowered {
			if strings.Contains(line, needle) {
				if _, exists := matchedLines[line]; !exists {
					matchedLines[line] = struct{}{}
					count++
				}
				break
			}
		}
	}
	if cacheKey != "" {
		reconCorpusMatchMu.Lock()
		reconCorpusMatchCache[cacheKey] = count
		reconCorpusMatchMu.Unlock()
	}
	return count
}

// reconCorpusNeedleMatchCount counts distinct needles found anywhere in file contents.
func reconCorpusNeedleMatchCount(path string, needles []string) int {
	path = strings.TrimSpace(path)
	if path == "" || len(needles) == 0 {
		return 0
	}
	lowered := normalizedNeedles(needles)
	if len(lowered) == 0 {
		return 0
	}
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	found := map[string]struct{}{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		if line == "" {
			continue
		}
		for _, needle := range lowered {
			if _, ok := found[needle]; ok {
				continue
			}
			if strings.Contains(line, needle) {
				found[needle] = struct{}{}
			}
		}
		if len(found) == len(lowered) {
			break
		}
	}
	return len(found)
}

func normalizedNeedles(needles []string) []string {
	out := make([]string, 0, len(needles))
	seen := map[string]struct{}{}
	for _, needle := range needles {
		needle = strings.ToLower(strings.TrimSpace(needle))
		if needle == "" {
			continue
		}
		if _, ok := seen[needle]; ok {
			continue
		}
		seen[needle] = struct{}{}
		out = append(out, needle)
	}
	sort.Strings(out)
	return out
}

func reconCorpusMatchCacheKey(path string, loweredNeedles []string) string {
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return strings.Join([]string{
		path,
		strconv.FormatInt(st.ModTime().UnixNano(), 10),
		strconv.FormatInt(st.Size(), 10),
		strings.Join(loweredNeedles, ","),
	}, "|")
}

func moduleNames(mods []exploit.Module) []string {
	out := make([]string, 0, len(mods))
	for _, m := range mods {
		out = append(out, m.Name())
	}
	return out
}

func flattenModuleStages(stages [][]exploit.Module) []exploit.Module {
	if len(stages) == 0 {
		return nil
	}
	out := make([]exploit.Module, 0, 32)
	for _, stage := range stages {
		out = append(out, stage...)
	}
	return out
}

func buildDependencyStages(mods []exploit.Module) ([][]exploit.Module, []string) {
	if len(mods) == 0 {
		return nil, nil
	}
	pending := make([]exploit.Module, len(mods))
	copy(pending, mods)
	present := map[string]struct{}{}
	for _, m := range mods {
		present[strings.ToLower(strings.TrimSpace(m.Name()))] = struct{}{}
	}
	completed := map[string]struct{}{}
	stages := make([][]exploit.Module, 0, len(mods))
	preview := []string{fmt.Sprintf("Dependency scheduler evaluating %d module(s)", len(mods))}
	for len(pending) > 0 {
		stage := make([]exploit.Module, 0, len(pending))
		rest := make([]exploit.Module, 0, len(pending))
		for _, m := range pending {
			name := strings.ToLower(strings.TrimSpace(m.Name()))
			if moduleDependenciesSatisfied(name, present, completed) {
				stage = append(stage, m)
				continue
			}
			rest = append(rest, m)
		}
		if len(stage) == 0 {
			stage = append(stage, pending[0])
			rest = pending[1:]
			preview = append(preview, fmt.Sprintf("Dependency scheduler forced %s due to dependency cycle", stage[0].Name()))
		}
		for _, m := range stage {
			completed[strings.ToLower(strings.TrimSpace(m.Name()))] = struct{}{}
		}
		stages = append(stages, stage)
		preview = append(preview, fmt.Sprintf("Dependency stage %d: %s", len(stages), strings.Join(moduleNames(stage), ", ")))
		pending = rest
	}
	if len(preview) > 12 {
		preview = append(preview[:12], fmt.Sprintf("Dependency scheduler omitted %d additional stage note(s)", len(preview)-12))
	}
	return stages, preview
}

func moduleDependenciesSatisfied(name string, present, completed map[string]struct{}) bool {
	deps := moduleDependencyNames(name)
	if len(deps) == 0 {
		return true
	}
	for _, dep := range deps {
		if _, tracked := present[dep]; !tracked {
			continue
		}
		if _, done := completed[dep]; !done {
			return false
		}
	}
	return true
}

func moduleDependencyNames(name string) []string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "auth-bypass":
		return []string{"open-redirect", "session-abuse", "privilege-path", "cors-poc"}
	case "idor-playbook":
		return []string{"session-abuse", "privilege-path"}
	case "idor-size":
		return []string{"session-abuse", "privilege-path"}
	case "mutation-engine":
		return []string{"http-method-tampering", "bypass-poc"}
	case "jwt-access":
		return []string{"session-abuse"}
	case "ssrf-prober":
		return []string{"open-redirect"}
	case "crlf-injection":
		return []string{"open-redirect", "http-method-tampering"}
	case "advanced-injection", "rsql-injection":
		return []string{"graphql-abuse", "js-endpoints"}
	case "saml-probe":
		return []string{"session-abuse"}
	case "mass-assign":
		return []string{"session-abuse"}
	case "race-condition":
		return []string{"state-change", "session-abuse"}
	default:
		return nil
	}
}

func filterModulesByAuthContextQuality(mods []exploit.Module, observed observedAuthContext) ([]exploit.Module, []models.ExploitModuleTelemetry, []string) {
	if len(mods) == 0 {
		return nil, nil, nil
	}
	planned := make([]exploit.Module, 0, len(mods))
	skipped := make([]models.ExploitModuleTelemetry, 0, len(mods))
	preview := []string{
		fmt.Sprintf("Auth quality guard user=%t admin=%t distinct=%t score=%d", observed.HasUser, observed.HasAdmin, observed.DistinctContexts, observed.QualityScore),
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, m := range mods {
		name := strings.ToLower(strings.TrimSpace(m.Name()))
		if moduleRequiresDistinctDualAuth(name) && !(observed.HasUser && observed.HasAdmin && observed.DistinctContexts) {
			reason := "requires distinct user/admin auth contexts"
			skipped = append(skipped, models.ExploitModuleTelemetry{
				Module:        m.Name(),
				StartedAt:     now,
				FinishedAt:    now,
				DurationMs:    0,
				FindingsCount: 0,
				ErrorCount:    0,
				Skipped:       true,
				SkippedReason: "auth-quality: " + reason,
			})
			preview = append(preview, fmt.Sprintf("Auth quality skipped %s: %s", m.Name(), reason))
			continue
		}
		planned = append(planned, m)
	}
	if len(preview) > 10 {
		preview = append(preview[:10], fmt.Sprintf("Auth quality omitted %d additional module decision(s)", len(preview)-10))
	}
	return planned, skipped, preview
}

func moduleRequiresDistinctDualAuth(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "auth-bypass", "idor-playbook", "idor-size", "mass-assign":
		return true
	default:
		return false
	}
}

func reconURLCorpusPath(rs models.ReconSummary) string {
	candidates := []string{
		rs.URLs.All,
		rs.Intel.URLsRevalidatedJSON,
		rs.Intel.URLsDiscoveredJSON,
		rs.Intel.EndpointsRankedJSON,
		rs.Intel.ResponseFingerprints,
		rs.Intel.EndpointClustersJSON,
		rs.Intel.ResponseClustersJSON,
		rs.Intel.BrowserWorkflowJSON,
		rs.Intel.FormsDiscoveredJSON,
		rs.Intel.ReconInventoryJSON,
	}
	for _, p := range candidates {
		if strings.TrimSpace(p) != "" {
			return p
		}
	}
	return ""
}

type observedAuthContext struct {
	UserCookie       string
	UserHeader       string
	AdminCookie      string
	AdminHeader      string
	HasUser          bool
	HasAdmin         bool
	DistinctContexts bool
	UserQuality      int
	AdminQuality     int
	QualityScore     int
	Source           string
}

func splitAuthBootstrapModules(mods []exploit.Module) ([]exploit.Module, []exploit.Module) {
	if len(mods) == 0 {
		return nil, nil
	}
	bootstrap := make([]exploit.Module, 0, 1)
	rest := make([]exploit.Module, 0, len(mods))
	for _, m := range mods {
		if moduleProducesAuthContext(m.Name()) {
			bootstrap = append(bootstrap, m)
			continue
		}
		rest = append(rest, m)
	}
	return bootstrap, rest
}

func moduleProducesAuthContext(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), "autoregister")
}

func applyObservedAuthFromSharedState(opt *exploit.Options, state *exploit.SharedState) observedAuthContext {
	if opt == nil {
		return observedAuthContext{Source: "none"}
	}
	observed := observedAuthFromSharedState(state)
	if observed.UserCookie != "" {
		opt.AuthUserCookie = observed.UserCookie
	}
	if observed.UserHeader != "" {
		opt.AuthUserHeaders = observed.UserHeader
	}
	if observed.AdminCookie != "" {
		opt.AuthAdminCookie = observed.AdminCookie
	}
	if observed.AdminHeader != "" {
		opt.AuthAdminHeaders = observed.AdminHeader
	}
	observed.UserQuality = authMaterialQuality(opt.AuthUserCookie, opt.AuthUserHeaders)
	observed.AdminQuality = authMaterialQuality(opt.AuthAdminCookie, opt.AuthAdminHeaders)
	observed.HasUser = observed.UserQuality > 0
	observed.HasAdmin = observed.AdminQuality > 0
	observed.DistinctContexts = authMaterialDistinct(opt.AuthUserCookie, opt.AuthUserHeaders, opt.AuthAdminCookie, opt.AuthAdminHeaders)
	observed.QualityScore = observed.UserQuality + observed.AdminQuality
	if observed.HasUser && observed.HasAdmin && !observed.DistinctContexts {
		observed.QualityScore--
	}
	if observed.QualityScore < 0 {
		observed.QualityScore = 0
	}
	if observed.Source == "" {
		switch {
		case observed.HasUser || observed.HasAdmin:
			observed.Source = "existing"
		default:
			observed.Source = "none"
		}
	}
	return observed
}

func observedAuthFromSharedState(state *exploit.SharedState) observedAuthContext {
	if state == nil {
		return observedAuthContext{Source: "none"}
	}
	out := observedAuthContext{}
	if v, ok := state.Get("autoregister.session_a"); ok {
		out.UserCookie = strings.TrimSpace(v)
	}
	if out.UserCookie == "" {
		if v, ok := state.Get("autoregister.session"); ok {
			out.UserCookie = strings.TrimSpace(v)
		}
	}
	if v, ok := state.Get("autoregister.header_a"); ok {
		out.UserHeader = strings.TrimSpace(v)
	}
	if out.UserHeader == "" {
		if v, ok := state.Get("autoregister.header"); ok {
			out.UserHeader = strings.TrimSpace(v)
		}
	}
	if v, ok := state.Get("autoregister.session_b"); ok {
		out.AdminCookie = strings.TrimSpace(v)
	}
	if v, ok := state.Get("autoregister.header_b"); ok {
		out.AdminHeader = strings.TrimSpace(v)
	}
	out.HasUser = out.UserCookie != "" || out.UserHeader != ""
	out.HasAdmin = out.AdminCookie != "" || out.AdminHeader != ""
	if out.HasUser || out.HasAdmin {
		out.Source = "autoregister"
	} else {
		out.Source = "none"
	}
	return out
}

func authMaterialQuality(cookie, header string) int {
	cookie = strings.TrimSpace(cookie)
	header = strings.TrimSpace(header)
	if cookie == "" && header == "" {
		return 0
	}
	combined := strings.ToLower(strings.TrimSpace(cookie + "\n" + header))
	if looksPlaceholderAuthMaterial(combined) {
		return 1
	}
	if (cookie != "" && strings.Contains(cookie, "=")) || (header != "" && strings.Contains(header, ":")) {
		return 2
	}
	return 1
}

func looksPlaceholderAuthMaterial(raw string) bool {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return false
	}
	tokens := []string{
		"changeme", "replace_me", "replace-this", "placeholder", "example",
		"your_cookie", "your token", "<cookie>", "<token>", "insert token",
		"insert cookie", "todo", "dummy",
	}
	for _, token := range tokens {
		if strings.Contains(raw, token) {
			return true
		}
	}
	return false
}

func authMaterialDistinct(userCookie, userHeaders, adminCookie, adminHeaders string) bool {
	userSig := authContextSignature(userCookie, userHeaders)
	adminSig := authContextSignature(adminCookie, adminHeaders)
	if userSig == "" || adminSig == "" {
		return false
	}
	return userSig != adminSig
}

func authContextSignature(cookie, headers string) string {
	cookie = strings.ToLower(strings.TrimSpace(cookie))
	headerRows := strings.FieldsFunc(strings.ToLower(strings.TrimSpace(headers)), func(r rune) bool {
		return r == '\n' || r == ';'
	})
	for i, row := range headerRows {
		headerRows[i] = strings.TrimSpace(row)
	}
	sort.Strings(headerRows)
	return cookie + "|" + strings.Join(headerRows, "|")
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
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

// enrichURLCorpusFromSharedState appends newly discovered endpoints (written
// by scouts under the "discovered.endpoint." prefix) into the recon URL corpus
// file. This ensures proof modules query the full, live-updated endpoint set.
func enrichURLCorpusFromSharedState(rs *models.ReconSummary, ss *exploit.SharedState) {
	if ss == nil || rs == nil {
		return
	}
	discovered := ss.GetAll("discovered.endpoint.")
	if len(discovered) == 0 {
		return
	}
	corpusPath := strings.TrimSpace(rs.URLs.All)
	if corpusPath == "" {
		return
	}
	f, err := os.OpenFile(corpusPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, ep := range discovered {
		ep = strings.TrimSpace(ep)
		if ep != "" {
			_, _ = fmt.Fprintln(w, ep)
		}
	}
	_ = w.Flush()
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
	hasURLCorpus := strings.TrimSpace(reconURLCorpusPath(rs)) != ""
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
	if hasURLCorpus {
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
	if hasURLCorpus || strings.TrimSpace(rs.Intel.EndpointsRankedJSON) != "" {
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
			"webhook_interactsh":                  opt.InteractshNotifier != nil,
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
	cacheKey := workflowSignalsCacheKey(rs)
	if cacheKey != "" {
		workflowSignalCacheMu.Lock()
		if cached, ok := workflowSignalCache[cacheKey]; ok {
			workflowSignalCacheMu.Unlock()
			return cached
		}
		workflowSignalCacheMu.Unlock()
	}
	signals := browserWorkflowSignals{}
	workdir := strings.TrimSpace(rs.Workdir)
	if workdir != "" {
		artifact, err := browsercapture.LoadArtifact(filepath.Join(workdir, "browser_capture_artifact.json"))
		if err == nil {
			signals = mergeBrowserWorkflowSignals(signals, summarizeBrowserCaptureArtifact(artifact))
		}
	}
	if path := strings.TrimSpace(rs.Intel.BrowserWorkflowJSON); path != "" {
		signals = mergeBrowserWorkflowSignals(signals, summarizeWorkflowItemsJSON(path))
	}
	if cacheKey != "" {
		workflowSignalCacheMu.Lock()
		workflowSignalCache[cacheKey] = signals
		workflowSignalCacheMu.Unlock()
	}
	return signals
}

func workflowSignalsCacheKey(rs models.ReconSummary) string {
	workdir := strings.TrimSpace(rs.Workdir)
	workflowPath := strings.TrimSpace(rs.Intel.BrowserWorkflowJSON)
	if workdir == "" && workflowPath == "" {
		return ""
	}
	artifactPath := ""
	if workdir != "" {
		artifactPath = filepath.Join(workdir, "browser_capture_artifact.json")
	}
	return strings.Join([]string{
		workdir,
		workflowPath,
		fileStamp(artifactPath),
		fileStamp(workflowPath),
	}, "|")
}

func fileStamp(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	st, err := os.Stat(path)
	if err != nil {
		return "missing"
	}
	return strconv.FormatInt(st.ModTime().UnixNano(), 10) + ":" + strconv.FormatInt(st.Size(), 10)
}

func summarizeBrowserCaptureArtifact(artifact browsercapture.Artifact) browserWorkflowSignals {
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

func summarizeWorkflowItemsJSON(path string) browserWorkflowSignals {
	b, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil || len(b) == 0 {
		return browserWorkflowSignals{}
	}
	var payload any
	if err := json.Unmarshal(b, &payload); err != nil {
		return browserWorkflowSignals{}
	}
	rows := extractWorkflowRows(payload)
	if len(rows) == 0 {
		return browserWorkflowSignals{}
	}
	signals := browserWorkflowSignals{
		Available:        true,
		RecordedWorkflow: len(rows),
	}
	routeSeen := map[string]struct{}{}
	for _, row := range rows {
		method := strings.ToUpper(strings.TrimSpace(asString(row["method"])))
		target := strings.ToLower(strings.TrimSpace(firstNonEmptyString(
			asString(row["route"]),
			asString(row["url"]),
			asString(row["page_url"]),
			asString(row["action_guess"]),
		)))
		fields := strings.Join(asStringSlice(row["fields"]), ",")
		kind := strings.ToLower(strings.TrimSpace(asString(row["kind"])))

		signals.RequestSteps++
		if target != "" {
			routeSeen[target] = struct{}{}
		}
		if kind == "form" {
			signals.FormCount++
		}
		writeAction := asBool(row["write_action"]) || method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete || kind == "form"
		if writeAction {
			signals.WriteSteps++
		}
		if strings.Contains(target, "upload") || strings.Contains(target, "import") || strings.Contains(target, "avatar") || strings.Contains(fields, "file") || strings.Contains(fields, "image") {
			signals.UploadSteps++
		}
		if strings.Contains(target, "query") || strings.Contains(target, "search") || strings.Contains(target, "filter") || strings.Contains(fields, "query") || strings.Contains(fields, "search") || strings.Contains(fields, "filter") || strings.Contains(fields, "id") || strings.Contains(fields, "sort") {
			signals.QueryLikeSteps++
		}
		if asBool(row["auth_action"]) || strings.Contains(target, "token") || strings.Contains(target, "oauth") || strings.Contains(target, "login") || strings.Contains(target, "auth") || strings.Contains(fields, "token") || strings.Contains(fields, "authorization") {
			signals.AuthLikeSteps++
		}
		if strings.Contains(target, "url=") || strings.Contains(target, "uri=") || strings.Contains(target, "redirect=") || strings.Contains(target, "next=") || strings.Contains(target, "/proxy") || strings.Contains(target, "/fetch") || strings.Contains(target, "/render") || strings.Contains(fields, "url") || strings.Contains(fields, "uri") || strings.Contains(fields, "callback") || strings.Contains(fields, "dest") {
			signals.SSRFLikeSteps++
		}
	}
	signals.RouteCount = len(routeSeen)
	return signals
}

func mergeBrowserWorkflowSignals(base, add browserWorkflowSignals) browserWorkflowSignals {
	base.Available = base.Available || add.Available
	base.RequestSteps += add.RequestSteps
	base.WriteSteps += add.WriteSteps
	base.UploadSteps += add.UploadSteps
	base.QueryLikeSteps += add.QueryLikeSteps
	base.AuthLikeSteps += add.AuthLikeSteps
	base.SSRFLikeSteps += add.SSRFLikeSteps
	base.RouteCount += add.RouteCount
	base.FormCount += add.FormCount
	base.RecordedWorkflow += add.RecordedWorkflow
	return base
}

func extractWorkflowRows(payload any) []map[string]any {
	appendRow := func(rows []map[string]any, v any) []map[string]any {
		if m, ok := v.(map[string]any); ok {
			rows = append(rows, m)
		}
		return rows
	}
	rows := make([]map[string]any, 0, 64)
	switch t := payload.(type) {
	case []any:
		for _, item := range t {
			rows = appendRow(rows, item)
		}
	case map[string]any:
		if arr, ok := t["items"].([]any); ok {
			for _, item := range arr {
				rows = appendRow(rows, item)
			}
		} else {
			rows = appendRow(rows, t)
		}
	}
	return rows
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func asStringSlice(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			s = strings.TrimSpace(strings.ToLower(s))
			if s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func asBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		lt := strings.TrimSpace(strings.ToLower(t))
		return lt == "1" || lt == "true" || lt == "yes" || lt == "on"
	default:
		return false
	}
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
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

func shouldInitializeOOBProvider(opt Options, scoutModules, proofModules []exploit.Module) bool {
	if strings.TrimSpace(opt.OOBHTTPPublicBaseURL) != "" {
		return true
	}
	if opt.AggressiveMode || opt.ProofMode {
		return true
	}
	oobCapable := map[string]struct{}{
		"ssrf-prober":        {},
		"xxeinjection":       {},
		"cmdinject":          {},
		"advanced-injection": {},
		"deserialization":    {},
	}
	for _, m := range append(append([]exploit.Module{}, scoutModules...), proofModules...) {
		name := strings.ToLower(strings.TrimSpace(m.Name()))
		if _, ok := oobCapable[name]; ok {
			return true
		}
	}
	return false
}

func resolvedOOBProviderLabel(opt Options) string {
	if strings.TrimSpace(opt.OOBHTTPPublicBaseURL) != "" {
		return "builtin-http"
	}
	return "interactsh"
}
