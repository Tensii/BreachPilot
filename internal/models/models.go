package models

import (
	"time"

	"breachpilot/internal/scoring"
)

const SchemaVersion = "1"

type JobStatus string

const (
	JobQueued    JobStatus = "queued"
	JobRunning   JobStatus = "running"
	JobDone      JobStatus = "done"
	JobFailed    JobStatus = "failed"
	JobRejected  JobStatus = "rejected"
	JobCancelled JobStatus = "cancelled"
)

type CreateJobRequest struct {
	Target           string   `json:"target"`
	Mode             string   `json:"mode,omitempty"`
	ReconSummary     string   `json:"recon_summary"`
	SafeMode         bool     `json:"safe_mode"`
	ApproveIntrusive bool     `json:"approve_intrusive"`
	ApprovalTicket   string   `json:"approval_ticket,omitempty"`
	Templates        []string `json:"templates,omitempty"`
}

// JobState tracks the resumable execution state of a job on disk.
type JobState struct {
	JobID           string   `json:"job_id"`
	Target          string   `json:"target"`
	Mode            string   `json:"mode"`
	ReconPath       string   `json:"recon_path,omitempty"`
	StartedAt       string   `json:"started_at"`
	LastUpdatedAt   string   `json:"last_updated_at"`
	ReconCompleted  bool     `json:"recon_completed"`
	NucleiCompleted bool     `json:"nuclei_completed"`
	ModulesFinished []string `json:"modules_finished"`
}

// ExploitFinding is a single verified exploit-phase result.
type ExploitFinding struct {
	Module           string                 `json:"module"`
	Severity         string                 `json:"severity"`   // CRITICAL / HIGH / MEDIUM / LOW / INFO
	Confidence       int                    `json:"confidence"` // 0–100
	Target           string                 `json:"target"`
	Title            string                 `json:"title"`
	Validation       string                 `json:"validation,omitempty"` // signal / verified / confirmed / weaponized
	Evidence         string                 `json:"evidence,omitempty"`
	ArtifactPath     string                 `json:"artifact_path,omitempty"`
	PoCHint          string                 `json:"poc_hint,omitempty"`
	Tags             []string               `json:"tags,omitempty"`
	CWE              string                 `json:"cwe,omitempty"`
	Timestamp        string                 `json:"timestamp"`
	DynamicMetadata  map[string]interface{} `json:"dynamic_metadata,omitempty"`
	DBMSGuess        string                 `json:"dbms_guess,omitempty"`
	DBMSConfidence   int                    `json:"dbms_confidence,omitempty"`
	ValidationFamily string                 `json:"validation_family,omitempty"`
	MatchedIndicator string                 `json:"matched_indicator,omitempty"`
	MatchedSnippet   string                 `json:"matched_snippet,omitempty"`
	Capabilities     []string               `json:"capabilities,omitempty"`

	// RiskScore holds the contextual score computed by the scoring engine.
	// Zero value = not yet scored.
	RiskScore riskscoring.RiskScore `json:"risk_score,omitempty"`
}

// SecretsFinding represents an exposed secret string discovered by ReconHarvest.
type SecretsFinding struct {
	Target  string `json:"target"`
	Match   string `json:"match"`
	Type    string `json:"type"`
	Context string `json:"context"`
}

// CORSFinding represents an insecure CORS misconfiguration discovered by ReconHarvest.
type CORSFinding struct {
	URL           string `json:"url"`
	MirrorHeaders string `json:"mirror_headers"`
	Credentials   string `json:"credentials"`
	Origin        string `json:"origin"`
}

type ReconSummary struct {
	Workdir string `json:"workdir"`
	Live    string `json:"live_hosts"`
	URLs    struct {
		All string `json:"all"`
	} `json:"urls"`
	Nuclei struct {
		Phase1JSONL string `json:"phase1_jsonl"`
	} `json:"nuclei"`
	Intel struct {
		EndpointsRankedJSON   string `json:"endpoints_ranked_json"`
		ParamsRankedJSON      string `json:"params_ranked_json"`
		SecretsJSON           string `json:"secrets_findings_json"`
		CORSJSON              string `json:"cors_findings_json"`
		BypassJSON            string `json:"bypass_403_findings_json"`
		PortScanJSON          string `json:"portscan_results_json"`
		NucleiPhase1JSONL     string `json:"nuclei_phase1_jsonl"`
		SubdomainTakeoverJSON string `json:"subdomain_takeover_json"`
		JSEndpointsJSON       string `json:"js_endpoints_json"`
	} `json:"intel"`
}

type ExploitModuleTelemetry struct {
	Module        string `json:"module"`
	StartedAt     string `json:"started_at"`
	FinishedAt    string `json:"finished_at"`
	DurationMs    int64  `json:"duration_ms"`
	FindingsCount int    `json:"findings_count"`
	AcceptedCount int    `json:"accepted_count"`
	FilteredCount int    `json:"filtered_count"`
	ErrorCount    int    `json:"error_count"`
	LastError     string `json:"last_error,omitempty"`
	Skipped       bool   `json:"skipped"`
	SkippedReason string `json:"skipped_reason,omitempty"`
	Canceled      bool   `json:"canceled"`
}

type RuntimeEvent struct {
	Kind      string           `json:"kind"`
	Stage     string           `json:"stage,omitempty"`
	Status    string           `json:"status,omitempty"`
	Message   string           `json:"message,omitempty"`
	Module    string           `json:"module,omitempty"`
	Target    string           `json:"target,omitempty"`
	Timestamp time.Time        `json:"timestamp"`
	Counts    map[string]int   `json:"counts,omitempty"`
	Progress  *RuntimeProgress `json:"progress,omitempty"`
	Finding   *FindingPreview  `json:"finding,omitempty"`
}

type RuntimeProgress struct {
	Label     string `json:"label,omitempty"`
	Unit      string `json:"unit,omitempty"`
	Completed int    `json:"completed,omitempty"`
	Total     int    `json:"total,omitempty"`
	Percent   int    `json:"percent,omitempty"`
}

type FindingPreview struct {
	Module     string `json:"module"`
	Severity   string `json:"severity"`
	Validation string `json:"validation,omitempty"`
	Title      string `json:"title"`
	Target     string `json:"target"`
}

type Job struct {
	ID                    string                      `json:"id"`
	Target                string                      `json:"target"`
	Mode                  string                      `json:"mode,omitempty"`
	SafeMode              bool                        `json:"safe_mode"`
	ApproveIntrusive      bool                        `json:"approve_intrusive"`
	Templates             []string                    `json:"templates,omitempty"`
	ApprovalTicket        string                      `json:"approval_ticket,omitempty"`
	ReconPath             string                      `json:"recon_summary"`
	Status                JobStatus                   `json:"status"`
	CreatedAt             time.Time                   `json:"created_at"`
	StartedAt             time.Time                   `json:"started_at,omitempty"`
	FinishedAt            time.Time                   `json:"finished_at,omitempty"`
	ErrorCode             string                      `json:"error_code,omitempty"`
	Error                 string                      `json:"error,omitempty"`
	PlanPreview           []string                    `json:"plan_preview,omitempty"`
	EvidencePath          string                      `json:"evidence_path,omitempty"`
	FindingsCount         int                         `json:"findings_count,omitempty"`
	ExploitFindingsCount  int                         `json:"exploit_findings_count,omitempty"`
	ExploitFindingsPath   string                      `json:"exploit_findings_path,omitempty"`
	ExploitReportPath     string                      `json:"exploit_report_path,omitempty"`
	ExploitHTMLReportPath string                      `json:"exploit_html_report_path,omitempty"`
	RiskScore             float64                     `json:"risk_score,omitempty"`
	RiskSummary           riskscoring.ScanRiskSummary `json:"risk_summary,omitempty"`
	ModuleTelemetry       []ExploitModuleTelemetry    `json:"module_telemetry,omitempty"`
	FilteredCount         int                         `json:"filtered_count,omitempty"`
	ReconDurationSec      float64                     `json:"recon_duration_sec,omitempty"`
	ExploitDurationSec    float64                     `json:"exploit_duration_sec,omitempty"`
	ReportPath            string                      `json:"report_path,omitempty"`
}
