package models

import "time"

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

type ReconSummary struct {
	Workdir string `json:"workdir"`
	Live    string `json:"live_hosts"`
	URLs    struct {
		All string `json:"all"`
	} `json:"urls"`
	Intel struct {
		EndpointsRankedJSON string `json:"endpoints_ranked_json"`
		ParamsRankedJSON    string `json:"params_ranked_json"`
	} `json:"intel"`
}

type Job struct {
	ID                 string    `json:"id"`
	Target             string    `json:"target"`
	Mode               string    `json:"mode,omitempty"`
	SafeMode           bool      `json:"safe_mode"`
	ApproveIntrusive   bool      `json:"approve_intrusive"`
	Templates          []string  `json:"templates,omitempty"`
	ApprovalTicket     string    `json:"approval_ticket,omitempty"`
	ReconPath          string    `json:"recon_summary"`
	Status             JobStatus `json:"status"`
	CreatedAt          time.Time `json:"created_at"`
	StartedAt          time.Time `json:"started_at,omitempty"`
	FinishedAt         time.Time `json:"finished_at,omitempty"`
	Error              string    `json:"error,omitempty"`
	PlanPreview        []string  `json:"plan_preview,omitempty"`
	EvidencePath       string    `json:"evidence_path,omitempty"`
	FindingsCount      int       `json:"findings_count,omitempty"`
	ReconDurationSec   float64   `json:"recon_duration_sec,omitempty"`
	ExploitDurationSec float64   `json:"exploit_duration_sec,omitempty"`
	ReportPath         string    `json:"report_path,omitempty"`
}
