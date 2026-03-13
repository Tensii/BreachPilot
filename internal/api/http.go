package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"breachpilot/internal/models"
	"breachpilot/internal/policy"
	"breachpilot/internal/queue"
	"breachpilot/internal/scope"

	"github.com/gorilla/mux"
)

type Server struct {
	Q             *queue.Manager
	Token         string
	TriggerSecret string
}

func (s *Server) Router() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/healthz", s.health).Methods(http.MethodGet)
	r.HandleFunc("/v1/jobs", s.createJob).Methods(http.MethodPost)
	r.HandleFunc("/v1/jobs/{id}", s.getJob).Methods(http.MethodGet)
	r.HandleFunc("/v1/jobs/{id}/cancel", s.cancelJob).Methods(http.MethodPost)
	r.HandleFunc("/v1/trigger/reconharvest", s.triggerReconHarvest).Methods(http.MethodPost)
	return r
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "service": "breachpilot"})
}

func (s *Server) createJob(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req models.CreateJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	job, code, errMsg := validateAndBuildJob(req)
	if code != 0 {
		http.Error(w, errMsg, code)
		return
	}
	if err := s.Q.Enqueue(job); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(job)
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	job, ok := s.Q.Get(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(job)
}

func (s *Server) cancelJob(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := mux.Vars(r)["id"]
	job, ok := s.Q.Cancel(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(job)
}

func (s *Server) triggerReconHarvest(w http.ResponseWriter, r *http.Request) {
	if s.TriggerSecret == "" {
		http.Error(w, "trigger secret not configured", http.StatusForbidden)
		return
	}
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	sig := strings.TrimSpace(r.Header.Get("X-BreachPilot-Signature"))
	if !verifySignature(payload, s.TriggerSecret, sig) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	var req models.CreateJobRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	job, code, errMsg := validateAndBuildJob(req)
	if code != 0 {
		http.Error(w, errMsg, code)
		return
	}
	if err := s.Q.Enqueue(job); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(job)
}

func (s *Server) authOK(r *http.Request) bool {
	if s.Token == "" {
		return true
	}
	got := strings.TrimSpace(r.Header.Get("X-BreachPilot-Token"))
	return got != "" && got == s.Token
}

func validateAndBuildJob(req models.CreateJobRequest) (*models.Job, int, string) {
	if err := scope.ValidateTarget(req.Target); err != nil {
		return nil, http.StatusBadRequest, err.Error()
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "ingest"
	}
	if mode != "ingest" && mode != "full" {
		return nil, http.StatusBadRequest, "mode must be one of: ingest, full"
	}
	if mode == "ingest" && strings.TrimSpace(req.ReconSummary) == "" {
		return nil, http.StatusBadRequest, "recon_summary is required in ingest mode"
	}
	if !req.SafeMode {
		if !req.ApproveIntrusive {
			return nil, http.StatusBadRequest, "intrusive mode requires approve_intrusive=true"
		}
		if strings.TrimSpace(req.ApprovalTicket) == "" {
			return nil, http.StatusBadRequest, "approval_ticket is required for intrusive mode"
		}
	}
	if policy.HasIntrusive(req.Templates) && !req.ApproveIntrusive {
		return nil, http.StatusBadRequest, "intrusive templates require approve_intrusive=true"
	}

	mode = strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "ingest"
	}
	job := &models.Job{
		ID:               newID(),
		Target:           strings.TrimSpace(req.Target),
		Mode:             mode,
		SafeMode:         req.SafeMode,
		ApproveIntrusive: req.ApproveIntrusive,
		Templates:        req.Templates,
		ApprovalTicket:   strings.TrimSpace(req.ApprovalTicket),
		ReconPath:        strings.TrimSpace(req.ReconSummary),
		Status:           models.JobQueued,
		CreatedAt:        time.Now().UTC(),
	}
	return job, 0, ""
}

func verifySignature(payload []byte, secret, provided string) bool {
	if secret == "" || provided == "" {
		return false
	}
	provided = strings.TrimPrefix(provided, "sha256=")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(provided))
}

func newID() string {
	return strings.ReplaceAll(time.Now().UTC().Format("20060102T150405.000000000"), ".", "")
}
