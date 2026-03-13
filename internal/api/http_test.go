package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"breachpilot/internal/engine"
	"breachpilot/internal/models"
	"breachpilot/internal/notify"
	"breachpilot/internal/queue"
)

func newTestServer() *Server {
	q := queue.New(10, engine.Options{}, &notify.Webhook{}, nil)
	return &Server{Q: q, Token: "tok"}
}

func TestCreateJobRequiresToken(t *testing.T) {
	s := newTestServer()
	r := httptest.NewRequest(http.MethodPost, "/v1/jobs", bytes.NewBufferString(`{}`))
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 got %d", w.Code)
	}
}

func TestCreateJobValidation(t *testing.T) {
	s := newTestServer()
	req := models.CreateJobRequest{Mode: "ingest", Target: "example.com", ReconSummary: "/tmp/summary.json", SafeMode: true}
	b, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/v1/jobs", bytes.NewReader(b))
	r.Header.Set("X-BreachPilot-Token", "tok")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatalf("want 202 got %d body=%s", w.Code, w.Body.String())
	}
}

func TestCreateJobIntrusiveNeedsTicket(t *testing.T) {
	s := newTestServer()
	req := models.CreateJobRequest{Mode: "full", Target: "example.com", SafeMode: false, ApproveIntrusive: true}
	b, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/v1/jobs", bytes.NewReader(b))
	r.Header.Set("X-BreachPilot-Token", "tok")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 got %d", w.Code)
	}
}
