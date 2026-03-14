package notify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"breachpilot/internal/models"
)

func TestWebhookStopFlushesQueuedEvents(t *testing.T) {
	var (
		mu     sync.Mutex
		events []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		name, _ := payload["event"].(string)
		mu.Lock()
		events = append(events, name)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	nf := &Webhook{URL: srv.URL, Retries: 1}
	job := &models.Job{ID: "j1", Target: "example.com"}

	nf.Send("job.cancelled", job)
	nf.SendGeneric("exploit.modules.completed", map[string]any{"job_id": "j1"})
	nf.Stop()

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Fatalf("expected 2 events flushed, got %d (%v)", len(events), events)
	}
}

func TestWebhookStopIsSafeWhenNeverStarted(t *testing.T) {
	nf := &Webhook{URL: "http://127.0.0.1:1"}
	done := make(chan struct{})
	go func() {
		nf.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Stop should return quickly when webhook not started")
	}
}
