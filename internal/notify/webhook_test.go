package notify

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"breachpilot/internal/models"
	"breachpilot/internal/testutil"
)

func TestWebhookStopFlushesQueuedEvents(t *testing.T) {
	var (
		mu     sync.Mutex
		events []string
	)
	srv := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func TestWebhookJobCompletedPreservesNormalQueueOrder(t *testing.T) {
	var (
		mu     sync.Mutex
		events []string
	)
	srv := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	nf.SendGeneric("exploit.finding", map[string]any{"job_id": "j1", "severity": "HIGH"})
	nf.Send("job.completed", job)
	nf.Stop()

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Fatalf("expected 2 events flushed, got %d (%v)", len(events), events)
	}
	if events[0] != "exploit.finding" || events[1] != "job.completed" {
		t.Fatalf("unexpected event order: %v", events)
	}
}

func TestWebhookFindingsCapPreventsSpam(t *testing.T) {
	var (
		mu    sync.Mutex
		count int
	)
	srv := testutil.NewServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if payload["event"] == "exploit.finding" {
			mu.Lock()
			count++
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	nf := &Webhook{URL: srv.URL, Retries: 1, FindingsCap: 3}
	for i := 0; i < 10; i++ {
		nf.SendGeneric("exploit.finding", map[string]any{"job_id": "j1", "idx": i})
	}
	nf.Stop()

	mu.Lock()
	defer mu.Unlock()
	if count > 3 {
		t.Fatalf("expected finding webhook cap to suppress spam, got %d sends", count)
	}
}

func TestWebhookReliableModeSpoolsOnQueueBackpressure(t *testing.T) {
	spoolPath := filepath.Join(t.TempDir(), "webhook-spool.jsonl")
	nf := &Webhook{
		URL:          "http://127.0.0.1:1",
		Retries:      1,
		ReliableMode: true,
		QueueTimeout: 1 * time.Millisecond,
		SpoolPath:    spoolPath,
	}

	for i := 0; i < 2000; i++ {
		nf.SendGeneric("exploit.finding", map[string]any{"job_id": "j1", "idx": i})
	}
	nf.Stop()

	if nf.SpooledEvents() == 0 {
		t.Fatal("expected reliable mode to spool events under sustained queue backpressure")
	}
	b, err := os.ReadFile(spoolPath)
	if err != nil {
		t.Fatalf("expected spool file to exist: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("expected spool file to contain queued events")
	}
}

func TestWebhookCountersAndCapsHelpers(t *testing.T) {
	var nilWebhook *Webhook
	if nilWebhook.FindingCap() != 0 {
		t.Fatal("expected nil webhook finding cap to be zero")
	}
	if nilWebhook.DroppedEvents() != 0 {
		t.Fatal("expected nil webhook dropped events to be zero")
	}
	if nilWebhook.SpooledEvents() != 0 {
		t.Fatal("expected nil webhook spooled events to be zero")
	}

	w := &Webhook{}
	if w.FindingCap() != 20 {
		t.Fatalf("expected default finding cap 20, got %d", w.FindingCap())
	}
	atomic.StoreInt64(&w.droppedEvents, 7)
	atomic.StoreInt64(&w.spooledEvents, 3)
	if w.DroppedEvents() != 7 {
		t.Fatalf("expected dropped events 7, got %d", w.DroppedEvents())
	}
	if w.SpooledEvents() != 3 {
		t.Fatalf("expected spooled events 3, got %d", w.SpooledEvents())
	}
}

func TestSignHMACSHA256IsDeterministic(t *testing.T) {
	one := signHMACSHA256([]byte("payload"), "secret")
	two := signHMACSHA256([]byte("payload"), "secret")
	if one == "" || two == "" {
		t.Fatal("expected non-empty signatures")
	}
	if one != two {
		t.Fatal("expected deterministic signature for same payload/secret")
	}
	three := signHMACSHA256([]byte("payload-2"), "secret")
	if one == three {
		t.Fatal("expected different payload to produce different signature")
	}
}

func TestRedactURLShortAndLong(t *testing.T) {
	if got := redactURL(""); got != "" {
		t.Fatalf("expected empty redact for empty input, got %q", got)
	}
	if got := redactURL("https://discord.com/api/webhooks/abc/def"); !strings.Contains(got, "<redacted>") {
		t.Fatalf("expected redacted webhook URL, got %q", got)
	}
	if got := redactURL("https://example.com/very/long/path"); !strings.Contains(got, "<redacted>") {
		t.Fatalf("expected redacted long URL, got %q", got)
	}
}
