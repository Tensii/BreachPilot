package notify

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"breachpilot/internal/models"
)

type webhookEvent struct {
	Name    string
	Job     *models.Job
	Payload any // non-nil for generic events
}

type Webhook struct {
	URL          string
	Secret       string
	Retries      int
	DebugLogPath string
	FindingsCap  int

	criticalCh chan webhookEvent
	normalCh   chan webhookEvent
	once       sync.Once
	stopOnce   sync.Once
	wg         sync.WaitGroup
	client     *http.Client
	logMu      sync.Mutex

	findingsSentThisRun int32
	droppedEvents       int64
	stopCh              chan struct{}
	logFile             *os.File
}

const findingCapCheckedKey = "_bp_finding_cap_checked"

func (w *Webhook) Start() {
	if w.URL == "" {
		return
	}
	w.once.Do(func() {
		if w.Retries <= 0 {
			w.Retries = 3
		}
		w.criticalCh = make(chan webhookEvent, 64)
		w.normalCh = make(chan webhookEvent, 512)
		w.stopCh = make(chan struct{})
		w.client = &http.Client{Timeout: 6 * time.Second}
		if strings.TrimSpace(w.DebugLogPath) != "" {
			_ = os.MkdirAll(filepath.Dir(w.DebugLogPath), 0o755)
			if lf, err := os.OpenFile(w.DebugLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
				w.logFile = lf
			}
		}
		w.wg.Add(1)
		go w.loop()
	})
}

func (w *Webhook) loop() {
	defer w.wg.Done()
	criticalCh := w.criticalCh
	normalCh := w.normalCh
	for criticalCh != nil || normalCh != nil {
		var (
			ev webhookEvent
			ok bool
		)
		// Always try critical first.
		select {
		case ev, ok = <-criticalCh:
			if !ok {
				criticalCh = nil
				continue
			}
		default:
			select {
			case ev, ok = <-criticalCh:
				if !ok {
					criticalCh = nil
					continue
				}
			case ev, ok = <-normalCh:
				if !ok {
					normalCh = nil
					continue
				}
			}
		}

		if ev.Payload != nil {
			w.sendNowGeneric(ev.Name, ev.Payload)
		} else {
			w.sendNow(ev.Name, ev.Job)
		}
	}
}

func (w *Webhook) Send(event string, job *models.Job) {
	if w.URL == "" || job == nil {
		return
	}
	w.Start()

	// Keep completion notices in normal queue order so they land after
	// any finding/module events already emitted for the same run.
	if event == "job.completed" {
		select {
		case w.normalCh <- webhookEvent{Name: event, Job: job}:
		case <-time.After(2 * time.Second):
			w.sendNow(event, job)
		}
		return
	}

	// Never drop terminal job events.
	if strings.HasPrefix(event, "job.") {
		select {
		case w.criticalCh <- webhookEvent{Name: event, Job: job}:
		case <-time.After(2 * time.Second):
			w.sendNow(event, job)
		}
		return
	}

	select {
	case w.normalCh <- webhookEvent{Name: event, Job: job}:
	default:
		atomic.AddInt64(&w.droppedEvents, 1)
	}
}

// SendGeneric sends an arbitrary payload as a webhook event.
// Satisfies the engine.Notifier interface.
func (w *Webhook) SendGeneric(eventType string, payload any) {
	if w.URL == "" || payload == nil {
		return
	}
	w.Start()
	if eventType == "exploit.finding" && !payloadFindingCapChecked(payload) && !w.ShouldSendFinding() {
		return
	}
	select {
	case w.normalCh <- webhookEvent{Name: eventType, Payload: payload}:
	default:
		atomic.AddInt64(&w.droppedEvents, 1)
	}
}

// Stop drains the pending webhook queue and shuts down the background worker.
// Call this before the process exits to ensure queued events are delivered.
func (w *Webhook) Stop() {
	if w.URL == "" {
		return
	}
	w.stopOnce.Do(func() {
		if w.criticalCh == nil && w.normalCh == nil {
			return
		}
		if w.stopCh != nil {
			close(w.stopCh)
		}
		if w.criticalCh != nil {
			close(w.criticalCh)
		}
		if w.normalCh != nil {
			close(w.normalCh)
		}
		done := make(chan struct{})
		go func() {
			w.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			log.Printf("[webhook] drain timeout: some queued events may not have been delivered (url=%s)", redactURL(w.URL))
		}
		if w.logFile != nil {
			_ = w.logFile.Close()
			w.logFile = nil
		}
	})
}

func (w *Webhook) sendNow(eventName string, job *models.Job) {
	body := map[string]any{
		"event": eventName,
		"job":   job,
		"ts":    time.Now().UTC().Format(time.RFC3339),
	}
	w.postJSON(body)
}

func (w *Webhook) sendNowGeneric(eventName string, payload any) {
	body := map[string]any{
		"event":   eventName,
		"payload": sanitizeGenericPayload(payload),
		"ts":      time.Now().UTC().Format(time.RFC3339),
	}
	w.postJSON(body)
}

func (w *Webhook) ShouldSendFinding() bool {
	if w == nil {
		return false
	}
	if w.FindingsCap < 0 {
		return false
	}
	if w.FindingsCap == 0 {
		return true
	}
	for {
		cur := atomic.LoadInt32(&w.findingsSentThisRun)
		if int(cur) >= w.FindingsCap {
			return false
		}
		if atomic.CompareAndSwapInt32(&w.findingsSentThisRun, cur, cur+1) {
			return true
		}
	}
}

func (w *Webhook) FindingCap() int {
	if w == nil {
		return 0
	}
	if w.FindingsCap == 0 {
		return 20
	}
	return w.FindingsCap
}

// DroppedEvents returns the number of non-critical webhook events dropped due to queue saturation.
func (w *Webhook) DroppedEvents() int64 {
	if w == nil {
		return 0
	}
	return atomic.LoadInt64(&w.droppedEvents)
}

func payloadFindingCapChecked(payload any) bool {
	m, ok := payload.(map[string]any)
	if !ok {
		return false
	}
	checked, _ := m[findingCapCheckedKey].(bool)
	return checked
}

func sanitizeGenericPayload(payload any) any {
	m, ok := payload.(map[string]any)
	if !ok {
		return payload
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if strings.HasPrefix(k, "_bp_") {
			continue
		}
		out[k] = v
	}
	return out
}

func (w *Webhook) postJSON(body map[string]any) {
	// Sign over the canonical body before any provider reshaping.
	canonicalBytes, _ := json.Marshal(body)
	var sig string
	if w.Secret != "" {
		sig = signHMACSHA256(canonicalBytes, w.Secret)
	}

	payload := body
	for _, p := range defaultProviders {
		if p.Matches(w.URL) {
			payload = p.Format(body)
			break
		}
	}
	b, _ := json.Marshal(payload)

	for attempt := 1; attempt <= w.Retries; attempt++ {
		req, err := http.NewRequest(http.MethodPost, w.URL, bytes.NewReader(b))
		if err != nil {
			w.logDelivery("request_error", body, attempt, 0, err.Error(), "")
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if sig != "" {
			req.Header.Set("X-BreachPilot-Signature", "sha256="+sig)
		}
		resp, err := w.client.Do(req)
		if err == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
			w.logDelivery("ok", body, attempt, resp.StatusCode, "", "")
			return
		}
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		w.logDelivery("retry", body, attempt, status, errMsg, "")
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		// Exponential backoff with a little jitter, interruptible on Stop().
		base := time.Duration(attempt*attempt) * 200 * time.Millisecond
		jitter := time.Duration((attempt*37)%120) * time.Millisecond
		select {
		case <-time.After(base + jitter):
		case <-w.stopCh:
			return
		}
	}
	w.logDelivery("failed", body, w.Retries, 0, "max retries exceeded", "")
}

func (w *Webhook) logDelivery(state string, body map[string]any, attempt int, status int, errMsg string, respBody string) {
	w.logMu.Lock()
	defer w.logMu.Unlock()
	if w.logFile == nil {
		return
	}
	entry := map[string]any{
		"ts":      time.Now().UTC().Format(time.RFC3339),
		"state":   state,
		"event":   body["event"],
		"attempt": attempt,
		"status":  status,
		"error":   redactSensitive(errMsg),
		"url":     redactURL(w.URL),
		"resp":    redactSensitive(respBody),
	}
	b, _ := json.Marshal(entry)
	_, _ = w.logFile.Write(append(b, '\n'))
}

func redactURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if i := strings.Index(raw, "/api/webhooks/"); i > 0 {
		return raw[:i] + "/api/webhooks/<redacted>"
	}
	if len(raw) > 16 {
		return raw[:8] + "...<redacted>"
	}
	return "<redacted>"
}

func redactSensitive(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	l := strings.ToLower(s)
	if strings.Contains(l, "token") || strings.Contains(l, "webhook") || strings.Contains(l, "authorization") {
		return "<redacted>"
	}
	return s
}

func signHMACSHA256(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
