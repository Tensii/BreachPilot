package notify

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

	criticalCh chan webhookEvent
	normalCh   chan webhookEvent
	once       sync.Once
	stopOnce   sync.Once
	wg         sync.WaitGroup
	client     *http.Client
	logMu      sync.Mutex
}

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
		w.client = &http.Client{Timeout: 6 * time.Second}
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
		// drop non-critical events when saturated
	}
}

// SendGeneric sends an arbitrary payload as a webhook event.
// Satisfies the engine.Notifier interface.
func (w *Webhook) SendGeneric(eventType string, payload any) {
	if w.URL == "" || payload == nil {
		return
	}
	w.Start()
	select {
	case w.normalCh <- webhookEvent{Name: eventType, Payload: payload}:
	default:
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
		"payload": payload,
		"ts":      time.Now().UTC().Format(time.RFC3339),
	}
	w.postJSON(body)
}

func (w *Webhook) postJSON(body map[string]any) {
	payload := body
	if isDiscordWebhookURL(w.URL) {
		payload = toDiscordPayload(body)
	}
	b, _ := json.Marshal(payload)

	for attempt := 1; attempt <= w.Retries; attempt++ {
		req, err := http.NewRequest(http.MethodPost, w.URL, bytes.NewReader(b))
		if err != nil {
			w.logDelivery("request_error", body, attempt, 0, err.Error(), "")
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if w.Secret != "" {
			sig := signHMACSHA256(b, w.Secret)
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
		// Exponential backoff with a little jitter.
		base := time.Duration(attempt*attempt) * 200 * time.Millisecond
		jitter := time.Duration((attempt*37)%120) * time.Millisecond
		time.Sleep(base + jitter)
	}
	w.logDelivery("failed", body, w.Retries, 0, "max retries exceeded", "")
}

func (w *Webhook) logDelivery(state string, body map[string]any, attempt int, status int, errMsg string, respBody string) {
	if strings.TrimSpace(w.DebugLogPath) == "" {
		return
	}
	entry := map[string]any{
		"ts":      time.Now().UTC().Format(time.RFC3339),
		"state":   state,
		"event":   body["event"],
		"attempt": attempt,
		"status":  status,
		"error":   errMsg,
		"url":     w.URL,
		"resp":    respBody,
	}
	b, _ := json.Marshal(entry)
	w.logMu.Lock()
	defer w.logMu.Unlock()
	_ = os.MkdirAll(filepath.Dir(w.DebugLogPath), 0o755)
	f, err := os.OpenFile(w.DebugLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

func isDiscordWebhookURL(u string) bool {
	u = strings.ToLower(strings.TrimSpace(u))
	return strings.Contains(u, "discord.com/api/webhooks/") || strings.Contains(u, "discordapp.com/api/webhooks/")
}

func toDiscordPayload(body map[string]any) map[string]any {
	event, _ := body["event"].(string)
	if event == "" {
		event = "event"
	}

	mentionHere := false
	content := ""
	embed := map[string]any{
		"title":       fmt.Sprintf("BreachPilot • %s", event),
		"description": "",
		"color":       0x95a5a6, // default gray
	}

	if job, ok := body["job"].(*models.Job); ok && job != nil {
		desc := fmt.Sprintf("id=%s\ntarget=%s\nstatus=%s", job.ID, job.Target, job.Status)
		if job.Error != "" && (event == "job.failed" || job.Status == "failed") {
			desc += fmt.Sprintf("\nerror=%s", job.Error)
		}
		embed["description"] = desc
		switch event {
		case "job.started":
			mentionHere = true
			embed["color"] = 0x95a5a6 // gray
			content = "@here BreachPilot exploit started"
		case "job.completed":
			mentionHere = true
			embed["color"] = 0x2ecc71 // green
			content = "@here BreachPilot exploit finished"
		case "job.cancelled":
			mentionHere = true
			embed["color"] = 0xe74c3c // red
			content = "@here BreachPilot exploit interrupted"
		case "job.failed":
			mentionHere = true
			embed["color"] = 0xe74c3c // red
			content = "@here BreachPilot exploit failed"
		default:
			embed["color"] = 0x95a5a6
		}
		return discordMessage(content, embed, mentionHere)
	}

	p, _ := body["payload"].(map[string]any)
	if p == nil {
		embed["description"] = fmt.Sprintf("event=%s", event)
		return discordMessage(content, embed, false)
	}

	switch event {
	case "job.resumed":
		jobID, _ := p["job_id"].(string)
		target, _ := p["target"].(string)
		reconDone := p["recon_completed"]
		nucleiDone := p["nuclei_completed"]
		modsDone := p["modules_finished"]
		embed["title"] = "Job resumed"
		embed["color"] = 0x95a5a6
		embed["description"] = fmt.Sprintf("job_id=%s\ntarget=%s\nrecon_completed=%v\nnuclei_completed=%v\nmodules_finished=%v", jobID, target, reconDone, nucleiDone, modsDone)
	case "exploit.started":
		jobID, _ := p["job_id"].(string)
		target, _ := p["target"].(string)
		mode, _ := p["mode"].(string)
		embed["title"] = "Exploit phase started"
		embed["color"] = 0x95a5a6
		embed["description"] = fmt.Sprintf("job_id=%s\ntarget=%s\nmode=%s", jobID, target, mode)
		content = "@here BreachPilot exploit started"
		return discordMessage(content, embed, true)
	case "exploit.finding":
		sev, _ := p["severity"].(string)
		module, _ := p["module"].(string)
		title, _ := p["title"].(string)
		target, _ := p["target"].(string)
		validation, _ := p["validation"].(string)
		embed["title"] = fmt.Sprintf("Finding • %s", strings.ToUpper(strings.TrimSpace(sev)))
		embed["color"] = severityColor(sev)
		embed["description"] = fmt.Sprintf("target=%s\nmodule=%s\n%s\nvalidation=%s", target, module, title, validation)
	case "exploit.module.progress":
		module, _ := p["module"].(string)
		stage, _ := p["stage"].(string)
		detail, _ := p["detail"].(string)
		jobID, _ := p["job_id"].(string)
		target, _ := p["target"].(string)
		embed["title"] = "Exploit module progress"
		embed["color"] = 0x95a5a6
		embed["description"] = fmt.Sprintf("job_id=%s\ntarget=%s\nstage=%s\nmodule=%s\n%s", jobID, target, stage, module, detail)
	case "exploit.modules.completed":
		jobID, _ := p["job_id"].(string)
		target, _ := p["target"].(string)
		findings := p["findings_count"]
		filtered := p["filtered_count"]
		risk := p["risk_score"]
		modules := p["module_count"]
		sevCounts, _ := p["severity_counts"].(map[string]any)
		topFindings, _ := p["top_findings"].([]any)
		topLine := ""
		if len(topFindings) > 0 {
			topLine = "\ntop_high_critical:"
			for i, tf := range topFindings {
				if i >= 3 {
					break
				}
				if m, ok := tf.(map[string]any); ok {
					topLine += fmt.Sprintf("\n- [%v] %v", m["severity"], m["title"])
				}
			}
		}
		sevLine := ""
		if sevCounts != nil {
			sevLine = fmt.Sprintf("\nsev: C=%v H=%v M=%v L=%v I=%v", sevCounts["CRITICAL"], sevCounts["HIGH"], sevCounts["MEDIUM"], sevCounts["LOW"], sevCounts["INFO"])
		}
		embed["title"] = "Exploit modules completed"
		embed["color"] = 0x2ecc71
		embed["description"] = fmt.Sprintf("job_id=%s\ntarget=%s\nfindings=%v\nfiltered=%v\nrisk=%v\nmodules=%v%s%s", jobID, target, findings, filtered, risk, modules, sevLine, topLine)
	default:
		if id, _ := p["job_id"].(string); id != "" {
			embed["description"] = fmt.Sprintf("event=%s\njob_id=%s", event, id)
		} else {
			embed["description"] = fmt.Sprintf("event=%s", event)
		}
	}

	return discordMessage(content, embed, false)
}

func discordMessage(content string, embed map[string]any, mentionHere bool) map[string]any {
	msg := map[string]any{"embeds": []map[string]any{embed}}
	if content != "" {
		msg["content"] = content
	}
	if mentionHere {
		msg["allowed_mentions"] = map[string]any{"parse": []string{"everyone"}}
	}
	return msg
}

func severityColor(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return 0xe74c3c // red
	case "HIGH":
		return 0xe67e22 // orange
	case "MEDIUM":
		return 0xf1c40f // yellow
	case "LOW":
		return 0x3498db // blue
	default:
		return 0x95a5a6 // gray/info
	}
}

func signHMACSHA256(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
