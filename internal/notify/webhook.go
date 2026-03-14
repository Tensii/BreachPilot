package notify

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
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
	URL     string
	Secret  string
	Retries int

	ch       chan webhookEvent
	once     sync.Once
	stopOnce sync.Once
	wg       sync.WaitGroup
	client   *http.Client
}

func (w *Webhook) Start() {
	if w.URL == "" {
		return
	}
	w.once.Do(func() {
		if w.Retries <= 0 {
			w.Retries = 3
		}
		w.ch = make(chan webhookEvent, 200)
		w.client = &http.Client{Timeout: 6 * time.Second}
		w.wg.Add(1)
		go w.loop()
	})
}

func (w *Webhook) loop() {
	defer w.wg.Done()
	for ev := range w.ch {
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

	// Never drop terminal job events (started/completed/failed/cancelled/rejected)
	// even when the queue is saturated by noisy finding events.
	if strings.HasPrefix(event, "job.") {
		select {
		case w.ch <- webhookEvent{Name: event, Job: job}:
		case <-time.After(2 * time.Second):
			// Fallback: send synchronously to avoid missing critical state transitions.
			w.sendNow(event, job)
		}
		return
	}

	select {
	case w.ch <- webhookEvent{Name: event, Job: job}:
	default:
		// drop non-critical events when saturated; queue protection
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
	case w.ch <- webhookEvent{Name: eventType, Payload: payload}:
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
		if w.ch == nil {
			return
		}
		close(w.ch)
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
			return
		}
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		time.Sleep(time.Duration(attempt*attempt) * 200 * time.Millisecond)
	}
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
		embed["title"] = "Exploit modules completed"
		embed["color"] = 0x2ecc71
		embed["description"] = fmt.Sprintf("job_id=%s\ntarget=%s\nfindings=%v\nfiltered=%v\nrisk=%v\nmodules=%v", jobID, target, findings, filtered, risk, modules)
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
