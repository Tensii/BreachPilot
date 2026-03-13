package notify

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"breachpilot/internal/models"
)

type webhookEvent struct {
	Name string
	Job  *models.Job
}

type Webhook struct {
	URL     string
	Secret  string
	Retries int

	ch     chan webhookEvent
	once   sync.Once
	client *http.Client
}

func (w *Webhook) Start() {
	w.once.Do(func() {
		if w.Retries <= 0 {
			w.Retries = 3
		}
		w.ch = make(chan webhookEvent, 200)
		w.client = &http.Client{Timeout: 6 * time.Second}
		go w.loop()
	})
}

func (w *Webhook) loop() {
	for ev := range w.ch {
		w.sendNow(ev.Name, ev.Job)
	}
}

func (w *Webhook) Send(event string, job *models.Job) {
	if w.URL == "" || job == nil {
		return
	}
	w.Start()
	select {
	case w.ch <- webhookEvent{Name: event, Job: job}:
	default:
		// drop when saturated; queue protection
	}
}

func (w *Webhook) sendNow(eventName string, job *models.Job) {
	body := map[string]any{
		"event": eventName,
		"job":   job,
		"ts":    time.Now().UTC().Format(time.RFC3339),
	}
	b, _ := json.Marshal(body)

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

func signHMACSHA256(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
