package notify

import (
	"testing"

	"breachpilot/internal/models"
)

func TestDiscordProviderBatchFormatting(t *testing.T) {
	p := &discordProvider{}
	body := map[string]any{
		"event": "exploit.findings.batch",
		"payload": map[string]any{
			"job_id": "x/1",
			"target": "example.com",
			"counts": map[string]any{"INFO": 1, "LOW": 2, "MEDIUM": 3},
			"sample": []any{map[string]any{"severity": "LOW", "title": "x"}},
		},
	}
	out := p.Format(body)
	embeds, ok := out["embeds"].([]map[string]any)
	if !ok || len(embeds) == 0 {
		t.Fatalf("expected embeds output")
	}
}

func TestProviderNamesAndMatches(t *testing.T) {
	dp := &discordProvider{}
	if dp.Name() != "Discord" {
		t.Fatalf("unexpected discord provider name: %s", dp.Name())
	}
	if !dp.Matches("https://discord.com/api/webhooks/abc/def") {
		t.Fatal("expected discord webhook URL to match")
	}
	if dp.Matches("https://example.com/webhook") {
		t.Fatal("did not expect non-discord URL to match")
	}

	sp := &slackProvider{}
	if sp.Name() != "Slack" {
		t.Fatalf("unexpected slack provider name: %s", sp.Name())
	}
	if !sp.Matches("https://hooks.slack.com/services/T/B/X") {
		t.Fatal("expected slack webhook URL to match")
	}
	if sp.Matches("https://example.com/hook") {
		t.Fatal("did not expect non-slack URL to match")
	}
}

func TestDiscordProviderJobFormatting(t *testing.T) {
	p := &discordProvider{}
	body := map[string]any{
		"event": "job.started",
		"job": mapToJob(map[string]any{
			"id":     "x/1",
			"target": "example.com",
			"status": "running",
		}),
	}
	out := p.Format(body)
	if _, ok := out["allowed_mentions"]; !ok {
		t.Fatal("expected allowed_mentions for started job event")
	}
	if got, _ := out["content"].(string); got == "" {
		t.Fatal("expected content mention text")
	}
}

func TestSlackProviderFormattingPaths(t *testing.T) {
	p := &slackProvider{}

	jobOut := p.Format(map[string]any{
		"event": "job.failed",
		"job": mapToJob(map[string]any{
			"id":     "x/2",
			"target": "example.org",
			"status": "failed",
			"error":  "boom",
		}),
	})
	if got, _ := jobOut["text"].(string); got == "" {
		t.Fatal("expected slack job text")
	}

	findingOut := p.Format(map[string]any{
		"event": "exploit.finding",
		"payload": map[string]any{
			"severity": "HIGH",
			"title":    "Interesting finding",
			"job_id":   "x/2",
		},
	})
	if got, _ := findingOut["text"].(string); got == "" {
		t.Fatal("expected finding summary text")
	}
}

func TestColorHelpers(t *testing.T) {
	if severityColor("critical") == severityColor("info") {
		t.Fatal("expected different colors for critical and info")
	}
	if slackColor("job.failed", false) != "danger" {
		t.Fatal("expected failed event to map to danger")
	}
	if severitySlackColor("MEDIUM") != "warning" {
		t.Fatal("expected medium severity slack color warning")
	}
}

func mapToJob(in map[string]any) *models.Job {
	j := &models.Job{}
	if v, ok := in["id"].(string); ok {
		j.ID = v
	}
	if v, ok := in["target"].(string); ok {
		j.Target = v
	}
	if v, ok := in["status"].(string); ok {
		j.Status = models.JobStatus(v)
	}
	if v, ok := in["error"].(string); ok {
		j.Error = v
	}
	return j
}
