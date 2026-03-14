package notify

import "testing"

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
