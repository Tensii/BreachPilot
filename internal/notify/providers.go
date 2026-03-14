package notify

import (
	"fmt"
	"strings"

	"breachpilot/internal/models"
)

// WebhookProvider defines how to format payloads for specific services.
type WebhookProvider interface {
	Name() string
	Matches(url string) bool
	Format(body map[string]any) map[string]any
}

// defaultProviders holds all registered webhook providers.
var defaultProviders = []WebhookProvider{
	&discordProvider{},
	&slackProvider{},
}

// -- Discord Provider --

type discordProvider struct{}

func (p *discordProvider) Name() string { return "Discord" }

func (p *discordProvider) Matches(url string) bool {
	u := strings.ToLower(strings.TrimSpace(url))
	return strings.Contains(u, "discord.com/api/webhooks/") || strings.Contains(u, "discordapp.com/api/webhooks/")
}

func (p *discordProvider) Format(body map[string]any) map[string]any {
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

	payloadRaw, _ := body["payload"].(map[string]any)
	if payloadRaw == nil {
		embed["description"] = fmt.Sprintf("event=%s", event)
		return discordMessage(content, embed, false)
	}

	switch event {
	case "job.resumed":
		jobID, _ := payloadRaw["job_id"].(string)
		target, _ := payloadRaw["target"].(string)
		reconDone := payloadRaw["recon_completed"]
		nucleiDone := payloadRaw["nuclei_completed"]
		modsDone := payloadRaw["modules_finished"]
		embed["title"] = "Job resumed"
		embed["color"] = 0x95a5a6
		embed["description"] = fmt.Sprintf("job_id=%s\ntarget=%s\nrecon_completed=%v\nnuclei_completed=%v\nmodules_finished=%v", jobID, target, reconDone, nucleiDone, modsDone)
	case "exploit.started":
		jobID, _ := payloadRaw["job_id"].(string)
		target, _ := payloadRaw["target"].(string)
		mode, _ := payloadRaw["mode"].(string)
		embed["title"] = "Exploit phase started"
		embed["color"] = 0x95a5a6
		embed["description"] = fmt.Sprintf("job_id=%s\ntarget=%s\nmode=%s", jobID, target, mode)
		content = "@here BreachPilot exploit started"
		return discordMessage(content, embed, true)
	case "exploit.finding":
		sev, _ := payloadRaw["severity"].(string)
		module, _ := payloadRaw["module"].(string)
		title, _ := payloadRaw["title"].(string)
		target, _ := payloadRaw["target"].(string)
		validation, _ := payloadRaw["validation"].(string)
		embed["title"] = fmt.Sprintf("Finding • %s", strings.ToUpper(strings.TrimSpace(sev)))
		embed["color"] = severityColor(sev)
		embed["description"] = fmt.Sprintf("target=%s\nmodule=%s\n%s\nvalidation=%s", target, module, title, validation)
	case "exploit.module.progress":
		module, _ := payloadRaw["module"].(string)
		stage, _ := payloadRaw["stage"].(string)
		detail, _ := payloadRaw["detail"].(string)
		jobID, _ := payloadRaw["job_id"].(string)
		target, _ := payloadRaw["target"].(string)
		embed["title"] = "Exploit module progress"
		embed["color"] = 0x95a5a6
		embed["description"] = fmt.Sprintf("job_id=%s\ntarget=%s\nstage=%s\nmodule=%s\n%s", jobID, target, stage, module, detail)
	case "exploit.modules.completed":
		jobID, _ := payloadRaw["job_id"].(string)
		target, _ := payloadRaw["target"].(string)
		findings := payloadRaw["findings_count"]
		filtered := payloadRaw["filtered_count"]
		risk := payloadRaw["risk_score"]
		modules := payloadRaw["module_count"]
		sevCounts, _ := payloadRaw["severity_counts"].(map[string]any)
		topFindings, _ := payloadRaw["top_findings"].([]any)
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
		if id, _ := payloadRaw["job_id"].(string); id != "" {
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

// -- Slack Provider --

type slackProvider struct{}

func (p *slackProvider) Name() string { return "Slack" }

func (p *slackProvider) Matches(url string) bool {
	u := strings.ToLower(strings.TrimSpace(url))
	return strings.Contains(u, "hooks.slack.com/services/") || strings.Contains(u, "slack.com/api/chat.postMessage")
}

func (p *slackProvider) Format(body map[string]any) map[string]any {
	// Simple Slack adaptation mapping events to attachments
	event, _ := body["event"].(string)
	if event == "" {
		event = "event"
	}

	text := fmt.Sprintf("*BreachPilot • %s*", event)

	if job, ok := body["job"].(*models.Job); ok && job != nil {
		desc := fmt.Sprintf("ID: `%s`\nTarget: `%s`\nStatus: `%s`", job.ID, job.Target, job.Status)
		if job.Error != "" {
			desc += fmt.Sprintf("\nError: `%s`", job.Error)
		}
		switch event {
		case "job.started":
			text = "<!here> BreachPilot exploit started"
		case "job.completed":
			text = "<!here> BreachPilot exploit finished"
		case "job.cancelled":
			text = "<!here> BreachPilot exploit interrupted"
		case "job.failed":
			text = "<!here> BreachPilot exploit failed"
		}
		return map[string]any{
			"text": text,
			"attachments": []map[string]any{
				{
					"text": desc,
					"color": slackColor(event, job.Error != ""),
				},
			},
		}
	}

	payloadRaw, _ := body["payload"].(map[string]any)
	if payloadRaw == nil {
		return map[string]any{"text": text}
	}

	// We can add more specific Slack formatting similar to Discord,
	// but for now we dump a formatted string of the payload into the attachment.
	attachmentText := ""
	for k, v := range payloadRaw {
		// exclude verbose nested maps for brief overview unless top tier
		if k == "top_findings" || k == "severity_counts" {
			// minimal layout
			continue
		}
		attachmentText += fmt.Sprintf("*%s*: `%v`\n", k, v)
	}

	if event == "exploit.finding" {
		sev, _ := payloadRaw["severity"].(string)
		title, _ := payloadRaw["title"].(string)
		return map[string]any{
			"text": fmt.Sprintf("*Finding • %s*", strings.ToUpper(strings.TrimSpace(sev))),
			"attachments": []map[string]any{
				{
					"title": title,
					"text":  attachmentText,
					"color": severitySlackColor(sev),
				},
			},
		}
	}

	return map[string]any{
		"text": text,
		"attachments": []map[string]any{
			{
				"text": attachmentText,
			},
		},
	}
}

func slackColor(event string, isError bool) string {
	if isError || strings.Contains(event, "failed") || strings.Contains(event, "cancelled") {
		return "danger"
	}
	if strings.Contains(event, "completed") {
		return "good"
	}
	return "#95a5a6"
}

func severitySlackColor(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL", "HIGH":
		return "danger"
	case "MEDIUM":
		return "warning"
	case "LOW":
		return "#3498db"
	default:
		return "#95a5a6"
	}
}
