package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"breachpilot/internal/models"
)

type moduleRuntimeState struct {
	Status   string
	Findings int
}

type cliRuntimeTracker struct {
	out             io.Writer
	startedAt       time.Time
	currentStage    string
	totalModules    int
	moduleStates    map[string]moduleRuntimeState
	totalFindings   int
	severityCounts  map[string]int
	recentFindings  []models.FindingPreview
	lastStageDetail string
}

func newCLIRuntimeTracker(out io.Writer) *cliRuntimeTracker {
	return &cliRuntimeTracker{
		out:          out,
		startedAt:    time.Now().UTC(),
		moduleStates: map[string]moduleRuntimeState{},
		severityCounts: map[string]int{
			"CRITICAL": 0,
			"HIGH":     0,
			"MEDIUM":   0,
			"LOW":      0,
			"INFO":     0,
		},
	}
}

func (t *cliRuntimeTracker) Handle(ev models.RuntimeEvent) {
	if t == nil || t.out == nil {
		return
	}
	switch ev.Kind {
	case "stage":
		t.handleStage(ev)
	case "module":
		t.handleModule(ev)
	case "finding":
		t.handleFinding(ev)
	case "summary":
		t.handleSummary(ev)
	case "log":
		if strings.HasPrefix(ev.Stage, "recon.log") || strings.HasPrefix(ev.Stage, "exploit.log") {
			fmt.Fprintln(t.out, renderRuntimeLog(ev))
		}
	}
}

func (t *cliRuntimeTracker) handleStage(ev models.RuntimeEvent) {
	if ev.Stage != "" {
		t.currentStage = ev.Stage
	}
	if strings.TrimSpace(ev.Message) != "" {
		t.lastStageDetail = ev.Message
	}
	fmt.Fprintln(t.out, renderRuntimeStage(ev, t.snapshot()))
}

func (t *cliRuntimeTracker) handleModule(ev models.RuntimeEvent) {
	if planned, ok := ev.Counts["planned"]; ok && planned > 0 {
		t.totalModules = planned
	}
	state := t.moduleStates[ev.Module]
	state.Status = ev.Status
	if findings, ok := ev.Counts["findings"]; ok {
		state.Findings = findings
	}
	t.moduleStates[ev.Module] = state
	fmt.Fprintln(t.out, renderRuntimeModule(ev, t.snapshot()))
}

func (t *cliRuntimeTracker) handleFinding(ev models.RuntimeEvent) {
	if ev.Finding == nil {
		return
	}
	sev := strings.ToUpper(strings.TrimSpace(ev.Finding.Severity))
	if _, ok := t.severityCounts[sev]; ok {
		t.severityCounts[sev]++
	}
	t.totalFindings++
	t.recentFindings = append([]models.FindingPreview{*ev.Finding}, t.recentFindings...)
	if len(t.recentFindings) > 5 {
		t.recentFindings = t.recentFindings[:5]
	}
	fmt.Fprintln(t.out, renderRuntimeFinding(*ev.Finding, t.snapshot()))
}

func (t *cliRuntimeTracker) handleSummary(ev models.RuntimeEvent) {
	fmt.Fprintln(t.out, renderRuntimeSummary(ev, t.snapshot()))
}

func (t *cliRuntimeTracker) snapshot() string {
	running := 0
	done := 0
	skipped := 0
	for _, st := range t.moduleStates {
		switch st.Status {
		case "started":
			running++
		case "completed":
			done++
		case "skipped":
			skipped++
		}
	}
	moduleProgress := "modules=0"
	switch {
	case t.totalModules > 0:
		moduleProgress = fmt.Sprintf("modules=%d/%d running=%d skipped=%d", done, t.totalModules, running, skipped)
	case len(t.moduleStates) > 0:
		moduleProgress = fmt.Sprintf("modules=%d running=%d skipped=%d", done, running, skipped)
	}
	elapsed := time.Since(t.startedAt).Round(time.Second)
	return fmt.Sprintf("elapsed=%s findings=%d high+critical=%d %s", elapsed, t.totalFindings, t.severityCounts["CRITICAL"]+t.severityCounts["HIGH"], moduleProgress)
}

func renderRuntimeStage(ev models.RuntimeEvent, snapshot string) string {
	label := stageLabel(ev.Stage)
	status := strings.ToUpper(emptyAs(ev.Status, "info"))
	return fmt.Sprintf("\x1b[36m[%s]\x1b[0m \x1b[1m%s\x1b[0m %s", status, label, snapshotWithDetail(snapshot, ev.Message))
}

func renderRuntimeModule(ev models.RuntimeEvent, snapshot string) string {
	color := "\x1b[33m"
	switch ev.Status {
	case "completed":
		color = "\x1b[32m"
	case "error":
		color = "\x1b[31m"
	case "skipped":
		color = "\x1b[90m"
	}
	detail := ev.Module
	if findings, ok := ev.Counts["findings"]; ok {
		detail = fmt.Sprintf("%s findings=%d", ev.Module, findings)
	}
	return fmt.Sprintf("%s[MODULE]\x1b[0m %s %s", color, detail, snapshot)
}

func renderRuntimeFinding(f models.FindingPreview, snapshot string) string {
	color := severityColor(f.Severity)
	title := strings.TrimSpace(f.Title)
	if len(title) > 78 {
		title = title[:78] + "..."
	}
	return fmt.Sprintf("%s[HIT]\x1b[0m %-8s %-9s %-18s %s | %s", color, strings.ToUpper(f.Severity), emptyAs(f.Validation, "signal"), f.Module, title, snapshot)
}

func renderRuntimeSummary(ev models.RuntimeEvent, snapshot string) string {
	nuclei := ev.Counts["nuclei"]
	exploit := ev.Counts["exploit"]
	filtered := ev.Counts["filtered"]
	return fmt.Sprintf("\x1b[35m[SUMMARY]\x1b[0m nuclei=%d exploit=%d filtered=%d %s", nuclei, exploit, filtered, snapshot)
}

func renderRuntimeLog(ev models.RuntimeEvent) string {
	return fmt.Sprintf("\x1b[90m[LOG]\x1b[0m %s", ev.Message)
}

func stageLabel(stage string) string {
	stage = strings.TrimSpace(stage)
	if stage == "" {
		return "runtime"
	}
	parts := strings.Split(stage, ".")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "module" {
			continue
		}
		out = append(out, strings.ToUpper(part))
	}
	if len(out) == 0 {
		return strings.ToUpper(stage)
	}
	return strings.Join(out, " / ")
}

func severityColor(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return "\x1b[31m"
	case "HIGH":
		return "\x1b[91m"
	case "MEDIUM":
		return "\x1b[33m"
	case "LOW":
		return "\x1b[36m"
	default:
		return "\x1b[90m"
	}
}

func snapshotWithDetail(snapshot, detail string) string {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return snapshot
	}
	if len(detail) > 90 {
		detail = detail[:90] + "..."
	}
	return detail + " | " + snapshot
}

func summarizeTopModules(job *models.Job) string {
	if job == nil || len(job.ModuleTelemetry) == 0 {
		return ""
	}
	items := append([]models.ExploitModuleTelemetry{}, job.ModuleTelemetry...)
	sort.Slice(items, func(i, j int) bool {
		if items[i].AcceptedCount != items[j].AcceptedCount {
			return items[i].AcceptedCount > items[j].AcceptedCount
		}
		if items[i].FindingsCount != items[j].FindingsCount {
			return items[i].FindingsCount > items[j].FindingsCount
		}
		return items[i].DurationMs > items[j].DurationMs
	})
	parts := make([]string, 0, 3)
	for _, item := range items {
		if item.Skipped || item.ErrorCount > 0 {
			continue
		}
		if item.AcceptedCount > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d/%d", item.Module, item.AcceptedCount, item.FindingsCount))
		} else if item.FindingsCount > 0 {
			parts = append(parts, fmt.Sprintf("%s=0/%d", item.Module, item.FindingsCount))
		} else {
			continue
		}
		if len(parts) == 3 {
			break
		}
	}
	return strings.Join(parts, ", ")
}
