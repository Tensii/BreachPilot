package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"breachpilot/internal/models"
)

type moduleRuntimeState struct {
	Status   string
	Findings int
}

type cliRuntimeTracker struct {
	mu               sync.Mutex
	out              io.Writer
	startedAt        time.Time
	currentStage     string
	totalModules     int
	moduleStates     map[string]moduleRuntimeState
	totalFindings    int
	severityCounts   map[string]int
	recentFindings   []models.FindingPreview
	lastProgress     *models.RuntimeProgress
	lastStageDetail  string
	lastErrorSummary string
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
	t.mu.Lock()
	defer t.mu.Unlock()

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
			t.trackProgress(ev)
			if ev.Progress != nil {
				fmt.Fprintln(t.out, renderRuntimeProgress(ev, t.snapshot()))
			} else {
				fmt.Fprintln(t.out, renderRuntimeLog(ev))
			}
		}
	}
}

func (t *cliRuntimeTracker) handleStage(ev models.RuntimeEvent) {
	t.trackProgress(ev)
	if ev.Stage != "" {
		t.currentStage = ev.Stage
	}
	if strings.TrimSpace(ev.Message) != "" {
		t.lastStageDetail = ev.Message
	}
	if ev.Stage == "exploit.errors" {
		t.lastErrorSummary = strings.TrimSpace(strings.TrimPrefix(ev.Message, "exploit.errors"))
	}
	fmt.Fprintln(t.out, renderRuntimeStage(ev, t.snapshot()))
}

func (t *cliRuntimeTracker) handleModule(ev models.RuntimeEvent) {
	t.trackProgress(ev)
	if ev.Progress != nil && ev.Progress.Total > 0 && strings.EqualFold(ev.Progress.Label, "modules") {
		t.totalModules = ev.Progress.Total
	} else if planned, ok := ev.Counts["planned"]; ok && planned > 0 {
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
	t.trackProgress(ev)
	fmt.Fprintln(t.out, renderRuntimeSummary(ev, t.snapshot()))
}

func (t *cliRuntimeTracker) trackProgress(ev models.RuntimeEvent) {
	if ev.Progress == nil {
		return
	}
	progress := *ev.Progress
	t.lastProgress = &progress
}

func (t *cliRuntimeTracker) snapshot() string {
	running := 0
	done := 0
	errored := 0
	skipped := 0
	activeModules := make([]string, 0, 3)
	for name, st := range t.moduleStates {
		switch st.Status {
		case "started":
			running++
			if len(activeModules) < 3 {
				activeModules = append(activeModules, name)
			}
		case "completed":
			done++
		case "error":
			errored++
		case "skipped":
			skipped++
		}
	}
	accounted := done + errored + skipped

	elapsed := time.Since(t.startedAt).Round(time.Second)
	parts := []string{
		fmt.Sprintf("findings=%d", t.totalFindings),
		fmt.Sprintf("C/H/M=%d/%d/%d", t.severityCounts["CRITICAL"], t.severityCounts["HIGH"], t.severityCounts["MEDIUM"]),
	}
	if accounted > 0 {
		parts = append(parts, fmt.Sprintf("done=%d/%d", accounted, t.totalModules))
	}
	if t.lastProgress != nil {
		parts = append(parts, formatRuntimeProgress(*t.lastProgress))
	}
	return fmt.Sprintf("[%s | %s]", elapsed, strings.Join(parts, " "))

}

func renderRuntimeStage(ev models.RuntimeEvent, snapshot string) string {
	label := stageLabel(ev.Stage)
	status := strings.ToUpper(emptyAs(ev.Status, "info"))
	color := statusColor(ev.Status)
	icon := statusIcon(ev.Status)
	
	// Specialized rendering for stages to be more dashboard-like
	return fmt.Sprintf("%s%s %-12s%s %-20s %s", color, icon, status, "\x1b[0m", label, snapshot)
}


func renderRuntimeModule(ev models.RuntimeEvent, snapshot string) string {
	color := "\x1b[33m"
	icon := "◉"
	switch ev.Status {
	case "completed":
		color = "\x1b[32m"
		icon = "✔"
	case "error":
		color = "\x1b[31m"
		icon = "✖"
	case "skipped":
		color = "\x1b[90m"
		icon = "⤼"
	case "started":
		color = "\x1b[36m"
		icon = "⚡"
	}
	detail := ev.Module
	if findings, ok := ev.Counts["findings"]; ok {
		detail = fmt.Sprintf("%s findings=%d", ev.Module, findings)
	}
	return fmt.Sprintf("%s[MODULE]%s %s %s %s", color, "\x1b[0m", icon, detail, snapshot)
}

func renderRuntimeFinding(f models.FindingPreview, snapshot string) string {
	color := severityColor(f.Severity)
	title := strings.TrimSpace(f.Title)
	if len(title) > 78 {
		title = title[:78] + "..."
	}
	return fmt.Sprintf("%s[HIT]%s ☣ %-8s %-9s %-18s %s | %s", color, "\x1b[0m", strings.ToUpper(f.Severity), emptyAs(f.Validation, "signal"), f.Module, title, snapshot)
}

func renderRuntimeSummary(ev models.RuntimeEvent, snapshot string) string {
	nuclei := ev.Counts["nuclei"]
	exploit := ev.Counts["exploit"]
	filtered := ev.Counts["filtered"]
	return fmt.Sprintf("\x1b[35m[SUMMARY]\x1b[0m ✔ nuclei=%d exploit=%d filtered=%d %s", nuclei, exploit, filtered, snapshot)
}

func renderRuntimeProgress(ev models.RuntimeEvent, snapshot string) string {
	bar := ""
	if ev.Progress != nil {
		bar = " " + progressBar(14, ev.Progress.Percent)
	}
	return fmt.Sprintf("\x1b[34m[PROGRESS]\x1b[0m%s %s | %s", bar, strings.TrimSpace(ev.Message), snapshot)
}

func renderRuntimeLog(ev models.RuntimeEvent) string {
	msg := ev.Message
	msg = strings.TrimPrefix(msg, "recon.log ")
	msg = strings.TrimPrefix(msg, "exploit.log ")
	msg = strings.TrimPrefix(msg, "[*] ")
	if strings.Contains(msg, "[LOG]") {
		return "" // Suppress redundant logs
	}
	return fmt.Sprintf("  \x1b[90m%s\x1b[0m", msg)
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

func statusColor(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed", "done", "success", "resumed":
		return "\x1b[32m"
	case "started", "running":
		return "\x1b[36m"
	case "warning", "planned", "polling":
		return "\x1b[33m"
	case "error", "failed", "cancelled", "rejected":
		return "\x1b[31m"
	default:
		return "\x1b[35m"
	}
}

func statusIcon(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed", "done", "success", "resumed":
		return "✔"
	case "started", "running":
		return "⚡"
	case "warning":
		return "⚠"
	case "error", "failed", "cancelled", "rejected":
		return "✖"
	case "polling":
		return "⌛"
	case "planned":
		return "◎"
	default:
		return "◆"
	}
}

func progressBar(width, percent int) string {
	if width <= 0 {
		width = 10
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	filled := (percent * width) / 100
	if filled > width {
		filled = width
	}
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + "]"
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

func formatRuntimeProgress(progress models.RuntimeProgress) string {
	label := strings.TrimSpace(progress.Label)
	if label == "" {
		label = "progress"
	}
	switch {
	case progress.Total > 0:
		return fmt.Sprintf("%s %d/%d (%d%%)", label, progress.Completed, progress.Total, progress.Percent)
	case progress.Percent > 0:
		return fmt.Sprintf("%s %d%%", label, progress.Percent)
	default:
		return label
	}
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
