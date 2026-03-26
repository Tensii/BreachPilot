package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	configpkg "breachpilot/internal/config"
	"breachpilot/internal/exploit"
	"breachpilot/internal/models"
)

func TestProcessReconTimeout(t *testing.T) {
	dir := t.TempDir()
	reconScript := filepath.Join(dir, "sleepy_recon.sh")
	script := `#!/usr/bin/env bash
set -e
if [[ "${1:-}" == "--help" ]]; then
  cat <<'EOF'
usage: reconHarvest.py [-h] [--run] [--resume RESUME] [-o OUTPUT] [target]
EOF
  exit 0
fi
sleep 2
`
	if err := os.WriteFile(reconScript, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	job := &models.Job{ID: "j1", Target: "example.com", Mode: "full", SafeMode: true}
	opt := Options{
		ReconHarvestCmd: reconScript,
		ReconTimeoutSec: 1,
		NucleiBin:       "true",
		ArtifactsRoot:   dir,
	}
	if err := Process(context.Background(), job, opt); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if job.Status != models.JobFailed {
		t.Fatalf("want failed got %s", job.Status)
	}
	if job.Error == "" {
		t.Fatal("expected timeout error")
	}
}

func TestProcessFileModeWritesReport(t *testing.T) {
	dir := t.TempDir()
	reconDir := filepath.Join(dir, "recon")
	_ = os.MkdirAll(reconDir, 0o755)
	summary := filepath.Join(reconDir, "summary.json")
	live := filepath.Join(reconDir, "live_hosts.txt")
	_ = os.WriteFile(live, []byte("https://example.com\n"), 0o644)
	_ = os.WriteFile(summary, []byte(`{"workdir":"`+reconDir+`","live_hosts":"`+live+`","urls":{"all":""},"intel":{"endpoints_ranked_json":"","params_ranked_json":""}}`), 0o644)

	job := &models.Job{ID: "j2", Target: "example.com", Mode: "ingest", SafeMode: true, ReconPath: summary}
	opt := Options{NucleiBin: "true", ArtifactsRoot: dir}
	if err := Process(context.Background(), job, opt); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if job.ReportPath == "" {
		t.Fatal("expected report path")
	}
	if _, err := os.Stat(job.ReportPath); err != nil {
		t.Fatalf("report missing: %v", err)
	}
	b, _ := os.ReadFile(job.ReportPath)
	if !strings.Contains(string(b), "\"schema_version\": \"1\"") {
		t.Fatalf("schema version missing in job report")
	}
}

func TestProcessFullModeAdaptsToOlderReconHarvestFlags(t *testing.T) {
	dir := t.TempDir()
	reconScript := filepath.Join(dir, "fake_recon.py")
	script := `#!/usr/bin/env bash
set -e
if [[ "${1:-}" == "--help" ]]; then
  cat <<'EOF'
usage: reconHarvest.py [-h] [--run] [--resume RESUME] [-o OUTPUT] [--skip-nuclei] [--overwrite] [target]
EOF
  exit 0
fi
for arg in "$@"; do
  if [[ "$arg" == "--arjun-threads" || "$arg" == "--vhost-threads" ]]; then
    echo "unexpected unsupported arg: $arg" >&2
    exit 2
  fi
done
out=""
target=""
resume=""
while (($#)); do
  case "$1" in
    --run|--skip-nuclei|--overwrite)
      shift
      ;;
    --resume)
      resume="$2"
      shift 2
      ;;
    -o|--output)
      out="$2"
      shift 2
      ;;
    *)
      if [[ -z "$target" ]]; then
        target="$1"
      fi
      shift
      ;;
  esac
done
if [[ -n "$resume" ]]; then
  out="$resume"
fi
mkdir -p "$out"
cat > "$out/summary.json" <<EOF
{"workdir":"$out","live_hosts":"$out/live_hosts.txt","urls":{"all":""},"intel":{"endpoints_ranked_json":"","params_ranked_json":""}}
EOF
echo "https://${target:-example.com}" > "$out/live_hosts.txt"
`
	if err := os.WriteFile(reconScript, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	job := &models.Job{ID: "compat-recon", Target: "example.com", Mode: "full", SafeMode: true}
	opt := Options{
		ReconHarvestCmd: reconScript,
		ReconTimeoutSec: 10,
		ReconRetries:    0,
		NucleiBin:       "true",
		ArtifactsRoot:   dir,
		SkipNuclei:      true,
	}
	if err := Process(context.Background(), job, opt); err != nil {
		t.Fatalf("expected compatible recon run, got %v", err)
	}
	if job.Status != models.JobDone {
		t.Fatalf("expected successful job, got %s error=%s", job.Status, job.Error)
	}
	if strings.TrimSpace(job.ReconPath) == "" {
		t.Fatalf("expected recon path to be populated")
	}
}

func TestProcessFullModeRunsRelativeInterpreterScriptFromChangedWorkdir(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	reconScript := filepath.Join(dir, "tools", "reconharvest", "reconHarvest.py")
	if err := os.MkdirAll(filepath.Dir(reconScript), 0o755); err != nil {
		t.Fatal(err)
	}
	script := `#!/usr/bin/env python3
import os
import sys

if "--help" in sys.argv:
    print("usage: reconHarvest.py [-h] [--run] [--resume RESUME] [-o OUTPUT] [--skip-nuclei] [--overwrite] [target]")
    sys.exit(0)

out = ""
target = ""
resume = ""
i = 1
while i < len(sys.argv):
    arg = sys.argv[i]
    if arg in ("--run", "--skip-nuclei", "--overwrite"):
        i += 1
        continue
    if arg == "--resume":
        resume = sys.argv[i + 1]
        i += 2
        continue
    if arg in ("-o", "--output"):
        out = sys.argv[i + 1]
        i += 2
        continue
    if not arg.startswith("-") and not target:
        target = arg
    i += 1

if resume:
    out = resume
os.makedirs(out, exist_ok=True)
with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as f:
    f.write("{\"workdir\":\"" + out + "\",\"live_hosts\":\"" + out + "/live_hosts.txt\",\"urls\":{\"all\":\"\"},\"intel\":{\"endpoints_ranked_json\":\"\",\"params_ranked_json\":\"\"}}")
with open(os.path.join(out, "live_hosts.txt"), "w", encoding="utf-8") as f:
    f.write("https://" + (target or "example.com") + "\n")
`
	if err := os.WriteFile(reconScript, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	job := &models.Job{ID: "relative-recon", Target: "example.com", Mode: "full", SafeMode: true}
	opt := Options{
		ReconHarvestCmd: "python3 ./tools/reconharvest/reconHarvest.py",
		ReconTimeoutSec: 10,
		ReconRetries:    0,
		NucleiBin:       "true",
		ArtifactsRoot:   dir,
		SkipNuclei:      true,
	}
	if err := Process(context.Background(), job, opt); err != nil {
		t.Fatalf("expected relative recon command to succeed, got %v", err)
	}
	if job.Status != models.JobDone {
		t.Fatalf("expected successful job, got %s error=%s", job.Status, job.Error)
	}
	if strings.TrimSpace(job.ReconPath) == "" {
		t.Fatalf("expected recon path to be populated")
	}
}

func TestProcessFailsWhenExploitFindingsWriteFails(t *testing.T) {
	dir := t.TempDir()
	reconDir := filepath.Join(dir, "recon")
	_ = os.MkdirAll(reconDir, 0o755)
	summary := filepath.Join(reconDir, "summary.json")
	live := filepath.Join(reconDir, "live_hosts.txt")
	cors := filepath.Join(reconDir, "cors.json")
	_ = os.WriteFile(live, []byte("https://example.com\n"), 0o644)
	_ = os.WriteFile(cors, []byte(`[{"host":"https://example.com","severity":"HIGH","acao":"*","acac":"true"}]`), 0o644)
	_ = os.WriteFile(summary, []byte(`{"workdir":"`+reconDir+`","live_hosts":"`+live+`","urls":{"all":""},"intel":{"endpoints_ranked_json":"","params_ranked_json":"","cors_findings_json":"`+cors+`"}}`), 0o644)

	nucleiScript := filepath.Join(dir, "fake_nuclei.sh")
	script := "#!/usr/bin/env bash\nset -e\nout=\"\"\nfor ((i=1;i<=$#;i++)); do if [[ \"${!i}\" == '-o' ]]; then j=$((i+1)); out=\"${!j}\"; fi; done\nmkdir -p \"$(dirname \"$out\")\"\necho '{\"template-id\":\"x\",\"info\":{\"name\":\"x\",\"severity\":\"high\"},\"matched-at\":\"https://example.com\"}' > \"$out\"\nchmod 500 \"$(dirname \"$out\")\"\n"
	_ = os.WriteFile(nucleiScript, []byte(script), 0o755)

	job := &models.Job{ID: "j3", Target: "example.com", Mode: "ingest", SafeMode: true, ReconPath: summary}
	opt := Options{NucleiBin: nucleiScript, ArtifactsRoot: dir}
	err := Process(context.Background(), job, opt)
	_ = os.Chmod(filepath.Join(dir, job.ID), 0o755)
	if err == nil {
		t.Fatal("expected error")
	}
	if job.Status != models.JobFailed {
		t.Fatalf("want failed got %s", job.Status)
	}
	if job.ExploitFindingsPath != "" {
		t.Fatalf("expected empty exploit findings path on failure")
	}
	if job.ExploitReportPath != "" || job.ExploitHTMLReportPath != "" {
		t.Fatalf("expected no exploit report paths on failure")
	}
}

func TestValidateReconSummarySchemaMismatch(t *testing.T) {
	dir := t.TempDir()
	summary := filepath.Join(dir, "summary.json")
	live := filepath.Join(dir, "live_hosts.txt")
	_ = os.WriteFile(live, []byte("https://example.com\n"), 0o644)
	_ = os.WriteFile(summary, []byte(`{"schema_version":"999","workdir":"`+dir+`","live_hosts":"`+live+`","urls":{"all":""},"intel":{"endpoints_ranked_json":"","params_ranked_json":""}}`), 0o644)
	_, err := validateReconSummary(summary, "example.com")
	if err == nil {
		t.Fatal("expected schema mismatch error")
	}
}

func TestFileAndFullProduceCompatibleCounts(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live_hosts.txt")
	_ = os.WriteFile(live, []byte("http://127.0.0.1:9\n"), 0o644)
	summary := filepath.Join(dir, "summary.json")
	_ = os.WriteFile(summary, []byte(`{"workdir":"`+dir+`","live_hosts":"`+live+`","urls":{"all":""},"intel":{"endpoints_ranked_json":"","params_ranked_json":""}}`), 0o644)

	jobFile := &models.Job{ID: "c1", Target: "example.com", Mode: "ingest", SafeMode: true, ReconPath: summary}
	opt := Options{NucleiBin: "true", ArtifactsRoot: dir}
	if err := Process(context.Background(), jobFile, opt); err != nil {
		t.Fatalf("ingest failed: %v", err)
	}

	reconScript := filepath.Join(dir, "fake_recon.sh")
	script := "#!/usr/bin/env bash\nset -e\nout=\"\"\nfor ((i=1;i<=$#;i++)); do if [[ \"${!i}\" == '-o' ]]; then j=$((i+1)); out=\"${!j}\"; fi; done\nmkdir -p \"$out\"\ncp \"" + summary + "\" \"$out/summary.json\"\n"
	_ = os.WriteFile(reconScript, []byte(script), 0o755)
	jobFull := &models.Job{ID: "c2", Target: "example.com", Mode: "full", SafeMode: true}
	opt2 := Options{NucleiBin: "true", ReconHarvestCmd: reconScript, ArtifactsRoot: dir}
	if err := Process(context.Background(), jobFull, opt2); err != nil {
		t.Fatalf("full failed: %v", err)
	}
	if jobFile.ExploitFindingsCount != jobFull.ExploitFindingsCount {
		t.Fatalf("incompatible exploit counts: %d vs %d", jobFile.ExploitFindingsCount, jobFull.ExploitFindingsCount)
	}
}

func TestAnnotateModuleTelemetryYield(t *testing.T) {
	in := []models.ExploitModuleTelemetry{
		{Module: "ssrf-prober", FindingsCount: 3},
		{Module: "cookie-security", FindingsCount: 2},
		{Module: "planner-only", Skipped: true},
	}
	raw := []models.ExploitFinding{
		{Module: "ssrf-prober"},
		{Module: "ssrf-prober"},
		{Module: "ssrf-prober"},
		{Module: "cookie-security"},
		{Module: "cookie-security"},
	}
	accepted := []models.ExploitFinding{
		{Module: "ssrf-prober"},
	}

	out := annotateModuleTelemetryYield(in, raw, accepted)
	if out[0].AcceptedCount != 1 || out[0].FilteredCount != 2 {
		t.Fatalf("expected ssrf-prober yield 1 accepted / 2 filtered, got %+v", out[0])
	}
	if out[1].AcceptedCount != 0 || out[1].FilteredCount != 2 {
		t.Fatalf("expected cookie-security to be fully filtered, got %+v", out[1])
	}
	if out[2].AcceptedCount != 0 || out[2].FilteredCount != 0 {
		t.Fatalf("expected skipped planner entry to remain zero-yield, got %+v", out[2])
	}
}

func TestWriteRuntimeConfigSnapshotIncludesResolvedExploitSettings(t *testing.T) {
	dir := t.TempDir()
	job := &models.Job{ID: "cfg/1", Target: "example.com", Mode: "full"}
	opt := Options{
		ArtifactsRoot:                  dir,
		ScanProfile:                    "exploit",
		MaxParallel:                    6,
		ModuleTimeoutSec:               900,
		ModuleRetries:                  2,
		AggressiveMode:                 true,
		ProofMode:                      true,
		OOBHTTPListenAddr:              "127.0.0.1:9091",
		OOBHTTPPublicBaseURL:           "https://oob.example.com/callback",
		SkipNuclei:                     true,
		AuthUserHeaders:                "Authorization: Bearer user",
		BrowserCaptureEnabled:          true,
		BrowserCaptureMaxPages:         8,
		BrowserCapturePerPageWaitMs:    1000,
		BrowserCaptureSettleWaitMs:     500,
		BrowserCaptureScrollSteps:      2,
		BrowserCaptureMaxRoutesPerPage: 10,
	}

	if err := os.MkdirAll(filepath.Join(dir, job.ID), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeRuntimeConfigSnapshot(job, opt); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(filepath.Join(dir, job.ID, "runtime_config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Config map[string]any `json:"config"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatal(err)
	}
	if got := int(parsed.Config["max_parallel"].(float64)); got != 6 {
		t.Fatalf("expected max_parallel=6, got %d", got)
	}
	if got := int(parsed.Config["http_max_inflight"].(float64)); got != 12 {
		t.Fatalf("expected http_max_inflight=12, got %d", got)
	}
	if got := int(parsed.Config["module_timeout_sec"].(float64)); got != 900 {
		t.Fatalf("expected module_timeout_sec=900, got %d", got)
	}
	if got := int(parsed.Config["module_retries"].(float64)); got != 2 {
		t.Fatalf("expected module_retries=2, got %d", got)
	}
	if got := parsed.Config["aggressive_mode"].(bool); !got {
		t.Fatal("expected aggressive_mode=true")
	}
	if got := parsed.Config["proof_mode"].(bool); !got {
		t.Fatal("expected proof_mode=true")
	}
	if got := parsed.Config["oob_provider"].(string); got != "builtin-http" {
		t.Fatalf("expected builtin-http oob provider, got %q", got)
	}
	if got := parsed.Config["skip_nuclei"].(bool); !got {
		t.Fatal("expected skip_nuclei=true")
	}
	if got := parsed.Config["has_auth_user_context"].(bool); !got {
		t.Fatal("expected has_auth_user_context=true")
	}
	if got := parsed.Config["has_auth_admin_context"].(bool); got {
		t.Fatal("expected has_auth_admin_context=false")
	}
}

func TestResolvedOOBProviderLabel(t *testing.T) {
	if got := resolvedOOBProviderLabel(Options{}); got != "disabled" {
		t.Fatalf("expected disabled provider label, got %q", got)
	}
	if got := resolvedOOBProviderLabel(Options{ProofMode: true}); got != "interactsh" {
		t.Fatalf("expected interactsh provider label, got %q", got)
	}
	if got := resolvedOOBProviderLabel(Options{OOBHTTPPublicBaseURL: "https://oob.example.com/callback"}); got != "builtin-http" {
		t.Fatalf("expected builtin-http provider label, got %q", got)
	}
}

func TestBuildReconHarvestExecutionArgsOmitsUnsupportedOptionalFlags(t *testing.T) {
	caps := configpkg.ReconHarvestCapabilities{}
	args := buildReconHarvestExecutionArgs("example.com", "run", "", false, caps)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "example.com --run -o run") {
		t.Fatalf("unexpected base recon args: %v", args)
	}
	if strings.Contains(joined, "--arjun-threads") || strings.Contains(joined, "--vhost-threads") || strings.Contains(joined, "--skip-nuclei") {
		t.Fatalf("expected unsupported optional flags to be omitted, got %v", args)
	}
}

func TestBuildNucleiExecutionArgsUsesSaneRemoteDefaults(t *testing.T) {
	job := &models.Job{Target: "example.com", SafeMode: false}
	args := buildNucleiExecutionArgs(job, "/tmp/targets.txt", "/tmp/out.jsonl", "/tmp/errors.jsonl", Options{RateLimitRPS: 5})
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-timeout 10") {
		t.Fatalf("expected remote nuclei request timeout 10s, got %v", args)
	}
	if !strings.Contains(joined, "-c 35") {
		t.Fatalf("expected remote nuclei concurrency 35, got %v", args)
	}
	if !strings.Contains(joined, "-max-host-error 35") {
		t.Fatalf("expected remote max-host-error 35, got %v", args)
	}
	if strings.Contains(joined, "-c 50") {
		t.Fatalf("did not expect old remote concurrency, got %v", args)
	}
	if !strings.Contains(joined, "-rl 5") {
		t.Fatalf("expected rate limit to be passed through, got %v", args)
	}
	if !strings.Contains(joined, "-error-log /tmp/errors.jsonl") {
		t.Fatalf("expected nuclei error log to be configured, got %v", args)
	}
}

func TestBuildNucleiExecutionArgsUsesLocalhostDefaults(t *testing.T) {
	job := &models.Job{Target: "127.0.0.1", SafeMode: true}
	args := buildNucleiExecutionArgs(job, "/tmp/targets.txt", "/tmp/out.jsonl", "/tmp/errors.jsonl", Options{})
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-timeout 5") {
		t.Fatalf("expected localhost nuclei request timeout 5s, got %v", args)
	}
	if !strings.Contains(joined, "-concurrency 10") {
		t.Fatalf("expected localhost concurrency 10, got %v", args)
	}
	if !strings.Contains(joined, "-max-host-error 10") {
		t.Fatalf("expected localhost max-host-error 10, got %v", args)
	}
	if !strings.Contains(joined, "-tags misconfig,exposure,tech") {
		t.Fatalf("expected safe-mode nuclei tags, got %v", args)
	}
}

func TestClassifyNucleiError(t *testing.T) {
	cases := []struct {
		name    string
		errText string
		kind    string
		want    string
	}{
		{name: "timeout", errText: "context deadline exceeded", want: "timeout"},
		{name: "tls", errText: "tls: failed handshake", want: "tls"},
		{name: "dns", errText: "lookup api.example.com: no such host", want: "dns"},
		{name: "refused", errText: "port closed or filtered", kind: "network-permanent-error", want: "refused"},
		{name: "403", errText: "status code 403", want: "blocked_403"},
		{name: "429", errText: "status code 429", want: "rate_429"},
	}
	for _, tc := range cases {
		if got := classifyNucleiError(tc.errText, tc.kind, nil); got != tc.want {
			t.Fatalf("%s: expected %q, got %q", tc.name, tc.want, got)
		}
	}
}

func TestFormatNucleiErrorSummary(t *testing.T) {
	summary := formatNucleiErrorSummary(map[string]int{
		"total":    12,
		"timeout":  5,
		"tls":      3,
		"refused":  2,
		"other":    2,
		"http_5xx": 1,
	})
	if !strings.Contains(summary, "total=12") {
		t.Fatalf("expected total in summary, got %q", summary)
	}
	if !strings.Contains(summary, "timeout=5") || !strings.Contains(summary, "tls=3") {
		t.Fatalf("expected top categories in summary, got %q", summary)
	}
}

func TestBuildRankedNucleiInputSkipsNonURLTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "endpoints_ranked.json")
	raw := `{"items":[
		{"url":"redirect"},
		{"url":"login"},
		{"url":"https://example.com/login"},
		{"url":"http://api.example.com/v1"},
		{"url":"https://example.com:8443/admin"},
		{"url":"https://example.com/admin"},
		{"url":"/guest_auth/guestIsUp.php"},
		{"url":"https://example.com/login"}
	]}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}

	out, count := buildRankedNucleiInput(path, dir)
	if count != 2 {
		t.Fatalf("expected only 2 unique URL origins, got %d", count)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(string(b))
	want := "https://example.com\nhttp://api.example.com"
	if got != want {
		t.Fatalf("unexpected ranked nuclei input:\nwant:\n%s\n\ngot:\n%s", want, got)
	}
}

func TestProcessDoesNotEmitReconStartedWhenReconPreflightFails(t *testing.T) {
	dir := t.TempDir()
	job := &models.Job{ID: "preflight-fail", Target: "example.com", Mode: "full", SafeMode: true}
	var events []models.RuntimeEvent
	opt := Options{
		ReconHarvestCmd: "",
		ArtifactsRoot:   dir,
		NucleiBin:       "true",
		Events: func(ev models.RuntimeEvent) {
			events = append(events, ev)
		},
	}

	err := Process(context.Background(), job, opt)
	if err == nil {
		t.Fatal("expected recon preflight error")
	}
	for _, ev := range events {
		if ev.Message == "recon.started" {
			t.Fatalf("did not expect recon.started event on preflight failure: %+v", events)
		}
	}
}

func TestFindPartialReconWorkdirFindsNestedWorkspace(t *testing.T) {
	dir := t.TempDir()
	workdir := filepath.Join(dir, "outputs", "example.com", "run")
	if err := os.MkdirAll(workdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "workspace_meta.json"), []byte(`{"target":"example.com"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := findPartialReconWorkdir(dir); got != workdir {
		t.Fatalf("expected nested recon workdir %q, got %q", workdir, got)
	}
}

func TestEffectiveReconTimeoutSecDisablesTimeoutInBoundlessMode(t *testing.T) {
	if got := effectiveReconTimeoutSec(Options{ReconTimeoutSec: 3600, BoundlessMode: true}); got != 0 {
		t.Fatalf("expected boundless recon timeout to be disabled, got %d", got)
	}
	if got := effectiveReconTimeoutSec(Options{ReconTimeoutSec: 3600, BoundlessMode: false}); got != 3600 {
		t.Fatalf("expected recon timeout to remain set, got %d", got)
	}
}

func TestEffectiveNucleiTimeoutSecDisablesTimeoutInBoundlessMode(t *testing.T) {
	if got := effectiveNucleiTimeoutSec(Options{NucleiTimeoutSec: 3600, BoundlessMode: true}); got != 0 {
		t.Fatalf("expected boundless nuclei timeout to be disabled, got %d", got)
	}
	if got := effectiveNucleiTimeoutSec(Options{NucleiTimeoutSec: 3600, BoundlessMode: false}); got != 3600 {
		t.Fatalf("expected nuclei timeout to remain set, got %d", got)
	}
}

func TestBuildDependencyStagesRespectsPrerequisites(t *testing.T) {
	mods := []exploit.Module{
		testModule{name: "auth-bypass"},
		testModule{name: "open-redirect"},
		testModule{name: "session-abuse"},
	}
	stages, _ := buildDependencyStages(mods)
	if len(stages) < 2 {
		t.Fatalf("expected at least two dependency stages, got %d", len(stages))
	}
	if stages[0][0].Name() != "open-redirect" || stages[0][1].Name() != "session-abuse" {
		t.Fatalf("expected first stage to run prerequisites first, got %v", moduleNames(stages[0]))
	}
	last := stages[len(stages)-1]
	if len(last) != 1 || last[0].Name() != "auth-bypass" {
		t.Fatalf("expected auth-bypass in final stage, got %v", moduleNames(last))
	}
}

func TestFilterModulesByAuthContextQualitySkipsDualAuthModulesOnWeakContext(t *testing.T) {
	mods := []exploit.Module{
		testModule{name: "auth-bypass"},
		testModule{name: "jwt-access"},
	}
	planned, skipped, _ := filterModulesByAuthContextQuality(mods, observedAuthContext{
		HasUser:          true,
		HasAdmin:         true,
		DistinctContexts: false,
		QualityScore:     2,
	})
	if len(skipped) != 1 || skipped[0].Module != "auth-bypass" {
		t.Fatalf("expected auth-bypass to be skipped by auth quality filter, got %+v", skipped)
	}
	if len(planned) != 1 || planned[0].Name() != "jwt-access" {
		t.Fatalf("expected jwt-access to remain planned, got %v", moduleNames(planned))
	}
}

type testModule struct{ name string }

func (m testModule) Name() string { return m.name }

func (m testModule) Run(context.Context, *models.Job, *models.ReconSummary, exploit.Options) ([]models.ExploitFinding, error) {
	return nil, nil
}
