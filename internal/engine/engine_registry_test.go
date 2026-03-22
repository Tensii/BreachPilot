package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"breachpilot/internal/exploit/browsercapture"
	"breachpilot/internal/models"
)

func TestRegistryIncludesNewModules(t *testing.T) {
	names := RegisteredModules()
	want := []string{"admin-surface", "exposed-files", "tls-audit", "dns-check", "csp-audit", "http-response"}
	for _, w := range want {
		ok := false
		for _, n := range names {
			if n == w {
				ok = true
				break
			}
		}
		if !ok {
			t.Fatalf("missing module %s", w)
		}
	}
}

func TestNewModulesRegistered(t *testing.T) {
	names := RegisteredModules()
	for _, want := range []string{"lfi", "cmdinject", "rxss"} {
		found := false
		for _, name := range names {
			if name == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing module %s", want)
		}
	}
}

func TestRegisteredModulesOrderMatchesInfos(t *testing.T) {
	infos := RegisteredModuleInfos()
	names := RegisteredModules()
	if len(infos) != len(names) {
		t.Fatalf("length mismatch")
	}
	for i := range names {
		if infos[i].Name != names[i] {
			t.Fatalf("order mismatch at %d: %s vs %s", i, infos[i].Name, names[i])
		}
	}
}

func TestSelectedModuleInstancesDefaultPrefersExploitCore(t *testing.T) {
	mods := selectedModuleInstances(Options{})
	names := make(map[string]struct{}, len(mods))
	for _, m := range mods {
		names[m.Name()] = struct{}{}
	}
	if _, ok := names["auth-bypass"]; !ok {
		t.Fatal("expected exploit-core module auth-bypass in default selection")
	}
	if _, ok := names["security-headers"]; ok {
		t.Fatal("did not expect context module security-headers in default selection")
	}
	if _, ok := names["cookie-security"]; ok {
		t.Fatal("did not expect context module cookie-security in default selection")
	}
}

func TestSelectedModuleInstancesOnlyModulesCanReachContextLane(t *testing.T) {
	mods := filterModules(selectedModuleInstances(Options{OnlyModules: "security-headers,cookie-security"}), "security-headers,cookie-security", "")
	if len(mods) != 2 {
		t.Fatalf("expected 2 explicitly selected context modules, got %d", len(mods))
	}
}

func TestSelectedModuleInstancesDeepIncludesContextLane(t *testing.T) {
	mods := selectedModuleInstances(Options{ScanProfile: "deep"})
	names := make(map[string]struct{}, len(mods))
	for _, m := range mods {
		names[m.Name()] = struct{}{}
	}
	if _, ok := names["security-headers"]; !ok {
		t.Fatal("expected deep profile to include context module security-headers")
	}
	if _, ok := names["auth-bypass"]; !ok {
		t.Fatal("expected deep profile to include exploit-core module auth-bypass")
	}
}

func TestPlanExploitModulesSkipsMissingPrerequisites(t *testing.T) {
	rs := models.ReconSummary{}
	rs.URLs.All = "/tmp/urls.txt"
	rs.Live = "/tmp/live_hosts.txt"
	mods := filterModules(selectedModuleInstances(Options{}), "auth-bypass,idor-playbook,open-redirect", "")
	planned, skipped, preview := planExploitModules(mods, rs, Options{})
	if len(preview) == 0 {
		t.Fatal("expected planner preview entries")
	}
	if len(planned) != 1 || planned[0].Name() != "open-redirect" {
		t.Fatalf("expected only open-redirect planned, got %d module(s)", len(planned))
	}
	if len(skipped) != 2 {
		t.Fatalf("expected 2 planner skips, got %d", len(skipped))
	}
}

func TestPlanExploitModulesAllowsStrongProofModulesWhenReady(t *testing.T) {
	rs := models.ReconSummary{}
	rs.URLs.All = "/tmp/urls.txt"
	rs.Intel.CORSJSON = "/tmp/cors.json"
	mods := filterModules(selectedModuleInstances(Options{OnlyModules: "auth-bypass,idor-playbook"}), "auth-bypass,idor-playbook", "")
	planned, skipped, _ := planExploitModules(mods, rs, Options{
		AggressiveMode:  true,
		ProofMode:       true,
		AuthUserCookie:  "user=1",
		AuthAdminCookie: "admin=1",
	})
	if len(skipped) != 0 {
		t.Fatalf("expected no planner skips, got %d", len(skipped))
	}
	if len(planned) != 2 {
		t.Fatalf("expected 2 planned modules, got %d", len(planned))
	}
}

func TestCorrelateProofModulesUsesScoutFindings(t *testing.T) {
	mods := filterModules(selectedModuleInstances(Options{}), "auth-bypass,idor-playbook,state-change", "")
	scoutSignals := buildCorrelationSignals([]models.ExploitFinding{
		{Module: "cors-poc", Validation: "verified"},
		{Module: "session-abuse", Validation: "verified"},
		{Module: "privilege-path", Validation: "verified"},
	})
	planned, skipped, preview := correlateProofModules(mods, scoutSignals, models.ReconSummary{}, Options{})
	if len(preview) == 0 {
		t.Fatal("expected correlation planner preview")
	}
	if len(skipped) != 0 {
		t.Fatalf("expected no correlation skips, got %d", len(skipped))
	}
	if len(planned) != 3 {
		t.Fatalf("expected 3 planned proof modules, got %d", len(planned))
	}
}

func TestCorrelateProofModulesFallsBackToReconSignals(t *testing.T) {
	dir := t.TempDir()
	urls := filepath.Join(dir, "urls.txt")
	params := filepath.Join(dir, "params.json")
	if err := os.WriteFile(urls, []byte("https://example.com/render?url=https://x\nhttps://example.com/oauth/authorize\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(params, []byte(`[{"name":"filter"},{"name":"query"}]`), 0o644); err != nil {
		t.Fatal(err)
	}

	rs := models.ReconSummary{}
	rs.URLs.All = urls
	rs.Intel.ParamsRankedJSON = params

	mods := filterModules(selectedModuleInstances(Options{OnlyModules: "ssrf-prober,advanced-injection,jwt-access"}), "ssrf-prober,advanced-injection,jwt-access", "")
	planned, skipped, _ := correlateProofModules(mods, correlationSignals{modules: map[string]int{}}, rs, Options{})
	if len(skipped) != 0 {
		t.Fatalf("expected recon-driven planning without skips, got %d", len(skipped))
	}
	if len(planned) != 3 {
		t.Fatalf("expected 3 proof modules planned from recon signals, got %d", len(planned))
	}
}

func TestCorrelateProofModulesSkipsWeakReconSignals(t *testing.T) {
	dir := t.TempDir()
	urls := filepath.Join(dir, "urls.txt")
	params := filepath.Join(dir, "params.json")
	if err := os.WriteFile(urls, []byte("https://example.com/login\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(params, []byte(`[{"name":"query"}]`), 0o644); err != nil {
		t.Fatal(err)
	}

	rs := models.ReconSummary{}
	rs.URLs.All = urls
	rs.Intel.ParamsRankedJSON = params

	mods := filterModules(selectedModuleInstances(Options{OnlyModules: "advanced-injection,jwt-access"}), "advanced-injection,jwt-access", "")
	planned, skipped, _ := correlateProofModules(mods, correlationSignals{modules: map[string]int{}}, rs, Options{})
	if len(planned) != 1 || planned[0].Name() != "jwt-access" {
		t.Fatalf("expected only jwt-access planned from auth URL fallback, got %v", moduleNames(planned))
	}
	if len(skipped) != 1 || skipped[0].Module != "advanced-injection" {
		t.Fatalf("expected only advanced-injection skipped for weak recon hints, got %+v", skipped)
	}
}

func TestCorrelateProofModulesUsesSavedBrowserWorkflowSignals(t *testing.T) {
	dir := t.TempDir()
	artifact := browsercapture.Artifact{
		Workflows: []browsercapture.CapturedWorkflow{{
			ID:       "wf-1",
			StartURL: "https://example.com/app",
			PageURL:  "https://example.com/app",
			Steps: []browsercapture.WorkflowStep{
				{Kind: "request", URL: "https://example.com/api/search", Method: "POST", Fields: []string{"query", "filter"}},
				{Kind: "request", URL: "https://example.com/render", Method: "POST", Fields: []string{"url"}},
				{Kind: "request", URL: "https://example.com/account/profile", Method: "POST", Fields: []string{"display_name"}},
			},
		}},
	}
	if err := browsercapture.SaveArtifact(filepath.Join(dir, "browser_capture_artifact.json"), artifact); err != nil {
		t.Fatal(err)
	}

	rs := models.ReconSummary{Workdir: dir}
	mods := filterModules(selectedModuleInstances(Options{OnlyModules: "advanced-injection,ssrf-prober,state-change"}), "advanced-injection,ssrf-prober,state-change", "")
	planned, skipped, _ := correlateProofModules(mods, correlationSignals{modules: map[string]int{}}, rs, Options{})
	if len(skipped) != 0 {
		t.Fatalf("expected browser workflow signals to avoid correlation skips, got %d", len(skipped))
	}
	if len(planned) != 3 {
		t.Fatalf("expected 3 proof modules planned from browser workflow signals, got %d", len(planned))
	}
}

func TestCorrelationPlannerAllowsInjectionOnURLCorpus(t *testing.T) {
	dir := t.TempDir()
	urls := filepath.Join(dir, "urls.txt")
	if err := os.WriteFile(urls, []byte("https://example.com/?id=1\nhttps://example.com/?q=test\nhttps://example.com/?file=home\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rs := models.ReconSummary{}
	rs.URLs.All = urls

	mods := filterModules(selectedModuleInstances(Options{OnlyModules: "lfi,rxss,advanced-injection"}), "lfi,rxss,advanced-injection", "")
	planned, skipped, _ := correlateProofModules(mods, correlationSignals{modules: map[string]int{}}, rs, Options{})
	if len(planned) != 3 {
		t.Fatalf("expected lfi, rxss, and advanced-injection planned, got %d", len(planned))
	}
	if len(skipped) != 0 {
		t.Fatalf("expected no correlation skips, got %d", len(skipped))
	}
}

func TestPrioritizeProofModulesPrefersStrongCorrelationChains(t *testing.T) {
	dir := t.TempDir()
	urls := filepath.Join(dir, "urls.txt")
	if err := os.WriteFile(urls, []byte("https://example.com/render?url=https://x\nhttps://example.com/account/settings\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rs := models.ReconSummary{}
	rs.URLs.All = urls
	mods := filterModules(selectedModuleInstances(Options{OnlyModules: "ssrf-prober,state-change"}), "ssrf-prober,state-change", "")
	signals := buildCorrelationSignals([]models.ExploitFinding{
		{Module: "open-redirect", Validation: "confirmed"},
		{Module: "session-abuse", Validation: "verified"},
	})

	prioritized := prioritizeProofModules(mods, signals, rs)
	if len(prioritized) != 2 {
		t.Fatalf("expected 2 prioritized modules, got %d", len(prioritized))
	}
	if prioritized[0].Name() != "ssrf-prober" {
		t.Fatalf("expected strongest correlated proof module first, got %s", prioritized[0].Name())
	}
}

func TestCorrelationSignalsArtifactRoundTrip(t *testing.T) {
	dir := t.TempDir()
	signals := mergeCorrelationSignals(
		buildCorrelationSignals([]models.ExploitFinding{{Module: "cors-poc", Validation: "verified"}, {Module: "session-abuse", Validation: "confirmed"}}),
		correlationSignals{modules: map[string]int{"open-redirect": 1}},
	)
	if err := saveCorrelationSignalsArtifact(dir, signals); err != nil {
		t.Fatal(err)
	}
	loaded := loadCorrelationSignalsArtifact(dir)
	if !loaded.hasModule("cors-poc") || !loaded.hasModule("session-abuse") || !loaded.hasModule("open-redirect") {
		t.Fatalf("expected persisted correlation signals to round-trip, got %#v", loaded.modules)
	}
	if loaded.strength("cors-poc") != 2 {
		t.Fatalf("expected verified finding to round-trip as strength 2, got %d", loaded.strength("cors-poc"))
	}
	if loaded.strength("session-abuse") != 3 {
		t.Fatalf("expected confirmed finding to round-trip as strength 3, got %d", loaded.strength("session-abuse"))
	}
}

func TestCorrelationSignalsArtifactSupportsLegacyListFormat(t *testing.T) {
	dir := t.TempDir()
	legacy := []byte("{\"modules\":[\"open-redirect\",\"session-abuse\"]}")
	if err := os.WriteFile(filepath.Join(dir, "correlation_signals.json"), legacy, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded := loadCorrelationSignalsArtifact(dir)
	if loaded.strength("open-redirect") != 1 || loaded.strength("session-abuse") != 1 {
		t.Fatalf("expected legacy correlation signals to load with strength 1, got %#v", loaded.modules)
	}
}

func TestLFIAndRXSSInExploitProfile(t *testing.T) {
	p, ok := GetProfile("exploit")
	if !ok {
		t.Fatal("expected exploit profile")
	}
	if !strings.Contains(p.OnlyModules, "lfi") {
		t.Fatalf("expected exploit profile to include lfi, got %s", p.OnlyModules)
	}
	if !strings.Contains(p.OnlyModules, "rxss") {
		t.Fatalf("expected exploit profile to include rxss, got %s", p.OnlyModules)
	}
	if !strings.Contains(p.OnlyModules, "cmdinject") {
		t.Fatalf("expected exploit profile to include cmdinject, got %s", p.OnlyModules)
	}
}
