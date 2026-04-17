package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"breachpilot/internal/models"
)

func TestEngineFindsVulnerabilitiesOnMockTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Query().Get("file") == "../../../etc/passwd":
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
		case r.URL.Query().Get("file") == "home":
			_, _ = w.Write([]byte("Welcome home"))
		case r.URL.Query().Get("q") != "":
			_, _ = w.Write([]byte("<html><body>" + r.URL.Query().Get("q") + "</body></html>"))
		case r.URL.Query().Get("id") == "1":
			_, _ = w.Write([]byte(`{"user":"alice"}`))
		case r.URL.Query().Get("id") == "2":
			_, _ = w.Write([]byte(`{"user":"bob"}`))
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer ts.Close()

	tempDir := t.TempDir()
	urlsPath := filepath.Join(tempDir, "urls_all.txt")
	livePath := filepath.Join(tempDir, "live_hosts.txt")
	if err := os.WriteFile(urlsPath, []byte(strings.Join([]string{
		ts.URL + "/?id=1",
		ts.URL + "/?file=home",
		ts.URL + "/?q=bp-xss-probe",
	}, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(livePath, []byte(ts.URL+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rs := models.ReconSummary{Workdir: tempDir, Live: livePath}
	rs.URLs.All = urlsPath
	summaryPath := filepath.Join(tempDir, "summary.json")
	summaryBytes, err := json.Marshal(rs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(summaryPath, summaryBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	job := &models.Job{
		ID:        "engine-integration",
		Mode:      "ingest",
		ReconPath: summaryPath,
		Target:    "from-summary",
	}
	err = Process(ctx, job, Options{
		NucleiBin:            "true",
		ArtifactsRoot:        tempDir,
		SkipNuclei:           true,
		AggressiveMode:       true,
		ProofMode:            false,
		MinSeverity:          "",
		OnlyModules:          "lfi,rxss",
		OOBHTTPListenAddr:    "127.0.0.1:0",
		OOBHTTPPublicBaseURL: "http://127.0.0.1",
		OOBSweepWaitSec:      1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != models.JobDone && job.Status != models.JobFailed {
		t.Fatalf("expected completed job state, got %s", job.Status)
	}
	if job.ExploitFindingsCount <= 0 {
		t.Fatalf("expected exploit findings, job=%+v", job)
	}
	if strings.TrimSpace(job.ExploitFindingsPath) == "" {
		t.Fatalf("expected exploit findings path, job=%+v", job)
	}

	f, err := os.Open(job.ExploitFindingsPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	foundHighSignal := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var finding models.ExploitFinding
		if err := json.Unmarshal(scanner.Bytes(), &finding); err != nil {
			t.Fatal(err)
		}
		if (finding.Module == "lfi" || finding.Module == "rxss") &&
			(finding.Severity == "HIGH" || finding.Severity == "CRITICAL") {
			foundHighSignal = true
			break
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if !foundHighSignal {
		t.Fatalf("expected at least one high-severity finding in %s", job.ExploitFindingsPath)
	}
}
