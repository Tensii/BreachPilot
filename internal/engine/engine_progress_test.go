package engine

import "testing"

func TestParseRuntimeLogProgressParsesFraction(t *testing.T) {
	progress := parseRuntimeLogProgress("exploit.log", "[INF] Requests: 25/100 (25%)")
	if progress == nil {
		t.Fatal("expected progress to be parsed")
	}
	if progress.Label != "targets" || progress.Unit != "targets" {
		t.Fatalf("unexpected progress scope: %+v", progress)
	}
	if progress.Completed != 25 || progress.Total != 100 || progress.Percent != 25 {
		t.Fatalf("unexpected progress values: %+v", progress)
	}
}

func TestParseRuntimeLogProgressIgnoresNoise(t *testing.T) {
	progress := parseRuntimeLogProgress("exploit.log", "GET /v1/200/404 HTTP/1.1")
	if progress != nil {
		t.Fatalf("expected noise to be ignored, got %+v", progress)
	}
}
