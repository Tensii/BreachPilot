package riskscoring

import (
	"testing"
)

func TestComputeCVSS(t *testing.T) {
	tests := []struct {
		name     string
		vector   CVSSVector
		expected float64
	}{
		{
			"High Severity SSRF",
			CVSSVector{AVNetwork, ACLow, PRNone, UINone, ScopeUnchanged, ImpactHigh, ImpactHigh, ImpactHigh},
			9.8,
		},
		{
			"Low Severity Info",
			CVSSVector{AVNetwork, ACLow, PRNone, UINone, ScopeUnchanged, ImpactLow, ImpactNone, ImpactNone},
			5.3,
		},
	}

	for _, tt := range tests {
		score := computeCVSS(tt.vector)
		if score != tt.expected {
			t.Errorf("computeCVSS(%s) = %.1f, expected %.1f", tt.name, score, tt.expected)
		}
	}
}

func TestScore(t *testing.T) {
	input := ScoreInput{
		Module:      "ssrf-prober",
		RawSeverity: "CRITICAL",
		Exposure:    ExposureInternet,
		Criticality: CriticalityPrimary,
		ChainBonus:  1.5,
	}

	score := Score(input)
	if score.Final < 9.0 {
		t.Errorf("Score for SSRF Critical on Internet Primary should be >= 9.0, got %f", score.Final)
	}
	if score.Band != BandCritical {
		t.Errorf("Band should be %s, got %s", BandCritical, score.Band)
	}
}

func TestAnalyzeChains(t *testing.T) {
	findings := []FindingMeta{
		{ID: "f1", Module: "open-redirect", URL: "http://target/redirect?url=http://evil.com"},
		{ID: "f2", Module: "ssrf", URL: "http://target/proxy?url=http://169.254.169.254/latest/meta-data/"},
	}

	analysis := AnalyzeChains(findings)
	if len(analysis) == 0 {
		t.Errorf("No chains detected, expected at least one")
	}

	// f2 (ssrf) should have a bonus if f1 (open-redirect) exists
	f2a, ok := analysis["f2"]
	if !ok || f2a.Bonus == 0 {
		t.Errorf("f2 (ssrf) should have a chain bonus, got %v", f2a)
	}
}
