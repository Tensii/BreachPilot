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

func TestApplyFindingOverridesMissingCSPLowersScore(t *testing.T) {
	input := ScoreInput{
		Module:      "csp-audit",
		RawSeverity: "LOW",
		Exposure:    ExposureInternet,
		Criticality: CriticalitySupporting,
	}

	input = ApplyFindingOverrides(input, "Missing Content-Security-Policy header", "verified")
	score := Score(input)

	if score.Final >= 4.0 {
		t.Fatalf("missing CSP should not score medium or higher, got %.1f (%s)", score.Final, score.Band)
	}
	if score.Band != BandLow {
		t.Fatalf("missing CSP should be low, got %s", score.Band)
	}
}

func TestApplyFindingOverridesUnsafeEvalStaysMediumOrAbove(t *testing.T) {
	input := ScoreInput{
		Module:      "csp-audit",
		RawSeverity: "HIGH",
		Exposure:    ExposureInternet,
		Criticality: CriticalitySupporting,
	}

	input = ApplyFindingOverrides(input, "CSP allows unsafe-eval", "verified")
	score := Score(input)

	if score.Final < 4.0 {
		t.Fatalf("unsafe-eval should remain materially ranked, got %.1f (%s)", score.Final, score.Band)
	}
}

func TestApplyFindingOverridesAdminRedirectStaysLow(t *testing.T) {
	input := ScoreInput{
		Module:      "admin-surface",
		RawSeverity: "LOW",
		Exposure:    ExposureInternet,
		Criticality: CriticalitySupporting,
	}

	input = ApplyFindingOverrides(input, "Administrative or login surface redirects", "signal")
	score := Score(input)

	if score.Band != BandLow {
		t.Fatalf("admin redirects should stay low after override, got %.1f (%s)", score.Final, score.Band)
	}
}

func TestApplyFindingOverridesExposedAdminSurfaceIsMedium(t *testing.T) {
	input := ScoreInput{
		Module:      "admin-surface",
		RawSeverity: "MEDIUM",
		Exposure:    ExposureInternet,
		Criticality: CriticalitySupporting,
	}

	input = ApplyFindingOverrides(input, "Exposed administrative or management surface", "verified")
	score := Score(input)

	if score.Band != BandMedium {
		t.Fatalf("strong admin surface should rank medium, got %.1f (%s)", score.Final, score.Band)
	}
}

func TestApplyFindingOverridesOIDCConfigIsLow(t *testing.T) {
	input := ScoreInput{
		Module:      "api-surface",
		RawSeverity: "LOW",
		Exposure:    ExposureInternet,
		Criticality: CriticalitySupporting,
	}

	input = ApplyFindingOverrides(input, "OIDC configuration exposed", "verified")
	score := Score(input)

	if score.Band != BandLow {
		t.Fatalf("oidc configuration should stay low, got %.1f (%s)", score.Final, score.Band)
	}
}

func TestApplyFindingOverridesPrivilegePathSignalIsLow(t *testing.T) {
	input := ScoreInput{
		Module:      "privilege-path",
		RawSeverity: "MEDIUM",
		Exposure:    ExposureInternet,
		Criticality: CriticalitySupporting,
	}

	input = ApplyFindingOverrides(input, "Potential privilege escalation path discovered", "signal")
	score := Score(input)

	if score.Band != BandLow {
		t.Fatalf("privilege-path signals should stay low, got %.1f (%s)", score.Final, score.Band)
	}
}

func TestApplyFindingOverridesCookieMissingSecureIsMedium(t *testing.T) {
	input := ScoreInput{
		Module:      "cookie-security",
		RawSeverity: "MEDIUM",
		Exposure:    ExposureInternet,
		Criticality: CriticalitySupporting,
	}

	input = ApplyFindingOverrides(input, "Cookie missing Secure flag", "verified")
	score := Score(input)

	if score.Band != BandMedium {
		t.Fatalf("missing Secure flag should rank medium, got %.1f (%s)", score.Final, score.Band)
	}
}

func TestApplyFindingOverridesGitMetadataIsMedium(t *testing.T) {
	input := ScoreInput{
		Module:      "info-disclosure",
		RawSeverity: "MEDIUM",
		Exposure:    ExposureInternet,
		Criticality: CriticalitySupporting,
	}

	input = ApplyFindingOverrides(input, "Exposed Git repository metadata", "verified")
	score := Score(input)

	if score.Band != BandMedium {
		t.Fatalf("exposed git metadata should rank medium, got %.1f (%s)", score.Final, score.Band)
	}
	if score.Final >= 7.0 {
		t.Fatalf("exposed git metadata should not rank high, got %.1f (%s)", score.Final, score.Band)
	}
}

func TestApplyFindingOverridesEnvConfigCanStayHigh(t *testing.T) {
	input := ScoreInput{
		Module:      "info-disclosure",
		RawSeverity: "HIGH",
		Exposure:    ExposureInternet,
		Criticality: CriticalitySupporting,
	}

	input = ApplyFindingOverrides(input, "Exposed environment configuration file", "verified")
	score := Score(input)

	if score.Band != BandHigh {
		t.Fatalf("exposed environment config should remain high, got %.1f (%s)", score.Final, score.Band)
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
