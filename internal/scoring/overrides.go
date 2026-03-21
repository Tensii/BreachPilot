package riskscoring

import "strings"

// ApplyFindingOverrides refines module-level defaults with finding-specific
// heuristics where a single module can emit materially different risk classes.
func ApplyFindingOverrides(input ScoreInput, title, validation string) ScoreInput {
	lt := strings.ToLower(strings.TrimSpace(title))
	_ = validation

	switch input.Module {
	case "csp-audit", "security-headers":
		return applyCSPOverrides(input, lt)
	default:
		return input
	}
}

func applyCSPOverrides(input ScoreInput, title string) ScoreInput {
	switch {
	case strings.Contains(title, "missing content-security-policy"):
		input.AttackVector = AVNetwork
		input.AttackComplexity = ACHigh
		input.PrivilegesRequired = PRNone
		input.UserInteraction = UIRequired
		input.Scope = ScopeUnchanged
		input.ConfidentialityImpact = ImpactNone
		input.IntegrityImpact = ImpactNone
		input.AvailabilityImpact = ImpactNone
	case strings.Contains(title, "csp missing default-src"):
		input.AttackVector = AVNetwork
		input.AttackComplexity = ACHigh
		input.PrivilegesRequired = PRNone
		input.UserInteraction = UIRequired
		input.Scope = ScopeUnchanged
		input.ConfidentialityImpact = ImpactNone
		input.IntegrityImpact = ImpactNone
		input.AvailabilityImpact = ImpactNone
	case strings.Contains(title, "unsafe-inline"):
		input.AttackVector = AVNetwork
		input.AttackComplexity = ACLow
		input.PrivilegesRequired = PRNone
		input.UserInteraction = UIRequired
		input.Scope = ScopeUnchanged
		input.ConfidentialityImpact = ImpactLow
		input.IntegrityImpact = ImpactLow
		input.AvailabilityImpact = ImpactNone
	case strings.Contains(title, "unsafe-eval"):
		input.AttackVector = AVNetwork
		input.AttackComplexity = ACLow
		input.PrivilegesRequired = PRNone
		input.UserInteraction = UIRequired
		input.Scope = ScopeUnchanged
		input.ConfidentialityImpact = ImpactLow
		input.IntegrityImpact = ImpactLow
		input.AvailabilityImpact = ImpactLow
	case strings.Contains(title, "wildcard source"):
		input.AttackVector = AVNetwork
		input.AttackComplexity = ACLow
		input.PrivilegesRequired = PRNone
		input.UserInteraction = UIRequired
		input.Scope = ScopeUnchanged
		input.ConfidentialityImpact = ImpactLow
		input.IntegrityImpact = ImpactLow
		input.AvailabilityImpact = ImpactNone
	}
	return input
}
