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
	case "admin-surface":
		return applyAdminSurfaceOverrides(input, lt)
	case "api-surface":
		return applyAPISurfaceOverrides(input, lt)
	case "http-response":
		return applyHTTPResponseOverrides(input, lt)
	case "privilege-path":
		return applyPrivilegePathOverrides(input, lt, validation)
	case "cookie-security":
		return applyCookieSecurityOverrides(input, lt)
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

func applyAdminSurfaceOverrides(input ScoreInput, title string) ScoreInput {
	switch {
	case strings.Contains(title, "administrative or login surface redirects"):
		input.AttackVector = AVNetwork
		input.AttackComplexity = ACHigh
		input.PrivilegesRequired = PRNone
		input.UserInteraction = UIRequired
		input.Scope = ScopeUnchanged
		input.ConfidentialityImpact = ImpactNone
		input.IntegrityImpact = ImpactNone
		input.AvailabilityImpact = ImpactNone
	case strings.Contains(title, "potential administrative surface exposed"):
		input.AttackVector = AVNetwork
		input.AttackComplexity = ACHigh
		input.PrivilegesRequired = PRNone
		input.UserInteraction = UIRequired
		input.Scope = ScopeUnchanged
		input.ConfidentialityImpact = ImpactLow
		input.IntegrityImpact = ImpactNone
		input.AvailabilityImpact = ImpactNone
	case strings.Contains(title, "exposed administrative or management surface"):
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

func applyAPISurfaceOverrides(input ScoreInput, title string) ScoreInput {
	switch {
	case strings.Contains(title, "oidc configuration exposed"):
		input.AttackVector = AVNetwork
		input.AttackComplexity = ACHigh
		input.PrivilegesRequired = PRNone
		input.UserInteraction = UINone
		input.Scope = ScopeUnchanged
		input.ConfidentialityImpact = ImpactNone
		input.IntegrityImpact = ImpactNone
		input.AvailabilityImpact = ImpactNone
	case strings.Contains(title, "graphql endpoint reachable"):
		input.AttackVector = AVNetwork
		input.AttackComplexity = ACLow
		input.PrivilegesRequired = PRNone
		input.UserInteraction = UINone
		input.Scope = ScopeUnchanged
		input.ConfidentialityImpact = ImpactLow
		input.IntegrityImpact = ImpactNone
		input.AvailabilityImpact = ImpactNone
	case strings.Contains(title, "graphql introspection enabled"):
		input.AttackVector = AVNetwork
		input.AttackComplexity = ACLow
		input.PrivilegesRequired = PRNone
		input.UserInteraction = UINone
		input.Scope = ScopeUnchanged
		input.ConfidentialityImpact = ImpactLow
		input.IntegrityImpact = ImpactLow
		input.AvailabilityImpact = ImpactNone
	case strings.Contains(title, "api specification exposed"):
		input.AttackVector = AVNetwork
		input.AttackComplexity = ACLow
		input.PrivilegesRequired = PRNone
		input.UserInteraction = UINone
		input.Scope = ScopeUnchanged
		input.ConfidentialityImpact = ImpactLow
		input.IntegrityImpact = ImpactNone
		input.AvailabilityImpact = ImpactNone
	}
	return input
}

func applyHTTPResponseOverrides(input ScoreInput, title string) ScoreInput {
	switch {
	case strings.Contains(title, "server header discloses version information"),
		strings.Contains(title, "x-powered-by header exposes technology stack"):
		input.AttackVector = AVNetwork
		input.AttackComplexity = ACHigh
		input.PrivilegesRequired = PRNone
		input.UserInteraction = UINone
		input.Scope = ScopeUnchanged
		input.ConfidentialityImpact = ImpactNone
		input.IntegrityImpact = ImpactNone
		input.AvailabilityImpact = ImpactNone
	case strings.Contains(title, "verbose error page may leak internal details"):
		input.AttackVector = AVNetwork
		input.AttackComplexity = ACHigh
		input.PrivilegesRequired = PRNone
		input.UserInteraction = UINone
		input.Scope = ScopeUnchanged
		input.ConfidentialityImpact = ImpactLow
		input.IntegrityImpact = ImpactNone
		input.AvailabilityImpact = ImpactNone
	case strings.Contains(title, "directory listing enabled"):
		input.AttackVector = AVNetwork
		input.AttackComplexity = ACLow
		input.PrivilegesRequired = PRNone
		input.UserInteraction = UINone
		input.Scope = ScopeUnchanged
		input.ConfidentialityImpact = ImpactLow
		input.IntegrityImpact = ImpactLow
		input.AvailabilityImpact = ImpactNone
	}
	return input
}

func applyPrivilegePathOverrides(input ScoreInput, title, validation string) ScoreInput {
	if !strings.Contains(title, "potential privilege escalation path discovered") {
		return input
	}
	switch strings.ToLower(strings.TrimSpace(validation)) {
	case "signal":
		input.AttackVector = AVNetwork
		input.AttackComplexity = ACHigh
		input.PrivilegesRequired = PRNone
		input.UserInteraction = UIRequired
		input.Scope = ScopeUnchanged
		input.ConfidentialityImpact = ImpactNone
		input.IntegrityImpact = ImpactNone
		input.AvailabilityImpact = ImpactNone
	case "verified":
		input.AttackVector = AVNetwork
		input.AttackComplexity = ACLow
		input.PrivilegesRequired = PRLow
		input.UserInteraction = UINone
		input.Scope = ScopeUnchanged
		input.ConfidentialityImpact = ImpactLow
		input.IntegrityImpact = ImpactLow
		input.AvailabilityImpact = ImpactNone
	}
	return input
}

func applyCookieSecurityOverrides(input ScoreInput, title string) ScoreInput {
	switch {
	case strings.Contains(title, "missing secure flag"):
		input.AttackVector = AVNetwork
		input.AttackComplexity = ACHigh
		input.PrivilegesRequired = PRNone
		input.UserInteraction = UIRequired
		input.Scope = ScopeUnchanged
		input.ConfidentialityImpact = ImpactLow
		input.IntegrityImpact = ImpactLow
		input.AvailabilityImpact = ImpactNone
	case strings.Contains(title, "missing httponly flag"):
		input.AttackVector = AVNetwork
		input.AttackComplexity = ACHigh
		input.PrivilegesRequired = PRNone
		input.UserInteraction = UIRequired
		input.Scope = ScopeUnchanged
		input.ConfidentialityImpact = ImpactLow
		input.IntegrityImpact = ImpactNone
		input.AvailabilityImpact = ImpactNone
	case strings.Contains(title, "missing samesite flag"):
		input.AttackVector = AVNetwork
		input.AttackComplexity = ACHigh
		input.PrivilegesRequired = PRNone
		input.UserInteraction = UIRequired
		input.Scope = ScopeUnchanged
		input.ConfidentialityImpact = ImpactNone
		input.IntegrityImpact = ImpactNone
		input.AvailabilityImpact = ImpactNone
	}
	return input
}
