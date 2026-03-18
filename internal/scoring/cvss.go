// File: internal/scoring/cvss.go
package riskscoring

import "math"

// CVSS 3.1 metric enumerations

type AttackVector string
type AttackComplexity string
type PrivilegesRequired string
type UserInteraction string
type Scope string
type Impact string

const (
	AVNetwork         AttackVector = "N"
	AVAdjacentNetwork AttackVector = "A"
	AVLocal           AttackVector = "L"
	AVPhysical        AttackVector = "P"

	ACLow  AttackComplexity = "L"
	ACHigh AttackComplexity = "H"

	PRNone PrivilegesRequired = "N"
	PRLow  PrivilegesRequired = "L"
	PRHigh PrivilegesRequired = "H"

	UINone     UserInteraction = "N"
	UIRequired UserInteraction = "R"

	ScopeUnchanged Scope = "U"
	ScopeChanged   Scope = "C"

	ImpactNone Impact = "N"
	ImpactLow  Impact = "L"
	ImpactHigh Impact = "H"
)

// CVSSVector holds the eight CVSS 3.1 base metrics.
type CVSSVector struct {
	AttackVector          AttackVector
	AttackComplexity      AttackComplexity
	PrivilegesRequired    PrivilegesRequired
	UserInteraction       UserInteraction
	Scope                 Scope
	ConfidentialityImpact Impact
	IntegrityImpact       Impact
	AvailabilityImpact    Impact
}

// moduleDefaultVectors defines the representative CVSS base vector for each
// BreachPilot module. These are used when a finding doesn't specify its own vector.
// Tuned to match typical real-world severity of each vulnerability class.
var moduleDefaultVectors = map[string]CVSSVector{
	"ssrf": {
		AVNetwork, ACLow, PRNone, UINone, ScopeChanged,
		ImpactHigh, ImpactLow, ImpactNone,
		// SSRF: network-exploitable, no auth needed, often breaks out of scope
		// Base: ~8.6 (High)
	},
	"open-redirect": {
		AVNetwork, ACLow, PRNone, UIRequired, ScopeUnchanged,
		ImpactLow, ImpactNone, ImpactNone,
		// Open redirect: requires user interaction, low confidentiality impact
		// Base: ~4.3 (Medium) — bumped by context if used in phishing chains
	},
	"idor": {
		AVNetwork, ACLow, PRLow, UINone, ScopeUnchanged,
		ImpactHigh, ImpactLow, ImpactNone,
		// IDOR: low privileges (authenticated user), high data exposure potential
		// Base: ~6.5 (Medium) — bumped to High by context on internet-facing targets
	},
	"subdomain-takeover": {
		AVNetwork, ACLow, PRNone, UINone, ScopeChanged,
		ImpactHigh, ImpactHigh, ImpactNone,
		// Full content control over a subdomain
		// Base: ~9.1 (Critical)
	},
	"cookie-security": {
		AVNetwork, ACHigh, PRNone, UIRequired, ScopeUnchanged,
		ImpactLow, ImpactLow, ImpactNone,
		// Cookie flags missing: requires specific conditions
		// Base: ~3.7 (Low)
	},
	"http-method-tampering": {
		AVNetwork, ACLow, PRLow, UINone, ScopeUnchanged,
		ImpactLow, ImpactLow, ImpactNone,
		// Method override: authenticated, limited direct impact
		// Base: ~5.4 (Medium)
	},
	"js-endpoint-signals": {
		AVNetwork, ACLow, PRNone, UINone, ScopeUnchanged,
		ImpactLow, ImpactNone, ImpactNone,
		// Exposed endpoints in JS: informational/low on its own
		// Base: ~5.3 (Medium) — context-dependent
	},
	"api-surface": {
		AVNetwork, ACLow, PRNone, UINone, ScopeUnchanged,
		ImpactLow, ImpactNone, ImpactNone,
		// API surface discovery: informational
		// Base: ~5.3 (Medium)
	},
	// Fallback for unknown modules
	"_default": {
		AVNetwork, ACLow, PRNone, UINone, ScopeUnchanged,
		ImpactLow, ImpactLow, ImpactNone,
	},
}

// resolveVector returns the CVSSVector for a ScoreInput, merging explicit
// per-finding fields over the module defaults. Zero-value fields are treated
// as "use module default".
func resolveVector(input ScoreInput) CVSSVector {
	base, ok := moduleDefaultVectors[input.Module]
	if !ok {
		base = moduleDefaultVectors["_default"]
	}

	// Override with explicit per-finding values when non-zero
	if input.AttackVector != "" {
		base.AttackVector = input.AttackVector
	}
	if input.AttackComplexity != "" {
		base.AttackComplexity = input.AttackComplexity
	}
	if input.PrivilegesRequired != "" {
		base.PrivilegesRequired = input.PrivilegesRequired
	}
	if input.UserInteraction != "" {
		base.UserInteraction = input.UserInteraction
	}
	if input.Scope != "" {
		base.Scope = input.Scope
	}
	if input.ConfidentialityImpact != "" {
		base.ConfidentialityImpact = input.ConfidentialityImpact
	}
	if input.IntegrityImpact != "" {
		base.IntegrityImpact = input.IntegrityImpact
	}
	if input.AvailabilityImpact != "" {
		base.AvailabilityImpact = input.AvailabilityImpact
	}

	return base
}

// computeCVSS implements the CVSS 3.1 base score formula as specified by FIRST.
// Reference: https://www.first.org/cvss/v3.1/specification-document
func computeCVSS(v CVSSVector) float64 {
	// Impact sub-score coefficients
	iscBase := 1 - (1-impactScore(v.ConfidentialityImpact))*
		(1-impactScore(v.IntegrityImpact))*
		(1-impactScore(v.AvailabilityImpact))

	var isc float64
	if v.Scope == ScopeUnchanged {
		isc = 6.42 * iscBase
	} else {
		isc = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	}

	// Exploitability sub-score
	esc := 8.22 *
		avScore(v.AttackVector) *
		acScore(v.AttackComplexity) *
		prScore(v.PrivilegesRequired, v.Scope) *
		uiScore(v.UserInteraction)

	// Base score
	if isc <= 0 {
		return 0.0
	}

	var raw float64
	if v.Scope == ScopeUnchanged {
		raw = math.Min(isc+esc, 10)
	} else {
		raw = math.Min(1.08*(isc+esc), 10)
	}

	// Round up to nearest 0.1 per CVSS spec
	return roundUp(raw)
}

// roundUp rounds to the nearest 0.1, always rounding up (CVSS 3.1 spec requirement).
func roundUp(v float64) float64 {
	return math.Ceil(v*10) / 10
}

// Metric numeric coefficients per CVSS 3.1 spec

func avScore(av AttackVector) float64 {
	switch av {
	case AVNetwork:
		return 0.85
	case AVAdjacentNetwork:
		return 0.62
	case AVLocal:
		return 0.55
	case AVPhysical:
		return 0.20
	default:
		return 0.85
	}
}

func acScore(ac AttackComplexity) float64 {
	switch ac {
	case ACLow:
		return 0.77
	case ACHigh:
		return 0.44
	default:
		return 0.77
	}
}

func prScore(pr PrivilegesRequired, scope Scope) float64 {
	// PR coefficients differ depending on whether scope is changed
	if scope == ScopeChanged {
		switch pr {
		case PRNone:
			return 0.85
		case PRLow:
			return 0.68
		case PRHigh:
			return 0.50
		}
	}
	switch pr {
	case PRNone:
		return 0.85
	case PRLow:
		return 0.62
	case PRHigh:
		return 0.27
	default:
		return 0.85
	}
}

func uiScore(ui UserInteraction) float64 {
	switch ui {
	case UINone:
		return 0.85
	case UIRequired:
		return 0.62
	default:
		return 0.85
	}
}

func impactScore(i Impact) float64 {
	switch i {
	case ImpactNone:
		return 0.00
	case ImpactLow:
		return 0.22
	case ImpactHigh:
		return 0.56
	default:
		return 0.00
	}
}
