// File: internal/scoring/scorer.go
package riskscoring

import "fmt"

// RiskBand is the human-readable severity label derived from a numeric score.
type RiskBand string

const (
	BandCritical RiskBand = "critical" // 9.0 – 10.0
	BandHigh     RiskBand = "high"     // 7.0 – 8.9
	BandMedium   RiskBand = "medium"   // 4.0 – 6.9
	BandLow      RiskBand = "low"      // 0.1 – 3.9
	BandInfo     RiskBand = "info"     // 0.0
)

// RiskScore holds every layer of the scoring pipeline for a single finding.
// All intermediate values are retained so reports can explain the score.
type RiskScore struct {
	// Base score: CVSS 3.1-derived, range [0.0, 10.0]
	BaseScore float64 `json:"base_score"`

	// Context modifier: additive adjustment from exposure + criticality, range [-2.0, +2.0]
	ContextDelta float64 `json:"context_delta"`

	// Chain bonus: additive bonus when this finding participates in an attack chain, range [0, +2.0]
	ChainBonus float64 `json:"chain_bonus"`

	// Final score: clamped to [0.0, 10.0]
	Final float64 `json:"final"`

	// Band derived from Final
	Band RiskBand `json:"band"`

	// Human-readable explanation of how the score was derived
	Rationale string `json:"rationale"`

	// Chains this finding participates in (populated by chain analyzer)
	Chains []ChainRef `json:"chains,omitempty"`
}

// ChainRef identifies an attack chain this finding is part of.
type ChainRef struct {
	ChainID     string   `json:"chain_id"`    // e.g. "open-redirect→ssrf"
	Description string   `json:"description"` // human-readable attack narrative
	Members     []string `json:"members"`     // Finding IDs in chain order
}

// Band returns the RiskBand for a given numeric score.
func BandFromScore(score float64) RiskBand {
	switch {
	case score >= 9.0:
		return BandCritical
	case score >= 7.0:
		return BandHigh
	case score >= 4.0:
		return BandMedium
	case score > 0.0:
		return BandLow
	default:
		return BandInfo
	}
}

// ScoreInput bundles everything the scorer needs for one finding.
type ScoreInput struct {
	// FindingID is used for chain membership tracking
	FindingID string

	// Module name — used to look up CVSS base vector defaults
	Module string

	// URL of the affected endpoint
	URL string

	// Raw module severity (used as fallback if no CVSS vector is configured)
	RawSeverity string

	// CVSS vector fields — all optional; scorer applies module defaults for missing fields
	AttackVector          AttackVector
	AttackComplexity      AttackComplexity
	PrivilegesRequired    PrivilegesRequired
	UserInteraction       UserInteraction
	Scope                 Scope
	ConfidentialityImpact Impact
	IntegrityImpact       Impact
	AvailabilityImpact    Impact

	// Context: target-level exposure and asset criticality (from recon data)
	Exposure    ExposureLevel
	Criticality CriticalityLevel

	// ChainBonus is pre-computed by the chain analyzer and passed in here
	ChainBonus float64
}

// Score computes a full RiskScore for a single finding.
func Score(input ScoreInput) RiskScore {
	// Step 1: resolve CVSS vector (explicit fields override module defaults)
	vec := resolveVector(input)

	// Step 2: compute CVSS 3.1 base score
	base := computeCVSS(vec)

	// Step 3: compute context delta
	delta := computeContextDelta(input.Exposure, input.Criticality)

	// Step 4: apply chain bonus
	chain := input.ChainBonus

	// Step 5: final score, clamped [0, 10]
	final := clamp(base+delta+chain, 0.0, 10.0)
	band := BandFromScore(final)

	rationale := fmt.Sprintf(
		"Base %.1f (CVSS AV:%s AC:%s PR:%s UI:%s S:%s C:%s I:%s A:%s) "+
			"+ context delta %.1f (exposure:%s criticality:%s) "+
			"+ chain bonus %.1f = final %.1f (%s)",
		base,
		vec.AttackVector, vec.AttackComplexity, vec.PrivilegesRequired,
		vec.UserInteraction, vec.Scope,
		vec.ConfidentialityImpact, vec.IntegrityImpact, vec.AvailabilityImpact,
		delta, input.Exposure, input.Criticality,
		chain, final, band,
	)

	return RiskScore{
		BaseScore:    base,
		ContextDelta: delta,
		ChainBonus:   chain,
		Final:        final,
		Band:         band,
		Rationale:    rationale,
	}
}

func clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
