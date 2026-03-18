// File: internal/scoring/summary.go
package riskscoring

import (
	"fmt"
	"sort"
	"strings"
)

// ScanRiskSummary aggregates scored findings into a scan-level risk profile.
// Attach this to the top-level scan result struct.
type ScanRiskSummary struct {
	// OverallBand is the highest band across all findings
	OverallBand RiskBand `json:"overall_band"`

	// OverallScore is the highest Final score across all findings
	OverallScore float64 `json:"overall_score"`

	// BandCounts maps each band to the count of findings in that band
	BandCounts map[RiskBand]int `json:"band_counts"`

	// TopFindings holds the top 5 findings by Final score, for executive summary
	TopFindings []ScoredFindingRef `json:"top_findings"`

	// ActiveChains holds all detected attack chains across the scan
	ActiveChains []ChainRef `json:"active_chains"`

	// ExposureSummary describes the target's exposure level
	ExposureSummary string `json:"exposure_summary"`

	// CriticalitySummary describes the target's asset criticality
	CriticalitySummary string `json:"criticality_summary"`

	// Narrative is a 3–5 sentence human-readable risk summary for report headers
	Narrative string `json:"narrative"`
}

// ScoredFindingRef is a lightweight reference to a finding with its score,
// used in top-findings lists without embedding the full Finding struct.
type ScoredFindingRef struct {
	ID     string    `json:"id"`
	Title  string    `json:"title"`
	Module string    `json:"module"`
	URL    string    `json:"url"`
	Score  RiskScore `json:"score"`
}

// ScoredFinding combines a finding reference with its computed RiskScore.
// Used as input to BuildSummary.
type ScoredFinding struct {
	ID     string
	Title  string
	Module string
	URL    string
	Score  RiskScore
}

// BuildSummary constructs a ScanRiskSummary from all scored findings in a scan.
func BuildSummary(
	findings []ScoredFinding,
	exposure ExposureLevel,
	criticality CriticalityLevel,
	chains []ChainRef,
) ScanRiskSummary {
	counts := map[RiskBand]int{
		BandCritical: 0,
		BandHigh:     0,
		BandMedium:   0,
		BandLow:      0,
		BandInfo:     0,
	}

	var topScore float64
	var topBand RiskBand = BandInfo

	for _, f := range findings {
		counts[f.Score.Band]++
		if f.Score.Final > topScore {
			topScore = f.Score.Final
			topBand = f.Score.Band
		}
	}

	// Sort findings by Final score descending, take top 5
	sorted := make([]ScoredFinding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Score.Final > sorted[j].Score.Final
	})

	topN := 5
	if len(sorted) < topN {
		topN = len(sorted)
	}
	var topRefs []ScoredFindingRef
	for _, f := range sorted[:topN] {
		topRefs = append(topRefs, ScoredFindingRef{
			ID: f.ID, Title: f.Title,
			Module: f.Module, URL: f.URL, Score: f.Score,
		})
	}

	// Deduplicate chains
	seenChains := make(map[string]struct{})
	var dedupedChains []ChainRef
	for _, c := range chains {
		if _, ok := seenChains[c.ChainID]; !ok {
			seenChains[c.ChainID] = struct{}{}
			dedupedChains = append(dedupedChains, c)
		}
	}

	narrative := buildNarrative(counts, topBand, exposure, criticality, dedupedChains)

	return ScanRiskSummary{
		OverallBand:        topBand,
		OverallScore:       topScore,
		BandCounts:         counts,
		TopFindings:        topRefs,
		ActiveChains:       dedupedChains,
		ExposureSummary:    string(exposure),
		CriticalitySummary: string(criticality),
		Narrative:          narrative,
	}
}

// buildNarrative generates a concise human-readable risk summary paragraph.
func buildNarrative(
	counts map[RiskBand]int,
	topBand RiskBand,
	exposure ExposureLevel,
	criticality CriticalityLevel,
	chains []ChainRef,
) string {
	total := counts[BandCritical] + counts[BandHigh] + counts[BandMedium] +
		counts[BandLow] + counts[BandInfo]
	if total == 0 {
		return "No findings were recorded in this scan."
	}

	var sb strings.Builder

	// Opening: overall posture
	sb.WriteString(fmt.Sprintf(
		"This scan identified %d finding(s) across a %s asset with %s exposure. ",
		total, criticality, exposure,
	))

	// Severity distribution
	sb.WriteString(fmt.Sprintf(
		"Overall risk is rated %s, with %d critical, %d high, %d medium, and %d low severity findings. ",
		topBand,
		counts[BandCritical], counts[BandHigh], counts[BandMedium], counts[BandLow],
	))

	// Chains
	if len(chains) > 0 {
		chainNames := make([]string, 0, len(chains))
		for _, c := range chains {
			chainNames = append(chainNames, c.ChainID)
		}
		sb.WriteString(fmt.Sprintf(
			"%d multi-step attack chain(s) were detected (%s), which elevate the "+
				"effective risk beyond individual finding scores. ",
			len(chains), strings.Join(chainNames, ", "),
		))
	}

	// Context impact note
	if exposure == ExposureInternet && criticality == CriticalityPrimary {
		sb.WriteString(
			"Because this is a primary production asset directly exposed to the internet, " +
				"remediation of critical and high findings should be prioritised immediately.",
		)
	} else if exposure == ExposureInternal {
		sb.WriteString(
			"The internal-only exposure reduces the immediate attack surface; however, " +
				"high and critical findings remain relevant to insider threat and post-breach lateral movement scenarios.",
		)
	} else {
		sb.WriteString(
			"Findings should be reviewed in order of final score, prioritising any " +
				"that participate in multi-step attack chains.",
		)
	}

	return sb.String()
}
