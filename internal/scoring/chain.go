// File: internal/scoring/chain.go
package riskscoring

import (
	"fmt"
	"strings"
)

// ChainRule defines a known multi-step attack pattern.
// Prerequisites are module names. If all are present in the finding set,
// the chain is active and each member finding gets a ChainBonus.
type ChainRule struct {
	// ID is a stable identifier for this chain, used in reports.
	ID string

	// Steps defines the ordered module names that make up this chain.
	// Order matters for narrative description but not for detection.
	Steps []string

	// Bonus is added to the Final score of every finding that participates.
	// Larger chains and chains with higher exploit potential get larger bonuses.
	Bonus float64

	// Description is displayed in reports to explain the chain to a reader.
	Description string
}

// knownChains is the registry of multi-step attack patterns BreachPilot knows about.
// Add new chains here as new modules are added.
var knownChains = []ChainRule{
	{
		ID:    "open-redirect→ssrf",
		Steps: []string{"open-redirect", "ssrf"},
		Bonus: 1.5,
		Description: "Open redirect combined with SSRF enables phishing-assisted " +
			"internal network access. Attacker lures a victim to the redirect, " +
			"which proxies a request to an internal service via the SSRF vector.",
	},
	{
		ID:    "idor→data-exfil",
		Steps: []string{"idor", "api-surface"},
		Bonus: 1.0,
		Description: "IDOR on an API surface with enumerable object IDs enables " +
			"systematic data exfiltration without requiring privilege escalation.",
	},
	{
		ID:    "subdomain-takeover→open-redirect",
		Steps: []string{"subdomain-takeover", "open-redirect"},
		Bonus: 1.5,
		Description: "A taken-over subdomain can serve a redirect page that " +
			"bypasses subdomain-based redirect allowlists, upgrading open " +
			"redirect from phishing to trusted-domain abuse.",
	},
	{
		ID:    "ssrf→internal-idor",
		Steps: []string{"ssrf", "idor"},
		Bonus: 2.0,
		Description: "SSRF reaching an internal API that has IDOR vulnerabilities " +
			"enables unauthenticated access to arbitrary internal objects. " +
			"High severity: no network position required, full object enumeration possible.",
	},
	{
		ID:    "js-endpoints→idor",
		Steps: []string{"js-endpoint-signals", "idor"},
		Bonus: 0.5,
		Description: "JS endpoint signals reveal internal API paths that correlate " +
			"with IDOR-vulnerable endpoints, enabling targeted object enumeration.",
	},
	{
		ID:    "cookie-security→session-fixation",
		Steps: []string{"cookie-security", "open-redirect"},
		Bonus: 1.0,
		Description: "Missing cookie security flags combined with an open redirect " +
			"enables session cookie theft via a redirect to an attacker-controlled page.",
	},
	{
		ID:    "subdomain-takeover→ssrf",
		Steps: []string{"subdomain-takeover", "ssrf"},
		Bonus: 1.5,
		Description: "A taken-over subdomain can host a response that an SSRF " +
			"vulnerability fetches, enabling attacker-controlled SSRF response content " +
			"without needing a standalone OOB server.",
	},
}

// FindingMeta is a minimal view of a Finding used by the chain analyzer.
// Using a separate type avoids a circular import between scoring and modules.
type FindingMeta struct {
	ID     string // unique finding ID
	Module string // module name that produced this finding
	URL    string // affected URL
}

// ChainAnalysis is the output of AnalyzeChains — one entry per finding.
type ChainAnalysis struct {
	// Bonus to add to this finding's Final score
	Bonus float64

	// Chains this finding participates in
	Chains []ChainRef
}

// AnalyzeChains takes the full finding set for a scan and returns a map of
// finding ID → ChainAnalysis. Call this once after all modules complete,
// before computing final scores.
func AnalyzeChains(findings []FindingMeta) map[string]ChainAnalysis {
	// Build a set of modules present in this scan's findings
	moduleFindings := make(map[string][]FindingMeta)
	for _, f := range findings {
		moduleFindings[f.Module] = append(moduleFindings[f.Module], f)
	}

	// Determine which chains are active
	type activeChain struct {
		rule    ChainRule
		members []FindingMeta // one representative finding per step
	}
	var active []activeChain

	for _, rule := range knownChains {
		// All steps must have at least one finding present
		allPresent := true
		var members []FindingMeta
		for _, step := range rule.Steps {
			stepFindings, ok := moduleFindings[step]
			if !ok || len(stepFindings) == 0 {
				allPresent = false
				break
			}
			// Pick the highest-URL finding as representative (arbitrary but stable)
			members = append(members, stepFindings[0])
		}
		if allPresent {
			active = append(active, activeChain{rule: rule, members: members})
		}
	}

	// Build result map: finding ID → accumulated bonus + chain refs
	result := make(map[string]ChainAnalysis)

	for _, ac := range active {
		memberIDs := make([]string, 0, len(ac.members))
		for _, m := range ac.members {
			memberIDs = append(memberIDs, m.ID)
		}

		ref := ChainRef{
			ChainID:     ac.rule.ID,
			Description: ac.rule.Description,
			Members:     memberIDs,
		}

		// Apply bonus and ref to every member finding
		// If a finding participates in multiple chains, bonuses stack
		// but are clamped to 2.0 in the final scoring step.
		for _, m := range ac.members {
			entry := result[m.ID]
			entry.Bonus += ac.rule.Bonus
			entry.Chains = append(entry.Chains, ref)
			result[m.ID] = entry
		}
	}

	return result
}

// FormatChainSummary returns a human-readable list of active chains for a report section.
func FormatChainSummary(findings []FindingMeta) string {
	analysis := AnalyzeChains(findings)

	// Deduplicate chains by ID
	seen := make(map[string]ChainRef)
	for _, ca := range analysis {
		for _, ref := range ca.Chains {
			seen[ref.ChainID] = ref
		}
	}

	if len(seen) == 0 {
		return "No multi-step attack chains detected."
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%d attack chain(s) detected:\n\n", len(seen)))
	for _, ref := range seen {
		sb.WriteString(fmt.Sprintf("  [%s]\n  %s\n  Members: %s\n\n",
			ref.ChainID, ref.Description, strings.Join(ref.Members, " → ")))
	}
	return sb.String()
}
