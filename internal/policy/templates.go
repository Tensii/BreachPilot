package policy

import "strings"

type Risk string

const (
	RiskSafe      Risk = "safe"
	RiskVerify    Risk = "verify"
	RiskIntrusive Risk = "intrusive"
)

func ClassifyTemplate(t string) Risk {
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "" {
		return RiskVerify
	}
	intrusiveHints := []string{"rce", "deserialization", "sqli", "ssti", "cmd-injection", "lfi", "xxe"}
	for _, h := range intrusiveHints {
		if strings.Contains(t, h) {
			return RiskIntrusive
		}
	}
	safeHints := []string{"misconfiguration", "exposure", "tech", "panel", "version"}
	for _, h := range safeHints {
		if strings.Contains(t, h) {
			return RiskSafe
		}
	}
	return RiskVerify
}

func HasIntrusive(templates []string) bool {
	for _, t := range templates {
		if ClassifyTemplate(t) == RiskIntrusive {
			return true
		}
	}
	return false
}
