// File: internal/scoring/exposure.go
package riskscoring

// ExposureLevel describes how exposed the target asset is to attackers.
// Derived from recon data: DNS records, IP ranges, ports, CDN presence.
type ExposureLevel string

const (
	// ExposureInternet: the asset is directly accessible from the public internet.
	// Highest risk — any attacker can reach it without network position.
	ExposureInternet ExposureLevel = "internet"

	// ExposureCDN: the asset is behind a CDN or WAF, reducing direct exposure
	// but still reachable from the internet.
	ExposureCDN ExposureLevel = "cdn"

	// ExposurePartner: the asset is accessible to authenticated external partners
	// or via VPN — not public but not fully internal.
	ExposurePartner ExposureLevel = "partner"

	// ExposureInternal: the asset is only accessible from within the internal network.
	// Lowest risk from external attacker perspective.
	ExposureInternal ExposureLevel = "internal"

	// ExposureUnknown: exposure could not be determined from recon data.
	ExposureUnknown ExposureLevel = "unknown"
)

// CriticalityLevel describes the business importance of the target asset.
// Derived from recon data: hostname keywords, port/service types, API patterns.
type CriticalityLevel string

const (
	// CriticalityPrimary: core production asset — auth, payment, data, admin surfaces.
	CriticalityPrimary CriticalityLevel = "primary"

	// CriticalitySupporting: important but not core — APIs, marketing, internal tools.
	CriticalitySupporting CriticalityLevel = "supporting"

	// CriticalityPeripheral: low-importance asset — staging, preview, CDN subdomains.
	CriticalityPeripheral CriticalityLevel = "peripheral"

	// CriticalityUnknown: criticality could not be determined.
	CriticalityUnknown CriticalityLevel = "unknown"
)

// exposureDelta is the additive score adjustment per exposure level.
// Internet-facing assets face a larger threat population → scores higher.
var exposureDelta = map[ExposureLevel]float64{
	ExposureInternet: +1.0,
	ExposureCDN:      +0.5,
	ExposurePartner:  +0.0,
	ExposureInternal: -1.5,
	ExposureUnknown:  +0.0,
}

// criticalityDelta is the additive score adjustment per criticality level.
// High-value assets have greater business impact from a successful exploit.
var criticalityDelta = map[CriticalityLevel]float64{
	CriticalityPrimary:    +1.0,
	CriticalitySupporting: +0.0,
	CriticalityPeripheral: -0.5,
	CriticalityUnknown:    +0.0,
}

// computeContextDelta returns the combined additive adjustment for exposure
// and asset criticality. Clamped to [-2.0, +2.0] to prevent domination
// over the CVSS base score.
func computeContextDelta(exposure ExposureLevel, criticality CriticalityLevel) float64 {
	delta := exposureDelta[exposure] + criticalityDelta[criticality]
	if delta > 2.0 {
		return 2.0
	}
	if delta < -2.0 {
		return -2.0
	}
	return delta
}

// InferExposure derives an ExposureLevel from Target recon fields.
// Call this during scan setup, not per-finding, to avoid repeated computation.
func InferExposure(target TargetMeta) ExposureLevel {
	if target.BehindCDN {
		return ExposureCDN
	}
	if target.IsInternetFacing {
		return ExposureInternet
	}
	if target.IsInternalOnly {
		return ExposureInternal
	}
	if target.RequiresVPN {
		return ExposurePartner
	}
	// Fallback: check IP range
	if isPublicIP(target.ResolvedIP) {
		return ExposureInternet
	}
	return ExposureUnknown
}

// InferCriticality derives a CriticalityLevel from hostname and service signals.
func InferCriticality(target TargetMeta) CriticalityLevel {
	host := target.Hostname

	// Primary: auth, payment, data, admin, API gateway surfaces
	primaryKeywords := []string{
		"auth", "login", "sso", "oauth", "pay", "payment", "checkout",
		"billing", "admin", "dashboard", "api", "api-gateway", "graphql",
		"db", "database", "data", "prod", "production", "secure",
	}
	for _, kw := range primaryKeywords {
		if containsFold(host, kw) {
			return CriticalityPrimary
		}
	}

	// Peripheral: staging, preview, dev, test, CDN, static assets
	peripheralKeywords := []string{
		"staging", "stage", "preview", "dev", "development", "test",
		"qa", "uat", "sandbox", "demo", "static", "assets", "cdn",
		"img", "images", "media",
	}
	for _, kw := range peripheralKeywords {
		if containsFold(host, kw) {
			return CriticalityPeripheral
		}
	}

	return CriticalitySupporting
}

// TargetMeta holds the target-level signals used for exposure + criticality inference.
type TargetMeta struct {
	Hostname         string
	ResolvedIP       string
	IsInternetFacing bool
	IsInternalOnly   bool
	BehindCDN        bool
	RequiresVPN      bool
}

// isPublicIP returns true if the IP is not RFC-1918, loopback, or link-local.
func isPublicIP(ip string) bool {
	if ip == "" {
		return false
	}
	privateRanges := []string{
		"10.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
		"172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
		"172.30.", "172.31.", "192.168.", "127.", "169.254.", "::1",
	}
	for _, r := range privateRanges {
		if len(ip) >= len(r) && ip[:len(r)] == r {
			return false
		}
	}
	return true
}

func containsFold(s, sub string) bool {
	return len(s) >= len(sub) &&
		func() bool {
			sl, subl := []byte(s), []byte(sub)
			for i := 0; i <= len(sl)-len(subl); i++ {
				match := true
				for j := range subl {
					c1, c2 := sl[i+j], subl[j]
					if c1 >= 'A' && c1 <= 'Z' {
						c1 += 32
					}
					if c2 >= 'A' && c2 <= 'Z' {
						c2 += 32
					}
					if c1 != c2 {
						match = false
						break
					}
				}
				if match {
					return true
				}
			}
			return false
		}()
}
