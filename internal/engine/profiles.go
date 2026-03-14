package engine

// ScanProfile defines a preset scan configuration.
type ScanProfile struct {
	Name        string
	Description string
	OnlyModules string
	SkipModules string
	MaxParallel int
}

var profiles = map[string]ScanProfile{
	"quick": {
		Name:        "quick",
		Description: "Fast surface-level scan",
		OnlyModules: "security-headers,cookie-security,csp-audit,http-response",
		MaxParallel: 8,
	},
	"standard": {
		Name:        "standard",
		Description: "Default balanced scan",
		MaxParallel: 4,
	},
	"deep": {
		Name:        "deep",
		Description: "Thorough scan with all modules",
		MaxParallel: 2,
	},
}

// GetProfile returns a scan profile by name.
func GetProfile(name string) (ScanProfile, bool) {
	p, ok := profiles[name]
	return p, ok
}
