package scope

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var hostRE = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

func ValidateTarget(target string) error {
	t := strings.TrimSpace(strings.ToLower(target))
	if t == "" {
		return errors.New("target is required")
	}
	// Strip protocol prefix for validation only (not for use as the target itself)
	check := t
	for _, pfx := range []string{"https://", "http://"} {
		if strings.HasPrefix(check, pfx) {
			check = check[len(pfx):]
			break
		}
	}
	check = strings.TrimRight(check, "/")
	// Strip port suffix for hostname validation
	if h, _, err := net.SplitHostPort(check); err == nil {
		check = h
	}
	if check == "localhost" {
		return nil
	}
	if ip := net.ParseIP(check); ip != nil {
		return nil
	}
	if hostRE.MatchString(check) {
		return nil
	}
	return fmt.Errorf("invalid target %q: must be a hostname, IP address, or host:port", target)
}

// NormalizeTargetForDir sanitizes a target into a safe directory name.
// This is used for artifact directory naming and should be used consistently
// when comparing targets against directory-derived names.
func NormalizeTargetForDir(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	// Remove protocol prefix if present
	for _, pfx := range []string{"https://", "http://"} {
		if strings.HasPrefix(strings.ToLower(s), pfx) {
			s = s[len(pfx):]
			break
		}
	}
	// Remove trailing slashes
	s = strings.TrimRight(s, "/")
	// Replace disallowed characters
	var out strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			out.WriteRune(r)
		default:
			out.WriteRune('_')
		}
	}
	result := out.String()
	if result == "" {
		return "unknown"
	}
	return result
}
