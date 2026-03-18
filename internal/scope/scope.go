package scope

import (
	"errors"
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
	if t == "localhost" || strings.HasPrefix(t, "localhost:") {
		return nil
	}
	if ip := net.ParseIP(t); ip != nil {
		// Allow local/private for dev/test purposes
		return nil
	}
	// Allow single-word targets if they look like hostnames (common in local labs)
	if hostRE.MatchString(t) {
		return nil
	}
	return nil
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
