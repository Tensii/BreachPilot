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
