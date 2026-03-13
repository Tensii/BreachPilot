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
	if ip := net.ParseIP(t); ip != nil {
		if isPrivateOrLocal(ip) {
			return errors.New("private/local IP targets are blocked")
		}
		return nil
	}
	if !hostRE.MatchString(t) || !strings.Contains(t, ".") {
		return errors.New("invalid target")
	}
	return nil
}

func isPrivateOrLocal(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	private := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7"}
	for _, cidr := range private {
		_, n, _ := net.ParseCIDR(cidr)
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
