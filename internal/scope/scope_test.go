package scope

import (
	"testing"
)

func TestNormalizeTargetForDir(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"plain domain", "example.com", "example.com"},
		{"http url", "http://example.com", "example.com"},
		{"https url", "https://example.com", "example.com"},
		{"url with path", "https://example.com/api/v1", "example.com_api_v1"},
		{"url with trailing slash", "https://example.com/", "example.com"},
		{"ip address", "127.0.0.1", "127.0.0.1"},
		{"localhost with port", "http://127.0.0.1:3001", "127.0.0.1_3001"},
		{"domain with port", "example.com:8080", "example.com_8080"},
		{"disallowed characters", "target@shoot.com", "target_shoot.com"},
		{"empty input", "", "unknown"},
		{"whitespace only", "   ", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeTargetForDir(tt.input); got != tt.expected {
				t.Errorf("NormalizeTargetForDir(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
