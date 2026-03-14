package engine

import "testing"

func TestSeverityAtLeast(t *testing.T) {
	tests := []struct {
		sev  string
		min  string
		want bool
	}{
		{"CRITICAL", "HIGH", true},
		{"HIGH", "HIGH", true},
		{"MEDIUM", "HIGH", false},
		{"LOW", "", true},
		{"INFO", "LOW", false},
	}

	for _, tc := range tests {
		if got := severityAtLeast(tc.sev, tc.min); got != tc.want {
			t.Fatalf("severityAtLeast(%q, %q)=%v want %v", tc.sev, tc.min, got, tc.want)
		}
	}
}
