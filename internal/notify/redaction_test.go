package notify

import "testing"

func TestRedactURL(t *testing.T) {
	in := "https://discord.com/api/webhooks/123/abcdef"
	got := redactURL(in)
	if got == in {
		t.Fatalf("expected redacted URL")
	}
}

func TestRedactSensitive(t *testing.T) {
	if got := redactSensitive("authorization failed token=abc"); got != "<redacted>" {
		t.Fatalf("expected redacted sensitive message")
	}
}
