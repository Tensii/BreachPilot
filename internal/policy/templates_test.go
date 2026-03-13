package policy

import "testing"

func TestClassifyTemplate(t *testing.T) {
	cases := []struct {
		in   string
		want Risk
	}{
		{"http/misconfiguration/test.yaml", RiskSafe},
		{"http/rce/test.yaml", RiskIntrusive},
		{"http/unknown/test.yaml", RiskVerify},
	}
	for _, c := range cases {
		if got := ClassifyTemplate(c.in); got != c.want {
			t.Fatalf("classify %q = %q want %q", c.in, got, c.want)
		}
	}
}

func TestHasIntrusive(t *testing.T) {
	if !HasIntrusive([]string{"http/rce/a.yaml"}) {
		t.Fatal("expected intrusive=true")
	}
	if HasIntrusive([]string{"http/misconfiguration/a.yaml"}) {
		t.Fatal("expected intrusive=false")
	}
}
