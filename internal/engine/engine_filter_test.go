package engine

import (
	"context"
	"testing"

	"breachpilot/internal/exploit"
	"breachpilot/internal/models"
)

type mod struct{ name string }

func (m *mod) Name() string { return m.name }
func (m *mod) Run(_ context.Context, _ *models.Job, _ *models.ReconSummary, _ exploit.Options) ([]models.ExploitFinding, error) {
	return nil, nil
}

func TestFilterModulesOnlyList(t *testing.T) {
	mods := []exploit.Module{&mod{name: "cors-poc"}, &mod{name: "security-headers"}, &mod{name: "port-service"}}
	out := filterModules(mods, "cors-poc", "security-headers")
	if len(out) != 1 {
		t.Fatalf("want 1 got %d", len(out))
	}
	if out[0].Name() != "cors-poc" {
		t.Fatalf("wrong module: %s", out[0].Name())
	}
}

func TestFilterModulesSkipList(t *testing.T) {
	mods := []exploit.Module{&mod{name: "cors-poc"}, &mod{name: "security-headers"}, &mod{name: "port-service"}}
	out := filterModules(mods, "", "cors-poc")
	if len(out) != 2 {
		t.Fatalf("want 2 got %d", len(out))
	}
	for _, m := range out {
		if m.Name() == "cors-poc" {
			t.Fatalf("cors-poc should be skipped")
		}
	}
}
