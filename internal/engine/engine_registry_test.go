package engine

import "testing"

func TestRegistryIncludesNewModules(t *testing.T) {
	names := RegisteredModules()
	want := []string{"admin-surface", "exposed-files"}
	for _, w := range want {
		ok := false
		for _, n := range names {
			if n == w {
				ok = true
				break
			}
		}
		if !ok {
			t.Fatalf("missing module %s", w)
		}
	}
}

func TestRegisteredModulesOrderMatchesInfos(t *testing.T) {
	infos := RegisteredModuleInfos()
	names := RegisteredModules()
	if len(infos) != len(names) {
		t.Fatalf("length mismatch")
	}
	for i := range names {
		if infos[i].Name != names[i] {
			t.Fatalf("order mismatch at %d: %s vs %s", i, infos[i].Name, names[i])
		}
	}
}
