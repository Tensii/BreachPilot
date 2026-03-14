package engine

import "testing"

func TestGetProfileQuick(t *testing.T) {
	p, ok := GetProfile("quick")
	if !ok {
		t.Fatal("expected quick profile")
	}
	if p.MaxParallel != 8 {
		t.Fatalf("expected MaxParallel=8, got %d", p.MaxParallel)
	}
	if p.OnlyModules == "" {
		t.Fatal("expected OnlyModules set for quick")
	}
}

func TestGetProfileDeep(t *testing.T) {
	p, ok := GetProfile("deep")
	if !ok {
		t.Fatal("expected deep profile")
	}
	if p.MaxParallel != 2 {
		t.Fatalf("expected MaxParallel=2, got %d", p.MaxParallel)
	}
}

func TestGetProfileUnknown(t *testing.T) {
	_, ok := GetProfile("unknown")
	if ok {
		t.Fatal("expected false for unknown profile")
	}
}
