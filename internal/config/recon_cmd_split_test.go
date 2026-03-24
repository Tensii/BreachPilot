package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSplitReconHarvestCommandNormalizesRelativeInterpreterScript(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	script := filepath.Join(dir, "tools", "reconharvest", "reconHarvest.py")
	if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("print('ok')\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	argv, err := SplitReconHarvestCommand("python3 ./tools/reconharvest/reconHarvest.py")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got, want := argv[1], script; got != want {
		t.Fatalf("expected normalized script path %q, got %q", want, got)
	}
}

func TestSplitReconHarvestCommandNormalizesRelativeExecutable(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	script := filepath.Join(dir, "fake_recon.sh")
	if err := os.WriteFile(script, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	argv, err := SplitReconHarvestCommand("./fake_recon.sh")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got, want := argv[0], script; got != want {
		t.Fatalf("expected normalized executable path %q, got %q", want, got)
	}
}
