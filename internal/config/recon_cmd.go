package config

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/shlex"
)

type ReconHarvestCapabilities struct {
	helpOutput string
	flags      map[string]bool
}

func ResolveReconHarvestCmd(configured string) string {
	if configured != "" {
		return configured
	}
	candidates := []string{
		"python3 /usr/local/share/breachpilot/tools/reconharvest/reconHarvest.py",
		"python3 ./tools/reconharvest/reconHarvest.py",
		"python3 tools/reconharvest/reconHarvest.py",
		"python3 ./reconHarvest.py",
		"python3 reconHarvest.py",
	}
	for _, c := range candidates {
		p := filepath.Clean(strings.TrimPrefix(c, "python3 "))
		if _, err := os.Stat(p); err == nil {
			return c
		}
	}
	return "python3 ./tools/reconharvest/reconHarvest.py"
}

func ProbeReconHarvestCapabilities(raw string) (ReconHarvestCapabilities, error) {
	argv, err := SplitReconHarvestCommand(raw)
	if err != nil {
		return ReconHarvestCapabilities{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, argv[0], append(append([]string{}, argv[1:]...), "--help")...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return ReconHarvestCapabilities{}, fmt.Errorf("recon command help timed out")
	}
	if err != nil {
		return ReconHarvestCapabilities{}, fmt.Errorf("recon command help failed: %w", err)
	}
	return parseReconHarvestHelp(string(out)), nil
}

func (c ReconHarvestCapabilities) Supports(flag string) bool {
	if c.flags == nil {
		return false
	}
	return c.flags[strings.TrimSpace(flag)]
}

func (c ReconHarvestCapabilities) HelpOutput() string {
	return c.helpOutput
}

func (c ReconHarvestCapabilities) SupportsCoreExecution() bool {
	return c.Supports("--run") &&
		(c.Supports("-o") || c.Supports("--output")) &&
		(c.Supports("--resume") || c.Supports("--resume-from-stage"))
}

func parseReconHarvestHelp(help string) ReconHarvestCapabilities {
	flags := map[string]bool{}
	for _, flag := range []string{
		"--run",
		"-o",
		"--output",
		"--resume",
		"--resume-from-stage",
		"--overwrite",
		"--skip-nuclei",
		"--arjun-threads",
		"--vhost-threads",
		"--arjun-host-cap",
		"--vhost-rate",
	} {
		if strings.Contains(help, flag) {
			flags[flag] = true
		}
	}
	return ReconHarvestCapabilities{
		helpOutput: help,
		flags:      flags,
	}
}

func SplitReconHarvestCommand(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty recon command")
	}
	argv, err := shlex.Split(raw)
	if err != nil || len(argv) == 0 {
		return nil, fmt.Errorf("invalid recon command: %q", raw)
	}
	argv = normalizeReconHarvestArgv(argv)
	if _, err := exec.LookPath(argv[0]); err != nil {
		return nil, fmt.Errorf("recon command executable not found: %w", err)
	}
	return argv, nil
}

func splitReconHarvestCommand(raw string) ([]string, error) {
	return SplitReconHarvestCommand(raw)
}

func normalizeReconHarvestArgv(argv []string) []string {
	if len(argv) == 0 {
		return argv
	}

	normalized := append([]string{}, argv...)
	if abs, ok := absolutizeIfLocalPath(normalized[0]); ok {
		normalized[0] = abs
	}
	if len(normalized) > 1 && isInterpreterCommand(normalized[0]) && !strings.HasPrefix(normalized[1], "-") {
		if abs, ok := absolutizeIfLocalPath(normalized[1]); ok {
			normalized[1] = abs
		}
	}
	return normalized
}

func absolutizeIfLocalPath(raw string) (string, bool) {
	if strings.TrimSpace(raw) == "" {
		return "", false
	}
	if filepath.IsAbs(raw) {
		if _, err := os.Stat(raw); err == nil {
			return raw, true
		}
		return "", false
	}
	if !(strings.ContainsRune(raw, os.PathSeparator) || strings.HasPrefix(raw, ".")) {
		return "", false
	}
	abs, err := filepath.Abs(raw)
	if err != nil {
		return "", false
	}
	if _, err := os.Stat(abs); err == nil {
		return abs, true
	}
	return "", false
}

func isInterpreterCommand(cmd string) bool {
	switch filepath.Base(cmd) {
	case "python", "python3", "python2", "bash", "sh", "zsh":
		return true
	default:
		return false
	}
}
