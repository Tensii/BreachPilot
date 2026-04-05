package config

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// BootstrapEnvironment ensures that common local binary paths are in the process's PATH.
// It also checks for core dependencies and can trigger an auto-install if they are missing.
func BootstrapEnvironment() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	// Paths to prepend to PATH if they exist and aren't already there.
	localBins := []string{
		filepath.Join(home, ".local", "bin"),
		filepath.Join(home, "go", "bin"),
		"/usr/local/go/bin",
		"/usr/local/bin",
	}

	currentPath := os.Getenv("PATH")
	pathParts := filepath.SplitList(currentPath)
	pathMap := make(map[string]bool)
	for _, p := range pathParts {
		pathMap[filepath.Clean(p)] = true
	}

	newParts := []string{}
	for _, lb := range localBins {
		cleanLb := filepath.Clean(lb)
		if _, err := os.Stat(cleanLb); err == nil {
			if !pathMap[cleanLb] {
				newParts = append(newParts, cleanLb)
				pathMap[cleanLb] = true
			}
		}
	}

	if len(newParts) > 0 {
		sep := string(os.PathListSeparator)
		newPath := strings.Join(newParts, sep) + sep + currentPath
		os.Setenv("PATH", newPath)
	}
}

// EnsureDependencies checks if nuclei is in PATH. If not, it attempts to run 
// the reconharvest bootstrap (usually by calling it with a non-destructive flag).
func EnsureDependencies(nucleiBin string, reconCmd string) error {
	if nucleiBin == "" {
		nucleiBin = "nuclei"
	}
	
	// If it's already in PATH, we're good.
	if _, err := exec.LookPath(nucleiBin); err == nil {
		return nil
	}

	fmt.Printf("[*] Core dependency %q not found in PATH.\n", nucleiBin)
	fmt.Printf("[*] Attempting automatic bootstrap via reconharvest.py...\n")

	// Trigger reconharvest setup. reconharvest.py's main() bootstrap runs 
	// before its argument parser if it detects missing core tools.
	// We run it with --help so it doesn't do anything destructive.
	args, err := SplitReconHarvestCommand(ResolveReconHarvestCmd(reconCmd))
	if err != nil {
		return fmt.Errorf("failed to resolve recon command for bootstrap: %w", err)
	}

	cmd := exec.Command(args[0], append(args[1:], "--doctor")...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("auto-bootstrap failed: %w (try running 'breachpilot setup' or installing manually)", err)
	}

	// Re-check after bootstrap.
	if _, err := exec.LookPath(nucleiBin); err != nil {
		return fmt.Errorf("dependency %q still missing after bootstrap: %w", nucleiBin, err)
	}

	fmt.Printf("[+] Dependency %q successfully installed and verified.\n", nucleiBin)
	return nil
}
