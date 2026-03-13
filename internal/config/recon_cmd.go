package config

import (
	"os"
	"path/filepath"
)

func ResolveReconHarvestCmd(configured string) string {
	if configured != "" {
		return configured
	}
	candidates := []string{
		"python3 ./tools/reconharvest/reconHarvest.py",
		"python3 tools/reconharvest/reconHarvest.py",
		"reconHarvest.py",
	}
	for _, c := range candidates {
		if c == "reconHarvest.py" {
			return c
		}
		p := filepath.Clean(c[len("python3 "):])
		if _, err := os.Stat(p); err == nil {
			return c
		}
	}
	return "python3 ./tools/reconharvest/reconHarvest.py"
}
