package config

import (
	"os"
	"path/filepath"
	"strings"
)

func ResolveReconHarvestCmd(configured string) string {
	if configured != "" {
		return configured
	}
	candidates := []string{
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
