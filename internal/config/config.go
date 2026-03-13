package config

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	WebhookURL        string
	ReconWebhookURL   string
	ExploitWebhookURL string
	WebhookSecret     string
	WebhookRetries    int
	NucleiBin         string
	ReconHarvestCmd   string
	ReconTimeoutSec   int
	ReconRetries      int
	NucleiTimeoutSec  int
	ArtifactsRoot     string
	ConfigPath        string
}

func Load() Config {
	configPath := getEnv("BREACHPILOT_CONFIG", "./breachpilot.env")
	_ = loadEnvFile(configPath)

	reconWH := os.Getenv("BREACHPILOT_WEBHOOK_RECON")
	exploitWH := os.Getenv("BREACHPILOT_WEBHOOK_EXPLOIT")
	legacyWH := os.Getenv("BREACHPILOT_WEBHOOK")
	if reconWH == "" {
		reconWH = legacyWH
	}
	if exploitWH == "" {
		exploitWH = legacyWH
	}

	return Config{
		WebhookURL:        legacyWH,
		ReconWebhookURL:   reconWH,
		ExploitWebhookURL: exploitWH,
		WebhookSecret:     os.Getenv("BREACHPILOT_WEBHOOK_SECRET"),
		WebhookRetries:    getEnvInt("BREACHPILOT_WEBHOOK_RETRIES", 3),
		NucleiBin:         getEnv("BREACHPILOT_NUCLEI_BIN", "nuclei"),
		ReconHarvestCmd:   getEnv("BREACHPILOT_RECONHARVEST_CMD", ""),
		ReconTimeoutSec:   getEnvInt("BREACHPILOT_RECON_TIMEOUT_SEC", 7200),
		ReconRetries:      getEnvInt("BREACHPILOT_RECON_RETRIES", 1),
		NucleiTimeoutSec:  getEnvInt("BREACHPILOT_NUCLEI_TIMEOUT_SEC", 1800),
		ArtifactsRoot:     getEnv("BREACHPILOT_ARTIFACTS", "./artifacts"),
		ConfigPath:        configPath,
	}
}

func getEnv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(k string, fallback int) int {
	v := os.Getenv(k)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func loadEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"`)
		if k == "" {
			continue
		}
		if os.Getenv(k) == "" {
			_ = os.Setenv(k, v)
		}
	}
	return s.Err()
}
