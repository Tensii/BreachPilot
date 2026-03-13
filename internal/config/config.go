package config

import (
	"flag"
	"os"
	"strconv"
)

type Config struct {
	Listen           string
	Workers          int
	QueueSize        int
	RequireToken     string
	WebhookURL       string
	WebhookSecret    string
	WebhookRetries   int
	TriggerSecret    string
	NucleiBin        string
	ReconHarvestCmd  string
	ReconTimeoutSec  int
	ReconRetries     int
	NucleiTimeoutSec int
	ArtifactsRoot    string
	DBPath           string
}

func Load() Config {
	cfg := Config{
		Listen:           getEnv("BREACHPILOT_LISTEN", ":8080"),
		Workers:          getEnvInt("BREACHPILOT_WORKERS", 2),
		QueueSize:        getEnvInt("BREACHPILOT_QUEUE_SIZE", 100),
		RequireToken:     os.Getenv("BREACHPILOT_TOKEN"),
		WebhookURL:       os.Getenv("BREACHPILOT_WEBHOOK"),
		WebhookSecret:    os.Getenv("BREACHPILOT_WEBHOOK_SECRET"),
		WebhookRetries:   getEnvInt("BREACHPILOT_WEBHOOK_RETRIES", 3),
		TriggerSecret:    os.Getenv("BREACHPILOT_TRIGGER_SECRET"),
		NucleiBin:        getEnv("BREACHPILOT_NUCLEI_BIN", "nuclei"),
		ReconHarvestCmd:  getEnv("BREACHPILOT_RECONHARVEST_CMD", "python3 /home/ubuntu/.openclaw/workspace/reconHarvest-PythonV/reconHarvest.py"),
		ReconTimeoutSec:  getEnvInt("BREACHPILOT_RECON_TIMEOUT_SEC", 7200),
		ReconRetries:     getEnvInt("BREACHPILOT_RECON_RETRIES", 1),
		NucleiTimeoutSec: getEnvInt("BREACHPILOT_NUCLEI_TIMEOUT_SEC", 1800),
		ArtifactsRoot:    getEnv("BREACHPILOT_ARTIFACTS", "./artifacts"),
		DBPath:           getEnv("BREACHPILOT_DB", "./breachpilot.db"),
	}
	flag.StringVar(&cfg.Listen, "listen", cfg.Listen, "listen address")
	flag.IntVar(&cfg.Workers, "workers", cfg.Workers, "worker count")
	flag.IntVar(&cfg.QueueSize, "queue-size", cfg.QueueSize, "queue size")
	flag.Parse()
	return cfg
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
