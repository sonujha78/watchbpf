package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config poori WatchBPF settings ka structure hai
type Config struct {
	Mode    string `yaml:"mode"`
	Enforce string `yaml:"enforce"`
	State   string `yaml:"state"`

	Thresholds struct {
		Alert int `yaml:"alert"`
		Soft  int `yaml:"soft"`
		Hard  int `yaml:"hard"`
	} `yaml:"thresholds"`

	ProtectedProcesses []string `yaml:"protected_processes"`

	RateLimit struct {
		MaxPerMinute int `yaml:"max_per_minute"`
	} `yaml:"rate_limit"`

	LLM struct {
		OllamaModel string `yaml:"ollama_model"`
		OllamaURL   string `yaml:"ollama_url"`
	} `yaml:"llm"`
}

// Default sensible defaults return karta hai (jo humne ab tak hardcode kiye the)
func Default() *Config {
	c := &Config{
		Mode:    "learn",
		Enforce: "dry-run",
		State:   "baseline.json",
	}
	c.Thresholds.Alert = 40
	c.Thresholds.Soft = 70
	c.Thresholds.Hard = 90
	c.ProtectedProcesses = []string{
		"systemd", "sshd", "init", "kubelet", "containerd",
		"dockerd", "watchbpf-agent", "NetworkManager",
	}
	c.RateLimit.MaxPerMinute = 50
	c.LLM.OllamaModel = "llama3.1:8b"
	c.LLM.OllamaURL = "http://localhost:11434"
	return c
}

// Load config file se padhta hai; file na mile to defaults return karta hai (error nahi)
func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // config file optional hai
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
