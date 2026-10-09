package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	// Server defaults
	if cfg.Server.Address != "localhost:50051" {
		t.Errorf("expected default server address localhost:50051, got %s", cfg.Server.Address)
	}
	if cfg.Server.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", cfg.Server.Timeout)
	}

	// Agent defaults
	if cfg.Agent.BatchSize != 200 {
		t.Errorf("expected batch size 200, got %d", cfg.Agent.BatchSize)
	}
	if cfg.Agent.BatchInterval != 2*time.Second {
		t.Errorf("expected batch interval 2s, got %v", cfg.Agent.BatchInterval)
	}
	if cfg.Agent.BufferSize != 5000 {
		t.Errorf("expected buffer size 5000, got %d", cfg.Agent.BufferSize)
	}
	if cfg.Agent.Compression != "snappy" {
		t.Errorf("expected compression snappy, got %s", cfg.Agent.Compression)
	}

	// Collectors defaults
	if !cfg.Collectors.ETWEnabled {
		t.Error("ETW should be enabled by default")
	}
	if !cfg.Collectors.WMIEnabled {
		t.Error("WMI should be enabled by default")
	}

	// Filtering defaults
	if len(cfg.Filtering.ExcludeProcesses) != 0 {
		t.Error("default process-name exclusions hide masquerading")
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{
			name:    "valid default config",
			modify:  func(c *Config) {},
			wantErr: false,
		},
		{
			name:    "empty server address",
			modify:  func(c *Config) { c.Server.Address = "" },
			wantErr: true,
		},
		{
			name:    "batch size too small",
			modify:  func(c *Config) { c.Agent.BatchSize = 0 },
			wantErr: true,
		},
		{
			name:    "batch size too large",
			modify:  func(c *Config) { c.Agent.BatchSize = 20000 },
			wantErr: true,
		},
		{
			name:    "batch interval too short",
			modify:  func(c *Config) { c.Agent.BatchInterval = 10 * time.Millisecond },
			wantErr: true,
		},
		{
			name:    "batch interval too long",
			modify:  func(c *Config) { c.Agent.BatchInterval = 2 * time.Minute },
			wantErr: true,
		},
		{
			name:    "buffer size too small",
			modify:  func(c *Config) { c.Agent.BufferSize = 50 },
			wantErr: true,
		},
		{
			name:    "buffer size too large",
			modify:  func(c *Config) { c.Agent.BufferSize = 200000 },
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()

			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	// Create temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  address: "test.example.com:50051"
  timeout: 60s

agent:
  batch_size: 100
  batch_interval: 2s
  buffer_size: 10000
  compression: "snappy"

logging:
  level: "DEBUG"
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Server.Address != "test.example.com:50051" {
		t.Errorf("expected test.example.com:50051, got %s", cfg.Server.Address)
	}
	if cfg.Agent.BatchSize != 100 {
		t.Errorf("expected batch size 100, got %d", cfg.Agent.BatchSize)
	}
	if cfg.Logging.Level != "DEBUG" {
		t.Errorf("expected log level DEBUG, got %s", cfg.Logging.Level)
	}
}

func TestLoadConfigNotFound(t *testing.T) {
	cfg, err := Load("/nonexistent/path/config.yaml")

	// Should return defaults when file not found
	if err != nil {
		t.Errorf("should not error on missing file: %v", err)
	}
	if cfg == nil {
		t.Fatal("should return default config")
	}
	if cfg.Server.Address != "localhost:50051" {
		t.Error("should have default values")
	}
}

func TestConfigClone(t *testing.T) {
	original := DefaultConfig()
	original.Server.Address = "original.com:50051"
	original.Filtering.ExcludeProcesses = []string{"test.exe"}

	clone := original.Clone()

	// Modify clone
	clone.Server.Address = "modified.com:50051"
	clone.Filtering.ExcludeProcesses = append(clone.Filtering.ExcludeProcesses, "new.exe")

	// Original should be unchanged
	if original.Server.Address != "original.com:50051" {
		t.Error("clone modified original server address")
	}
	if len(original.Filtering.ExcludeProcesses) != 1 {
		t.Error("clone modified original exclude list")
	}
}

func TestConfigSave(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "saved_config.yaml")

	cfg := DefaultConfig()
	cfg.Server.Address = "saved.example.com:50051"
	cfg.Agent.BatchSize = 200

	if err := cfg.Save(configPath); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load saved config
	loaded, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Server.Address != "saved.example.com:50051" {
		t.Errorf("saved address not loaded correctly")
	}
	if loaded.Agent.BatchSize != 200 {
		t.Errorf("saved batch size not loaded correctly")
	}
}

func TestAgentIDGeneration(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Agent.ID == "" {
		t.Error("Agent ID should be auto-generated")
	}

	// Should be UUID format (36 chars)
	if len(cfg.Agent.ID) != 36 {
		t.Errorf("Agent ID should be UUID format, got length %d", len(cfg.Agent.ID))
	}
}
