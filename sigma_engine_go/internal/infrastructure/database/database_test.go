// Package database provides unit tests for database components.
package database

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, "localhost", cfg.Host)
	assert.Equal(t, 5432, cfg.Port)
	assert.Equal(t, "edr_platform", cfg.Database)
	assert.Equal(t, "prefer", cfg.SSLMode)
	assert.Equal(t, int32(25), cfg.MaxConns)
	assert.Equal(t, int32(5), cfg.MinConns)
}

func TestConnectionString(t *testing.T) {
	cfg := Config{
		Host:     "localhost",
		Port:     5432,
		User:     "testuser",
		Password: "testpass",
		Database: "testdb",
		SSLMode:  "disable",
	}

	connStr := cfg.ConnectionString()

	assert.Contains(t, connStr, "host=localhost")
	assert.Contains(t, connStr, "port=5432")
	assert.Contains(t, connStr, "user=testuser")
	assert.Contains(t, connStr, "password=testpass")
	assert.Contains(t, connStr, "dbname=testdb")
	assert.Contains(t, connStr, "sslmode=disable")
}

func TestAlertFilters(t *testing.T) {
	filters := AlertFilters{
		AgentID:   "agent-123",
		RuleID:    "rule-456",
		Severity:  []string{"critical", "high"},
		Status:    []string{"open"},
		Limit:     50,
		Offset:    0,
		SortBy:    "timestamp",
		SortOrder: "desc",
	}

	assert.Equal(t, "agent-123", filters.AgentID)
	assert.Equal(t, "rule-456", filters.RuleID)
	assert.Len(t, filters.Severity, 2)
	assert.Equal(t, 50, filters.Limit)
}

func TestRuleFilters(t *testing.T) {
	enabled := true
	filters := RuleFilters{
		Enabled:  &enabled,
		Product:  "windows",
		Category: "process_creation",
		Search:   "powershell",
		Limit:    100,
	}

	assert.NotNil(t, filters.Enabled)
	assert.True(t, *filters.Enabled)
	assert.Equal(t, "windows", filters.Product)
	assert.Equal(t, "powershell", filters.Search)
}

func TestAlertStats(t *testing.T) {
	stats := &AlertStats{
		TotalAlerts: 1000,
		BySeverity:  map[string]int64{"critical": 100, "high": 300, "medium": 600},
		ByStatus:    map[string]int64{"open": 800, "acknowledged": 200},
		Last24Hours: 50,
		Last7Days:   200,
	}

	assert.Equal(t, int64(1000), stats.TotalAlerts)
	assert.Equal(t, int64(100), stats.BySeverity["critical"])
	assert.Equal(t, int64(50), stats.Last24Hours)
}

func TestRuleStats(t *testing.T) {
	stats := &RuleStats{
		TotalRules:    4367,
		EnabledRules:  4200,
		DisabledRules: 167,
		BySeverity:    map[string]int64{"high": 1000, "medium": 2000, "low": 1367},
	}

	assert.Equal(t, int64(4367), stats.TotalRules)
	assert.Equal(t, int64(4200), stats.EnabledRules)
	assert.Equal(t, int64(167), stats.DisabledRules)
}

func TestDefaultAlertWriterConfig(t *testing.T) {
	cfg := DefaultAlertWriterConfig()

	assert.Equal(t, 30*time.Minute, cfg.DeduplicationWindow, "sliding window measured from the last occurrence")
	assert.Equal(t, 25, cfg.BatchSize)
	assert.Equal(t, 100*time.Millisecond, cfg.FlushInterval)
	assert.Equal(t, 10000, cfg.MaxQueueSize)
}

func TestAlertWriterMetricsSnapshot(t *testing.T) {
	m := &AlertWriterMetrics{}

	m.AlertsWritten = 100
	m.AlertsDeduplicated = 20
	m.WriteErrors = 5
	m.BatchesWritten = 10

	snapshot := m.Snapshot()

	assert.Equal(t, uint64(100), snapshot.AlertsWritten)
	assert.Equal(t, uint64(20), snapshot.AlertsDeduplicated)
	assert.Equal(t, uint64(5), snapshot.WriteErrors)
	assert.Equal(t, uint64(10), snapshot.BatchesWritten)
}

func TestAlert(t *testing.T) {
	confidence := 0.85
	alert := &Alert{
		ID:              "alert-123",
		Timestamp:       time.Now(),
		AgentID:         "agent-456",
		RuleID:          "rule-789",
		RuleTitle:       "Suspicious Process",
		Severity:        "high",
		Category:        "process_creation",
		EventCount:      3,
		EventIDs:        []string{"e1", "e2", "e3"},
		MitreTactics:    []string{"Execution"},
		MitreTechniques: []string{"T1059"},
		MatchedFields:   map[string]interface{}{"CommandLine": "powershell.exe"},
		Status:          "open",
		Confidence:      &confidence,
	}

	assert.Equal(t, "alert-123", alert.ID)
	assert.Equal(t, "high", alert.Severity)
	assert.Equal(t, 3, alert.EventCount)
	assert.Len(t, alert.EventIDs, 3)
	assert.Equal(t, 0.85, *alert.Confidence)
}

func TestRule(t *testing.T) {
	rule := &Rule{
		ID:              "rule-123",
		Title:           "Suspicious PowerShell Command",
		Description:     "Detects suspicious PowerShell usage",
		Content:         "title: Suspicious PowerShell\nstatus: stable",
		Enabled:         true,
		Status:          "stable",
		Product:         "windows",
		Category:        "process_creation",
		Severity:        "high",
		MitreTactics:    []string{"Execution"},
		MitreTechniques: []string{"T1059.001"},
		Source:          "official",
		Version:         1,
	}

	assert.Equal(t, "rule-123", rule.ID)
	assert.True(t, rule.Enabled)
	assert.Equal(t, "stable", rule.Status)
	assert.Equal(t, "official", rule.Source)
}
