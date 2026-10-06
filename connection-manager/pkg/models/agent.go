// Package models defines the domain models for the connection-manager.
package models

import (
	"time"

	"github.com/google/uuid"
)

// Agent represents an EDR agent registered with the server.
type Agent struct {
	ID       uuid.UUID `db:"id" json:"id"`
	Hostname string    `db:"hostname" json:"hostname"`
	Status   string    `db:"status" json:"status"` // pending, online, offline, degraded, suspended

	// Device information
	OSType    string `db:"os_type" json:"os_type"`       // windows, linux, macos
	OSVersion string `db:"os_version" json:"os_version"` // e.g., "Windows 10 21H2"
	HardwareID string `db:"hardware_id" json:"hardware_id"`
	CPUCount  int    `db:"cpu_count" json:"cpu_count"`
	MemoryMB  int64  `db:"memory_mb" json:"memory_mb"`

	// Agent metadata
	AgentVersion  string     `db:"agent_version" json:"agent_version"`
	InstalledDate *time.Time `db:"installed_date" json:"installed_date"`
	LastSeen      time.Time  `db:"last_seen" json:"last_seen"`

	// Metrics
	EventsCollected int64   `db:"events_collected" json:"events_collected"`
	EventsDelivered int64   `db:"events_delivered" json:"events_delivered"`
	EventsDropped   int64   `db:"events_dropped" json:"events_dropped"`
	QueueDepth      int     `db:"queue_depth" json:"queue_depth"`
	CPUUsage        float64 `db:"cpu_usage" json:"cpu_usage"`
	MemoryUsedMB    int64   `db:"memory_used_mb" json:"memory_used_mb"`
	HealthScore     float64 `db:"health_score" json:"health_score"`

	// Network telemetry
	IPAddresses []string `db:"ip_addresses" json:"ip_addresses"`
	IsIsolated  bool     `db:"is_isolated" json:"is_isolated"` // Smart network isolation active

	// Sysmon telemetry (populated from agent heartbeat)
	SysmonInstalled bool `db:"sysmon_installed" json:"sysmon_installed"` // Sysmon64 service is registered on the endpoint
	SysmonRunning   bool `db:"sysmon_running" json:"sysmon_running"`     // Sysmon64 service is in RUNNING state

	// Certificate
	CurrentCertID *uuid.UUID `db:"current_cert_id" json:"current_cert_id"`
	CertExpiresAt *time.Time `db:"cert_expires_at" json:"cert_expires_at"`

	// Metadata
	Tags     map[string]string `db:"tags" json:"tags"`
	Metadata map[string]string `db:"metadata" json:"metadata"`

	// Asset criticality (Phase 3 — Risk-adjusted prioritization)
	// Drives the priority_score formula on linked vulnerability findings.
	Criticality   string `db:"criticality" json:"criticality"`     // low, medium, high, critical
	BusinessUnit  string `db:"business_unit" json:"business_unit"` // free-form (e.g. "Finance", "Engineering")
	Environment   string `db:"environment" json:"environment"`     // production, staging, development, ''

	// Timestamps
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// AgentStatus constants
const (
	AgentStatusPending          = "pending"
	AgentStatusOnline           = "online"
	AgentStatusOffline          = "offline"
	AgentStatusDegraded         = "degraded"
	AgentStatusSuspended        = "suspended"
	AgentStatusPendingUninstall = "pending_uninstall" // Server sent UNINSTALL_AGENT; awaiting agent confirmation
	AgentStatusUninstalled      = "uninstalled"       // Agent confirmed local cleanup — no new commands will be dispatched
	AgentStatusDeleted          = "deleted"           // Removed from the dashboard (soft delete): hidden from lists, history kept, connections rejected
)

// IsOnline returns true if the agent is currently online.
func (a *Agent) IsOnline() bool {
	return a.Status == AgentStatusOnline
}

// IsApproved returns true if the agent has been approved (not pending).
func (a *Agent) IsApproved() bool {
	return a.Status != AgentStatusPending
}

// NeedsCertRenewal returns true if the certificate expires within the given duration.
func (a *Agent) NeedsCertRenewal(within time.Duration) bool {
	if a.CertExpiresAt == nil || a.CertExpiresAt.IsZero() {
		return true
	}
	return time.Until(*a.CertExpiresAt) < within
}

// UpdateMetrics updates the agent's metrics from a heartbeat.
func (a *Agent) UpdateMetrics(cpuUsage float64, memoryUsedMB int64, queueDepth int, eventsGenerated, eventsSent, eventsDropped int64) {
	a.CPUUsage = cpuUsage
	a.MemoryUsedMB = memoryUsedMB
	a.QueueDepth = queueDepth
	a.EventsCollected = eventsGenerated
	a.EventsDelivered = eventsSent
	a.EventsDropped = eventsDropped
	a.LastSeen = time.Now()
	a.UpdatedAt = time.Now()
}

// CalculateHealthScore calculates the agent's health score based on metrics.
//
// FIX ISSUE-11: Unified with heartbeat.calculateHealthScore() — both now use
// the same 4-factor model (NIST SP 800-137 aligned):
//
//   health_score = delivery×0.40 + status×0.30 + dropRate×0.20 + resource×0.10
//
// Factors:
//   1. Delivery Quality (40%): events_delivered / events_collected × 100
//   2. Status Score (30%): online=100, degraded=80, offline=50, suspended=0
//   3. Drop Rate Penalty (20%): >20% drops → 0 (blinding attack indicator, MITRE T1562)
//   4. Resource Pressure (10%): CPU/memory utilization penalty
//
// Why this matters for response automation:
//   - Low health score triggers investigation workflow
//   - Score < 25 ("critical") can trigger automatic agent isolation
//   - Score is displayed on the dashboard Endpoints page
func (a *Agent) CalculateHealthScore() float64 {
	// Factor 1: Delivery Quality (40% weight)
	var deliveryRatio float64 = 100.0
	if a.EventsCollected > 0 {
		deliveryRatio = float64(a.EventsDelivered) / float64(a.EventsCollected) * 100
		if deliveryRatio > 100.0 {
			deliveryRatio = 100.0
		}
	}

	// Factor 2: Status Score (30% weight)
	statusScore := 100.0
	switch a.Status {
	case AgentStatusOnline:
		statusScore = 100.0
	case AgentStatusDegraded:
		statusScore = 80.0
	case AgentStatusOffline:
		statusScore = 50.0
	case AgentStatusSuspended:
		statusScore = 0.0
	default:
		statusScore = 60.0
	}

	// Factor 3: Drop Rate Penalty (20% weight)
	// >20% drop rate = potential blinding attack (MITRE ATT&CK T1562.001)
	dropScore := 100.0
	if a.EventsCollected > 0 {
		dropRate := float64(a.EventsDropped) / float64(a.EventsCollected)
		switch {
		case dropRate > 0.20:
			dropScore = 0.0 // Severe: potential blinding attack
		case dropRate > 0.05:
			// Linear degradation from 100→0 between 5% and 20%
			dropScore = (0.20 - dropRate) / 0.15 * 100
		}
	}

	// Factor 4: Resource Pressure (10% weight)
	// High CPU/memory indicates resource exhaustion or DoS
	resourceScore := 100.0
	if a.CPUUsage > 90.0 {
		resourceScore -= 50.0
	} else if a.CPUUsage > 70.0 {
		resourceScore -= (a.CPUUsage - 70.0) / 20.0 * 30.0
	}
	if a.MemoryMB > 0 && a.MemoryUsedMB > 0 {
		memUsagePercent := float64(a.MemoryUsedMB) / float64(a.MemoryMB) * 100
		if memUsagePercent > 95.0 {
			resourceScore -= 50.0
		} else if memUsagePercent > 80.0 {
			resourceScore -= (memUsagePercent - 80.0) / 15.0 * 30.0
		}
	}
	if resourceScore < 0 {
		resourceScore = 0
	}

	// Combined score with unified weights
	a.HealthScore = (deliveryRatio * 0.40) + (statusScore * 0.30) + (dropScore * 0.20) + (resourceScore * 0.10)
	return a.HealthScore
}
