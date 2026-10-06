// Package playbook implements the post-isolation playbook engine.
// It automatically dispatches a series of forensic/triage commands to an
// agent whenever an isolation.succeeded event is emitted by the gRPC server.
package playbook

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/handlers"
	"github.com/edr-platform/connection-manager/pkg/models"
	edrv1 "github.com/edr-platform/connection-manager/proto/v1"
)

//go:embed playbooks/*.yaml
var embeddedPlaybooks embed.FS

// ─────────────────────────────────────────────────────────────────────────────
// YAML schema
// ─────────────────────────────────────────────────────────────────────────────

type playbookDef struct {
	Name           string    `yaml:"name"`
	Version        int       `yaml:"version"`
	Trigger        string    `yaml:"trigger"`
	Description    string    `yaml:"description"`
	TimeoutSeconds int       `yaml:"timeout_seconds"`
	Steps          []stepDef `yaml:"steps"`
}

type stepDef struct {
	ID             string            `yaml:"id"`
	Name           string            `yaml:"name"`
	CommandType    string            `yaml:"command_type"`
	Description    string            `yaml:"description"`
	TimeoutSeconds int               `yaml:"timeout_seconds"`
	Params         map[string]string `yaml:"params"`
	OnFailure      string            `yaml:"on_failure"` // "stop" | "continue"
}

// ─────────────────────────────────────────────────────────────────────────────
// Engine
// ─────────────────────────────────────────────────────────────────────────────

// Engine dispatches post-isolation playbooks.
type Engine struct {
	logger       *logrus.Logger
	incidentRepo repository.IncidentRepository
	commandRepo  repository.CommandRepository
	registry     *handlers.AgentRegistry
	playbooks    map[string]*playbookDef

	mu      sync.Mutex
	running map[string]bool // agentID → in-flight
}

// NewEngine creates and initialises a playbook Engine.
func NewEngine(
	logger *logrus.Logger,
	incidentRepo repository.IncidentRepository,
	commandRepo repository.CommandRepository,
	registry *handlers.AgentRegistry,
) *Engine {
	e := &Engine{
		logger:       logger,
		incidentRepo: incidentRepo,
		commandRepo:  commandRepo,
		registry:     registry,
		playbooks:    make(map[string]*playbookDef),
		running:      make(map[string]bool),
	}
	e.loadEmbeddedPlaybooks()
	return e
}

func (e *Engine) loadEmbeddedPlaybooks() {
	_ = fs.WalkDir(embeddedPlaybooks, "playbooks", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, readErr := embeddedPlaybooks.ReadFile(path)
		if readErr != nil {
			e.logger.WithError(readErr).Warnf("[Playbook] Read failed: %s", path)
			return nil
		}
		var pb playbookDef
		if yamlErr := yaml.Unmarshal(data, &pb); yamlErr != nil {
			e.logger.WithError(yamlErr).Warnf("[Playbook] Parse failed: %s", path)
			return nil
		}
		e.playbooks[pb.Name] = &pb
		e.logger.Infof("[Playbook] Loaded: %s (%d steps)", pb.Name, len(pb.Steps))
		return nil
	})
}

// OnIsolationSucceeded is called by the gRPC server after is_isolated=true is committed.
// It launches the default playbook asynchronously.
func (e *Engine) OnIsolationSucceeded(agentID uuid.UUID) {
	if e.incidentRepo == nil || e.commandRepo == nil || e.registry == nil {
		return
	}

	e.mu.Lock()
	if e.running[agentID.String()] {
		e.mu.Unlock()
		e.logger.WithField("agent_id", agentID).Info("[Playbook] Already running — skipping duplicate")
		return
	}
	e.running[agentID.String()] = true
	e.mu.Unlock()

	go func() {
		defer func() {
			e.mu.Lock()
			delete(e.running, agentID.String())
			e.mu.Unlock()
		}()
		e.runPlaybook(agentID, "default_post_isolation")
	}()
}

func (e *Engine) runPlaybook(agentID uuid.UUID, playbookName string) {
	pb, ok := e.playbooks[playbookName]
	if !ok {
		e.logger.Warnf("[Playbook] Unknown playbook: %s", playbookName)
		return
	}

	totalTimeout := 300 * time.Second
	if pb.TimeoutSeconds > 0 {
		totalTimeout = time.Duration(pb.TimeoutSeconds) * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()

	run := &repository.PlaybookRun{
		AgentID:   agentID,
		Playbook:  playbookName,
		Trigger:   pb.Trigger,
		Status:    "running",
		StartedAt: time.Now(),
	}
	runID, err := e.incidentRepo.CreateRun(ctx, run)
	if err != nil {
		e.logger.WithError(err).Error("[Playbook] Failed to create run record")
		return
	}

	e.logger.WithFields(logrus.Fields{
		"agent_id": agentID, "run_id": runID, "playbook": playbookName,
	}).Info("[Playbook] Started")

	successCount, failCount := 0, 0

	// cumulativeOffset tracks the sum of all preceding step timeouts.
	// Each command's ExpiresAt must account for the time the agent needs
	// to finish ALL prior steps before it even starts this one.
	// Without this, step N expires while steps 1..N-1 are still running
	// on the agent, causing spurious "command expired" failures.
	var cumulativeOffset time.Duration

	for _, step := range pb.Steps {
		select {
		case <-ctx.Done():
			e.logger.Warnf("[Playbook] Timeout at step %s", step.ID)
			goto done
		default:
		}

		func(s stepDef) {
			stepTimeout := time.Duration(s.TimeoutSeconds) * time.Second
			if stepTimeout <= 0 {
				stepTimeout = 60 * time.Second
			}

			stepRec := &repository.PlaybookStep{
				RunID:       runID,
				StepName:    s.Name,
				CommandType: s.CommandType,
				Status:      "pending",
			}
			stepID, err := e.incidentRepo.CreateStep(ctx, stepRec)
			if err != nil {
				e.logger.WithError(err).Warnf("[Playbook] Cannot create step %s", s.ID)
				return
			}

			if !e.registry.IsOnline(agentID.String()) {
				_ = e.incidentRepo.UpdateStep(ctx, stepID, "skipped", nil, "agent offline")
				return
			}
			_ = e.incidentRepo.UpdateStep(ctx, stepID, "running", nil, "")

			params := make(map[string]string)
			for k, v := range s.Params {
				params[k] = v
			}
			// Server-authored playbook step: grant the extended (library) tier.
			params["authz_tier"] = "library"
			params["from_playbook"] = "true" // legacy marker for older agents

			// Expiry = cumulative wait for prior steps + this step's own timeout + 60s grace.
			// The 60s grace covers network latency, gRPC queuing, and agent dispatch overhead.
			effectiveExpiry := cumulativeOffset + stepTimeout + 60*time.Second

			cmdID := uuid.New()
			dbCmd := &models.Command{
				ID:          cmdID,
				AgentID:     agentID,
				CommandType: models.CommandType(s.CommandType),
				Parameters: func() map[string]any {
					m := make(map[string]any)
					for k, v := range params {
						m[k] = v
					}
					return m
				}(),
				Priority:       5,
				Status:         models.CommandStatusSent,
				IssuedAt:       time.Now(),
				ExpiresAt:      time.Now().Add(effectiveExpiry),
				TimeoutSeconds: int(stepTimeout.Seconds()),
				Metadata: map[string]any{
					"playbook":  playbookName,
					"run_id":    runID,
					"step_id":   stepID,
					"step_name": s.Name,
				},
			}
			if createErr := e.commandRepo.Create(ctx, dbCmd); createErr != nil {
				e.logger.WithError(createErr).Warnf("[Playbook] Cannot persist command for step %s", s.ID)
				_ = e.incidentRepo.UpdateStep(ctx, stepID, "failed", nil, createErr.Error())
				failCount++
				return
			}

			_ = e.incidentRepo.UpdateStep(ctx, stepID, "running", &cmdID, "")

			protoCmd := &edrv1.Command{
				CommandId:  cmdID.String(),
				Timestamp:  timestamppb.Now(),
				Type:       protoCommandType(s.CommandType),
				Parameters: params,
				Priority:   5,
				ExpiresAt:  timestamppb.New(time.Now().Add(effectiveExpiry)),
			}

			if sendErr := e.registry.Send(agentID.String(), protoCmd); sendErr != nil {
				e.logger.WithError(sendErr).Warnf("[Playbook] Send failed for step %s", s.ID)
				_ = e.incidentRepo.UpdateStep(ctx, stepID, "failed", &cmdID, sendErr.Error())
				failCount++
				return
			}
			successCount++
			e.logger.Infof("[Playbook] Dispatched %s (cmd %s, expires_in=%v)", s.ID, cmdID, effectiveExpiry)

			// Advance cumulative offset so the next step's expiry accounts for this step.
			cumulativeOffset += stepTimeout

			time.Sleep(200 * time.Millisecond)
		}(step)
	}

done:
	finalStatus := "completed"
	if failCount > 0 && successCount == 0 {
		finalStatus = "failed"
	} else if failCount > 0 {
		finalStatus = "partial"
	}
	_ = e.incidentRepo.FinishRun(ctx, runID, finalStatus)
	e.logger.WithFields(logrus.Fields{
		"agent_id": agentID, "run_id": runID, "status": finalStatus,
		"success": successCount, "failed": failCount,
	}).Info("[Playbook] Finished")
}

// OnCommandResult updates the step status when a command result arrives from the agent.
// agentID is passed directly from the gRPC server (res.AgentId).
func (e *Engine) OnCommandResult(ctx context.Context, agentID uuid.UUID, commandID uuid.UUID, status, output string) {
	if e.incidentRepo == nil {
		return
	}

	step, err := e.incidentRepo.GetStepByCommandID(ctx, commandID)
	if err != nil {
		return // Not a playbook command
	}

	stepStatus := "success"
	errMsg := ""
	statusLower := strings.ToLower(status)
	if statusLower == "failed" || statusLower == "error" {
		stepStatus = "failed"
		errMsg = "agent reported failure"
	} else if statusLower == "timeout" {
		stepStatus = "failed"
		errMsg = "timeout"
	}

	_ = e.incidentRepo.UpdateStep(ctx, step.ID, stepStatus, &commandID, errMsg)

	// Persist triage snapshot on success
	if stepStatus == "success" && output != "" {
		trimmed := strings.TrimSpace(output)
		if strings.HasPrefix(trimmed, "{") {
			var payload map[string]any
			if json.Unmarshal([]byte(trimmed), &payload) == nil {
				runID := step.RunID
				snap := &repository.TriageSnapshot{
					AgentID: agentID,
					RunID:   &runID,
					Kind:    step.CommandType,
					Payload: payload,
				}
				if upsertErr := e.incidentRepo.UpsertSnapshot(ctx, snap); upsertErr != nil {
					e.logger.WithError(upsertErr).Warnf("[Playbook] Failed to persist snapshot for %s", step.CommandType)
				}
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// protoCommandType maps YAML command_type → proto enum.
// ─────────────────────────────────────────────────────────────────────────────

func protoCommandType(ct string) edrv1.CommandType {
	switch strings.ToLower(strings.TrimSpace(ct)) {
	case "post_isolation_triage":
		return edrv1.CommandType_COMMAND_TYPE_POST_ISOLATION_TRIAGE
	case "process_tree_snapshot":
		return edrv1.CommandType_COMMAND_TYPE_PROCESS_TREE_SNAPSHOT
	case "persistence_scan":
		return edrv1.CommandType_COMMAND_TYPE_PERSISTENCE_SCAN
	case "lsass_access_audit":
		return edrv1.CommandType_COMMAND_TYPE_LSASS_ACCESS_AUDIT
	case "filesystem_timeline":
		return edrv1.CommandType_COMMAND_TYPE_FILESYSTEM_TIMELINE
	case "network_last_seen":
		return edrv1.CommandType_COMMAND_TYPE_NETWORK_LAST_SEEN
	case "agent_integrity_check":
		return edrv1.CommandType_COMMAND_TYPE_AGENT_INTEGRITY_CHECK
	case "memory_dump":
		return edrv1.CommandType_COMMAND_TYPE_MEMORY_DUMP
	case "collect_forensics":
		return edrv1.CommandType_COMMAND_TYPE_COLLECT_FORENSICS
	default:
		return edrv1.CommandType_COMMAND_TYPE_UNSPECIFIED
	}
}
