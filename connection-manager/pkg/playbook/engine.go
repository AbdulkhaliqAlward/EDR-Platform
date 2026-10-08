// Package playbook implements the post-isolation playbook engine.
// It automatically dispatches a series of forensic/triage commands to an
// agent whenever an isolation.succeeded event is emitted by the gRPC server.
package playbook

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
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

	mu             sync.Mutex
	running        map[string]bool      // agentID → in-flight
	lastRun        map[string]time.Time // agentID → last post-isolation triage start
	automationGate func(context.Context) bool
	endpointGate   func(context.Context, string) (func(), error)
	commandPoll    time.Duration
}

// SetEndpointGate wires legacy runs into the response engine's endpoint queue.
// Set before the server accepts command results.
func (e *Engine) SetEndpointGate(gate func(context.Context, string) (func(), error)) {
	e.endpointGate = gate
}

// SetAutomationGate connects this legacy automated path to the same
// server-authoritative switch as alert-triggered playbooks. Wire before use.
func (e *Engine) SetAutomationGate(gate func(context.Context) bool) {
	e.automationGate = gate
}

func (e *Engine) automationEnabled() bool {
	if e.automationGate == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return e.automationGate(ctx)
}

// triageDedupWindow suppresses a second post-isolation triage for the same
// endpoint (e.g. a repeated isolate command while already isolated): the
// first run already captured the evidence.
const triageDedupWindow = 30 * time.Minute

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
		lastRun:      make(map[string]time.Time),
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
	if !e.automationEnabled() {
		return
	}
	if e.incidentRepo == nil || e.commandRepo == nil || e.registry == nil {
		return
	}

	e.mu.Lock()
	if e.running[agentID.String()] {
		e.mu.Unlock()
		e.logger.WithField("agent_id", agentID).Info("[Playbook] Already running — skipping duplicate")
		return
	}
	if last, ok := e.lastRun[agentID.String()]; ok && time.Since(last) < triageDedupWindow {
		e.mu.Unlock()
		e.logger.WithField("agent_id", agentID).Infof("[Playbook] Post-isolation triage ran %s ago — skipping duplicate", time.Since(last).Round(time.Second))
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

// OnIsolationRestored resets the triage de-duplication window so the next,
// separate isolation of the endpoint is triaged again.
func (e *Engine) OnIsolationRestored(agentID uuid.UUID) {
	e.mu.Lock()
	delete(e.lastRun, agentID.String())
	e.mu.Unlock()
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
	if e.endpointGate != nil {
		release, err := e.endpointGate(ctx, agentID.String())
		if err != nil {
			e.logger.WithError(err).Warn("[Playbook] Endpoint queue wait failed")
			return
		}
		defer release()
	}
	if !e.automationEnabled() {
		return
	}

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
	e.mu.Lock()
	e.lastRun[agentID.String()] = time.Now()
	e.mu.Unlock()

	e.logger.WithFields(logrus.Fields{
		"agent_id": agentID, "run_id": runID, "playbook": playbookName,
	}).Info("[Playbook] Started")

	successCount, failCount := 0, 0

	for _, step := range pb.Steps {
		if !e.automationEnabled() {
			_ = e.incidentRepo.FinishRun(ctx, runID, "cancelled")
			return
		}
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
				failCount++
				return
			}

			if !e.registry.IsOnline(agentID.String()) {
				_ = e.incidentRepo.UpdateStep(ctx, stepID, "skipped", nil, "agent offline")
				failCount++
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

			// Dispatch follows the preceding result, so no cumulative offset is needed.
			effectiveExpiry := stepTimeout + 30*time.Second

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
				_ = e.commandRepo.UpdateStatus(ctx, cmdID, models.CommandStatusFailed, nil, sendErr.Error())
				e.logger.WithError(sendErr).Warnf("[Playbook] Send failed for step %s", s.ID)
				_ = e.incidentRepo.UpdateStep(ctx, stepID, "failed", &cmdID, sendErr.Error())
				failCount++
				return
			}
			e.logger.Infof("[Playbook] Dispatched %s (cmd %s, expires_in=%v)", s.ID, cmdID, effectiveExpiry)
			if waitErr := e.awaitCommand(ctx, cmdID, effectiveExpiry); waitErr != nil {
				_ = e.incidentRepo.UpdateStep(ctx, stepID, "failed", &cmdID, waitErr.Error())
				failCount++
				return
			}
			_ = e.incidentRepo.UpdateStep(ctx, stepID, "success", &cmdID, "")
			successCount++
		}(step)
	}

done:
	finalStatus := "completed"
	if ctx.Err() != nil {
		finalStatus = "cancelled"
	} else if failCount > 0 && successCount == 0 {
		finalStatus = "failed"
	} else if failCount > 0 {
		finalStatus = "partial"
	}
	finishCtx, finishCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer finishCancel()
	_ = e.incidentRepo.FinishRun(finishCtx, runID, finalStatus)
	e.logger.WithFields(logrus.Fields{
		"agent_id": agentID, "run_id": runID, "status": finalStatus,
		"success": successCount, "failed": failCount,
	}).Info("[Playbook] Finished")
}

// A successful Send only means queued delivery. Run/step success requires an
// actual terminal result written by the authenticated gRPC result handler.
func (e *Engine) awaitCommand(ctx context.Context, id uuid.UUID, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	poll := e.commandPoll
	if poll <= 0 {
		poll = time.Second
	}
	tick := time.NewTicker(poll)
	defer tick.Stop()
	for {
		cmd, err := e.commandRepo.GetByID(ctx, id)
		if err == nil && cmd != nil {
			switch cmd.Status {
			case models.CommandStatusCompleted:
				return nil
			case models.CommandStatusFailed, models.CommandStatusTimeout, models.CommandStatusCancelled:
				return fmt.Errorf("agent command %s: %s", cmd.Status, cmd.ErrorMessage)
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("command result unverified: %w", ctx.Err())
		case <-tick.C:
		}
	}
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

	stepStatus, errMsg := "failed", ""
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed", "success", "ok", "succeeded", "done":
		stepStatus = "success"
	case "failed", "error":
		errMsg = "agent reported failure"
	case "timeout":
		errMsg = "timeout"
	case "cancelled", "canceled":
		errMsg = "cancelled"
	default:
		return // acknowledgements/unknown states do not prove success
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
