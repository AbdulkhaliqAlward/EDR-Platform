package response

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/commandtypes"
	"github.com/edr-platform/connection-manager/pkg/models"
	edrv1 "github.com/edr-platform/connection-manager/proto/v1"
)

// Errors returned by Prepare / Start.
var (
	ErrPlaybookNotFound = errors.New("playbook not found")
	ErrPlaybookDisabled = errors.New("playbook is disabled")
	ErrAlertNotFound    = errors.New("alert not found")
	ErrNoTarget         = errors.New("no target endpoint: the alert has no agent and none was given")
	ErrAgentMismatch    = errors.New("the requested endpoint is not the alert's endpoint")
	ErrAgentUnavailable = errors.New("the endpoint cannot receive commands (unknown, deleted or uninstalled)")
	ErrAgentOffline     = errors.New("the endpoint is offline")
	ErrNotReady         = errors.New("the playbook cannot run: some steps have missing or invalid parameters")
)

// Dispatcher delivers commands to connected agents (implemented by the gRPC
// AgentRegistry).
type Dispatcher interface {
	Send(agentID string, cmd *edrv1.Command) error
	IsOnline(agentID string) bool
}

// AgentStore looks up agents.
type AgentStore interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Agent, error)
}

// Store is the engine's persistence (implemented by
// repository.ResponseEngineRepository).
type Store interface {
	GetSigmaAlert(ctx context.Context, id uuid.UUID) (*repository.SigmaAlertRecord, error)
	ListUnclaimedSigmaAlerts(ctx context.Context, since time.Time, settle time.Duration, limit int) ([]uuid.UUID, error)
	ClaimSigmaAlert(ctx context.Context, id uuid.UUID) (bool, error)
	CompleteInbox(ctx context.Context, id uuid.UUID, outcome string) error
	CleanupInbox(ctx context.Context, olderThan time.Duration) (int64, error)
	GetOrInitState(ctx context.Context, key, def string) (string, error)
	ReserveRule(ctx context.Context, ruleID, agentID uuid.UUID, cooldownMinutes int) (bool, error)
	RefreshRuleSuccessRate(ctx context.Context, ruleID uuid.UUID) error
	CreateExecution(ctx context.Context, e *repository.ExecutionRecord) error
	UpdateExecution(ctx context.Context, e *repository.ExecutionRecord) error
	FailOrphanedExecutions(ctx context.Context, olderThan time.Duration) (int64, error)
}

// ScriptStore looks up response-library scripts.
type ScriptStore interface {
	GetByID(ctx context.Context, id uuid.UUID) (*repository.ResponseScript, error)
}

// Config tunes the engine.
type Config struct {
	// GRPCAddress is injected into isolation commands so the agent keeps its
	// connection to the server.
	GRPCAddress string
	// MaxConcurrentRuns bounds playbook runs executing at once.
	MaxConcurrentRuns int
	// AutoExecute lets enabled automation rules with auto_execute=true run
	// playbooks without a human. When false, alerts are still evaluated and
	// recorded but nothing runs automatically.
	AutoExecute bool
	// PollInterval is how often new Sigma alerts are picked up.
	PollInterval time.Duration
}

// Engine is the server-side response engine.
type Engine struct {
	cfg        Config
	logger     *logrus.Logger
	store      Store
	commands   repository.CommandRepository
	playbooks  repository.ResponsePlaybookRepository
	rules      repository.AutomationRuleRepository
	scripts    ScriptStore
	agents     AgentStore
	dispatcher Dispatcher

	sem     chan struct{}
	baseCtx context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	once    sync.Once

	commandPoll time.Duration // test hook
}

// New creates an engine. Call Start to begin automated triggering.
func New(cfg Config, logger *logrus.Logger, store Store,
	commands repository.CommandRepository, playbooks repository.ResponsePlaybookRepository,
	rules repository.AutomationRuleRepository, scripts ScriptStore, agents AgentStore, dispatcher Dispatcher) *Engine {
	if cfg.MaxConcurrentRuns <= 0 {
		cfg.MaxConcurrentRuns = 4
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 3 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{
		cfg: cfg, logger: logger, store: store, commands: commands, playbooks: playbooks,
		rules: rules, scripts: scripts, agents: agents, dispatcher: dispatcher,
		sem: make(chan struct{}, cfg.MaxConcurrentRuns), baseCtx: ctx, cancel: cancel,
		commandPoll: time.Second,
	}
}

// RunRequest asks the engine to run a playbook.
type RunRequest struct {
	PlaybookID uuid.UUID
	AlertID    *uuid.UUID
	AgentID    string // optional when AlertID is set
	RuleID     *uuid.UUID
	Trigger    string // "manual" | "automation"
	Username   string
	// Overrides replaces step parameters by step index (manual runs).
	Overrides map[int]map[string]string
}

// BoundStep is a playbook step with its parameters bound to the alert, plus
// its runtime state.
type BoundStep struct {
	Index       int               `json:"index"`
	Type        string            `json:"type"`
	Label       string            `json:"label"`
	Description string            `json:"description,omitempty"`
	Timeout     int               `json:"timeout"`
	OnFailure   string            `json:"on_failure"`
	Params      map[string]string `json:"params"`
	ScriptID    string            `json:"script_id,omitempty"`
	ScriptName  string            `json:"script_name,omitempty"`
	Errors      []string          `json:"errors,omitempty"`

	Status      string     `json:"status"` // pending | running | success | failed | skipped
	CommandID   string     `json:"command_id,omitempty"`
	Error       string     `json:"error,omitempty"`
	Output      string     `json:"output,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// Plan is a fully bound, validated playbook run (also the preview result).
type Plan struct {
	PlaybookID    string      `json:"playbook_id"`
	PlaybookName  string      `json:"playbook_name"`
	AlertID       string      `json:"alert_id,omitempty"`
	AgentID       string      `json:"agent_id"`
	AgentHostname string      `json:"agent_hostname,omitempty"`
	AgentOnline   bool        `json:"agent_online"`
	Steps         []BoundStep `json:"steps"`
	Variables     AlertVars   `json:"variables"`
	Warnings      []string    `json:"warnings,omitempty"`
	Ready         bool        `json:"ready"`
}

// NotReadyError carries the plan whose steps failed validation.
type NotReadyError struct{ Plan *Plan }

func (e *NotReadyError) Error() string { return ErrNotReady.Error() }
func (e *NotReadyError) Unwrap() error { return ErrNotReady }

const (
	defaultStepTimeout = 300
	maxStepTimeout     = 3600
	maxOutputChars     = 4000
	pidReuseWarnAge    = 15 * time.Minute
)

// Prepare loads the playbook, alert and target endpoint and binds every
// step's parameters. It never dispatches anything (used for previews).
func (e *Engine) Prepare(ctx context.Context, req RunRequest) (*Plan, error) {
	pb, err := e.playbooks.GetByID(ctx, req.PlaybookID)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, ErrPlaybookNotFound
	}
	if err != nil {
		return nil, err
	}
	if !pb.Enabled {
		return nil, ErrPlaybookDisabled
	}

	plan := &Plan{PlaybookID: pb.ID.String(), PlaybookName: pb.Name, Variables: AlertVars{}}
	var alert *repository.SigmaAlertRecord
	if req.AlertID != nil {
		alert, err = e.store.GetSigmaAlert(ctx, *req.AlertID)
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrAlertNotFound
		}
		if err != nil {
			return nil, err
		}
		plan.AlertID = alert.ID
		plan.Variables = BuildAlertVars(alert)
	}

	// Target endpoint: the alert's agent; an explicit agent must match it so
	// alert-derived values (PIDs, paths) are never applied to another host.
	target := NormalizeAgentID(req.AgentID)
	if alertAgent := plan.Variables["agent_id"]; alertAgent != "" {
		if target != "" && !strings.EqualFold(target, alertAgent) {
			return nil, ErrAgentMismatch
		}
		target = alertAgent
	}
	if target == "" {
		return nil, ErrNoTarget
	}
	agentID, err := uuid.Parse(target)
	if err != nil {
		return nil, ErrNoTarget
	}
	agent, err := e.agents.GetByID(ctx, agentID)
	if err != nil || agent == nil {
		return nil, ErrAgentUnavailable
	}
	switch agent.Status {
	case models.AgentStatusDeleted, models.AgentStatusUninstalled, models.AgentStatusPendingUninstall:
		return nil, ErrAgentUnavailable
	}
	plan.AgentID = agentID.String()
	plan.AgentHostname = agent.Hostname
	plan.AgentOnline = e.dispatcher.IsOnline(agentID.String())
	if !plan.AgentOnline {
		plan.Warnings = append(plan.Warnings, "the endpoint is currently offline")
	}

	var steps []models.PlaybookCommand
	if err := json.Unmarshal(pb.Commands, &steps); err != nil {
		return nil, fmt.Errorf("playbook steps are not valid JSON: %w", err)
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("playbook has no steps")
	}
	plan.Ready = true
	for i, cmd := range steps {
		bs := e.bindStep(ctx, i, cmd, plan.Variables, req.Overrides[i])
		if len(bs.Errors) > 0 {
			plan.Ready = false
		}
		if bs.Type == "terminate_process" && alert != nil && time.Since(alert.CreatedAt) > pidReuseWarnAge {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf(
				"step %d terminates PID %s from an alert raised %s ago; the process may have exited and the PID been reused",
				i+1, bs.Params["pid"], time.Since(alert.CreatedAt).Round(time.Minute)))
		}
		plan.Steps = append(plan.Steps, bs)
	}
	return plan, nil
}

// bindStep resolves and validates one step's parameters.
func (e *Engine) bindStep(ctx context.Context, idx int, cmd models.PlaybookCommand, vars AlertVars, overrides map[string]string) BoundStep {
	bs := BoundStep{
		Index:       idx,
		Type:        CanonicalType(cmd.Type),
		Description: cmd.Description,
		Timeout:     cmd.Timeout,
		OnFailure:   "stop",
		Params:      map[string]string{},
		Status:      "pending",
	}
	if strings.EqualFold(strings.TrimSpace(cmd.OnFailure), "continue") {
		bs.OnFailure = "continue"
	}
	if bs.Timeout <= 0 {
		bs.Timeout = defaultStepTimeout
	}
	if bs.Timeout > maxStepTimeout {
		bs.Timeout = maxStepTimeout
	}
	for k, v := range cmd.Parameters {
		if s := scalar(v); s != "" {
			bs.Params[k] = s
		}
	}
	fail := func(format string, a ...any) { bs.Errors = append(bs.Errors, fmt.Sprintf(format, a...)) }

	switch bs.Type {
	case "run_script":
		bs.Label = "Run library script"
		sid := strings.TrimSpace(cmd.ScriptID)
		if sid == "" {
			sid = bs.Params["script_id"]
		}
		id, err := uuid.Parse(sid)
		if err != nil {
			fail("no library script selected")
			return bs
		}
		bs.ScriptID = id.String()
		script, err := e.scripts.GetByID(ctx, id)
		if err != nil || script == nil {
			fail("library script %s not found", id)
			return bs
		}
		bs.ScriptName = script.Name
		if !script.Enabled {
			fail("library script %q is disabled", script.Name)
		}
		if err := commandtypes.ValidateLibraryCommand(script.Cmd); err != nil {
			fail("library script %q is invalid: %v", script.Name, err)
		}
		bs.Params = map[string]string{"cmd": script.Cmd}
		return bs

	case "run_cmd":
		// Legacy free-text step (seeded / older playbooks). Never templated:
		// alert values are attacker-influenced and must not reach a command line.
		bs.Label = "Run command (legacy)"
		c := bs.Params["cmd"]
		bs.Params = map[string]string{"cmd": c}
		if hasTemplate(c) {
			fail("alert variables are not allowed in command lines")
		} else if err := commandtypes.ValidateLibraryCommand(c); err != nil {
			fail("command rejected: %v", err)
		}
		return bs
	}

	action, ok := ActionFor(bs.Type)
	if !ok || commandtypes.ToProto(bs.Type) == edrv1.CommandType_COMMAND_TYPE_UNSPECIFIED {
		fail("unsupported step type %q", cmd.Type)
		return bs
	}
	bs.Label = action.Label

	// Only the action's declared parameters reach the agent (stored and
	// override values alike); anything else is dropped.
	declared := make(map[string]bool, len(action.Params))
	for _, p := range action.Params {
		declared[p.Key] = true
	}
	for k := range bs.Params {
		if !declared[k] {
			delete(bs.Params, k)
		}
	}
	for k, v := range overrides {
		if declared[k] {
			bs.Params[k] = strings.TrimSpace(v)
		}
	}
	// Resolve templates in every parameter.
	for _, k := range sortedKeys(bs.Params) {
		val, missing := resolveTemplates(bs.Params[k], vars)
		if len(missing) > 0 {
			fail("%s: the alert has no value for %s", k, strings.Join(missing, ", "))
			delete(bs.Params, k)
			continue
		}
		bs.Params[k] = val
	}
	// Auto-fill and validate the action's declared parameters.
	for _, p := range action.Params {
		val := strings.TrimSpace(bs.Params[p.Key])
		if val == "" && p.AlertVar != "" {
			val = vars[p.AlertVar]
		}
		if val == "" {
			if p.Required {
				if p.Key == "pid" {
					fail("%s is required (the agent terminates by PID) and the alert has none", p.Label)
				} else {
					fail("%s is required and neither the playbook nor the alert provides it", p.Label)
				}
			}
			delete(bs.Params, p.Key)
			continue
		}
		if err := validateParam(p, val); err != nil {
			fail("%v", err)
			continue
		}
		bs.Params[p.Key] = val
	}
	return bs
}

// Start validates a run, records it and executes it asynchronously.
func (e *Engine) Start(ctx context.Context, req RunRequest) (*repository.ExecutionRecord, *Plan, error) {
	plan, err := e.Prepare(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	if !plan.Ready {
		return nil, plan, &NotReadyError{Plan: plan}
	}
	if !plan.AgentOnline {
		return nil, plan, ErrAgentOffline
	}
	rec, err := e.newExecution(ctx, req, plan, "running", "")
	if err != nil {
		return nil, plan, err
	}

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		select {
		case e.sem <- struct{}{}:
			defer func() { <-e.sem }()
		case <-e.baseCtx.Done():
			e.finish(rec, plan, "failed", "server shutting down before the playbook started")
			return
		}
		e.execute(rec, plan)
	}()
	return rec, plan, nil
}

func (e *Engine) newExecution(ctx context.Context, req RunRequest, plan *Plan, status, errMsg string) (*repository.ExecutionRecord, error) {
	agentID, _ := uuid.Parse(plan.AgentID)
	pbID, _ := uuid.Parse(plan.PlaybookID)
	trigger := req.Trigger
	if trigger == "" {
		trigger = "manual"
	}
	rec := &repository.ExecutionRecord{
		AlertID:           req.AlertID,
		PlaybookID:        pbID,
		PlaybookName:      plan.PlaybookName,
		RuleID:            req.RuleID,
		AgentID:           agentID,
		Status:            status,
		TriggerSource:     trigger,
		CreatedByUsername: req.Username,
		CommandsTotal:     len(plan.Steps),
		Steps:             marshalSteps(plan.Steps),
		ErrorMessage:      errMsg,
	}
	if err := e.store.CreateExecution(ctx, rec); err != nil {
		return nil, err
	}
	return rec, nil
}

func marshalSteps(steps []BoundStep) json.RawMessage {
	b, err := json.Marshal(steps)
	if err != nil {
		return json.RawMessage("[]")
	}
	return b
}

// execute runs the steps in order. Each step is dispatched only after the
// previous one reached a terminal state; on_failure=stop ends the run.
func (e *Engine) execute(rec *repository.ExecutionRecord, plan *Plan) {
	ctx := e.baseCtx
	log := e.logger.WithFields(logrus.Fields{"execution_id": rec.ID, "playbook": plan.PlaybookName, "agent_id": plan.AgentID})
	log.Info("[Response] Playbook run started")

	succeeded, failed := 0, 0
	stopped := false
	firstErr := ""
	for i := range plan.Steps {
		s := &plan.Steps[i]
		if stopped {
			s.Status = "skipped"
			continue
		}
		if ctx.Err() != nil {
			s.Status, s.Error = "failed", "server shutting down"
			failed++
			stopped = true
			continue
		}
		now := time.Now().UTC()
		s.Status, s.StartedAt = "running", &now
		e.persist(rec, plan)

		err := e.runStep(ctx, rec, plan, s)
		done := time.Now().UTC()
		s.CompletedAt = &done
		if err == nil {
			s.Status = "success"
			succeeded++
		} else {
			s.Status, s.Error = "failed", err.Error()
			failed++
			if firstErr == "" {
				firstErr = fmt.Sprintf("step %d (%s): %v", i+1, s.Type, err)
			}
			if s.OnFailure != "continue" {
				stopped = true
			}
		}
		rec.CommandsExecuted = succeeded + failed
		e.persist(rec, plan)
	}

	status := "completed"
	switch {
	case stopped:
		status = "failed"
	case failed > 0:
		status = "partial"
	}
	e.finish(rec, plan, status, firstErr)
	log.WithFields(logrus.Fields{"status": status, "succeeded": succeeded, "failed": failed}).Info("[Response] Playbook run finished")
}

// persist saves progress; it uses its own context so updates still land
// while the engine is shutting down.
func (e *Engine) persist(rec *repository.ExecutionRecord, plan *Plan) {
	rec.Steps = marshalSteps(plan.Steps)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.store.UpdateExecution(ctx, rec); err != nil {
		e.logger.WithError(err).WithField("execution_id", rec.ID).Warn("[Response] Failed to persist execution progress")
	}
}

func (e *Engine) finish(rec *repository.ExecutionRecord, plan *Plan, status, errMsg string) {
	now := time.Now().UTC()
	rec.Status = status
	rec.CompletedAt = &now
	rec.ErrorMessage = errMsg
	rec.ExecutionTimeMs = int(now.Sub(rec.StartedAt).Milliseconds())
	e.persist(rec, plan)
	if rec.RuleID != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := e.store.RefreshRuleSuccessRate(ctx, *rec.RuleID); err != nil {
			e.logger.WithError(err).Warn("[Response] Failed to refresh rule success rate")
		}
	}
}

// runStep dispatches one command and waits for its terminal status.
func (e *Engine) runStep(ctx context.Context, rec *repository.ExecutionRecord, plan *Plan, s *BoundStep) error {
	agentID := plan.AgentID
	if !e.dispatcher.IsOnline(agentID) {
		return ErrAgentOffline
	}

	cmdType := s.Type
	params := make(map[string]string, len(s.Params)+3)
	for k, v := range s.Params {
		params[k] = v
	}
	switch cmdType {
	case "run_script", "run_cmd":
		// Server-authored playbook command: library tier (curated allowlist;
		// powershell limited to -Command). The cmd was validated when bound.
		cmdType = "run_cmd"
		params = map[string]string{"cmd": s.Params["cmd"], "authz_tier": "library", "from_playbook": "true"}
	case "isolate_network", "unisolate_network":
		if e.cfg.GRPCAddress != "" {
			params["server_address"] = e.cfg.GRPCAddress
		}
	}
	protoType := commandtypes.ToProto(cmdType)
	if protoType == edrv1.CommandType_COMMAND_TYPE_UNSPECIFIED {
		return fmt.Errorf("unsupported command type %q", cmdType)
	}
	agentUUID, _ := uuid.Parse(agentID)

	issuer := rec.CreatedByUsername
	if issuer == "" {
		issuer = rec.TriggerSource
	}
	anyParams := make(map[string]any, len(params))
	for k, v := range params {
		anyParams[k] = v
	}
	cmdID := uuid.New()
	issued := time.Now()
	dbCmd := &models.Command{
		ID:             cmdID,
		AgentID:        agentUUID,
		CommandType:    models.CommandType(cmdType),
		Parameters:     anyParams,
		Priority:       5,
		Status:         models.CommandStatusPending,
		TimeoutSeconds: s.Timeout,
		IssuedAt:       issued,
		Metadata: map[string]any{
			"issued_by_username":    issuer,
			"playbook_execution_id": rec.ID.String(),
			"playbook_id":           plan.PlaybookID,
			"playbook_step":         s.Index,
			"trigger":               rec.TriggerSource,
		},
	}
	if err := e.commands.Create(ctx, dbCmd); err != nil {
		return fmt.Errorf("could not record command: %w", err)
	}
	s.CommandID = cmdID.String()

	if err := e.dispatcher.Send(agentID, &edrv1.Command{
		CommandId:  cmdID.String(),
		Timestamp:  timestamppb.New(issued),
		Type:       protoType,
		Parameters: params,
		Priority:   5,
		ExpiresAt:  timestamppb.New(dbCmd.ExpiresAt),
	}); err != nil {
		_ = e.commands.UpdateStatus(context.Background(), cmdID, models.CommandStatusFailed, nil, err.Error())
		return fmt.Errorf("could not deliver command: %w", err)
	}
	_ = e.commands.UpdateStatus(ctx, cmdID, models.CommandStatusSent, nil, "")
	return e.awaitResult(ctx, cmdID, s)
}

// awaitResult polls the command until the agent reports a terminal status
// (written by the gRPC SendCommandResult handler) or the step times out.
func (e *Engine) awaitResult(ctx context.Context, cmdID uuid.UUID, s *BoundStep) error {
	deadline := time.Now().Add(time.Duration(s.Timeout)*time.Second + 30*time.Second)
	ticker := time.NewTicker(e.commandPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("interrupted: %w", ctx.Err())
		case <-ticker.C:
		}
		cmd, err := e.commands.GetByID(ctx, cmdID)
		if err == nil && cmd != nil {
			if out := commandOutput(cmd.Result); out != "" {
				s.Output = out
			}
			switch cmd.Status {
			case models.CommandStatusCompleted:
				return nil
			case models.CommandStatusFailed, models.CommandStatusTimeout, models.CommandStatusCancelled:
				msg := strings.TrimSpace(cmd.ErrorMessage)
				if msg == "" {
					msg = "agent reported " + string(cmd.Status)
				}
				return errors.New(msg)
			}
		}
		if time.Now().After(deadline) {
			_ = e.commands.UpdateStatus(context.Background(), cmdID, models.CommandStatusTimeout, nil,
				fmt.Sprintf("no result from the agent within %ds", s.Timeout+30))
			return fmt.Errorf("timed out after %ds waiting for the agent", s.Timeout+30)
		}
	}
}

func commandOutput(result map[string]any) string {
	if result == nil {
		return ""
	}
	var out string
	if s, ok := result["output"].(string); ok {
		out = s
	} else if b, err := json.Marshal(result); err == nil {
		out = string(b)
	}
	if len(out) > maxOutputChars {
		out = out[:maxOutputChars] + "… [truncated]"
	}
	return out
}

// Stop cancels running work and waits (bounded) for runs to record their state.
func (e *Engine) Stop(timeout time.Duration) {
	e.once.Do(func() {
		e.cancel()
		done := make(chan struct{})
		go func() { e.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(timeout):
			e.logger.Warn("[Response] Shutdown timeout: some playbook runs did not finish recording")
		}
	})
}
