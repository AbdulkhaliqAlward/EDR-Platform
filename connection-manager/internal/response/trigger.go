package response

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/models"
)

const (
	stateAutomationStarted = "automation_started_at"
	// maxLookback bounds how far back unclaimed alerts are picked up after
	// an outage; older alerts are left for manual response.
	maxLookback = time.Hour
	// settleDelay lets in-flight alert inserts commit before they are read,
	// so an alert is never skipped by an out-of-order commit.
	settleDelay  = 2 * time.Second
	pollBatch    = 100
	inboxRetain  = 7 * 24 * time.Hour
	orphanMaxAge = 2 * time.Hour
)

// StartTrigger launches the automated trigger loop. It returns immediately.
func (e *Engine) StartTrigger() {
	if !e.admitWork() {
		return
	}
	go func() {
		defer e.wg.Done()
		e.triggerLoop()
	}()
}

func (e *Engine) triggerLoop() {
	ctx := e.baseCtx

	// Runs left "running" by a previous process can never complete.
	if n, err := e.store.FailOrphanedExecutions(ctx, orphanMaxAge); err != nil {
		e.logger.WithError(err).Warn("[Response] Could not close orphaned executions")
	} else if n > 0 {
		e.logger.Warnf("[Response] Marked %d interrupted playbook run(s) as failed", n)
	}

	// First-start marker: alerts created before the engine was first enabled
	// must never trigger automated actions retroactively.
	var since time.Time
	for {
		v, err := e.store.GetOrInitState(ctx, stateAutomationStarted, time.Now().UTC().Format(time.RFC3339Nano))
		if err == nil {
			if t, perr := time.Parse(time.RFC3339Nano, v); perr == nil {
				since = t
				break
			}
		}
		e.logger.WithError(err).Warn("[Response] Response engine state unavailable — retrying")
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
	e.logger.Infof("[Response] Automation trigger started (auto-execute=%v, enabled since %s)", e.cfg.AutoExecute, since.Format(time.RFC3339))

	ticker := time.NewTicker(e.cfg.PollInterval)
	defer ticker.Stop()
	housekeeping := time.NewTicker(time.Hour)
	defer housekeeping.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-housekeeping.C:
			if n, err := e.store.CleanupInbox(ctx, inboxRetain); err == nil && n > 0 {
				e.logger.Debugf("[Response] Pruned %d processed alert record(s)", n)
			}
		case <-ticker.C:
			e.pollOnce(ctx, since)
		}
	}
}

func (e *Engine) pollOnce(ctx context.Context, since time.Time) {
	from := since
	if floor := time.Now().Add(-maxLookback); floor.After(from) {
		from = floor
	}
	ids, err := e.store.ListUnclaimedSigmaAlerts(ctx, from, settleDelay, pollBatch)
	if err != nil {
		if ctx.Err() == nil {
			e.logger.WithError(err).Warn("[Response] Could not list new alerts")
		}
		return
	}
	if len(ids) == 0 {
		return
	}
	// Read the switch once per batch. While automation is off, new alerts are
	// still claimed (outcome recorded) so re-enabling it never replays
	// automated actions for alerts that arrived in the meantime.
	enabled := e.autoResponseEnabled(ctx)
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		claimed, err := e.store.ClaimSigmaAlert(ctx, id)
		if err != nil {
			e.logger.WithError(err).Warn("[Response] Could not claim alert")
			continue
		}
		if !claimed {
			continue // another replica took it
		}
		outcome := "automated response disabled"
		if enabled {
			outcome = e.processAlert(ctx, id)
		}
		if err := e.store.CompleteInbox(context.Background(), id, outcome); err != nil {
			e.logger.WithError(err).Warn("[Response] Could not record alert outcome")
		}
	}
}

// closedAlertStatuses are analyst verdicts after which nothing may run.
var closedAlertStatuses = map[string]bool{"false_positive": true, "resolved": true, "closed": true}

// processAlert evaluates automation rules for one new alert and starts the
// playbooks of matching auto-execute rules. It returns a short outcome.
func (e *Engine) processAlert(ctx context.Context, alertID uuid.UUID) string {
	alert, err := e.store.GetSigmaAlert(ctx, alertID)
	if err != nil {
		return "alert unavailable: " + err.Error()
	}
	if closedAlertStatuses[strings.ToLower(alert.Status)] {
		return "alert already closed by an analyst (" + alert.Status + ")"
	}
	rules, err := e.rules.List(ctx)
	if err != nil {
		return "rules unavailable: " + err.Error()
	}
	candidates := make([]*models.AutomationRule, 0, len(rules))
	for _, r := range rules {
		if r != nil && r.Enabled && r.AutoExecute {
			candidates = append(candidates, r)
		}
	}
	// Lower priority value runs first (1 = most important).
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].Priority < candidates[j].Priority })

	agentID, err := uuid.Parse(NormalizeAgentID(alert.AgentID))
	if err != nil {
		return "alert has no valid endpoint"
	}

	var outcomes []string
	for _, r := range candidates {
		cond, ok := ParseConditions(r.TriggerConditions)
		if !ok || !cond.Matches(alert) {
			continue
		}
		reserved, err := e.store.ReserveRule(ctx, r.ID, agentID, r.CooldownMinutes)
		if err != nil {
			outcomes = append(outcomes, fmt.Sprintf("rule %q: %v", r.Name, err))
			continue
		}
		if !reserved {
			outcomes = append(outcomes, fmt.Sprintf("rule %q: cooling down for this endpoint", r.Name))
			continue
		}
		ruleID, aID := r.ID, alertID
		guardCond := cond
		req := RunRequest{
			PlaybookID: r.PlaybookID,
			AlertID:    &aID,
			RuleID:     &ruleID,
			Trigger:    "automation",
			Username:   "automation: " + r.Name,
			// Automated containment only for high-fidelity triggers: a
			// destructive playbook needs a high/critical alert, or the
			// alert's rule listed explicitly in the automation rule.
			Guard: func(p *Plan) error {
				if !planIsDestructive(p) || (guardCond.ScopedForContainment() && guardCond.ContainmentAllowedFor(alert)) {
					return nil
				}
				return &GuardrailError{Reason: fmt.Sprintf(
					"automated containment requires a high or critical alert, or the detection rule listed in the automation rule "+
						"(alert severity: %s). Review the alert and run the playbook manually if appropriate", alert.Severity)}
			},
		}
		rec, plan, err := e.Start(ctx, req)
		var guard *GuardrailError
		switch {
		case err == nil:
			outcomes = append(outcomes, fmt.Sprintf("rule %q started execution %s", r.Name, rec.ID))
		case errors.Is(err, repository.ErrDuplicateExecution):
			outcomes = append(outcomes, fmt.Sprintf("rule %q: already executed for this alert", r.Name))
		case errors.As(err, &guard):
			outcomes = append(outcomes, fmt.Sprintf("rule %q: %v", r.Name, err))
			e.recordNotStarted(ctx, req, plan, "cancelled", err)
		default:
			outcomes = append(outcomes, fmt.Sprintf("rule %q: not started: %v", r.Name, err))
			e.recordNotStarted(ctx, req, plan, "failed", err)
		}
	}
	if len(outcomes) == 0 {
		return "no matching automation rule"
	}
	return strings.Join(outcomes, "; ")
}

func planIsDestructive(p *Plan) bool {
	for _, s := range p.Steps {
		if s.Destructive {
			return true
		}
	}
	return false
}

// recordNotStarted stores an automated run that could not (failed) or was
// not allowed to (cancelled) start, so the analyst sees it in the dashboard.
func (e *Engine) recordNotStarted(ctx context.Context, req RunRequest, plan *Plan, status string, cause error) {
	if plan == nil || plan.AgentID == "" {
		e.logger.WithError(cause).Warnf("[Response] Automated playbook %s not started", req.PlaybookID)
		return
	}
	msg := cause.Error()
	var nr *NotReadyError
	if errors.As(cause, &nr) {
		var details []string
		for _, s := range nr.Plan.Steps {
			for _, e := range s.Errors {
				details = append(details, fmt.Sprintf("step %d: %s", s.Index+1, e))
			}
		}
		if len(details) > 0 {
			msg += " — " + strings.Join(details, "; ")
		}
	}
	for i := range plan.Steps {
		plan.Steps[i].Status = "skipped"
	}
	rec, err := e.newExecution(ctx, req, plan, status, msg)
	if err != nil {
		e.logger.WithError(err).Warn("[Response] Could not record failed automated run")
		return
	}
	now := time.Now().UTC()
	rec.CompletedAt = &now
	e.persist(rec, plan)
}
