package response

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// stateAutoResponse stores the operator switch for automated response.
const stateAutoResponse = "auto_response"

// AutomationSettings is the effective state of automated response.
type AutomationSettings struct {
	// Enabled is the effective state: automation rules may run playbooks.
	Enabled bool `json:"enabled"`
	// Configured is the operator's choice stored on the server.
	Configured bool `json:"configured"`
	// Locked is true when the server configuration
	// (AUTOMATION_AUTO_EXECUTE=false) forces automation off; the operator
	// switch cannot override it.
	Locked    bool       `json:"locked"`
	UpdatedBy string     `json:"updated_by,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

type storedAutoResponse struct {
	Enabled   bool   `json:"enabled"`
	UpdatedBy string `json:"updated_by,omitempty"`
}

// AutomationSettings returns the effective automated-response state.
// Without a stored choice automation is on (rules still need auto_execute).
func (e *Engine) AutomationSettings(ctx context.Context) (AutomationSettings, error) {
	out := AutomationSettings{Configured: true, Locked: !e.cfg.AutoExecute}
	v, at, found, err := e.store.GetState(ctx, stateAutoResponse)
	if err != nil {
		return AutomationSettings{Locked: out.Locked}, err
	}
	if found {
		var st storedAutoResponse
		if err := json.Unmarshal([]byte(v), &st); err != nil {
			return AutomationSettings{Locked: out.Locked}, fmt.Errorf("invalid automated response setting: %w", err)
		} else {
			out.Configured = st.Enabled
			out.UpdatedBy = st.UpdatedBy
			t := at.UTC()
			out.UpdatedAt = &t
		}
	}
	out.Enabled = out.Configured && !out.Locked
	return out, nil
}

// SetAutoResponse stores the operator switch. It takes effect on the next
// poll (seconds); runs already started are not interrupted.
func (e *Engine) SetAutoResponse(ctx context.Context, enabled bool, username string) (AutomationSettings, error) {
	b, _ := json.Marshal(storedAutoResponse{Enabled: enabled, UpdatedBy: strings.TrimSpace(username)})
	if err := e.store.SetState(ctx, stateAutoResponse, string(b)); err != nil {
		return AutomationSettings{}, err
	}
	e.logger.Warnf("[Response] Automated response %s by %s", map[bool]string{true: "ENABLED", false: "DISABLED"}[enabled], username)
	return e.AutomationSettings(ctx)
}

// autoResponseEnabled is the trigger's view; a read error fails closed.
func (e *Engine) autoResponseEnabled(ctx context.Context) bool {
	s, err := e.AutomationSettings(ctx)
	if err != nil {
		e.logger.WithError(err).Warn("[Response] Automation setting unavailable — treating automated response as disabled")
		return false
	}
	return s.Enabled
}
