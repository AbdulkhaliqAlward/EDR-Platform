package response

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/edr-platform/connection-manager/pkg/commandtypes"
	"github.com/edr-platform/connection-manager/pkg/models"
)

// MaxPlaybookSteps bounds the number of steps in a playbook.
const MaxPlaybookSteps = 25

// ErrFreeTextCommandNotAllowed is returned when a non-admin saves a playbook
// containing a free-text run_cmd step.
var ErrFreeTextCommandNotAllowed = errors.New("free-text commands (run_cmd) in playbooks require an administrator; use a library script (run_script) instead")

// DefinitionIsDestructive reports whether stored playbook steps contain a
// containment action (or a script/command, which can change the host).
func DefinitionIsDestructive(raw []byte) bool {
	var steps []models.PlaybookCommand
	if json.Unmarshal(raw, &steps) != nil {
		return true // unknown content: treat as destructive (fail safe)
	}
	for _, s := range steps {
		t := CanonicalType(s.Type)
		if t == "run_script" || t == "run_cmd" {
			return true
		}
		if a, ok := ActionFor(t); ok && a.Destructive {
			return true
		}
	}
	return false
}

// ValidateDefinition checks playbook steps when a playbook is created or
// updated (alert binding is checked later, per run):
//   - every step is a catalog action, run_script or (admin only) run_cmd;
//   - run_script references an existing, enabled library script;
//   - run_cmd commands pass the library-command rules and contain no alert
//     templates (alert values must never reach a command line);
//   - timeouts and the failure policy are within bounds.
//
// It normalises steps in place (canonical type, defaults) and returns them.
func ValidateDefinition(ctx context.Context, steps []models.PlaybookCommand, scripts ScriptStore, allowFreeText bool) ([]models.PlaybookCommand, error) {
	if len(steps) == 0 {
		return nil, errors.New("at least one step is required")
	}
	if len(steps) > MaxPlaybookSteps {
		return nil, fmt.Errorf("a playbook may have at most %d steps", MaxPlaybookSteps)
	}
	out := make([]models.PlaybookCommand, len(steps))
	for i, s := range steps {
		n := i + 1
		s.Type = CanonicalType(s.Type)
		if s.Timeout <= 0 {
			s.Timeout = defaultStepTimeout
		}
		if s.Timeout > maxStepTimeout {
			return nil, fmt.Errorf("step %d: timeout must be at most %d seconds", n, maxStepTimeout)
		}
		switch strings.ToLower(strings.TrimSpace(s.OnFailure)) {
		case "", "stop":
			s.OnFailure = "stop"
		case "continue":
			s.OnFailure = "continue"
		default:
			return nil, fmt.Errorf("step %d: on_failure must be stop or continue", n)
		}
		if len(s.Description) > 500 {
			return nil, fmt.Errorf("step %d: description is too long", n)
		}

		switch s.Type {
		case "run_script":
			id, err := uuid.Parse(strings.TrimSpace(s.ScriptID))
			if err != nil {
				return nil, fmt.Errorf("step %d: select a library script", n)
			}
			if scripts == nil {
				return nil, fmt.Errorf("step %d: the script library is unavailable", n)
			}
			script, err := scripts.GetByID(ctx, id)
			if err != nil || script == nil {
				return nil, fmt.Errorf("step %d: library script not found", n)
			}
			if !script.Enabled {
				return nil, fmt.Errorf("step %d: library script %q is disabled", n, script.Name)
			}
			s.ScriptID = id.String()
			s.Parameters = nil // the command always comes from the library

		case "run_cmd":
			if !allowFreeText {
				return nil, ErrFreeTextCommandNotAllowed
			}
			cmd := strings.TrimSpace(scalar(s.Parameters["cmd"]))
			if hasTemplate(cmd) {
				return nil, fmt.Errorf("step %d: alert variables are not allowed in command lines", n)
			}
			if err := commandtypes.ValidateLibraryCommand(cmd); err != nil {
				return nil, fmt.Errorf("step %d: %v", n, err)
			}
			s.Parameters = map[string]interface{}{"cmd": cmd}

		default:
			action, ok := ActionFor(s.Type)
			if !ok {
				return nil, fmt.Errorf("step %d: unsupported action %q", n, s.Type)
			}
			// Static checks of literal values (templates are checked per run).
			for _, p := range action.Params {
				v := strings.TrimSpace(scalar(s.Parameters[p.Key]))
				if v == "" || hasTemplate(v) {
					continue
				}
				if err := validateParam(p, v); err != nil {
					return nil, fmt.Errorf("step %d: %v", n, err)
				}
			}
			for k, v := range s.Parameters {
				if str := scalar(v); commandtypes.HasControlChars(str) || len(str) > 1024 || len(k) > 64 {
					return nil, fmt.Errorf("step %d: parameter %q is invalid", n, k)
				}
			}
		}
		out[i] = s
	}
	return out, nil
}
