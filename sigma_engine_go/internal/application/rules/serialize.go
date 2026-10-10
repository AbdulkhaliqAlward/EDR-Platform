package rules

import (
	"fmt"
	"strings"

	"github.com/edr-platform/sigma-engine/internal/domain"
	"gopkg.in/yaml.v3"
)

// MarshalSigmaRule writes Sigma YAML rather than the detector's internal AST.
// Both new seeds and legacy decoding use this to pass through the same parser.
func MarshalSigmaRule(rule *domain.SigmaRule) ([]byte, error) {
	if rule == nil {
		return nil, fmt.Errorf("missing rule")
	}
	detection := map[string]interface{}{"condition": rule.Detection.Condition}
	if rule.Detection.Timeframe != nil {
		detection["timeframe"] = *rule.Detection.Timeframe
	}
	for name, selection := range rule.Detection.Selections {
		if name == "condition" || name == "timeframe" {
			return nil, fmt.Errorf("reserved selection name %q", name)
		}
		value, err := sigmaSelection(selection)
		if err != nil {
			return nil, fmt.Errorf("selection %s: %w", name, err)
		}
		detection[name] = value
	}
	return yaml.Marshal(yamlRule{
		ID: rule.ID, Title: rule.Title, Status: rule.Status, Description: rule.Description,
		LogSource: yamlLogSource{Product: rule.LogSource.Product, Category: rule.LogSource.Category, Service: rule.LogSource.Service},
		Detection: detection, Level: rule.Level, Tags: rule.Tags, FalsePositives: rule.FalsePositives,
		Author: rule.Author, Date: rule.Date, Modified: rule.Modified, References: rule.References,
	})
}

func sigmaSelection(selection *domain.Selection) (interface{}, error) {
	if selection == nil || selection.IsEmpty() {
		return nil, fmt.Errorf("empty selection")
	}
	if len(selection.Alternatives) > 0 {
		if len(selection.Fields) > 0 || len(selection.Keywords) > 0 {
			return nil, fmt.Errorf("mixed alternatives and fields")
		}
		values := make([]interface{}, 0, len(selection.Alternatives))
		for i := range selection.Alternatives {
			value, err := sigmaSelection(&selection.Alternatives[i])
			if err != nil {
				return nil, err
			}
			if _, ok := value.(map[string]interface{}); !ok {
				return nil, fmt.Errorf("alternative must contain fields")
			}
			values = append(values, value)
		}
		return values, nil
	}
	if selection.IsKeywordSelection {
		if len(selection.Fields) > 0 || len(selection.Keywords) == 0 {
			return nil, fmt.Errorf("invalid keyword selection")
		}
		return selection.Keywords, nil
	}
	if len(selection.Keywords) > 0 {
		return nil, fmt.Errorf("unexpected keywords")
	}
	fields := make(map[string]interface{}, len(selection.Fields))
	for _, field := range selection.Fields {
		// Empty field names are used by Sigma keyword modifiers (e.g. |all).
		if field.IsNegated || len(field.Values) == 0 {
			return nil, fmt.Errorf("invalid or unsupported field")
		}
		key := strings.Join(append([]string{field.FieldName}, field.Modifiers...), "|")
		if _, exists := fields[key]; exists {
			return nil, fmt.Errorf("duplicate field %s", key)
		}
		fields[key] = field.Values
	}
	return fields, nil
}
