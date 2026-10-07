package domain

import (
	"fmt"
	"regexp"
	"strings"
)

// LogSource defines which events a Sigma rule applies to based on product, category, and service.
type LogSource struct {
	Product  *string `yaml:"product,omitempty" json:"product,omitempty"`
	Category *string `yaml:"category,omitempty" json:"category,omitempty"`
	Service  *string `yaml:"service,omitempty" json:"service,omitempty"`
}

// Matches checks if the logsource matches an event's characteristics.
// None values in logsource act as wildcards.
func (ls *LogSource) Matches(eventProduct, eventCategory, eventService string) bool {
	if ls.Product != nil && !strings.EqualFold(*ls.Product, eventProduct) {
		return false
	}
	if ls.Category != nil && !strings.EqualFold(*ls.Category, eventCategory) {
		return false
	}
	if ls.Service != nil && !strings.EqualFold(*ls.Service, eventService) {
		return false
	}
	return true
}

// IndexKey generates a colon-separated key for rule lookup: "product:category:service".
func (ls *LogSource) IndexKey() string {
	product := "*"
	if ls.Product != nil {
		product = *ls.Product
	}
	category := "*"
	if ls.Category != nil {
		category = *ls.Category
	}
	service := "*"
	if ls.Service != nil {
		service = *ls.Service
	}
	return strings.Join([]string{product, category, service}, ":")
}

// SelectionField represents a single field condition within a selection with modifiers.
type SelectionField struct {
	FieldName string        `yaml:"field_name" json:"field_name"`
	Values    []interface{} `yaml:"values" json:"values"`
	Modifiers []string      `yaml:"modifiers,omitempty" json:"modifiers,omitempty"`
	IsNegated bool          `yaml:"is_negated,omitempty" json:"is_negated,omitempty"`

	// CompiledRegex contains pre-compiled regex patterns for performance.
	// Only populated when field has "regex" or "re" modifier.
	// Note: This field is not serialized in cache (regexp.Regexp doesn't support gob).
	CompiledRegex []*regexp.Regexp `yaml:"-" json:"-"`
}

// HasModifier checks if the field has a specific modifier.
func (sf *SelectionField) HasModifier(modifier string) bool {
	modLower := strings.ToLower(modifier)
	for _, m := range sf.Modifiers {
		if strings.EqualFold(m, modLower) {
			return true
		}
	}
	return false
}

// RequiresAllMatch returns true if all values must match (AND logic).
func (sf *SelectionField) RequiresAllMatch() bool {
	return sf.HasModifier("all")
}

// Selection represents a named group of field conditions combined with AND logic.
type Selection struct {
	Name               string           `yaml:"name" json:"name"`
	Fields             []SelectionField `yaml:"fields,omitempty" json:"fields,omitempty"`
	IsKeywordSelection bool             `yaml:"is_keyword_selection,omitempty" json:"is_keyword_selection,omitempty"`
	Keywords           []string         `yaml:"keywords,omitempty" json:"keywords,omitempty"`

	// Alternatives holds the Sigma "list of maps" form: the selection matches
	// when ANY alternative matches, and each alternative matches when ALL of
	// its fields match. When set, Fields and Keywords are empty.
	Alternatives []Selection `yaml:"alternatives,omitempty" json:"alternatives,omitempty"`
}

// IsEmpty checks if the selection has no conditions.
func (s *Selection) IsEmpty() bool {
	return len(s.Fields) == 0 && len(s.Keywords) == 0 && len(s.Alternatives) == 0
}

// Detection contains all selections and the condition expression that combines them.
type Detection struct {
	Selections map[string]*Selection `yaml:"selections,omitempty" json:"selections,omitempty"`
	Condition  string                `yaml:"condition" json:"condition"`
	Timeframe  *string               `yaml:"timeframe,omitempty" json:"timeframe,omitempty"`
}

// GetSelectionNames returns all selection names.
func (d *Detection) GetSelectionNames() []string {
	names := make([]string, 0, len(d.Selections))
	for name := range d.Selections {
		names = append(names, name)
	}
	return names
}

// GetSelection returns a selection by name.
func (d *Detection) GetSelection(name string) *Selection {
	return d.Selections[name]
}

// HasFilter checks if detection has a filter (negation) selection.
func (d *Detection) HasFilter() bool {
	for name := range d.Selections {
		if strings.HasPrefix(name, "filter") {
			return true
		}
	}
	return false
}

// SigmaRule represents a complete Sigma detection rule with all components pre-parsed.
type SigmaRule struct {
	ID             string    `yaml:"id,omitempty" json:"id,omitempty"`
	Title          string    `yaml:"title" json:"title"`
	Status         string    `yaml:"status,omitempty" json:"status,omitempty"`
	Description    string    `yaml:"description,omitempty" json:"description,omitempty"`
	LogSource      LogSource `yaml:"logsource,omitempty" json:"logsource,omitempty"`
	Detection      Detection `yaml:"detection" json:"detection"`
	Level          string    `yaml:"level,omitempty" json:"level,omitempty"`
	Tags           []string  `yaml:"tags,omitempty" json:"tags,omitempty"`
	FalsePositives []string  `yaml:"falsepositives,omitempty" json:"falsepositives,omitempty"`
	Author         string    `yaml:"author,omitempty" json:"author,omitempty"`
	Date           string    `yaml:"date,omitempty" json:"date,omitempty"`
	Modified       string    `yaml:"modified,omitempty" json:"modified,omitempty"`
	References     []string  `yaml:"references,omitempty" json:"references,omitempty"`

	severity        *Severity
	mitreTechniques []string
	indexKey        *string
}

// Severity returns the severity as an enum, computing it if necessary.
func (r *SigmaRule) Severity() Severity {
	if r.severity == nil {
		sev := SeverityFromStringSafe(r.Level)
		r.severity = &sev
	}
	return *r.severity
}

// MITRETechniques extracts MITRE ATT&CK technique IDs from tags.
func (r *SigmaRule) MITRETechniques() []string {
	if r.mitreTechniques != nil {
		return r.mitreTechniques
	}

	r.mitreTechniques = make([]string, 0)
	for _, tag := range r.Tags {
		tagLower := strings.ToLower(tag)
		if strings.HasPrefix(tagLower, "attack.t") {
			parts := strings.SplitN(tag, ".", 2)
			if len(parts) == 2 {
				r.mitreTechniques = append(r.mitreTechniques, strings.ToUpper(parts[1]))
			}
		}
	}
	return r.mitreTechniques
}

// IndexKey returns the logsource index key for rule lookup.
func (r *SigmaRule) IndexKey() string {
	if r.indexKey == nil {
		key := r.LogSource.IndexKey()
		r.indexKey = &key
	}
	return *r.indexKey
}

// MatchesLogSource checks if the rule's logsource matches given parameters.
func (r *SigmaRule) MatchesLogSource(product, category, service string) bool {
	return r.LogSource.Matches(product, category, service)
}

// GetSelectionNames returns all selection names in detection.
func (r *SigmaRule) GetSelectionNames() []string {
	return r.Detection.GetSelectionNames()
}

// GetSelection returns a selection by name.
func (r *SigmaRule) GetSelection(name string) *Selection {
	return r.Detection.GetSelection(name)
}

// Validate checks if the rule has all required fields and valid structure.
func (r *SigmaRule) Validate() error {
	if r.Title == "" {
		return fmt.Errorf("rule title is required")
	}

	if r.Detection.Condition == "" {
		return fmt.Errorf("detection.condition is required")
	}

	if len(r.Detection.Selections) == 0 {
		return fmt.Errorf("detection must have at least one selection")
	}

	// Validate logsource
	if err := r.LogSource.Validate(); err != nil {
		return fmt.Errorf("invalid logsource: %w", err)
	}

	// Validate detection
	if err := r.Detection.Validate(); err != nil {
		return fmt.Errorf("invalid detection: %w", err)
	}

	// Validate level
	validLevels := map[string]bool{
		"informational": true,
		"low":           true,
		"medium":        true,
		"high":          true,
		"critical":      true,
	}
	if !validLevels[strings.ToLower(r.Level)] {
		return fmt.Errorf("invalid level: %s", r.Level)
	}

	return nil
}

// Validate validates the logsource structure.
func (ls *LogSource) Validate() error {
	// At least one field should be specified
	if ls.Product == nil && ls.Category == nil && ls.Service == nil {
		return fmt.Errorf("logsource must specify at least one of: product, category, service")
	}

	// Validate product if specified
	if ls.Product != nil {
		validProducts := map[string]bool{
			"windows": true,
			"linux":   true,
			"macos":   true,
			"freebsd": true,
			"aix":     true,
		}
		if !validProducts[strings.ToLower(*ls.Product)] {
			return fmt.Errorf("invalid product: %s", *ls.Product)
		}
	}

	return nil
}

// Validate validates the detection structure.
func (d *Detection) Validate() error {
	if d.Condition == "" {
		return fmt.Errorf("condition is required")
	}

	if len(d.Selections) == 0 {
		return fmt.Errorf("at least one selection is required")
	}

	// Selection references are validated by the real condition parser when
	// the detection engine compiles the rule. The former word-splitting check
	// lowercased identifiers and treated the count in "1 of selection_*" as a
	// selection name, wrongly rejecting ~28% of SigmaHQ Windows rules.
	return d.ValidateCondition()
}

// ValidateCondition validates the condition syntax.
func (d *Detection) ValidateCondition() error {
	// Basic syntax validation
	condition := strings.TrimSpace(d.Condition)
	if condition == "" {
		return fmt.Errorf("condition cannot be empty")
	}

	// Check balanced parentheses
	parenCount := 0
	for _, ch := range condition {
		if ch == '(' {
			parenCount++
		} else if ch == ')' {
			parenCount--
			if parenCount < 0 {
				return fmt.Errorf("unbalanced parentheses in condition")
			}
		}
	}
	if parenCount != 0 {
		return fmt.Errorf("unbalanced parentheses in condition")
	}

	return nil
}

// IsEnabled checks if the rule is enabled (not deprecated or unsupported).
func (r *SigmaRule) IsEnabled() bool {
	status := strings.ToLower(r.Status)
	return status != "deprecated" && status != "unsupported"
}

// String returns a human-readable string representation of the rule.
func (r *SigmaRule) String() string {
	return fmt.Sprintf("SigmaRule{id=%s, title=%q, level=%s, status=%s}",
		r.ID, r.Title, r.Level, r.Status)
}

// GetID returns the rule ID.
// Implements ports.Rule interface.
func (r *SigmaRule) GetID() string {
	return r.ID
}

// GetTitle returns the rule title.
// Implements ports.Rule interface.
func (r *SigmaRule) GetTitle() string {
	return r.Title
}

// GetLevel returns the rule severity level.
// Implements ports.Rule interface.
func (r *SigmaRule) GetLevel() string {
	return r.Level
}

// GetTags returns the rule tags.
// Implements ports.Rule interface.
func (r *SigmaRule) GetTags() []string {
	return r.Tags
}
