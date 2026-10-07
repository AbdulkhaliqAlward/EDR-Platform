package detection

import (
	"fmt"
	"sort"

	"github.com/edr-platform/sigma-engine/internal/application/rules"
	"github.com/edr-platform/sigma-engine/internal/domain"
)

// compiledRule is a rule prepared for fast, allocation-light evaluation:
// every selection is compiled and the condition is parsed exactly once at
// load time (previously the condition was re-parsed on every evaluation).
type compiledRule struct {
	rule       *domain.SigmaRule
	condition  rules.Node
	selections map[string]*compiledSelection
	names      []string // selection names, sorted for deterministic output

	// implicitFilters are filter* selections the condition never references.
	// The condition is authoritative for every referenced selection; these
	// are applied as suppression only when QualityConfig.EnableFilters is on.
	implicitFilters []string

	needsParent bool // rule tests ParentImage / ParentCommandLine
	needsCmd    bool // rule tests CommandLine
	needsUser   bool // rule tests User
}

// compileRule validates and compiles a rule. Any unsupported construct
// (unknown modifier, invalid regex, unknown selection reference …) is an
// error so the rule is rejected visibly instead of silently mis-matching.
func compileRule(rule *domain.SigmaRule) (*compiledRule, error) {
	if rule == nil {
		return nil, fmt.Errorf("nil rule")
	}
	if len(rule.Detection.Selections) == 0 {
		return nil, fmt.Errorf("rule has no selections")
	}

	cr := &compiledRule{
		rule:       rule,
		selections: make(map[string]*compiledSelection, len(rule.Detection.Selections)),
	}
	for name, sel := range rule.Detection.Selections {
		cs, err := compileSelection(sel)
		if err != nil {
			return nil, fmt.Errorf("selection %s: %w", name, err)
		}
		cs.name = name
		cr.selections[name] = cs
		cr.names = append(cr.names, name)
	}
	sort.Strings(cr.names)

	cond, err := rules.NewConditionParser().Parse(rule.Detection.Condition, cr.names)
	if err != nil {
		return nil, err
	}
	cr.condition = cond

	referenced := make(map[string]bool)
	collectReferences(cond, referenced)
	for _, name := range cr.names {
		if isFilterSelection(name) && !referenced[name] {
			cr.implicitFilters = append(cr.implicitFilters, name)
		}
	}

	for _, cs := range cr.selections {
		if isFilterSelection(cs.name) {
			continue
		}
		cr.needsParent = cr.needsParent || cs.referencesField("ParentImage") || cs.referencesField("ParentCommandLine")
		cr.needsCmd = cr.needsCmd || cs.referencesField("CommandLine")
		cr.needsUser = cr.needsUser || cs.referencesField("User")
	}
	return cr, nil
}

// collectReferences records every selection name a condition AST uses.
func collectReferences(n rules.Node, out map[string]bool) {
	switch t := n.(type) {
	case *rules.SelectionNode:
		out[t.Name] = true
	case *rules.PatternNode:
		for _, name := range t.Names {
			out[name] = true
		}
	case *rules.AndNode:
		collectReferences(t.Left, out)
		collectReferences(t.Right, out)
	case *rules.OrNode:
		collectReferences(t.Left, out)
		collectReferences(t.Right, out)
	case *rules.NotNode:
		collectReferences(t.Child, out)
	}
}

// ruleOutcome is the result of evaluating one compiled rule against an event.
type ruleOutcome struct {
	matchedSelections []string
	matchedFields     map[string]interface{}
	selectionResults  map[string]bool
}

// evaluate runs the compiled rule. It returns nil when the condition is not
// satisfied or an unreferenced filter suppresses the match.
func (cr *compiledRule) evaluate(ec *eventContext, applyImplicitFilters bool) *ruleOutcome {
	results := make(map[string]bool, len(cr.names))
	fieldsBySel := make(map[string][]string, len(cr.names))
	for _, name := range cr.names {
		ok, fields := cr.selections[name].evaluate(ec)
		results[name] = ok
		if ok {
			fieldsBySel[name] = fields
		}
	}

	if !cr.condition.Evaluate(results) {
		return nil
	}
	if applyImplicitFilters {
		for _, name := range cr.implicitFilters {
			if results[name] {
				return nil
			}
		}
	}

	out := &ruleOutcome{
		matchedFields:    make(map[string]interface{}),
		selectionResults: results,
	}
	for _, name := range cr.names {
		if !results[name] {
			continue
		}
		out.matchedSelections = append(out.matchedSelections, name)
		// Filters never contribute evidence, even when they matched.
		if isFilterSelection(name) {
			continue
		}
		for _, field := range fieldsBySel[name] {
			if rf := ec.resolve(field); rf.present {
				out.matchedFields[field] = rf.value
			}
		}
	}
	return out
}
