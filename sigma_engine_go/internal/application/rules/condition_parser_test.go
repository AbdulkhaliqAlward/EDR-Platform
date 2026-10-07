package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// CATEGORY 1: BASIC FUNCTIONALITY TESTS
// =============================================================================

func TestTokenizer_Basic(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []TokenType
	}{
		{
			name:     "Simple identifier",
			input:    "selection1",
			expected: []TokenType{TokenIdentifier, TokenEOF},
		},
		{
			name:     "AND keyword",
			input:    "sel1 and sel2",
			expected: []TokenType{TokenIdentifier, TokenAnd, TokenIdentifier, TokenEOF},
		},
		{
			name:     "OR keyword",
			input:    "sel1 or sel2",
			expected: []TokenType{TokenIdentifier, TokenOr, TokenIdentifier, TokenEOF},
		},
		{
			name:     "NOT keyword",
			input:    "not sel1",
			expected: []TokenType{TokenNot, TokenIdentifier, TokenEOF},
		},
		{
			name:     "Parentheses",
			input:    "(sel1)",
			expected: []TokenType{TokenLParen, TokenIdentifier, TokenRParen, TokenEOF},
		},
		{
			name:     "Number and of",
			input:    "1 of selection",
			expected: []TokenType{TokenNumber, TokenOf, TokenIdentifier, TokenEOF},
		},
		{
			name:     "All of them",
			input:    "all of them",
			expected: []TokenType{TokenAll, TokenOf, TokenThem, TokenEOF},
		},
		{
			name:     "Complex expression",
			input:    "(sel1 and sel2) or not sel3",
			expected: []TokenType{TokenLParen, TokenIdentifier, TokenAnd, TokenIdentifier, TokenRParen, TokenOr, TokenNot, TokenIdentifier, TokenEOF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenizer := NewTokenizer(tt.input)
			var tokens []TokenType
			for {
				tok := tokenizer.NextToken()
				tokens = append(tokens, tok.Type)
				if tok.Type == TokenEOF {
					break
				}
			}
			assert.Equal(t, tt.expected, tokens)
		})
	}
}

func TestConditionParser_SimpleSelection(t *testing.T) {
	parser := NewConditionParser()
	selectionNames := []string{"selection1"}
	ast, err := parser.Parse("selection1", selectionNames)
	require.NoError(t, err)
	require.NotNil(t, ast)

	selections := map[string]bool{
		"selection1": true,
	}
	assert.True(t, ast.Evaluate(selections))

	selections["selection1"] = false
	assert.False(t, ast.Evaluate(selections))
}

func TestConditionParser_UnknownSelection(t *testing.T) {
	parser := NewConditionParser()
	selectionNames := []string{"selection1"}
	ast, err := parser.Parse("selection1", selectionNames)
	require.NoError(t, err)

	// Empty selections map - unknown selection should return false
	selections := map[string]bool{}
	assert.False(t, ast.Evaluate(selections))
}

func TestConditionParser_EmptyCondition(t *testing.T) {
	parser := NewConditionParser()
	selectionNames := []string{}
	ast, err := parser.Parse("", selectionNames)

	// Sigma requires a condition. An empty one used to yield a node that
	// looked up a non-existent "true" selection (so it never matched); it is
	// now rejected at load time so the broken rule is visible.
	require.Error(t, err)
	require.Nil(t, ast)
}

func TestConditionParser_UnknownSelectionRejected(t *testing.T) {
	parser := NewConditionParser()
	_, err := parser.Parse("selection and not filter", []string{"selection"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown selection")
}

func TestConditionParser_PatternsResolvedAtParseTime(t *testing.T) {
	parser := NewConditionParser()
	names := []string{"selection_a", "selection_b", "filter_x", "_helper"}

	ast, err := parser.Parse("1 of selection_* and not 1 of filter_*", names)
	require.NoError(t, err)
	assert.True(t, ast.Evaluate(map[string]bool{"selection_b": true}))
	assert.False(t, ast.Evaluate(map[string]bool{"selection_b": true, "filter_x": true}))

	// "them" excludes identifiers starting with "_".
	ast, err = parser.Parse("all of them", names)
	require.NoError(t, err)
	assert.True(t, ast.Evaluate(map[string]bool{"selection_a": true, "selection_b": true, "filter_x": true}))
}

func TestNode_String(t *testing.T) {
	// Test SelectionNode
	sel := &SelectionNode{Name: "test"}
	assert.Equal(t, "test", sel.String())

	// Test AndNode
	andNode := &AndNode{
		Left:  &SelectionNode{Name: "a"},
		Right: &SelectionNode{Name: "b"},
	}
	assert.Contains(t, andNode.String(), "AND")

	// Test OrNode
	orNode := &OrNode{
		Left:  &SelectionNode{Name: "a"},
		Right: &SelectionNode{Name: "b"},
	}
	assert.Contains(t, orNode.String(), "OR")

	// Test NotNode
	notNode := &NotNode{
		Child: &SelectionNode{Name: "a"},
	}
	assert.Contains(t, notNode.String(), "NOT")
}

// =============================================================================
// CATEGORY 2: BOOLEAN LOGIC TESTS
// =============================================================================

func TestConditionParser_AndLogic(t *testing.T) {
	parser := NewConditionParser()
	selectionNames := []string{"sel1", "sel2"}
	ast, err := parser.Parse("sel1 and sel2", selectionNames)
	require.NoError(t, err)

	tests := []struct {
		name     string
		sel1     bool
		sel2     bool
		expected bool
	}{
		{"T AND T = T", true, true, true},
		{"T AND F = F", true, false, false},
		{"F AND T = F", false, true, false},
		{"F AND F = F", false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selections := map[string]bool{
				"sel1": tt.sel1,
				"sel2": tt.sel2,
			}
			assert.Equal(t, tt.expected, ast.Evaluate(selections))
		})
	}
}

func TestConditionParser_OrLogic(t *testing.T) {
	parser := NewConditionParser()
	selectionNames := []string{"sel1", "sel2"}
	ast, err := parser.Parse("sel1 or sel2", selectionNames)
	require.NoError(t, err)

	tests := []struct {
		name     string
		sel1     bool
		sel2     bool
		expected bool
	}{
		{"T OR T = T", true, true, true},
		{"T OR F = T", true, false, true},
		{"F OR T = T", false, true, true},
		{"F OR F = F", false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selections := map[string]bool{
				"sel1": tt.sel1,
				"sel2": tt.sel2,
			}
			assert.Equal(t, tt.expected, ast.Evaluate(selections))
		})
	}
}

func TestConditionParser_NotLogic(t *testing.T) {
	parser := NewConditionParser()
	selectionNames := []string{"sel1"}
	ast, err := parser.Parse("not sel1", selectionNames)
	require.NoError(t, err)

	tests := []struct {
		name     string
		sel1     bool
		expected bool
	}{
		{"NOT T = F", true, false},
		{"NOT F = T", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selections := map[string]bool{
				"sel1": tt.sel1,
			}
			assert.Equal(t, tt.expected, ast.Evaluate(selections))
		})
	}
}

func TestConditionParser_CombinedLogic(t *testing.T) {
	parser := NewConditionParser()

	tests := []struct {
		name           string
		condition      string
		selectionNames []string
		selections     map[string]bool
		expected       bool
	}{
		{
			name:           "sel1 and sel2 or sel3 - sel1+sel2 true",
			condition:      "sel1 and sel2 or sel3",
			selectionNames: []string{"sel1", "sel2", "sel3"},
			selections: map[string]bool{
				"sel1": true,
				"sel2": true,
				"sel3": false,
			},
			expected: true,
		},
		{
			name:           "sel1 and sel2 or sel3 - only sel3 true",
			condition:      "sel1 and sel2 or sel3",
			selectionNames: []string{"sel1", "sel2", "sel3"},
			selections: map[string]bool{
				"sel1": false,
				"sel2": false,
				"sel3": true,
			},
			expected: true,
		},
		{
			name:           "sel1 and not sel2",
			condition:      "sel1 and not sel2",
			selectionNames: []string{"sel1", "sel2"},
			selections: map[string]bool{
				"sel1": true,
				"sel2": false,
			},
			expected: true,
		},
		{
			name:           "sel1 and not sel2 - sel2 true should fail",
			condition:      "sel1 and not sel2",
			selectionNames: []string{"sel1", "sel2"},
			selections: map[string]bool{
				"sel1": true,
				"sel2": true,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.Parse(tt.condition, tt.selectionNames)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, ast.Evaluate(tt.selections))
		})
	}
}

// =============================================================================
// CATEGORY 3: ADVANCED FEATURES TESTS
// =============================================================================

func TestConditionParser_ParenthesesPrecedence(t *testing.T) {
	parser := NewConditionParser()

	tests := []struct {
		name           string
		condition      string
		selectionNames []string
		selections     map[string]bool
		expected       bool
	}{
		{
			name:           "(sel1 or sel2) and sel3 - all true",
			condition:      "(sel1 or sel2) and sel3",
			selectionNames: []string{"sel1", "sel2", "sel3"},
			selections: map[string]bool{
				"sel1": true,
				"sel2": false,
				"sel3": true,
			},
			expected: true,
		},
		{
			name:           "(sel1 or sel2) and sel3 - sel3 false",
			condition:      "(sel1 or sel2) and sel3",
			selectionNames: []string{"sel1", "sel2", "sel3"},
			selections: map[string]bool{
				"sel1": true,
				"sel2": true,
				"sel3": false,
			},
			expected: false, // (T or T) and F = F
		},
		{
			name:           "sel1 or (sel2 and sel3) - sel1 true",
			condition:      "sel1 or (sel2 and sel3)",
			selectionNames: []string{"sel1", "sel2", "sel3"},
			selections: map[string]bool{
				"sel1": true,
				"sel2": false,
				"sel3": false,
			},
			expected: true, // T or (F and F) = T
		},
		{
			name:           "nested parens: ((sel1 or sel2) and sel3) or sel4",
			condition:      "((sel1 or sel2) and sel3) or sel4",
			selectionNames: []string{"sel1", "sel2", "sel3", "sel4"},
			selections: map[string]bool{
				"sel1": false,
				"sel2": false,
				"sel3": true,
				"sel4": true,
			},
			expected: true, // ((F or F) and T) or T = F or T = T
		},
		{
			name:           "double not: not not sel1",
			condition:      "not not sel1",
			selectionNames: []string{"sel1"},
			selections: map[string]bool{
				"sel1": true,
			},
			expected: true, // not not T = T
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.Parse(tt.condition, tt.selectionNames)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, ast.Evaluate(tt.selections))
		})
	}
}

func TestConditionParser_WildcardPatterns(t *testing.T) {
	parser := NewConditionParser()

	tests := []struct {
		name           string
		condition      string
		selectionNames []string
		selections     map[string]bool
		expected       bool
	}{
		{
			name:           "1 of selection_* - one matches",
			condition:      "1 of selection_*",
			selectionNames: []string{"selection_a", "selection_b", "selection_c"},
			selections: map[string]bool{
				"selection_a": true,
				"selection_b": false,
				"selection_c": false,
			},
			expected: true,
		},
		{
			name:           "1 of selection_* - none match",
			condition:      "1 of selection_*",
			selectionNames: []string{"selection_a", "selection_b"},
			selections: map[string]bool{
				"selection_a": false,
				"selection_b": false,
			},
			expected: false,
		},
		{
			name:           "2 of selection_* - two match",
			condition:      "2 of selection_*",
			selectionNames: []string{"selection_a", "selection_b", "selection_c"},
			selections: map[string]bool{
				"selection_a": true,
				"selection_b": true,
				"selection_c": false,
			},
			expected: true,
		},
		{
			name:           "2 of selection_* - only one matches",
			condition:      "2 of selection_*",
			selectionNames: []string{"selection_a", "selection_b"},
			selections: map[string]bool{
				"selection_a": true,
				"selection_b": false,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.Parse(tt.condition, tt.selectionNames)
			require.NoError(t, err, "Failed to parse condition: %s", tt.condition)
			if ast != nil {
				assert.Equal(t, tt.expected, ast.Evaluate(tt.selections))
			}
		})
	}
}

func TestConditionParser_AllOfOperator(t *testing.T) {
	parser := NewConditionParser()

	tests := []struct {
		name           string
		condition      string
		selectionNames []string
		selections     map[string]bool
		expected       bool
	}{
		{
			name:           "all of them - all true",
			condition:      "all of them",
			selectionNames: []string{"selection_a", "selection_b"},
			selections: map[string]bool{
				"selection_a": true,
				"selection_b": true,
			},
			expected: true,
		},
		{
			name:           "all of them - one false",
			condition:      "all of them",
			selectionNames: []string{"selection_a", "selection_b"},
			selections: map[string]bool{
				"selection_a": true,
				"selection_b": false,
			},
			expected: false,
		},
		{
			name:           "all of selection_* - all matching selections true",
			condition:      "all of selection_*",
			selectionNames: []string{"selection_a", "selection_b", "filter_c"},
			selections: map[string]bool{
				"selection_a": true,
				"selection_b": true,
				"filter_c":    false, // doesn't match pattern, ignored
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.Parse(tt.condition, tt.selectionNames)
			require.NoError(t, err, "Failed to parse: %s", tt.condition)
			if ast != nil {
				assert.Equal(t, tt.expected, ast.Evaluate(tt.selections))
			}
		})
	}
}

func TestConditionParser_AnyOfOperator(t *testing.T) {
	parser := NewConditionParser()

	tests := []struct {
		name           string
		condition      string
		selectionNames []string
		selections     map[string]bool
		expected       bool
	}{
		{
			name:           "any of them - one true",
			condition:      "any of them",
			selectionNames: []string{"selection_a", "selection_b"},
			selections: map[string]bool{
				"selection_a": false,
				"selection_b": true,
			},
			expected: true,
		},
		{
			name:           "any of them - none true",
			condition:      "any of them",
			selectionNames: []string{"selection_a", "selection_b"},
			selections: map[string]bool{
				"selection_a": false,
				"selection_b": false,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.Parse(tt.condition, tt.selectionNames)
			require.NoError(t, err, "Failed to parse: %s", tt.condition)
			if ast != nil {
				assert.Equal(t, tt.expected, ast.Evaluate(tt.selections))
			}
		})
	}
}

func TestConditionParser_CombinedWithFilters(t *testing.T) {
	parser := NewConditionParser()

	tests := []struct {
		name           string
		condition      string
		selectionNames []string
		selections     map[string]bool
		expected       bool
	}{
		{
			name:           "selection and not filter",
			condition:      "selection and not filter",
			selectionNames: []string{"selection", "filter"},
			selections: map[string]bool{
				"selection": true,
				"filter":    false,
			},
			expected: true,
		},
		{
			name:           "selection and not filter - filter matches",
			condition:      "selection and not filter",
			selectionNames: []string{"selection", "filter"},
			selections: map[string]bool{
				"selection": true,
				"filter":    true,
			},
			expected: false,
		},
		{
			name:           "1 of selection_* and not filter",
			condition:      "1 of selection_* and not filter",
			selectionNames: []string{"selection_a", "filter"},
			selections: map[string]bool{
				"selection_a": true,
				"filter":      false,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.Parse(tt.condition, tt.selectionNames)
			require.NoError(t, err, "Failed to parse: %s", tt.condition)
			if ast != nil {
				assert.Equal(t, tt.expected, ast.Evaluate(tt.selections))
			}
		})
	}
}

// =============================================================================
// CATEGORY 4: ERROR HANDLING TESTS
// =============================================================================

func TestConditionParser_ErrorHandling(t *testing.T) {
	parser := NewConditionParser()

	tests := []struct {
		name           string
		condition      string
		selectionNames []string
		expectErr      bool
	}{
		{
			name:           "Valid simple condition",
			condition:      "selection1",
			selectionNames: []string{"selection1"},
			expectErr:      false,
		},
		{
			name:           "Valid complex condition",
			condition:      "(sel1 or sel2) and not sel3",
			selectionNames: []string{"sel1", "sel2", "sel3"},
			expectErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.Parse(tt.condition, tt.selectionNames)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, ast)
			}
		})
	}
}

func TestConditionParser_EdgeCases(t *testing.T) {
	parser := NewConditionParser()

	tests := []struct {
		name           string
		condition      string
		selectionNames []string
		selections     map[string]bool
		expected       bool
	}{
		{
			name:           "Underscore in selection name",
			condition:      "selection_with_underscores",
			selectionNames: []string{"selection_with_underscores"},
			selections: map[string]bool{
				"selection_with_underscores": true,
			},
			expected: true,
		},
		{
			name:           "Selection name with numbers",
			condition:      "selection123",
			selectionNames: []string{"selection123"},
			selections: map[string]bool{
				"selection123": true,
			},
			expected: true,
		},
		{
			name:           "Case sensitivity - lowercase",
			condition:      "sel1 AND sel2", // uppercase AND
			selectionNames: []string{"sel1", "sel2"},
			selections: map[string]bool{
				"sel1": true,
				"sel2": true,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := parser.Parse(tt.condition, tt.selectionNames)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, ast.Evaluate(tt.selections))
		})
	}
}

// =============================================================================
// CATEGORY 5: BENCHMARKS
// =============================================================================

func BenchmarkConditionParser_SimpleEvaluation(b *testing.B) {
	parser := NewConditionParser()
	selectionNames := []string{"sel1", "sel2"}
	ast, _ := parser.Parse("sel1 and sel2", selectionNames)
	selections := map[string]bool{
		"sel1": true,
		"sel2": true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ast.Evaluate(selections)
	}
}

func BenchmarkConditionParser_ComplexEvaluation(b *testing.B) {
	parser := NewConditionParser()
	selectionNames := []string{"sel1", "sel2", "sel3", "sel4", "sel5"}
	ast, _ := parser.Parse("((sel1 or sel2) and not sel3) or (sel4 and sel5)", selectionNames)
	selections := map[string]bool{
		"sel1": true,
		"sel2": false,
		"sel3": false,
		"sel4": true,
		"sel5": true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ast.Evaluate(selections)
	}
}

func BenchmarkConditionParser_WildcardEvaluation(b *testing.B) {
	parser := NewConditionParser()
	selectionNames := []string{"selection_a", "selection_b", "selection_c", "selection_d", "selection_e"}
	ast, _ := parser.Parse("2 of selection_*", selectionNames)
	selections := map[string]bool{
		"selection_a": true,
		"selection_b": true,
		"selection_c": false,
		"selection_d": false,
		"selection_e": false,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ast.Evaluate(selections)
	}
}

func BenchmarkConditionParser_Parsing(b *testing.B) {
	parser := NewConditionParser()
	condition := "((sel1 or sel2) and not sel3) or (sel4 and sel5)"
	selectionNames := []string{"sel1", "sel2", "sel3", "sel4", "sel5"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parser.Parse(condition, selectionNames)
	}
}

func BenchmarkTokenizer(b *testing.B) {
	input := "((sel1 or sel2) and not sel3) or (sel4 and sel5)"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tokenizer := NewTokenizer(input)
		for {
			tok := tokenizer.NextToken()
			if tok.Type == TokenEOF {
				break
			}
		}
	}
}
