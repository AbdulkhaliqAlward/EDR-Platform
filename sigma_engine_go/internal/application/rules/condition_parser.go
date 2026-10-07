package rules

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// TokenType represents the type of a token in the condition expression.
type TokenType int

const (
	TokenEOF TokenType = iota
	TokenIdentifier
	TokenAnd
	TokenOr
	TokenNot
	TokenLParen
	TokenRParen
	TokenNumber
	TokenOf
	TokenThem
	TokenAll
	TokenAny
)

// Token represents a single token in the condition expression.
type Token struct {
	Type    TokenType
	Literal string
	Line    int
	Col     int
}

func (t Token) String() string {
	return fmt.Sprintf("Token{Type=%d, Literal=%q, Line=%d, Col=%d}", t.Type, t.Literal, t.Line, t.Col)
}

// Tokenizer tokenizes condition strings into tokens.
// Thread-safe: Each parse creates a new tokenizer instance.
type Tokenizer struct {
	input  string
	pos    int
	line   int
	col    int
	length int
}

// NewTokenizer creates a new tokenizer for the given input.
func NewTokenizer(input string) *Tokenizer {
	return &Tokenizer{
		input:  input,
		pos:    0,
		line:   1,
		col:    1,
		length: len(input),
	}
}

// NextToken returns the next token from the input.
func (t *Tokenizer) NextToken() Token {
	t.skipWhitespace()

	if t.pos >= t.length {
		return Token{Type: TokenEOF, Line: t.line, Col: t.col}
	}

	ch := t.input[t.pos]
	startLine, startCol := t.line, t.col

	switch ch {
	case '(':
		t.advance()
		return Token{Type: TokenLParen, Literal: "(", Line: startLine, Col: startCol}
	case ')':
		t.advance()
		return Token{Type: TokenRParen, Literal: ")", Line: startLine, Col: startCol}
	}

	// Number
	if unicode.IsDigit(rune(ch)) {
		return t.readNumber(startLine, startCol)
	}

	// Identifier or keyword
	if unicode.IsLetter(rune(ch)) || ch == '_' {
		return t.readIdentifier(startLine, startCol)
	}

	// Unknown character - return as error token
	t.advance()
	return Token{Type: TokenEOF, Literal: string(ch), Line: startLine, Col: startCol}
}

func (t *Tokenizer) skipWhitespace() {
	for t.pos < t.length {
		ch := t.input[t.pos]
		if ch == ' ' || ch == '\t' || ch == '\r' {
			t.advance()
		} else if ch == '\n' {
			t.line++
			t.col = 1
			t.pos++
		} else {
			break
		}
	}
}

func (t *Tokenizer) advance() {
	if t.pos < t.length {
		t.pos++
		t.col++
	}
}

func (t *Tokenizer) readNumber(line, col int) Token {
	start := t.pos
	for t.pos < t.length && unicode.IsDigit(rune(t.input[t.pos])) {
		t.advance()
	}
	return Token{
		Type:    TokenNumber,
		Literal: t.input[start:t.pos],
		Line:    line,
		Col:     col,
	}
}

func (t *Tokenizer) readIdentifier(line, col int) Token {
	start := t.pos
	for t.pos < t.length {
		ch := t.input[t.pos]
		if unicode.IsLetter(rune(ch)) || unicode.IsDigit(rune(ch)) || ch == '_' || ch == '-' || ch == '*' {
			t.advance()
		} else {
			break
		}
	}

	literal := t.input[start:t.pos]
	lower := strings.ToLower(literal)

	// Check keywords (case-insensitive)
	switch lower {
	case "and":
		return Token{Type: TokenAnd, Literal: literal, Line: line, Col: col}
	case "or":
		return Token{Type: TokenOr, Literal: literal, Line: line, Col: col}
	case "not":
		return Token{Type: TokenNot, Literal: literal, Line: line, Col: col}
	case "of":
		return Token{Type: TokenOf, Literal: literal, Line: line, Col: col}
	case "them":
		return Token{Type: TokenThem, Literal: literal, Line: line, Col: col}
	case "all":
		return Token{Type: TokenAll, Literal: literal, Line: line, Col: col}
	case "any":
		return Token{Type: TokenAny, Literal: literal, Line: line, Col: col}
	}

	// Check for wildcard pattern (contains *)
	if strings.Contains(literal, "*") {
		return Token{Type: TokenIdentifier, Literal: literal, Line: line, Col: col}
	}

	return Token{Type: TokenIdentifier, Literal: literal, Line: line, Col: col}
}

// Node represents a node in the condition AST.
type Node interface {
	Evaluate(selections map[string]bool) bool
	String() string
}

// AndNode represents an AND operation.
type AndNode struct {
	Left  Node
	Right Node
}

func (n *AndNode) Evaluate(selections map[string]bool) bool {
	return n.Left.Evaluate(selections) && n.Right.Evaluate(selections)
}

func (n *AndNode) String() string {
	return fmt.Sprintf("(%s AND %s)", n.Left.String(), n.Right.String())
}

// OrNode represents an OR operation.
type OrNode struct {
	Left  Node
	Right Node
}

func (n *OrNode) Evaluate(selections map[string]bool) bool {
	return n.Left.Evaluate(selections) || n.Right.Evaluate(selections)
}

func (n *OrNode) String() string {
	return fmt.Sprintf("(%s OR %s)", n.Left.String(), n.Right.String())
}

// NotNode represents a NOT operation.
type NotNode struct {
	Child Node
}

func (n *NotNode) Evaluate(selections map[string]bool) bool {
	return !n.Child.Evaluate(selections)
}

func (n *NotNode) String() string {
	return fmt.Sprintf("NOT %s", n.Child.String())
}

// SelectionNode represents a selection identifier.
type SelectionNode struct {
	Name string
}

func (n *SelectionNode) Evaluate(selections map[string]bool) bool {
	// Explicitly check if key exists - return false if missing (don't rely on zero value)
	value, exists := selections[n.Name]
	if !exists {
		return false
	}
	return value
}

func (n *SelectionNode) String() string {
	return n.Name
}

// PatternNode represents a pattern match like "1 of selection_*".
type PatternNode struct {
	Pattern  string
	Operator string // "1 of", "all of", "any of"
	Count    int

	// Names is the pattern resolved against the rule's selection names at
	// parse time (nil when the node was built without resolution).
	Names    []string
	resolved bool
}

func (n *PatternNode) Evaluate(selections map[string]bool) bool {
	// Expand pattern to matching selection names (pre-resolved when parsed).
	matchingKeys := n.Names
	if !n.resolved {
		matchingKeys = n.expandPattern(selections)
	}

	if len(matchingKeys) == 0 {
		return false
	}

	// Count matches
	matched := 0
	for _, key := range matchingKeys {
		if selections[key] {
			matched++
		}
	}

	switch n.Operator {
	case "1 of", "any of":
		return matched >= n.Count
	case "all of":
		return matched == len(matchingKeys)
	default:
		// For "N of" where N > 1
		return matched >= n.Count
	}
}

func (n *PatternNode) String() string {
	return fmt.Sprintf("%s %s", n.Operator, n.Pattern)
}

// expandPattern expands a wildcard pattern to matching selection names.
// Used only for nodes that were not resolved at parse time.
func (n *PatternNode) expandPattern(selections map[string]bool) []string {
	names := make([]string, 0, len(selections))
	for key := range selections {
		names = append(names, key)
	}
	return resolveSelectionPattern(n.Pattern, names)
}

// resolveSelectionPattern returns the selection names matched by a condition
// pattern. "*" (used for "them") matches every selection except those whose
// name starts with "_" (Sigma convention for helper identifiers); otherwise
// "*" is the only wildcard and all other characters match literally.
func resolveSelectionPattern(pattern string, names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		if pattern == "*" {
			if !strings.HasPrefix(name, "_") {
				out = append(out, name)
			}
			continue
		}
		if wildcardMatch(pattern, name) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// wildcardMatch matches s against a pattern where '*' matches any run of
// characters and every other character matches literally.
func wildcardMatch(pattern, s string) bool {
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		if p < len(pattern) && pattern[p] == '*' {
			star, mark = p, i
			p++
		} else if p < len(pattern) && pattern[p] == s[i] {
			p++
			i++
		} else if star >= 0 {
			p = star + 1
			mark++
			i = mark
		} else {
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// resolvedPattern builds a PatternNode whose selection names are resolved
// against the rule's selections at parse time.
func (ps *parserState) resolvedPattern(pattern, operator string, count int) *PatternNode {
	names := make([]string, 0, len(ps.selectionNames))
	for name := range ps.selectionNames {
		names = append(names, name)
	}
	return &PatternNode{
		Pattern:  pattern,
		Operator: operator,
		Count:    count,
		Names:    resolveSelectionPattern(pattern, names),
		resolved: true,
	}
}

// ConditionParser parses condition expressions into AST.
// Thread-safe: All parsing state is local to Parse() method.
type ConditionParser struct {
	// No mutable state - parser is stateless for thread safety
}

// NewConditionParser creates a new condition parser.
func NewConditionParser() *ConditionParser {
	return &ConditionParser{}
}

// parserState holds the parsing state for a single parse operation.
// This is thread-safe because each Parse() call creates a new state.
type parserState struct {
	tokenizer       *Tokenizer
	selectionNames  map[string]bool
	currentToken    Token
	peekToken       Token
	originalCondition string
}

// Parse parses a condition string into an AST.
// Thread-safe: All parsing state is stored in local variables.
func (p *ConditionParser) Parse(condition string, selectionNames []string) (Node, error) {
	if strings.TrimSpace(condition) == "" {
		return nil, fmt.Errorf("condition is empty")
	}

	// All parsing state is local to this method (thread-safe)
	tokenizer := NewTokenizer(condition)
	selectionNamesMap := make(map[string]bool)
	for _, name := range selectionNames {
		selectionNamesMap[name] = true
	}

	// Create parser state with lookahead
	state := &parserState{
		tokenizer:          tokenizer,
		selectionNames:     selectionNamesMap,
		originalCondition: condition,
	}

	// Initialize lookahead (two tokens)
	state.nextToken()
	state.nextToken()

	// Parse using recursive descent
	node, err := p.parseExpression(state)
	if err != nil {
		return nil, fmt.Errorf("parse error in condition %q: %w", condition, err)
	}

	// Verify we consumed all tokens
	if state.currentToken.Type != TokenEOF {
		return nil, fmt.Errorf("unexpected token after expression in condition %q: %v", condition, state.currentToken)
	}

	return node, nil
}

// nextToken advances to the next token (lookahead pattern).
func (ps *parserState) nextToken() {
	ps.currentToken = ps.peekToken
	ps.peekToken = ps.tokenizer.NextToken()
}

// expectToken checks if the current token matches the expected type and advances.
func (ps *parserState) expectToken(expected TokenType) error {
	if ps.currentToken.Type != expected {
		return fmt.Errorf("expected token type %d, got %v", expected, ps.currentToken)
	}
	ps.nextToken()
	return nil
}

// parseExpression implements: Expression -> Term { OR Term }
func (p *ConditionParser) parseExpression(state *parserState) (Node, error) {
	left, err := p.parseTerm(state)
	if err != nil {
		return nil, err
	}

	// Check for OR operators using lookahead
	for state.currentToken.Type == TokenOr {
		state.nextToken() // consume OR
		right, err := p.parseTerm(state)
		if err != nil {
			return nil, err
		}
		left = &OrNode{Left: left, Right: right}
	}

	return left, nil
}

// parseTerm implements: Term -> Factor { AND Factor }
func (p *ConditionParser) parseTerm(state *parserState) (Node, error) {
	left, err := p.parseFactor(state)
	if err != nil {
		return nil, err
	}

	// Check for AND operators using lookahead
	for state.currentToken.Type == TokenAnd {
		state.nextToken() // consume AND
		right, err := p.parseFactor(state)
		if err != nil {
			return nil, err
		}
		left = &AndNode{Left: left, Right: right}
	}

	return left, nil
}

// parseFactor implements: Factor -> NOT Factor | ( Expression ) | Aggregation | Identifier
func (p *ConditionParser) parseFactor(state *parserState) (Node, error) {
	token := state.currentToken
	state.nextToken() // consume current token

	switch token.Type {
	case TokenNot:
		child, err := p.parseFactor(state)
		if err != nil {
			return nil, err
		}
		return &NotNode{Child: child}, nil

	case TokenLParen:
		expr, err := p.parseExpression(state)
		if err != nil {
			return nil, err
		}
		if state.currentToken.Type != TokenRParen {
			return nil, fmt.Errorf("expected ')', got %v", state.currentToken)
		}
		state.nextToken() // consume ')'
		return expr, nil

	case TokenNumber:
		// This is "N of ..." pattern
		return p.parseAggregation(state, token)

	case TokenAll:
		// This is "all of ..." pattern
		return p.parseAllOf(state)

	case TokenAny:
		// This is "any of ..." pattern
		return p.parseAnyOf(state)

	case TokenIdentifier:
		name := token.Literal
		if !state.selectionNames[name] {
			return nil, fmt.Errorf("condition references unknown selection %q", name)
		}
		return &SelectionNode{Name: name}, nil

	default:
		return nil, fmt.Errorf("unexpected token: %v", token)
	}
}

// parseAggregation parses "N of pattern" or "N of them"
func (p *ConditionParser) parseAggregation(state *parserState, countToken Token) (Node, error) {
	count, err := parseInt(countToken.Literal)
	if err != nil {
		return nil, fmt.Errorf("invalid number: %s", countToken.Literal)
	}

	// Expect "of"
	if state.currentToken.Type != TokenOf {
		return nil, fmt.Errorf("expected 'of' after number, got %v", state.currentToken)
	}
	state.nextToken() // consume "of"

	// Get target (pattern, identifier, or "them")
	targetToken := state.currentToken
	state.nextToken() // consume target

	if targetToken.Type == TokenThem {
		// "N of them" - match all selections
		return state.resolvedPattern("*", "1 of", count), nil
	}

	if targetToken.Type == TokenIdentifier {
		return state.resolvedPattern(targetToken.Literal, "1 of", count), nil
	}

	return nil, fmt.Errorf("expected selection pattern or 'them' after 'of', got %v", targetToken)
}

// parseAllOf parses "all of pattern" or "all of them"
func (p *ConditionParser) parseAllOf(state *parserState) (Node, error) {
	// Expect "of"
	if state.currentToken.Type != TokenOf {
		return nil, fmt.Errorf("expected 'of' after 'all', got %v", state.currentToken)
	}
	state.nextToken() // consume "of"

	// Get target
	targetToken := state.currentToken
	state.nextToken() // consume target

	if targetToken.Type == TokenThem {
		// "all of them" - all selections must match
		return state.resolvedPattern("*", "all of", 0), nil
	}

	if targetToken.Type == TokenIdentifier {
		return state.resolvedPattern(targetToken.Literal, "all of", 0), nil
	}

	return nil, fmt.Errorf("expected selection pattern or 'them' after 'all of', got %v", targetToken)
}

// parseAnyOf parses "any of pattern" or "any of them"
func (p *ConditionParser) parseAnyOf(state *parserState) (Node, error) {
	// Expect "of"
	if state.currentToken.Type != TokenOf {
		return nil, fmt.Errorf("expected 'of' after 'any', got %v", state.currentToken)
	}
	state.nextToken() // consume "of"

	// Get target
	targetToken := state.currentToken
	state.nextToken() // consume target

	if targetToken.Type == TokenThem {
		// "any of them" - at least one selection must match
		return state.resolvedPattern("*", "any of", 1), nil
	}

	if targetToken.Type == TokenIdentifier {
		return state.resolvedPattern(targetToken.Literal, "any of", 1), nil
	}

	return nil, fmt.Errorf("expected selection pattern or 'them' after 'any of', got %v", targetToken)
}

// parseInt parses an integer string.
func parseInt(s string) (int, error) {
	result := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("invalid number: %s", s)
		}
		result = result*10 + int(ch-'0')
	}
	return result, nil
}

// matchesPattern checks if a string matches a glob pattern ('*' wildcard only;
// all other characters, including regex metacharacters, match literally).
func matchesPattern(s, pattern string) bool {
	return wildcardMatch(pattern, s)
}

// ConditionEvaluator evaluates a parsed condition AST.
// Thread-safe: Stateless evaluator, only reads from input selections map.
type ConditionEvaluator struct {
	node Node
}

// NewConditionEvaluator creates a new condition evaluator.
func NewConditionEvaluator(node Node) *ConditionEvaluator {
	return &ConditionEvaluator{
		node: node,
	}
}

// Evaluate evaluates the condition with given selection results.
// Thread-safe: Only reads from selections map, no shared mutable state.
func (ce *ConditionEvaluator) Evaluate(selections map[string]bool) bool {
	return ce.node.Evaluate(selections)
}
