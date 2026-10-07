package detection

// Spec-compliant Sigma value matching.
//
// Every SelectionField is compiled once, when a rule is loaded, into a
// compiledField. Matching then needs no parsing, no regex compilation and no
// allocation on the hot path beyond per-event field resolution.
//
// Semantics follow the Sigma specification (and pySigma, its reference
// implementation):
//   - String values support the wildcards '*' (any run) and '?' (one char).
//     A backslash escapes '*', '?' and '\'; any other backslash is literal.
//   - contains / startswith / endswith wrap the value in wildcards.
//   - Matching is case-insensitive unless the "cased" modifier is present.
//   - Transformation modifiers (windash, base64, base64offset, wide/utf16*)
//     are applied in order to the rule value; their results are literal.
//   - re is a case-sensitive RE2 regex; flags i / m / s follow it.
//   - A null value matches only when the field is absent; exists tests
//     presence; fieldref compares against another field of the same event.
//   - Unknown or unsupported modifiers are a rule load error, never a silent
//     fallback to "contains".

import (
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/edr-platform/sigma-engine/internal/application/mapping"
	"github.com/edr-platform/sigma-engine/internal/domain"
)

// ─────────────────────────────────────────────────────────────────────────────
// Sigma string patterns
// ─────────────────────────────────────────────────────────────────────────────

type tokKind uint8

const (
	tokLit tokKind = iota
	tokAny         // '*'
	tokOne         // '?'
)

type patToken struct {
	kind tokKind
	lit  string
}

type stringOp uint8

const (
	opEquals stringOp = iota
	opContains
	opStartsWith
	opEndsWith
)

type patMode uint8

const (
	modeExact patMode = iota
	modePrefix
	modeSuffix
	modeContains
	modeAnything
	modeGlob
)

// sigmaPattern is a compiled Sigma string value.
type sigmaPattern struct {
	mode   patMode
	lit    string // literal for the fast modes
	tokens []patToken
	cased  bool
}

// parseSigmaWildcards splits a Sigma string into literal runs and wildcards,
// applying the spec's escape rules.
func parseSigmaWildcards(raw string) []patToken {
	var toks []patToken
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			toks = append(toks, patToken{kind: tokLit, lit: lit.String()})
			lit.Reset()
		}
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch c {
		case '\\':
			if i+1 < len(raw) && (raw[i+1] == '*' || raw[i+1] == '?' || raw[i+1] == '\\') {
				lit.WriteByte(raw[i+1])
				i++
			} else {
				lit.WriteByte('\\')
			}
		case '*':
			flush()
			toks = append(toks, patToken{kind: tokAny})
		case '?':
			flush()
			toks = append(toks, patToken{kind: tokOne})
		default:
			lit.WriteByte(c)
		}
	}
	flush()
	return toks
}

// unescapeSigma returns the literal text of a Sigma string that contains no
// wildcards, and reports whether it contained any.
func unescapeSigma(raw string) (string, bool) {
	var b strings.Builder
	for _, t := range parseSigmaWildcards(raw) {
		if t.kind != tokLit {
			return "", true
		}
		b.WriteString(t.lit)
	}
	return b.String(), false
}

// newSigmaPattern compiles a value for the given string operation. When
// literal is true the value is taken verbatim (already-transformed bytes).
func newSigmaPattern(raw string, op stringOp, cased, literal bool) *sigmaPattern {
	var toks []patToken
	if literal {
		if raw != "" {
			toks = []patToken{{kind: tokLit, lit: raw}}
		}
	} else {
		toks = parseSigmaWildcards(raw)
	}

	switch op {
	case opContains:
		toks = append(append([]patToken{{kind: tokAny}}, toks...), patToken{kind: tokAny})
	case opStartsWith:
		toks = append(toks, patToken{kind: tokAny})
	case opEndsWith:
		toks = append([]patToken{{kind: tokAny}}, toks...)
	}

	// Normalise: lowercase literals for case-insensitive matching, merge
	// adjacent literals and collapse runs of '*'.
	norm := make([]patToken, 0, len(toks))
	for _, t := range toks {
		if t.kind == tokLit && !cased {
			t.lit = strings.ToLower(t.lit)
		}
		if n := len(norm); n > 0 {
			last := &norm[n-1]
			if t.kind == tokAny && last.kind == tokAny {
				continue
			}
			if t.kind == tokLit && last.kind == tokLit {
				last.lit += t.lit
				continue
			}
		}
		norm = append(norm, t)
	}

	p := &sigmaPattern{tokens: norm, cased: cased, mode: modeGlob}
	switch {
	case len(norm) == 0:
		p.mode, p.lit = modeExact, ""
	case len(norm) == 1 && norm[0].kind == tokLit:
		p.mode, p.lit = modeExact, norm[0].lit
	case len(norm) == 1 && norm[0].kind == tokAny:
		p.mode = modeAnything
	case len(norm) == 2 && norm[0].kind == tokLit && norm[1].kind == tokAny:
		p.mode, p.lit = modePrefix, norm[0].lit
	case len(norm) == 2 && norm[0].kind == tokAny && norm[1].kind == tokLit:
		p.mode, p.lit = modeSuffix, norm[1].lit
	case len(norm) == 3 && norm[0].kind == tokAny && norm[1].kind == tokLit && norm[2].kind == tokAny:
		p.mode, p.lit = modeContains, norm[1].lit
	}
	return p
}

// matchValue matches an event value; lower is the lowercased form of raw.
func (p *sigmaPattern) matchValue(raw, lower string) bool {
	s := lower
	if p.cased {
		s = raw
	}
	switch p.mode {
	case modeExact:
		return s == p.lit
	case modePrefix:
		return strings.HasPrefix(s, p.lit)
	case modeSuffix:
		return strings.HasSuffix(s, p.lit)
	case modeContains:
		return strings.Contains(s, p.lit)
	case modeAnything:
		return true
	default:
		return globMatch(p.tokens, s)
	}
}

// globMatch is an iterative wildcard matcher with single-star backtracking
// (linear in practice, O(n·m) worst case, no recursion, no allocation).
func globMatch(toks []patToken, s string) bool {
	ti, si := 0, 0
	starTi, starSi := -1, 0
	for {
		if ti < len(toks) {
			t := toks[ti]
			switch t.kind {
			case tokAny:
				starTi, starSi = ti, si
				ti++
				continue
			case tokOne:
				if si < len(s) {
					_, w := utf8.DecodeRuneInString(s[si:])
					si += w
					ti++
					continue
				}
			case tokLit:
				if strings.HasPrefix(s[si:], t.lit) {
					si += len(t.lit)
					ti++
					continue
				}
			}
		} else if si == len(s) {
			return true
		}
		// Mismatch: let the last '*' absorb one more character and retry.
		if starTi < 0 || starSi >= len(s) {
			return false
		}
		_, w := utf8.DecodeRuneInString(s[starSi:])
		starSi += w
		ti, si = starTi+1, starSi
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Value transformations (windash, base64, base64offset, utf16)
// ─────────────────────────────────────────────────────────────────────────────

// valueVariant is one concrete form of a rule value after transformations.
// literal marks values that no longer carry Sigma wildcard/escape syntax.
type valueVariant struct {
	s       string
	literal bool
}

var windashChars = []string{"-", "/", "–", "—", "―"}

const maxWindashPositions = 4 // 5^4 = 625 variants upper bound per value

func isWordByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// windashVariants expands every command-line flag dash ('-' or '/' that
// starts a word, i.e. regex \B[-/]\b) into all Windows dash variants.
func windashVariants(s string) []string {
	var pos []int
	for i := 0; i < len(s); i++ {
		if s[i] != '-' && s[i] != '/' {
			continue
		}
		prevWord := i > 0 && isWordByte(s[i-1])
		nextWord := i+1 < len(s) && isWordByte(s[i+1])
		if !prevWord && nextWord {
			pos = append(pos, i)
		}
	}
	if len(pos) == 0 {
		return []string{s}
	}
	if len(pos) > maxWindashPositions {
		// Bound the expansion: vary all flags together.
		out := make([]string, 0, len(windashChars))
		for _, d := range windashChars {
			var b strings.Builder
			last := 0
			for _, p := range pos {
				b.WriteString(s[last:p])
				b.WriteString(d)
				last = p + 1
			}
			b.WriteString(s[last:])
			out = append(out, b.String())
		}
		return out
	}
	out := []string{""}
	last := 0
	for _, p := range pos {
		seg := s[last:p]
		next := make([]string, 0, len(out)*len(windashChars))
		for _, prefix := range out {
			for _, d := range windashChars {
				next = append(next, prefix+seg+d)
			}
		}
		out = next
		last = p + 1
	}
	for i := range out {
		out[i] += s[last:]
	}
	return out
}

// base64OffsetVariants implements the Sigma base64offset modifier: the three
// encodings of value at byte offsets 0, 1 and 2, trimmed to the characters
// that do not depend on the surrounding bytes.
func base64OffsetVariants(val []byte) []string {
	startOffsets := []int{0, 2, 3}
	endOffsets := []int{0, -3, -2} // 0 = to end
	out := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		padded := append([]byte(strings.Repeat(" ", i)), val...)
		enc := base64.StdEncoding.EncodeToString(padded)
		start := startOffsets[i]
		end := len(enc)
		if e := endOffsets[(len(val)+i)%3]; e != 0 {
			end = len(enc) + e
		}
		if start < end {
			out = append(out, enc[start:end])
		}
	}
	return out
}

func utf16Bytes(s string, bigEndian, bom bool) string {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(units)*2+2)
	if bom {
		b = append(b, 0xFF, 0xFE)
	}
	for _, u := range units {
		if bigEndian {
			b = append(b, byte(u>>8), byte(u))
		} else {
			b = append(b, byte(u), byte(u>>8))
		}
	}
	return string(b)
}

// applyTransforms runs the transformation modifiers in rule order.
func applyTransforms(raw string, transforms []string) ([]valueVariant, error) {
	vals := []valueVariant{{s: raw}}
	for _, t := range transforms {
		next := make([]valueVariant, 0, len(vals))
		for _, v := range vals {
			if t == "windash" {
				for _, w := range windashVariants(v.s) {
					next = append(next, valueVariant{s: w, literal: v.literal})
				}
				continue
			}
			// Encoding transforms operate on the literal value.
			text := v.s
			if !v.literal {
				lit, hasWildcard := unescapeSigma(v.s)
				if hasWildcard {
					return nil, fmt.Errorf("wildcards cannot be combined with the %s modifier", t)
				}
				text = lit
			}
			switch t {
			case "base64":
				next = append(next, valueVariant{s: base64.StdEncoding.EncodeToString([]byte(text)), literal: true})
			case "base64offset":
				for _, enc := range base64OffsetVariants([]byte(text)) {
					next = append(next, valueVariant{s: enc, literal: true})
				}
			case "wide", "utf16le":
				next = append(next, valueVariant{s: utf16Bytes(text, false, false), literal: true})
			case "utf16be":
				next = append(next, valueVariant{s: utf16Bytes(text, true, false), literal: true})
			case "utf16":
				next = append(next, valueVariant{s: utf16Bytes(text, false, true), literal: true})
			default:
				return nil, fmt.Errorf("unsupported transformation %q", t)
			}
		}
		vals = dedupeVariants(next)
	}
	return vals, nil
}

func dedupeVariants(in []valueVariant) []valueVariant {
	seen := make(map[valueVariant]struct{}, len(in))
	out := in[:0]
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Non-string value matchers
// ─────────────────────────────────────────────────────────────────────────────

type valueMatcher interface {
	matchValue(raw, lower string) bool
}

type regexMatcher struct{ re *regexp.Regexp }

func (m regexMatcher) matchValue(raw, _ string) bool { return m.re.MatchString(raw) }

type cidrMatcher struct{ network *net.IPNet }

func (m cidrMatcher) matchValue(raw, _ string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	return ip != nil && m.network.Contains(ip)
}

type numericMatcher struct {
	cmp string // lt, lte, gt, gte
	n   float64
}

func (m numericMatcher) matchValue(raw, _ string) bool {
	f, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return false
	}
	switch m.cmp {
	case "lt":
		return f < m.n
	case "lte":
		return f <= m.n
	case "gt":
		return f > m.n
	default:
		return f >= m.n
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Compiled fields
// ─────────────────────────────────────────────────────────────────────────────

type fieldKind uint8

const (
	kindValues   fieldKind = iota // string / regex / cidr / numeric values
	kindExists                    // |exists
	kindFieldRef                  // |fieldref
)

type compiledField struct {
	name string
	kind fieldKind
	all  bool

	// keyword marks an unbound field ('|all': [...] in Sigma): values are
	// searched in every string of the event, with contains semantics.
	keyword bool

	// groups holds one entry per rule value; each entry is the OR of that
	// value's transformed variants. Without |all any group may match; with
	// |all every group must match.
	groups      [][]valueMatcher
	nullAllowed bool // a null rule value: matches when the field is absent

	existsWant bool

	refFields []string
	refOp     stringOp
	cased     bool
}

func compileField(sf domain.SelectionField) (*compiledField, error) {
	f := &compiledField{name: sf.FieldName}
	// An empty field name is a Sigma keyword with modifiers, e.g.
	//   keywords:
	//     '|all': ['Export-', 'PfxCertificate']
	// Unbound values are full-text searches (contains semantics).
	f.keyword = strings.TrimSpace(sf.FieldName) == ""

	op := ""
	setOp := func(o string) error {
		if op != "" && op != o {
			return fmt.Errorf("conflicting modifiers %q and %q", op, o)
		}
		op = o
		return nil
	}
	var transforms []string
	reFlags := ""
	for _, raw := range sf.Modifiers {
		m := strings.ToLower(strings.TrimSpace(raw))
		switch m {
		case "all":
			f.all = true
		case "cased":
			f.cased = true
		case "contains", "startswith", "endswith", "re", "cidr", "lt", "lte", "gt", "gte", "exists", "fieldref":
			if err := setOp(m); err != nil {
				return nil, err
			}
		case "regex":
			if err := setOp("re"); err != nil {
				return nil, err
			}
		case "i", "m", "s":
			if op != "re" {
				return nil, fmt.Errorf("regex flag modifier %q must follow re", m)
			}
			reFlags += m
		case "windash", "base64", "base64offset", "wide", "utf16le", "utf16be", "utf16":
			transforms = append(transforms, m)
		case "expand":
			return nil, fmt.Errorf("modifier expand (placeholders) is not supported")
		default:
			return nil, fmt.Errorf("unknown modifier %q", raw)
		}
	}
	if len(sf.Values) == 0 {
		return nil, fmt.Errorf("field %s has no values", sf.FieldName)
	}

	stringOps := map[string]stringOp{"": opEquals, "contains": opContains, "startswith": opStartsWith, "endswith": opEndsWith}
	if f.keyword {
		switch op {
		case "", "contains":
			op = "contains"
		case "re":
		default:
			return nil, fmt.Errorf("keyword values do not support the %s modifier", op)
		}
	}
	if len(transforms) > 0 {
		if _, ok := stringOps[op]; !ok {
			return nil, fmt.Errorf("transformation modifiers cannot be combined with %s", op)
		}
	}

	switch op {
	case "exists":
		if len(sf.Values) != 1 {
			return nil, fmt.Errorf("exists takes a single boolean value")
		}
		b, ok := sf.Values[0].(bool)
		if !ok {
			return nil, fmt.Errorf("exists value must be true or false")
		}
		f.kind, f.existsWant = kindExists, b
		return f, nil

	case "fieldref":
		f.kind = kindFieldRef
		f.refOp = opEquals
		for _, v := range sf.Values {
			s, ok := v.(string)
			if !ok || strings.TrimSpace(s) == "" {
				return nil, fmt.Errorf("fieldref values must be field names")
			}
			f.refFields = append(f.refFields, s)
		}
		return f, nil
	}

	for _, v := range sf.Values {
		if v == nil {
			if op != "" {
				return nil, fmt.Errorf("null value cannot be combined with %s", op)
			}
			f.nullAllowed = true
			continue
		}
		var group []valueMatcher
		switch op {
		case "re":
			pattern := domain.ValueToString(v)
			if reFlags != "" {
				pattern = "(?" + reFlags + ")" + pattern
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid regex %q: %w", domain.ValueToString(v), err)
			}
			group = []valueMatcher{regexMatcher{re: re}}
		case "cidr":
			_, network, err := net.ParseCIDR(strings.TrimSpace(domain.ValueToString(v)))
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", domain.ValueToString(v), err)
			}
			group = []valueMatcher{cidrMatcher{network: network}}
		case "lt", "lte", "gt", "gte":
			n, err := strconv.ParseFloat(strings.TrimSpace(domain.ValueToString(v)), 64)
			if err != nil {
				return nil, fmt.Errorf("%s value %v is not numeric", op, v)
			}
			group = []valueMatcher{numericMatcher{cmp: op, n: n}}
		default:
			variants, err := applyTransforms(domain.ValueToString(v), transforms)
			if err != nil {
				return nil, err
			}
			sop := stringOps[op]
			for _, vv := range variants {
				// Encoded (base64/utf16) variants are byte-exact: match cased.
				group = append(group, newSigmaPattern(vv.s, sop, f.cased || vv.literal, vv.literal))
			}
		}
		f.groups = append(f.groups, group)
	}
	if len(f.groups) == 0 && !f.nullAllowed {
		return nil, fmt.Errorf("field %s has no usable values", sf.FieldName)
	}
	return f, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-event field resolution (memoised for the duration of one event)
// ─────────────────────────────────────────────────────────────────────────────

type resolvedField struct {
	present bool
	value   interface{}
	raw     []string
	lower   []string
}

// eventContext memoises field resolution for one event across every rule
// evaluated against it. It is created per event and never shared, so no
// locking is needed and values can never leak between events.
type eventContext struct {
	event  *domain.LogEvent
	mapper *mapping.FieldMapper
	fields map[string]*resolvedField
}

func newEventContext(event *domain.LogEvent, mapper *mapping.FieldMapper) *eventContext {
	return &eventContext{event: event, mapper: mapper, fields: make(map[string]*resolvedField, 16)}
}

func (ec *eventContext) resolve(name string) *resolvedField {
	if rf, ok := ec.fields[name]; ok {
		return rf
	}
	rf := &resolvedField{}
	if v, _, err := ec.mapper.ResolveField(ec.event.RawData, name); err == nil && v != nil {
		rf.present = true
		rf.value = v
		rf.raw = flattenValues(v)
		rf.lower = make([]string, len(rf.raw))
		for i, s := range rf.raw {
			rf.lower[i] = strings.ToLower(s)
		}
	}
	ec.fields[name] = rf
	return rf
}

// keywordValues exposes every string of the event (already lowercased) as a
// pseudo-field for unbound keyword values.
func (ec *eventContext) keywordValues() *resolvedField {
	const key = "\x00keywords"
	if rf, ok := ec.fields[key]; ok {
		return rf
	}
	vals := ec.event.SearchValues()
	rf := &resolvedField{present: len(vals) > 0, raw: vals, lower: vals}
	ec.fields[key] = rf
	return rf
}

// flattenValues renders a resolved field value as one or more strings
// (arrays match when any element matches).
func flattenValues(v interface{}) []string {
	switch t := v.(type) {
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if e == nil {
				continue
			}
			if _, isMap := e.(map[string]interface{}); isMap {
				continue
			}
			out = append(out, domain.ValueToString(e))
		}
		return out
	case []string:
		return append([]string(nil), t...)
	case map[string]interface{}:
		return nil
	default:
		return []string{domain.ValueToString(t)}
	}
}

func (f *compiledField) evaluate(ec *eventContext) bool {
	var rf *resolvedField
	if f.keyword {
		rf = ec.keywordValues()
	} else {
		rf = ec.resolve(f.name)
	}
	switch f.kind {
	case kindExists:
		return rf.present == f.existsWant
	case kindFieldRef:
		if !rf.present {
			return false
		}
		for _, ref := range f.refFields {
			other := ec.resolve(ref)
			if !other.present {
				return false
			}
			if !anyPairEqual(rf, other, f.cased) {
				return false
			}
		}
		return true
	}

	if !rf.present || len(rf.raw) == 0 {
		return f.nullAllowed
	}
	if f.all {
		for _, g := range f.groups {
			if !groupMatches(g, rf) {
				return false
			}
		}
		return len(f.groups) > 0
	}
	for _, g := range f.groups {
		if groupMatches(g, rf) {
			return true
		}
	}
	return false
}

func groupMatches(g []valueMatcher, rf *resolvedField) bool {
	for _, m := range g {
		for i := range rf.raw {
			if m.matchValue(rf.raw[i], rf.lower[i]) {
				return true
			}
		}
	}
	return false
}

func anyPairEqual(a, b *resolvedField, cased bool) bool {
	for i := range a.raw {
		for j := range b.raw {
			if cased {
				if a.raw[i] == b.raw[j] {
					return true
				}
			} else if a.lower[i] == b.lower[j] {
				return true
			}
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// Compiled selections
// ─────────────────────────────────────────────────────────────────────────────

type compiledSelection struct {
	name         string
	fields       []*compiledField     // AND
	keywords     []*sigmaPattern      // OR, full-text over all event values
	alternatives []*compiledSelection // OR (Sigma list of maps)
}

func compileSelection(sel *domain.Selection) (*compiledSelection, error) {
	if sel == nil || sel.IsEmpty() {
		return nil, fmt.Errorf("selection is empty")
	}
	cs := &compiledSelection{name: sel.Name}
	switch {
	case len(sel.Alternatives) > 0:
		for i := range sel.Alternatives {
			alt, err := compileSelection(&sel.Alternatives[i])
			if err != nil {
				return nil, fmt.Errorf("alternative %d: %w", i, err)
			}
			cs.alternatives = append(cs.alternatives, alt)
		}
	case sel.IsKeywordSelection:
		for _, kw := range sel.Keywords {
			cs.keywords = append(cs.keywords, newSigmaPattern(kw, opContains, false, false))
		}
	default:
		for _, sf := range sel.Fields {
			cf, err := compileField(sf)
			if err != nil {
				return nil, fmt.Errorf("field %s: %w", sf.FieldName, err)
			}
			cs.fields = append(cs.fields, cf)
		}
	}
	return cs, nil
}

// evaluate reports whether the selection matches and, when it does, the
// names of the fields that satisfied it (for matched_fields / confidence).
func (cs *compiledSelection) evaluate(ec *eventContext) (bool, []string) {
	if len(cs.alternatives) > 0 {
		for _, alt := range cs.alternatives {
			if ok, names := alt.evaluate(ec); ok {
				return true, names
			}
		}
		return false, nil
	}
	if len(cs.keywords) > 0 {
		for _, v := range ec.event.SearchValues() {
			for _, kw := range cs.keywords {
				if kw.matchValue(v, v) {
					return true, nil
				}
			}
		}
		return false, nil
	}
	for _, f := range cs.fields {
		if !f.evaluate(ec) {
			return false, nil
		}
	}
	names := make([]string, 0, len(cs.fields))
	for _, f := range cs.fields {
		if f.keyword || (f.kind == kindExists && !f.existsWant) {
			continue // keywords / absent fields are not per-field evidence
		}
		names = append(names, f.name)
	}
	return true, names
}

// referencesField reports whether the selection (or any alternative) tests
// the given field (case-insensitive).
func (cs *compiledSelection) referencesField(name string) bool {
	for _, f := range cs.fields {
		if strings.EqualFold(f.name, name) {
			return true
		}
	}
	for _, alt := range cs.alternatives {
		if alt.referencesField(name) {
			return true
		}
	}
	return false
}
