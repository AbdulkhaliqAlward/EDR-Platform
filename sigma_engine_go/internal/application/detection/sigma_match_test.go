package detection

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edr-platform/sigma-engine/internal/application/mapping"
	"github.com/edr-platform/sigma-engine/internal/application/rules"
	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/cache"
)

// ── pattern semantics ────────────────────────────────────────────────────────

func TestSigmaPattern_WildcardsAndEscapes(t *testing.T) {
	cases := []struct {
		raw   string
		op    stringOp
		value string
		want  bool
	}{
		{`C:\Windows\System32\cmd.exe`, opEquals, `c:\windows\system32\CMD.EXE`, true}, // case-insensitive
		// Per the Sigma spec a backslash before '*' escapes it, so a path
		// separator followed by a wildcard is written as \\*.
		{`C:\Users\\*\AppData\\*.exe`, opEquals, `C:\Users\bob\AppData\x.exe`, true}, // internal wildcards
		{`C:\Users\\*\AppData\\*.exe`, opEquals, `C:\Users\bob\Temp\x.exe`, false},
		{`C:\Users\*\AppData`, opEquals, `C:\Users*\AppData`, true}, // \* is a literal star
		{`C:\Users\*\AppData`, opEquals, `C:\Users\bob\AppData`, false},
		{`ab?d`, opEquals, `abcd`, true},
		{`ab?d`, opEquals, `abd`, false},
		{`(objectclass=\*)`, opEquals, `(objectclass=*)`, true}, // \* is a literal star
		{`(objectclass=\*)`, opEquals, `(objectclass=x)`, false},
		{`\\\?\?\C:Windows`, opContains, `x \??\C:Windows y`, true}, // \\ -> \, \? -> ?
		{`\\*\IPC$`, opEquals, `\\server\IPC$`, true},               // \\ then wildcard
		{`\cmd.exe`, opEndsWith, `C:\Windows\System32\cmd.exe`, true},
		{`-enc`, opContains, `powershell -ENC abc`, true},
		{`C:\Windows\`, opStartsWith, `c:\windows\temp\a`, true},
		{``, opEquals, ``, true},
		{``, opEquals, `x`, false},
	}
	for _, c := range cases {
		p := newSigmaPattern(c.raw, c.op, false, false)
		got := p.matchValue(c.value, strings.ToLower(c.value))
		assert.Equalf(t, c.want, got, "pattern %q op %d value %q", c.raw, c.op, c.value)
	}
}

func TestSigmaPattern_Cased(t *testing.T) {
	p := newSigmaPattern("Abc", opContains, true, false)
	assert.True(t, p.matchValue("xxAbcxx", "xxabcxx"))
	assert.False(t, p.matchValue("xxabcxx", "xxabcxx"))
}

func TestGlobMatch_Unicode(t *testing.T) {
	p := newSigmaPattern("caf?", opEquals, false, false)
	assert.True(t, p.matchValue("café", "café")) // ? consumes one rune, not one byte
}

// ── transformations ──────────────────────────────────────────────────────────

func TestWindashVariants(t *testing.T) {
	v := windashVariants(" -enc ")
	assert.Len(t, v, 5)
	assert.Contains(t, v, " /enc ")
	assert.Contains(t, v, " \u2013enc ")
	// A dash inside a word is not a flag.
	assert.Equal(t, []string{"x-y"}, windashVariants("x-y"))
}

// TestBase64Offset verifies the defining property: for any position of the
// value inside a larger byte string, one variant is a substring of the
// encoded string.
func TestBase64Offset(t *testing.T) {
	val := []byte("Invoke-Mimikatz")
	variants := base64OffsetVariants(val)
	require.Len(t, variants, 3)
	for prefix := 0; prefix < 6; prefix++ {
		for suffix := 0; suffix < 4; suffix++ {
			data := append(append([]byte(strings.Repeat("A", prefix)), val...), []byte(strings.Repeat("B", suffix))...)
			enc := base64.StdEncoding.EncodeToString(data)
			found := false
			for _, v := range variants {
				if strings.Contains(enc, v) {
					found = true
				}
			}
			assert.Truef(t, found, "prefix=%d suffix=%d enc=%s variants=%v", prefix, suffix, enc, variants)
		}
	}
}

func TestCompileField_WideBase64OffsetMatchesEncodedPowerShell(t *testing.T) {
	cf, err := compileField(domain.SelectionField{
		FieldName: "CommandLine",
		Modifiers: []string{"wide", "base64offset", "contains"},
		Values:    []interface{}{"IEX"},
	})
	require.NoError(t, err)
	script := utf16Bytes("$x=1; IEX (New-Object Net.WebClient)", false, false)
	cmd := "powershell -enc " + base64.StdEncoding.EncodeToString([]byte(script))
	ec := testContext(t, map[string]interface{}{"data": map[string]interface{}{"command_line": cmd}})
	assert.True(t, cf.evaluate(ec))
}

func TestCompileField_Errors(t *testing.T) {
	bad := []domain.SelectionField{
		{FieldName: "A", Modifiers: []string{"bogus"}, Values: []interface{}{"x"}},
		{FieldName: "A", Modifiers: []string{"contains", "startswith"}, Values: []interface{}{"x"}},
		{FieldName: "A", Modifiers: []string{"expand"}, Values: []interface{}{"%x%"}},
		{FieldName: "A", Modifiers: []string{"re"}, Values: []interface{}{"(?<=x)y"}}, // lookbehind unsupported in RE2
		{FieldName: "A", Modifiers: []string{"base64", "contains"}, Values: []interface{}{"a*b"}},
		{FieldName: "A", Modifiers: []string{"i"}, Values: []interface{}{"x"}},
		{FieldName: "A", Modifiers: []string{"cidr"}, Values: []interface{}{"10.0.0.0/33"}},
		{FieldName: "A", Modifiers: []string{"exists"}, Values: []interface{}{"yes"}},
		{FieldName: "A", Modifiers: []string{"contains"}, Values: []interface{}{nil}},
	}
	for _, sf := range bad {
		_, err := compileField(sf)
		assert.Errorf(t, err, "expected error for modifiers %v values %v", sf.Modifiers, sf.Values)
	}
}

// ── field semantics ──────────────────────────────────────────────────────────

func testContext(t *testing.T, raw map[string]interface{}) *eventContext {
	t.Helper()
	fc, err := cache.NewFieldResolutionCache(64)
	require.NoError(t, err)
	ev, err := domain.NewLogEvent(raw)
	require.NoError(t, err)
	return newEventContext(ev, mapping.NewFieldMapper(fc))
}

func evalField(t *testing.T, sf domain.SelectionField, raw map[string]interface{}) bool {
	t.Helper()
	cf, err := compileField(sf)
	require.NoError(t, err)
	return cf.evaluate(testContext(t, raw))
}

func TestFieldSemantics(t *testing.T) {
	ev := map[string]interface{}{"data": map[string]interface{}{
		"command_line":   "cmd.exe /c whoami",
		"executable":     `C:\Windows\System32\cmd.exe`,
		"destination_ip": "10.1.2.3",
		"pid":            float64(4688),
	}}

	// null matches only when the field is absent
	assert.True(t, evalField(t, domain.SelectionField{FieldName: "OriginalFileName", Values: []interface{}{nil}}, ev))
	assert.False(t, evalField(t, domain.SelectionField{FieldName: "CommandLine", Values: []interface{}{nil}}, ev))

	// exists
	assert.True(t, evalField(t, domain.SelectionField{FieldName: "CommandLine", Modifiers: []string{"exists"}, Values: []interface{}{true}}, ev))
	assert.True(t, evalField(t, domain.SelectionField{FieldName: "Hashes", Modifiers: []string{"exists"}, Values: []interface{}{false}}, ev))

	// all
	assert.True(t, evalField(t, domain.SelectionField{FieldName: "CommandLine", Modifiers: []string{"contains", "all"}, Values: []interface{}{"cmd", "whoami"}}, ev))
	assert.False(t, evalField(t, domain.SelectionField{FieldName: "CommandLine", Modifiers: []string{"contains", "all"}, Values: []interface{}{"cmd", "net user"}}, ev))

	// windash
	assert.True(t, evalField(t, domain.SelectionField{FieldName: "CommandLine", Modifiers: []string{"contains", "windash"}, Values: []interface{}{" -c "}}, ev))

	// regex is case-sensitive by default; |i makes it insensitive
	assert.False(t, evalField(t, domain.SelectionField{FieldName: "CommandLine", Modifiers: []string{"re"}, Values: []interface{}{"WHOAMI$"}}, ev))
	assert.True(t, evalField(t, domain.SelectionField{FieldName: "CommandLine", Modifiers: []string{"re", "i"}, Values: []interface{}{"WHOAMI$"}}, ev))

	// cidr and numeric
	assert.True(t, evalField(t, domain.SelectionField{FieldName: "DestinationIp", Modifiers: []string{"cidr"}, Values: []interface{}{"10.0.0.0/8"}}, ev))
	assert.True(t, evalField(t, domain.SelectionField{FieldName: "data.pid", Modifiers: []string{"gte"}, Values: []interface{}{4000}}, ev))

	// integral floats render without exponent
	assert.True(t, evalField(t, domain.SelectionField{FieldName: "data.pid", Values: []interface{}{4688}}, ev))
}

// ── end-to-end through parser + engine ───────────────────────────────────────

func loadRuleYAML(t *testing.T, yml string) *domain.SigmaRule {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rule.yml")
	require.NoError(t, os.WriteFile(p, []byte(yml), 0o600))
	r, err := rules.NewRuleParser(false).ParseFile(p)
	require.NoError(t, err)
	return r
}

func newTestEngine(t *testing.T, rs ...*domain.SigmaRule) *SigmaDetectionEngine {
	t.Helper()
	fc, err := cache.NewFieldResolutionCache(64)
	require.NoError(t, err)
	e := NewSigmaDetectionEngine(mapping.NewFieldMapper(fc), NewModifierRegistry(nil), fc,
		QualityConfig{MinConfidence: 0.6, EnableFilters: true, EnableContextValidation: true})
	require.NoError(t, e.LoadRules(rs))
	return e
}

func agentEvent(t *testing.T, eventType string, data map[string]interface{}) *domain.LogEvent {
	t.Helper()
	ev, err := domain.NewLogEvent(map[string]interface{}{
		"event_id":   "6f1c2d3e-0000-4000-8000-000000000001",
		"event_type": eventType,
		"timestamp":  "2026-10-07T10:00:00Z",
		"data":       data,
	})
	require.NoError(t, err)
	return ev
}

const ruleHeader = "title: Test rule for engine\nid: %s\nstatus: test\nlevel: high\nlogsource:\n  product: windows\n  category: %s\n"

func rule(t *testing.T, id, category, detection string) *domain.SigmaRule {
	return loadRuleYAML(t, strings.Replace(strings.Replace(ruleHeader, "%s", id, 1), "%s", category, 1)+detection)
}

func TestEngine_OneOfAndListOfMaps(t *testing.T) {
	r := rule(t, "a0000000-0000-4000-8000-000000000001", "process_creation", `detection:
  selection_img:
    - Image|endswith: '\rundll32.exe'
    - OriginalFileName: 'RUNDLL32.EXE'
  selection_cli:
    CommandLine|contains: 'javascript:'
  condition: all of selection_*
`)
	e := newTestEngine(t, r)
	hit := agentEvent(t, "process", map[string]interface{}{
		"action": "process_creation", "executable": `C:\Windows\System32\rundll32.exe`,
		"command_line": `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"`,
	})
	res := e.DetectAggregated(hit)
	require.Equal(t, 1, len(res.Matches), "list-of-maps + 'all of' rule must match")
	assert.Contains(t, res.Matches[0].MatchedFields, "Image")

	miss := agentEvent(t, "process", map[string]interface{}{
		"action": "process_creation", "executable": `C:\Windows\System32\notepad.exe`,
		"command_line": `notepad javascript:`,
	})
	assert.Empty(t, e.DetectAggregated(miss).Matches)
}

func TestEngine_EventIDNeverMatchesRecordUUID(t *testing.T) {
	r := rule(t, "a0000000-0000-4000-8000-000000000002", "process_creation", `detection:
  selection:
    EventID: 1
    Image|endswith: '\cmd.exe'
  condition: selection
`)
	e := newTestEngine(t, r)
	// Agent ETW event: record UUID only, no provider code → must not match EventID 1.
	ev := agentEvent(t, "process", map[string]interface{}{"action": "process_creation", "executable": `C:\x\cmd.exe`})
	assert.Equal(t, "6f1c2d3e-0000-4000-8000-000000000001", *ev.EventID, "record identity preserved for alert linking")
	assert.Nil(t, ev.EventCode)
	assert.Empty(t, e.DetectAggregated(ev).Matches)

	// Event that carries a real provider code matches.
	ev2 := agentEvent(t, "process", map[string]interface{}{"action": "process_creation", "executable": `C:\x\cmd.exe`, "event_id": "1"})
	require.NotNil(t, ev2.EventCode)
	assert.Equal(t, 1, *ev2.EventCode)
	assert.Len(t, e.DetectAggregated(ev2).Matches, 1)
}

func TestEngine_CategoryRouting(t *testing.T) {
	regEvent := rule(t, "a0000000-0000-4000-8000-000000000003", "registry_event", `detection:
  selection:
    TargetObject|contains: '\CurrentVersion\Run'
  condition: selection
`)
	regSet := rule(t, "a0000000-0000-4000-8000-000000000004", "registry_set", `detection:
  selection:
    TargetObject|contains: '\CurrentVersion\Run'
  condition: selection
`)
	procCreate := rule(t, "a0000000-0000-4000-8000-000000000005", "process_creation", `detection:
  selection:
    Image|endswith: '\evil.exe'
  condition: selection
`)
	e := newTestEngine(t, regEvent, regSet, procCreate)

	set := agentEvent(t, "registry", map[string]interface{}{"action": "value_set", "target_object": `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\x`})
	assert.Equal(t, domain.EventCategoryRegistrySet, set.Category)
	assert.Len(t, e.DetectAggregated(set).Matches, 2, "registry_set reaches registry_set AND registry_event rules")

	term := agentEvent(t, "process", map[string]interface{}{"action": "process_termination", "executable": `C:\x\evil.exe`})
	assert.Equal(t, domain.EventCategoryProcessTermination, term.Category)
	assert.Empty(t, e.DetectAggregated(term).Matches, "termination must not hit process_creation rules")
}

func TestEngine_ConfidenceNotDeflatedBySharedFieldBranch(t *testing.T) {
	// The unmatched branch shares Image with the matched one; previously its
	// fields inflated the denominator and dropped the alert below 0.6.
	r := rule(t, "a0000000-0000-4000-8000-000000000006", "process_creation", `detection:
  selection_a:
    Image|endswith: '\a.exe'
  selection_b:
    Image|endswith: '\b.exe'
    CommandLine|contains: 'x'
    ParentImage|endswith: '\p.exe'
  condition: 1 of selection_*
`)
	e := newTestEngine(t, r)
	ev := agentEvent(t, "process", map[string]interface{}{"action": "process_creation", "executable": `C:\a.exe`, "command_line": "a", "parent_executable": `C:\explorer.exe`})
	res := e.DetectAggregated(ev)
	require.Len(t, res.Matches, 1)
	assert.InDelta(t, 0.85, res.Matches[0].Confidence, 0.0001)
}

func TestEngine_FilterSemantics(t *testing.T) {
	// Referenced filter: the condition decides.
	referenced := rule(t, "a0000000-0000-4000-8000-000000000007", "process_creation", `detection:
  selection:
    Image|endswith: '\cmd.exe'
  filter_main:
    ParentImage|endswith: '\explorer.exe'
  condition: selection and not filter_main
`)
	// Unreferenced filter: applied as suppression only because EnableFilters is on.
	unreferenced := rule(t, "a0000000-0000-4000-8000-000000000008", "process_creation", `detection:
  selection:
    Image|endswith: '\cmd.exe'
  filter_extra:
    CommandLine|contains: 'benign'
  condition: selection
`)
	e := newTestEngine(t, referenced, unreferenced)
	ev := agentEvent(t, "process", map[string]interface{}{"action": "process_creation", "executable": `C:\cmd.exe`, "parent_executable": `C:\explorer.exe`, "command_line": "cmd benign"})
	assert.Empty(t, e.DetectAggregated(ev).Matches)

	ev2 := agentEvent(t, "process", map[string]interface{}{"action": "process_creation", "executable": `C:\cmd.exe`, "parent_executable": `C:\winword.exe`, "command_line": "cmd /c calc"})
	assert.Len(t, e.DetectAggregated(ev2).Matches, 2)
}

func TestEngine_KeywordsMatchRawBackslashes(t *testing.T) {
	r := rule(t, "a0000000-0000-4000-8000-000000000009", "process_creation", `detection:
  keywords:
    - '\AppData\Local\Temp\\*.ps1'
  condition: keywords
`)
	e := newTestEngine(t, r)
	ev := agentEvent(t, "process", map[string]interface{}{"action": "process_creation", "command_line": `powershell -f C:\Users\a\AppData\Local\Temp\run.ps1`})
	assert.Len(t, e.DetectAggregated(ev).Matches, 1)
}

func TestEngine_InvalidRulesRejectedNotLoaded(t *testing.T) {
	good := rule(t, "a0000000-0000-4000-8000-00000000000a", "process_creation", `detection:
  selection:
    Image|endswith: '\cmd.exe'
  condition: selection
`)
	bad := rule(t, "a0000000-0000-4000-8000-00000000000b", "process_creation", `detection:
  selection:
    Image|bogusmodifier: 'x'
  condition: selection
`)
	e := newTestEngine(t, good, bad)
	assert.Equal(t, 1, e.RuleCount())
}

func TestRuleIndexer_RemoveRuleDoesNotDuplicate(t *testing.T) {
	a := rule(t, "a0000000-0000-4000-8000-00000000000c", "process_creation", "detection:\n  selection:\n    Image: a\n  condition: selection\n")
	b := rule(t, "a0000000-0000-4000-8000-00000000000d", "process_creation", "detection:\n  selection:\n    Image: b\n  condition: selection\n")
	c := rule(t, "a0000000-0000-4000-8000-00000000000e", "process_creation", "detection:\n  selection:\n    Image: c\n  condition: selection\n")
	idx := rules.NewRuleIndexer()
	idx.BuildIndex([]*domain.SigmaRule{a, b, c})
	require.NoError(t, idx.RemoveRule(a.ID))
	got := idx.GetCandidateRules("windows", []string{"process_creation"}, "")
	ids := []string{}
	for _, r := range got {
		ids = append(ids, r.ID)
	}
	assert.ElementsMatch(t, []string{b.ID, c.ID}, ids)
}
