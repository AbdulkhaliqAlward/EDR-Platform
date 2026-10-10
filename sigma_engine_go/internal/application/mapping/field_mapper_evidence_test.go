package mapping

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveFieldPreservesDecodedEvidence(t *testing.T) {
	fm := NewFieldMapper(nil)
	for _, value := range []string{`\\server\share\payload.exe`, `\\.\C:`, `New-Object IO.FileStream "\\.\C:"`, `pattern = '\\w+'`} {
		for _, tc := range []struct {
			field string
			event map[string]interface{}
		}{
			{"ScriptBlockText", map[string]interface{}{"ScriptBlockText": value}},
			{"ScriptBlockText", map[string]interface{}{"data": map[string]interface{}{"script_block_text": value}}},
			{"Image", map[string]interface{}{"process": map[string]interface{}{"executable": value}}},
			{"CommandLine", map[string]interface{}{"data": map[string]interface{}{"command_line": value}}},
		} {
			wire, err := json.Marshal(tc.event)
			require.NoError(t, err)
			var decoded map[string]interface{}
			require.NoError(t, json.Unmarshal(wire, &decoded))
			got, _, err := fm.ResolveField(decoded, tc.field)
			require.NoError(t, err)
			require.Equal(t, value, got, "must not unescape JSON-decoded %s a second time", tc.field)
		}
	}
}
