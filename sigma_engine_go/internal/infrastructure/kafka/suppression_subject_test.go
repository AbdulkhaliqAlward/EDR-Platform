package kafka

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/edr-platform/sigma-engine/internal/domain"
)

func subjectOf(t *testing.T, eventType string, data map[string]interface{}) string {
	t.Helper()
	ev, err := domain.NewLogEvent(map[string]interface{}{"event_type": eventType, "data": data})
	require.NoError(t, err)
	return suppressionSubject(ev)
}

func TestSuppressionSubject_DistinguishesTargets(t *testing.T) {
	// Same process, different DNS names → different subjects (previously
	// these collided because DNS events have no "name"/"pid" variance).
	a := subjectOf(t, "dns", map[string]interface{}{"pid": float64(10), "query_name": "a.example"})
	b := subjectOf(t, "dns", map[string]interface{}{"pid": float64(10), "query_name": "b.example"})
	assert.NotEqual(t, a, b)

	n1 := subjectOf(t, "network", map[string]interface{}{"name": "x.exe", "pid": float64(1), "destination_ip": "1.1.1.1", "destination_port": float64(443)})
	n2 := subjectOf(t, "network", map[string]interface{}{"name": "x.exe", "pid": float64(1), "destination_ip": "1.1.1.1", "destination_port": float64(80)})
	assert.NotEqual(t, n1, n2)

	f1 := subjectOf(t, "file", map[string]interface{}{"process_name": "x.exe", "name": "a.txt", "pid": float64(1), "action": "created", "path": `C:\a.txt`})
	f2 := subjectOf(t, "file", map[string]interface{}{"process_name": "x.exe", "name": "b.txt", "pid": float64(1), "action": "created", "path": `C:\b.txt`})
	assert.NotEqual(t, f1, f2)
	assert.Contains(t, f1, "x.exe", "file events key on the acting process, not the file name")
}

func TestSuppressionSubject_SameActivityCollapses(t *testing.T) {
	a := subjectOf(t, "registry", map[string]interface{}{"process_name": "x.exe", "pid": float64(5), "action": "value_set", "TargetObject": `HKLM\Run\A`})
	b := subjectOf(t, "registry", map[string]interface{}{"process_name": "x.exe", "pid": float64(5), "action": "value_set", "TargetObject": `HKLM\Run\A`})
	assert.Equal(t, a, b)
}
