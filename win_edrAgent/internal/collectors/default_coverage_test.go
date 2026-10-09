package collectors

import (
	"github.com/edr-platform/win-agent/internal/config"
	"github.com/edr-platform/win-agent/internal/event"
	"testing"
)

func TestDefaultFiltersRetainTempAndMasqueradingEvidence(t *testing.T) {
	cfg := config.DefaultConfig().Filtering
	f := NewFilter(FilterConfig{ExcludeProcesses: cfg.ExcludeProcesses, ExcludePaths: cfg.ExcludePaths, IncludePaths: cfg.IncludePaths}, nil)
	for _, name := range []string{"services.exe", "dllhost.exe", "agent.exe", "powershell.exe"} {
		for _, path := range []string{`C:\Windows\Temp\` + name, `C:\Users\user\AppData\Local\Temp\` + name} {
			if f.ShouldFilter(&event.Event{Type: event.EventTypeProcess, Data: map[string]interface{}{"name": name, "executable": path}}) {
				t.Errorf("lost process evidence: %s", path)
			}
			if f.ShouldFilter(&event.Event{Type: event.EventTypeFile, Data: map[string]interface{}{"path": path}}) {
				t.Errorf("lost file evidence: %s", path)
			}
		}
	}
}
