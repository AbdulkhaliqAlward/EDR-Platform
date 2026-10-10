-- Local discovery is ambiguous administrative activity. Collect bounded evidence;
-- never terminate or isolate solely because an account query matched.
INSERT INTO response_playbooks
    (id, name, description, category, severity_filter, commands, mitre_techniques, enabled)
VALUES
    ('1e13819d-8d38-44e9-8f74-8ab945e85835', 'MITRAS - Investigate local account discovery',
     'Collect up to 200 events per channel (Security, Windows PowerShell and PowerShell Core) from the preceding 15 minutes. No containment. Requires the server automation switch and an online endpoint.',
     'investigation', ARRAY['medium','high','critical'],
     '[{"type":"collect_logs","params":{"log_types":"Security,Microsoft-Windows-PowerShell/Operational,PowerShellCore/Operational","time_range":"15m","max_events":"200"},"timeout":60}]'::jsonb,
     ARRAY['T1087.001','T1069.001'], true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO automation_rules
    (id, name, description, trigger_conditions, playbook_id, priority, auto_execute, cooldown_minutes, enabled)
VALUES
    ('56956211-fd47-49a1-ad67-7d6586e7d61a', 'MITRAS - Local discovery evidence collection',
     'Investigate exact MITRAS local discovery rule matches at most once per endpoint per 30 minutes. Global automation settings and existing response coordination still apply.',
     '{"rule_ids":["9f8f4f57-6d7e-4d23-a60a-319f7c36910a","bcc784ca-8489-4b37-938b-b0929df6b996","2b39a76c-d927-443d-93ac-2e8c0770b8cb"]}'::jsonb,
     '1e13819d-8d38-44e9-8f74-8ab945e85835', 200, true, 30, true)
ON CONFLICT (id) DO NOTHING;
