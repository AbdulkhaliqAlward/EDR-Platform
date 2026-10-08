import { useState, useEffect, useRef, useCallback } from 'react';
import { useLocation, useSearchParams } from 'react-router-dom';
import { AlertContextPanel } from '../../components/automation/AlertContextPanel';
import { UserAssistant } from '../../components/automation/UserAssistant';
import { PlaybookRunPanel } from '../../components/automation/PlaybookRunPanel';
import { apiErrorMessage } from '../../api/apiError';
import { Play, Shield, Clock, TrendingUp, AlertTriangle, Plus, Terminal, X, Target, Trash2, Filter, Zap, ToggleRight, ChevronUp, ChevronDown, Pencil, History } from 'lucide-react';
import {
  automationApi, agentsApi, alertsApi,
  type ResponseCatalog, type ResponseAction, type PlaybookSuggestion, type PlaybookExecution, type PlaybookInput,
} from '../../api/client';

// Windows event log channels available for collection.
// These are the exact channel names accepted by wevtutil / Get-WinEvent.
const LOG_TYPE_OPTIONS = [
  { value: 'System',      label: 'System',      desc: 'OS & driver events' },
  { value: 'Security',    label: 'Security',    desc: 'Logon, audit & access' },
  { value: 'Application', label: 'Application', desc: 'App-level events' },
  { value: 'Microsoft-Windows-Sysmon/Operational', label: 'Sysmon', desc: 'Process, network, file' },
  { value: 'Microsoft-Windows-PowerShell/Operational', label: 'PowerShell', desc: 'PS script activity' },
  { value: 'Microsoft-Windows-TaskScheduler/Operational', label: 'Task Scheduler', desc: 'Scheduled task events' },
  { value: 'Microsoft-Windows-Windows Defender/Operational', label: 'Defender', desc: 'AV detections' },
];

const ACTION_GROUPS = ['Containment', 'Investigation', 'Remediation', 'Validation'];

// Old step type names still found in stored playbooks (mirrors the server's
// response.CanonicalType); saved back under the catalog name.
const LEGACY_TYPES: Record<string, string> = {
  process_terminate: 'terminate_process',
  kill_process: 'terminate_process',
  network_isolate: 'isolate_network',
  isolate: 'isolate_network',
  restore_network: 'unisolate_network',
  unisolate: 'unisolate_network',
  yara_scan: 'scan_file',
  log_pull: 'collect_logs',
  forensic_dump: 'collect_forensics',
};
const canonicalType = (t: string) => LEGACY_TYPES[t] || t;

interface PlaybookStep {
  type: string;
  description: string;
  timeout: number;
  on_failure?: string;
  script_id?: string;
  params: Record<string, string>;
}

interface Playbook {
  id: string;
  name: string;
  description: string;
  category: string;
  commands: PlaybookStep[];
  mitreTechniques: string[];
  enabled: boolean;
  createdAt: string;
  severityFilter: string[];
  rulePattern: string;
}

interface DraftStep {
  key: number;
  type: string;
  description: string;
  timeout: string;
  onFailure: 'stop' | 'continue';
  scriptId: string;
  params: Record<string, string>;
}

interface AlertContext {
  alertId: string;
  alertDetails: {
    severity: string;
    ruleName: string;
    agentId: string;
    title: string;
    description?: string;
    riskScore?: number;
  };
  timestamp: string;
}

const toText = (v: unknown) => (v === undefined || v === null ? '' : String(v));

// A step as stored by the server (seeded or API-created).
interface StoredStep {
  type?: string;
  command_type?: string;
  description?: string;
  timeout?: number;
  on_failure?: string;
  script_id?: string;
  params?: Record<string, unknown>;
  parameters?: Record<string, unknown>;
}

const statusBadge: Record<string, string> = {
  completed: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400',
  partial: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400',
  failed: 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-400',
  running: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-400',
};

export function PlaybooksPage() {
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const queryAlertId = searchParams.get('alert_id') || '';

  const [alertContext, setAlertContext] = useState<AlertContext | null>(null);
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [suggestions, setSuggestions] = useState<PlaybookSuggestion[]>([]);
  const [loading, setLoading] = useState(true);
  const [catalog, setCatalog] = useState<ResponseCatalog | null>(null);
  const [agents, setAgents] = useState<{ id: string; hostname: string }[]>([]);
  const [executions, setExecutions] = useState<PlaybookExecution[]>([]);

  // Run modal
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null);
  const [agentIdInput, setAgentIdInput] = useState('');
  const [runBusy, setRunBusy] = useState(false);

  // Builder (create + edit)
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draftName, setDraftName] = useState('');
  const [draftDesc, setDraftDesc] = useState('');
  const [draftCategory, setDraftCategory] = useState('investigation');
  const [draftEnabled, setDraftEnabled] = useState(true);
  const [draftSeverities, setDraftSeverities] = useState<string[]>([]);
  const [draftRulePattern, setDraftRulePattern] = useState('');
  const [draftMitre, setDraftMitre] = useState('');
  const [draftSteps, setDraftSteps] = useState<DraftStep[]>([]);
  const [isSaving, setIsSaving] = useState(false);
  const stepKeyRef = useRef(0);

  const [viewPlaybook, setViewPlaybook] = useState<Playbook | null>(null);

  const activeAlertId = alertContext?.alertId || '';

  const actionByType = useCallback(
    (type: string): ResponseAction | undefined => catalog?.actions.find(a => a.type === type),
    [catalog],
  );
  const actionLabel = (type: string) => {
    if (type === 'run_cmd') return 'Run command (legacy)';
    return actionByType(type)?.label || type;
  };

  // Alert context: ?alert_id=… (shareable link) or router state from Alerts.
  useEffect(() => {
    const state = location.state as { alertId?: string; alertDetails?: AlertContext['alertDetails'] } | null;
    if (state?.alertId && state.alertDetails && (!queryAlertId || state.alertId === queryAlertId)) {
      setAlertContext({ alertId: state.alertId, alertDetails: state.alertDetails, timestamp: new Date().toISOString() });
      return;
    }
    if (!queryAlertId) {
      setAlertContext(null);
      return;
    }
    let cancelled = false;
    alertsApi.get(queryAlertId)
      .then(a => {
        if (cancelled) return;
        setAlertContext({
          alertId: a.id,
          alertDetails: {
            severity: a.severity, ruleName: a.rule_title, agentId: a.agent_id, title: a.rule_title,
            description: a.human_summary, riskScore: a.risk_score,
          },
          timestamp: new Date().toISOString(),
        });
      })
      .catch(() => {
        if (!cancelled) {
          setAlertContext({
            alertId: queryAlertId,
            alertDetails: { severity: 'unknown', ruleName: 'Alert', agentId: '', title: 'Alert' },
            timestamp: new Date().toISOString(),
          });
        }
      });
    return () => { cancelled = true; };
  }, [location.state, queryAlertId]);

  const fetchPlaybooks = useCallback(async () => {
    try {
      setLoading(true);
      const res = await automationApi.listPlaybooks();
      setPlaybooks((res.playbooks || []).map(p => ({
        id: p.id,
        name: p.name,
        description: p.description || '',
        category: p.category,
        commands: (Array.isArray(p.commands) ? (p.commands as StoredStep[]) : []).map(cmd => {
          // Seeded playbooks store step params under "params", API-created
          // ones under "parameters"; read both.
          const raw = cmd.params || cmd.parameters || {};
          const params: Record<string, string> = {};
          Object.entries(raw).forEach(([k, v]) => { params[k] = toText(v); });
          return {
            type: cmd.type || cmd.command_type || 'unknown',
            description: cmd.description || '',
            timeout: Number(cmd.timeout) || 300,
            on_failure: cmd.on_failure || 'stop',
            script_id: cmd.script_id || params.script_id || '',
            params,
          };
        }),
        mitreTechniques: p.mitre_techniques || [],
        enabled: !!p.enabled,
        createdAt: p.created_at || new Date().toISOString(),
        severityFilter: p.severity_filter || [],
        rulePattern: p.rule_pattern || '',
      })));
    } catch (error) {
      console.error('Failed to fetch playbooks:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchExecutions = useCallback(async () => {
    try {
      setExecutions(await automationApi.listExecutions(activeAlertId ? { alert_id: activeAlertId, limit: 20 } : { limit: 20 }));
    } catch {
      setExecutions([]);
    }
  }, [activeAlertId]);

  useEffect(() => {
    fetchPlaybooks();
    automationApi.getCatalog().then(setCatalog).catch(err => console.error('Failed to load response catalog:', err));
    agentsApi.list({ limit: 100 })
      .then(res => setAgents((res?.data || []).map(a => ({ id: a.id, hostname: a.hostname || a.id }))))
      .catch(err => console.error('Failed to fetch agents:', err));
  }, [fetchPlaybooks]);

  useEffect(() => { fetchExecutions(); }, [fetchExecutions]);

  // Server-ranked suggestions for the active alert.
  useEffect(() => {
    if (!activeAlertId) {
      setSuggestions([]);
      return;
    }
    let cancelled = false;
    automationApi.getAlertSuggestions(activeAlertId)
      .then(res => { if (!cancelled) setSuggestions(res.suggestions || []); })
      .catch(() => { if (!cancelled) setSuggestions([]); });
    return () => { cancelled = true; };
  }, [activeAlertId]);

  const handleSuggestionAction = (action: string) => {
    console.log('Suggestion action:', action);
  };

  const handleDeletePlaybook = async (playbookId: string) => {
    if (!window.confirm('Are you sure you want to delete this playbook?')) return;
    try {
      await automationApi.deletePlaybook(playbookId);
      setPlaybooks(prev => prev.filter(p => p.id !== playbookId));
      setSuggestions(prev => prev.filter(s => s.playbook_id !== playbookId));
    } catch (error) {
      alert(`Failed to delete playbook: ${apiErrorMessage(error)}`);
    }
  };

  const openRunModal = (playbook: Playbook) => {
    setSelectedPlaybook(playbook);
    setAgentIdInput(alertContext?.alertDetails?.agentId || '');
    setRunBusy(false);
  };
  const openRunById = (playbookId: string) => {
    const pb = playbooks.find(p => p.id === playbookId);
    if (pb) openRunModal(pb);
  };
  const closeRunModal = () => {
    if (runBusy && !window.confirm('The playbook keeps running on the server. Close this window?')) return;
    setSelectedPlaybook(null);
    fetchExecutions();
  };

  // ── Builder ────────────────────────────────────────────────────────────
  const newDraftStep = (type = 'isolate_network'): DraftStep => {
    stepKeyRef.current += 1;
    return { key: stepKeyRef.current, type, description: '', timeout: '300', onFailure: 'stop', scriptId: '', params: {} };
  };

  const openCreatePlaybook = () => {
    setEditingId(null);
    setDraftName('');
    setDraftDesc('');
    setDraftCategory('investigation');
    setDraftEnabled(true);
    setDraftSeverities([]);
    setDraftRulePattern('');
    setDraftMitre('');
    setDraftSteps([]);
    setEditorOpen(true);
  };

  const openEditPlaybook = (pb: Playbook) => {
    setViewPlaybook(null);
    setEditingId(pb.id);
    setDraftName(pb.name);
    setDraftDesc(pb.description);
    setDraftCategory(pb.category);
    setDraftEnabled(pb.enabled);
    setDraftSeverities(pb.severityFilter);
    setDraftRulePattern(pb.rulePattern);
    setDraftMitre(pb.mitreTechniques.join(', '));
    setDraftSteps(pb.commands.map(c => ({
      ...newDraftStep(canonicalType(c.type)),
      description: c.description,
      timeout: String(c.timeout || 300),
      onFailure: c.on_failure === 'continue' ? 'continue' : 'stop',
      scriptId: c.script_id || '',
      params: { ...c.params },
    })));
    setEditorOpen(true);
  };

  const addStep = () => setDraftSteps(prev => [...prev, newDraftStep()]);
  const updateStep = (key: number, patch: Partial<DraftStep>) =>
    setDraftSteps(prev => prev.map(s => (s.key === key ? { ...s, ...patch } : s)));
  const setStepParam = (key: number, param: string, value: string) =>
    setDraftSteps(prev => prev.map(s => (s.key === key ? { ...s, params: { ...s.params, [param]: value } } : s)));
  const moveStep = (index: number, delta: number) => {
    setDraftSteps(prev => {
      const target = index + delta;
      if (target < 0 || target >= prev.length) return prev;
      const next = [...prev];
      [next[index], next[target]] = [next[target], next[index]];
      return next;
    });
  };
  const removeStep = (key: number) => setDraftSteps(prev => prev.filter(s => s.key !== key));

  const savePlaybook = async () => {
    const problems: string[] = [];
    if (!draftName.trim()) problems.push('Name is required.');
    if (!draftDesc.trim()) problems.push('Description is required.');
    if (draftSteps.length === 0) problems.push('Add at least one action step.');
    draftSteps.forEach((s, idx) => {
      const label = `Step ${idx + 1} (${actionLabel(s.type)})`;
      const t = Number(s.timeout);
      if (!Number.isInteger(t) || t < 1 || t > 3600) problems.push(`${label}: timeout must be a whole number between 1 and 3600 seconds.`);
      if (s.type === 'run_script' && !s.scriptId) problems.push(`${label}: select a library script.`);
      (actionByType(s.type)?.params || []).forEach(p => {
        const v = (s.params[p.key] || '').trim();
        if (p.kind === 'int' && v && !/^[1-9]\d*$/.test(v)) problems.push(`${label}: ${p.label} must be a positive whole number.`);
      });
    });
    if (problems.length > 0) {
      alert(`Please fix the following:\n\n- ${problems.join('\n- ')}`);
      return;
    }

    const payload: PlaybookInput = {
      name: draftName.trim(),
      description: draftDesc.trim(),
      category: draftCategory,
      enabled: draftEnabled,
      severity_filter: draftSeverities,
      rule_pattern: draftRulePattern.trim(),
      mitre_techniques: draftMitre.split(',').map(t => t.trim().toUpperCase()).filter(Boolean),
      commands: draftSteps.map(s => {
        const base = {
          type: s.type,
          description: s.description.trim() || actionLabel(s.type),
          timeout: Number(s.timeout),
          on_failure: s.onFailure,
        };
        if (s.type === 'run_script') return { ...base, script_id: s.scriptId };
        if (s.type === 'run_cmd') return { ...base, parameters: { cmd: s.params.cmd || '' } };
        // Only the action's declared parameters, and only when set.
        const parameters: Record<string, string> = {};
        (actionByType(s.type)?.params || []).forEach(p => {
          const v = (s.params[p.key] || '').trim();
          if (v) parameters[p.key] = v;
        });
        return { ...base, parameters };
      }),
    };

    setIsSaving(true);
    try {
      if (editingId) await automationApi.updatePlaybook(editingId, payload);
      else await automationApi.createPlaybook(payload);
      setEditorOpen(false);
      fetchPlaybooks();
    } catch (err) {
      alert(`Failed to save playbook: ${apiErrorMessage(err)}`);
    } finally {
      setIsSaving(false);
    }
  };

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'containment': return 'bg-rose-100 text-rose-800 dark:bg-rose-900/20 dark:text-rose-400 border border-rose-200 dark:border-rose-800/50';
      case 'investigation': return 'bg-amber-100 text-amber-800 dark:bg-amber-900/20 dark:text-amber-400 border border-amber-200 dark:border-amber-800/50';
      case 'remediation': return 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/20 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800/50';
      case 'validation': return 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400 border border-blue-200 dark:border-blue-800/50';
      default: return 'bg-slate-100 text-slate-800 dark:bg-slate-900/20 dark:text-slate-400 border border-slate-200 dark:border-slate-700/50';
    }
  };

  const getCategoryLabel = (category: string) =>
    category ? category.charAt(0).toUpperCase() + category.slice(1) : '';

  const inputClass = 'w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-indigo-500 outline-none';

  return (
    <div className="space-y-6 relative">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-indigo-100 dark:bg-indigo-900/30 rounded-lg">
            <Terminal className="w-6 h-6 text-indigo-600 dark:text-indigo-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
              Incident Response Playbooks
            </h1>
            <p className="text-sm text-slate-500 mt-1">Workflows run by the server-side response engine on the target endpoint.</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          {alertContext && (
            <div className="flex items-center gap-2 text-sm text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-900/20 px-3 py-1.5 rounded-full border border-emerald-200 dark:border-emerald-800/50 font-medium">
              <AlertTriangle className="w-4 h-4" />
              <span>Active Alert Context</span>
            </div>
          )}
          <button onClick={openCreatePlaybook} className="btn btn-primary flex items-center gap-2">
            <Plus className="w-4 h-4" />
            Create Playbook
          </button>
        </div>
      </div>

      {/* Alert Context Panel */}
      {alertContext && (
        <AlertContextPanel
          alertId={alertContext.alertId}
          alertDetails={alertContext.alertDetails}
          onClearContext={() => setAlertContext(null)}
        />
      )}

      {/* User Assistant */}
      <UserAssistant
        alertContext={alertContext || undefined}
        onSuggestionAction={handleSuggestionAction}
      />

      {/* Suggestions for Current Alert (ranked by the server) */}
      {alertContext && suggestions.length > 0 && (
        <div className="bg-indigo-50 dark:bg-indigo-900/10 rounded-xl border border-indigo-200 dark:border-indigo-800/50 p-6 shadow-sm">
          <h3 className="text-lg font-bold text-indigo-900 dark:text-indigo-100 mb-4 flex items-center gap-2">
            <TrendingUp className="w-5 h-5" />
            Recommended Playbooks for Current Alert
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {suggestions.map((s, i) => (
              <div key={s.playbook_id} className="bg-white dark:bg-slate-800 rounded-lg border border-indigo-100 dark:border-indigo-800 p-5 shadow-sm hover:shadow-md transition-shadow flex flex-col h-full">
                <div className="flex items-center justify-between mb-3 gap-2">
                  <h4 className="font-semibold text-slate-900 dark:text-white truncate flex-1" title={s.playbook_name}>
                    {i === 0 && <span className="text-[10px] uppercase font-bold text-indigo-500 mr-1.5">Best</span>}
                    {s.playbook_name}
                  </h4>
                  <span className={`shrink-0 px-2.5 py-0.5 text-[10px] uppercase tracking-wider rounded-full font-bold ${getCategoryColor(s.category)}`}>
                    {getCategoryLabel(s.category)}
                  </span>
                </div>
                {s.reasons && s.reasons.length > 0 && (
                  <ul className="text-xs text-slate-600 dark:text-slate-400 mb-4 list-disc list-inside space-y-0.5">
                    {s.reasons.map((r, j) => <li key={j}>{r}</li>)}
                  </ul>
                )}
                <div className="mt-auto">
                  <button
                    onClick={() => openRunById(s.playbook_id)}
                    className="w-full px-4 py-2.5 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 font-medium flex items-center justify-center gap-2 transition-colors"
                  >
                    <Play className="w-4 h-4" />
                    Run Playbook
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* All Playbooks */}
      <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 shadow-sm overflow-hidden">
        <div className="p-6 border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50">
          <h2 className="text-lg font-bold text-slate-900 dark:text-white">Available Playbooks</h2>
          <p className="text-sm text-slate-500 mt-1">Standard operating procedures configured for the automation engine.</p>
        </div>

        {loading ? (
          <div className="p-12 text-center">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
            <p className="text-sm font-medium text-slate-500 mt-4">Loading playbooks...</p>
          </div>
        ) : (
          <div className="divide-y divide-slate-200 dark:divide-slate-700/80">
            {playbooks.map((playbook) => (
              <div key={playbook.id} className="p-6 hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors">
                <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-6">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <h3 className="font-bold text-lg text-slate-900 dark:text-white">{playbook.name}</h3>
                      <span className={`px-2.5 py-0.5 text-[11px] uppercase tracking-wider font-bold rounded-md ${getCategoryColor(playbook.category)}`}>
                        {getCategoryLabel(playbook.category)}
                      </span>
                    </div>
                    <p className="text-sm text-slate-600 dark:text-slate-400 mb-4 max-w-3xl">{playbook.description}</p>

                    <div className="flex flex-wrap items-center gap-3 text-xs mb-5">
                      <div
                        className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-100 dark:bg-slate-800 rounded-md text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700 cursor-help"
                        title={playbook.commands.map((c, i) => `${i + 1}. ${actionLabel(canonicalType(c.type))}`).join('\n')}
                      >
                        <Terminal className="w-3.5 h-3.5" />
                        <span className="font-semibold">{playbook.commands.length} Steps</span>
                      </div>
                      {playbook.severityFilter.length > 0 && (
                        <div className="flex items-center gap-1.5 px-2.5 py-1 bg-rose-50 dark:bg-rose-900/20 rounded-md text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-800/50">
                          <Filter className="w-3.5 h-3.5" />
                          <span className="font-semibold capitalize">Severity: {playbook.severityFilter.join(', ')}</span>
                        </div>
                      )}
                      {playbook.rulePattern && (
                        <div className="flex items-center gap-1.5 px-2.5 py-1 bg-indigo-50 dark:bg-indigo-900/20 rounded-md text-indigo-600 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-800/50">
                          <Zap className="w-3.5 h-3.5" />
                          <span className="font-semibold font-mono text-[10px] truncate max-w-[200px]" title={playbook.rulePattern}>{playbook.rulePattern}</span>
                        </div>
                      )}
                      {playbook.mitreTechniques.length > 0 && (
                        <div className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-100 dark:bg-slate-800 rounded-md text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                          <Shield className="w-3.5 h-3.5" />
                          <span className="font-semibold">{playbook.mitreTechniques.join(', ')}</span>
                        </div>
                      )}
                      <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md border ${playbook.enabled ? 'bg-emerald-50 dark:bg-emerald-900/20 text-emerald-600 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800/50' : 'bg-slate-50 dark:bg-slate-800/50 text-slate-500 border-slate-200 dark:border-slate-700'}`}>
                        <ToggleRight className="w-3.5 h-3.5" />
                        <span className="font-semibold">{playbook.enabled ? 'Enabled' : 'Disabled'}</span>
                      </div>
                      <div className="flex items-center gap-1.5 px-2.5 py-1 text-slate-500">
                        <Clock className="w-3.5 h-3.5" />
                        <span>Created {new Date(playbook.createdAt).toLocaleDateString()}</span>
                      </div>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex lg:flex-col items-center gap-3 shrink-0">
                    <button
                      onClick={() => openRunModal(playbook)}
                      disabled={!playbook.enabled}
                      title={playbook.enabled ? 'Run this playbook' : 'Enable the playbook to run it'}
                      className="px-6 py-2.5 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 font-medium flex items-center justify-center gap-2 w-full transition-colors shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <Play className="w-4 h-4" />
                      Execute
                    </button>
                    <div className="flex w-full gap-2">
                      <button
                        onClick={() => setViewPlaybook(playbook)}
                        className="flex-1 px-4 py-2 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-600 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-700 font-medium transition-colors text-sm"
                      >
                        View Details
                      </button>
                      <button
                        onClick={() => openEditPlaybook(playbook)}
                        className="px-3 py-2 bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-300 dark:border-slate-600 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-700 flex items-center justify-center"
                        title="Edit Playbook"
                      >
                        <Pencil className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleDeletePlaybook(playbook.id)}
                        className="px-3 py-2 bg-white dark:bg-slate-800 text-rose-600 dark:text-rose-400 border border-slate-300 dark:border-slate-600 rounded-lg hover:bg-rose-50 dark:hover:bg-rose-900/20 font-medium transition-colors flex items-center justify-center"
                        title="Delete Playbook"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Recent runs */}
      <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 shadow-sm overflow-hidden">
        <div className="p-6 border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <History className="w-5 h-5" /> Recent Runs{activeAlertId ? ' for this Alert' : ''}
            </h2>
            <p className="text-sm text-slate-500 mt-1">Manual and automated playbook executions recorded by the server.</p>
          </div>
          <button onClick={fetchExecutions} className="text-sm text-indigo-600 dark:text-indigo-400 hover:underline">Refresh</button>
        </div>
        {executions.length === 0 ? (
          <p className="p-6 text-sm text-slate-500">No runs yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-xs uppercase text-slate-500 bg-slate-50 dark:bg-slate-900/40">
                <tr>
                  <th className="text-left px-6 py-2">Playbook</th>
                  <th className="text-left px-3 py-2">Status</th>
                  <th className="text-left px-3 py-2">Trigger</th>
                  <th className="text-left px-3 py-2">Steps</th>
                  <th className="text-left px-3 py-2">Started</th>
                  <th className="text-left px-3 py-2">By</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-700/80">
                {executions.map(e => (
                  <tr key={e.id}>
                    <td className="px-6 py-2 text-slate-800 dark:text-slate-200">
                      {e.playbook_name || e.playbook_id}
                      {e.error_message && <div className="text-xs text-rose-600 dark:text-rose-400 truncate max-w-md" title={e.error_message}>{e.error_message}</div>}
                    </td>
                    <td className="px-3 py-2"><span className={`px-2 py-0.5 rounded text-xs font-semibold ${statusBadge[e.status] || 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300'}`}>{e.status}</span></td>
                    <td className="px-3 py-2 text-slate-600 dark:text-slate-400">{e.trigger_source}</td>
                    <td className="px-3 py-2 text-slate-600 dark:text-slate-400">{e.commands_executed}/{e.commands_total}</td>
                    <td className="px-3 py-2 text-slate-600 dark:text-slate-400">{new Date(e.started_at).toLocaleString()}</td>
                    <td className="px-3 py-2 text-slate-600 dark:text-slate-400">{e.created_by_username || (e.trigger_source === 'automation' ? 'automation' : '—')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Run Modal (server-side execution) */}
      {selectedPlaybook && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl w-full max-w-2xl flex flex-col border border-slate-200 dark:border-slate-800" style={{ maxHeight: '92vh' }}>
            <div className="flex items-center justify-between p-6 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/30">
              <div>
                <h2 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <Play className="w-5 h-5 text-indigo-500" />
                  Run Playbook
                </h2>
                <p className="text-sm text-slate-500 mt-1">{selectedPlaybook.name}</p>
              </div>
              <button onClick={closeRunModal} className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-800 transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="overflow-y-auto flex-1 p-6 space-y-5">
              {!activeAlertId && (
                <div>
                  <label className="block text-sm font-bold text-slate-700 dark:text-slate-300 mb-2">
                    Target Agent <span className="text-rose-500">*</span>
                  </label>
                  <div className="relative">
                    <select
                      value={agentIdInput}
                      onChange={(e) => setAgentIdInput(e.target.value)}
                      disabled={runBusy}
                      className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-3 text-slate-900 dark:text-white focus:ring-2 focus:ring-indigo-500 outline-none appearance-none pl-10"
                    >
                      <option value="" disabled>Select Target Agent</option>
                      {agents.map(a => (
                        <option key={a.id} value={a.id}>{a.hostname} ({a.id})</option>
                      ))}
                    </select>
                    <Target className="w-5 h-5 text-slate-400 absolute left-3 top-3.5" />
                  </div>
                  <p className="text-xs text-slate-500 mt-2">Without an alert, steps that need alert values (PID, file, IP) must be filled in below.</p>
                </div>
              )}
              <PlaybookRunPanel
                playbookId={selectedPlaybook.id}
                alertId={activeAlertId || undefined}
                agentId={activeAlertId ? undefined : (agentIdInput || undefined)}
                onStarted={() => setRunBusy(true)}
                onFinished={() => { setRunBusy(false); fetchExecutions(); }}
              />
            </div>

            <div className="flex items-center justify-end gap-3 p-6 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/30">
              <button onClick={closeRunModal} className="px-5 py-2.5 font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-800 rounded-lg transition-colors">
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create / Edit Playbook Modal */}
      {editorOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl w-full max-w-3xl flex flex-col border border-slate-200 dark:border-slate-800" style={{ maxHeight: '92vh' }}>
            <div className="flex items-center justify-between p-6 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/30 shrink-0">
              <div>
                <h2 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-indigo-500" />
                  {editingId ? 'Edit Response Playbook' : 'Create Response Playbook'}
                </h2>
                <p className="text-sm text-slate-500 mt-1">Steps use approved actions and library scripts only.</p>
              </div>
              <button onClick={() => setEditorOpen(false)} className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-800 transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-5 overflow-y-auto flex-1">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="sm:col-span-2">
                  <label className="block text-sm font-bold text-slate-700 dark:text-slate-300 mb-2">Playbook Name <span className="text-rose-500">*</span></label>
                  <input type="text" value={draftName} maxLength={255} onChange={e => setDraftName(e.target.value)} placeholder="e.g., Critical Database Isolation" className={inputClass} />
                </div>
                <div>
                  <label className="block text-sm font-bold text-slate-700 dark:text-slate-300 mb-2">Category</label>
                  <select value={draftCategory} onChange={e => setDraftCategory(e.target.value)} className={inputClass}>
                    <option value="containment">Containment</option>
                    <option value="investigation">Investigation</option>
                    <option value="remediation">Remediation</option>
                    <option value="validation">Validation</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-bold text-slate-700 dark:text-slate-300 mb-2">Description <span className="text-rose-500">*</span></label>
                <textarea value={draftDesc} onChange={e => setDraftDesc(e.target.value)} placeholder="Describe the purpose of this playbook..." className={`${inputClass} h-20`} />
              </div>

              {/* Matching hints used to suggest this playbook for alerts */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Suggest for severities</label>
                  <div className="flex flex-wrap gap-1.5">
                    {['critical', 'high', 'medium', 'low'].map(sev => {
                      const on = draftSeverities.includes(sev);
                      return (
                        <button key={sev} type="button"
                          onClick={() => setDraftSeverities(prev => on ? prev.filter(s => s !== sev) : [...prev, sev])}
                          className={`px-2.5 py-1 rounded-md border text-xs font-medium capitalize ${on ? 'bg-indigo-600 border-indigo-600 text-white' : 'bg-white dark:bg-slate-900 border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300'}`}>
                          {sev}
                        </button>
                      );
                    })}
                  </div>
                </div>
                <div className="flex items-end">
                  <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
                    <input type="checkbox" checked={draftEnabled} onChange={e => setDraftEnabled(e.target.checked)} />
                    Enabled (disabled playbooks never run)
                  </label>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Rule title pattern (regex, optional)</label>
                  <input type="text" value={draftRulePattern} maxLength={500} onChange={e => setDraftRulePattern(e.target.value)} placeholder="e.g., (?i)ransomware|vssadmin" className={`${inputClass} font-mono`} />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">MITRE techniques (comma separated)</label>
                  <input type="text" value={draftMitre} onChange={e => setDraftMitre(e.target.value)} placeholder="e.g., T1486, T1490" className={`${inputClass} font-mono`} />
                </div>
              </div>

              {/* Action steps */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="block text-sm font-bold text-slate-700 dark:text-slate-300">Action Steps <span className="text-rose-500">*</span></label>
                  <span className="text-xs text-slate-500">Steps run in order on the alert's endpoint.</span>
                </div>
                {catalog && catalog.variables.length > 0 && (
                  <p className="text-xs text-slate-500 mb-2">
                    Parameters may use alert values, e.g. <code className="font-mono text-indigo-600 dark:text-indigo-400">{'{{alert.file_path}}'}</code>. Empty parameters are filled from the alert when possible.
                  </p>
                )}

                {draftSteps.length === 0 && (
                  <div className="text-sm text-slate-500 border border-dashed border-slate-300 dark:border-slate-700 rounded-lg p-4 text-center">
                    No steps yet. Add the first action this playbook should perform.
                  </div>
                )}

                <div className="space-y-3">
                  {draftSteps.map((step, idx) => {
                    const action = actionByType(step.type);
                    const isLegacyCmd = step.type === 'run_cmd';
                    return (
                      <div key={step.key} className="border border-slate-200 dark:border-slate-700 rounded-xl p-4 bg-slate-50/60 dark:bg-slate-950/40">
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center gap-2">
                            <span className="flex items-center justify-center w-6 h-6 rounded-full text-xs font-bold bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-400">{idx + 1}</span>
                            <span className="text-sm font-semibold text-slate-800 dark:text-slate-200">{actionLabel(step.type)}</span>
                            {action?.destructive && <span className="text-[10px] uppercase font-bold text-rose-500">destructive</span>}
                          </div>
                          <div className="flex items-center gap-1">
                            <button type="button" onClick={() => moveStep(idx, -1)} disabled={idx === 0}
                              className="p-1.5 rounded-md text-slate-500 hover:bg-slate-200 dark:hover:bg-slate-800 disabled:opacity-30 disabled:cursor-not-allowed" title="Move up">
                              <ChevronUp className="w-4 h-4" />
                            </button>
                            <button type="button" onClick={() => moveStep(idx, 1)} disabled={idx === draftSteps.length - 1}
                              className="p-1.5 rounded-md text-slate-500 hover:bg-slate-200 dark:hover:bg-slate-800 disabled:opacity-30 disabled:cursor-not-allowed" title="Move down">
                              <ChevronDown className="w-4 h-4" />
                            </button>
                            <button type="button" onClick={() => removeStep(step.key)}
                              className="p-1.5 rounded-md text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-900/20" title="Remove step">
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                          <div className="sm:col-span-2">
                            <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Action</label>
                            {isLegacyCmd ? (
                              <div className="text-xs text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/10 border border-amber-200 dark:border-amber-800/50 rounded-lg px-3 py-2">
                                Legacy free-text command — only administrators can save it. Prefer a library script.
                              </div>
                            ) : (
                              <select
                                value={step.type}
                                onChange={e => updateStep(step.key, { type: e.target.value, params: {}, scriptId: '' })}
                                className={inputClass}
                              >
                                {!action && <option value={step.type}>{step.type} (unsupported)</option>}
                                {ACTION_GROUPS.map(group => (
                                  <optgroup key={group} label={group}>
                                    {(catalog?.actions || []).filter(a => a.group === group).map(a => (
                                      <option key={a.type} value={a.type}>{a.label}</option>
                                    ))}
                                  </optgroup>
                                ))}
                              </select>
                            )}
                          </div>
                          <div>
                            <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Timeout (s)</label>
                            <input type="number" min={1} max={3600} value={step.timeout} onChange={e => updateStep(step.key, { timeout: e.target.value })} className={inputClass} />
                          </div>
                          <div>
                            <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">On failure</label>
                            <select value={step.onFailure} onChange={e => updateStep(step.key, { onFailure: e.target.value as DraftStep['onFailure'] })} className={inputClass}>
                              <option value="stop">Stop playbook</option>
                              <option value="continue">Continue</option>
                            </select>
                          </div>
                        </div>

                        {action?.description && <p className="text-xs text-slate-500 mt-2">{action.description}</p>}

                        {/* Library script picker */}
                        {step.type === 'run_script' && (
                          <div className="mt-3">
                            <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Library script <span className="text-rose-500">*</span></label>
                            <select value={step.scriptId} onChange={e => updateStep(step.key, { scriptId: e.target.value })} className={inputClass}>
                              <option value="">Select an approved script…</option>
                              {(catalog?.scripts || []).map(s => (
                                <option key={s.id} value={s.id}>{s.name}</option>
                              ))}
                              {step.scriptId && !(catalog?.scripts || []).some(s => s.id === step.scriptId) && (
                                <option value={step.scriptId}>Unavailable script ({step.scriptId.slice(0, 8)})</option>
                              )}
                            </select>
                            {(catalog?.scripts || []).length === 0 && (
                              <p className="text-xs text-slate-500 mt-1">No enabled scripts. An administrator can add them in the Script Library.</p>
                            )}
                          </div>
                        )}

                        {/* Legacy command (read-only) */}
                        {isLegacyCmd && (
                          <div className="mt-3">
                            <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Command</label>
                            <input type="text" value={step.params.cmd || ''} onChange={e => setStepParam(step.key, 'cmd', e.target.value)} className={`${inputClass} font-mono`} />
                          </div>
                        )}

                        {/* Catalog parameters */}
                        {(action?.params || []).map(p => {
                          if (p.kind === 'log_channels') {
                            const selected = new Set((step.params[p.key] || '').split(',').map(v => v.trim()).filter(Boolean));
                            const toggle = (val: string) => {
                              const next = new Set(selected);
                              if (next.has(val)) next.delete(val); else next.add(val);
                              setStepParam(step.key, p.key, [...next].join(','));
                            };
                            return (
                              <div key={p.key} className="mt-3">
                                <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">
                                  {p.label} <span className="font-normal text-slate-400">(none selected = agent default)</span>
                                </label>
                                <div className="flex flex-wrap gap-1.5">
                                  {LOG_TYPE_OPTIONS.map(opt => (
                                    <button key={opt.value} type="button" onClick={() => toggle(opt.value)} title={opt.desc}
                                      className={`px-2.5 py-1 rounded-md border text-xs font-medium transition-colors ${selected.has(opt.value)
                                        ? 'bg-indigo-600 border-indigo-600 text-white'
                                        : 'bg-white dark:bg-slate-900 border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-indigo-400'}`}>
                                      {opt.label}
                                    </button>
                                  ))}
                                </div>
                              </div>
                            );
                          }
                          return (
                            <div key={p.key} className="mt-3">
                              <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">
                                {p.label}
                                {p.required && !p.alert_var && <span className="text-rose-500 ml-1">*</span>}
                                {p.alert_var && <span className="font-normal text-slate-400 ml-1">(empty = alert's {p.alert_var})</span>}
                              </label>
                              <input
                                type="text"
                                value={step.params[p.key] || ''}
                                onChange={e => setStepParam(step.key, p.key, e.target.value)}
                                placeholder={p.alert_var ? `{{alert.${p.alert_var}}}` : ''}
                                className={`${inputClass} font-mono`}
                              />
                            </div>
                          );
                        })}

                        <div className="mt-3">
                          <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Description (optional)</label>
                          <input type="text" value={step.description} maxLength={500} onChange={e => updateStep(step.key, { description: e.target.value })} placeholder={actionLabel(step.type)} className={inputClass} />
                        </div>
                      </div>
                    );
                  })}
                </div>

                <button
                  type="button"
                  onClick={addStep}
                  disabled={!catalog || draftSteps.length >= 25}
                  className="mt-3 w-full px-4 py-2.5 border border-dashed border-indigo-300 dark:border-indigo-700 text-indigo-600 dark:text-indigo-400 rounded-lg hover:bg-indigo-50 dark:hover:bg-indigo-900/20 font-medium flex items-center justify-center gap-2 transition-colors text-sm disabled:opacity-50"
                >
                  <Plus className="w-4 h-4" />
                  {catalog ? 'Add Step' : 'Loading actions…'}
                </button>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 p-6 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/30 shrink-0">
              <button onClick={() => setEditorOpen(false)} disabled={isSaving}
                className="px-5 py-2.5 font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-800 rounded-lg transition-colors">
                Cancel
              </button>
              <button onClick={savePlaybook} disabled={isSaving}
                className="px-6 py-2.5 font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg shadow-md transition-all flex items-center gap-2 disabled:opacity-70 disabled:cursor-not-allowed">
                {isSaving ? 'Saving...' : editingId ? 'Save Changes' : 'Create Playbook'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* View Details Modal */}
      {viewPlaybook && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl w-full max-w-3xl flex flex-col border border-slate-200 dark:border-slate-800" style={{ maxHeight: '92vh' }}>
            <div className="flex items-center justify-between p-6 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/30 shrink-0">
              <h2 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <Shield className="w-5 h-5 text-indigo-500" />
                Playbook Details
              </h2>
              <button onClick={() => setViewPlaybook(null)} className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-800 transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-6 overflow-y-auto flex-1">
              <div>
                <h3 className="text-lg font-bold text-slate-900 dark:text-white">{viewPlaybook.name}</h3>
                <p className="text-sm text-slate-600 dark:text-slate-400 mt-2">{viewPlaybook.description}</p>
                <div className="flex flex-wrap gap-3 mt-4">
                  <span className={`px-2.5 py-1 text-xs font-bold rounded-md ${getCategoryColor(viewPlaybook.category)}`}>{getCategoryLabel(viewPlaybook.category)}</span>
                  {viewPlaybook.severityFilter.length > 0 && (
                    <span className="flex items-center gap-1.5 px-2.5 py-1 bg-rose-50 dark:bg-rose-900/20 text-rose-600 dark:text-rose-400 rounded-md text-xs font-bold uppercase border border-rose-200 dark:border-rose-800/50">
                      <Filter className="w-3.5 h-3.5" />{viewPlaybook.severityFilter.join(', ')}
                    </span>
                  )}
                  {viewPlaybook.rulePattern && (
                    <span className="flex items-center gap-1.5 px-2.5 py-1 bg-indigo-50 dark:bg-indigo-900/20 text-indigo-600 dark:text-indigo-400 rounded-md text-xs font-mono border border-indigo-200 dark:border-indigo-800/50">
                      <Zap className="w-3.5 h-3.5" />{viewPlaybook.rulePattern}
                    </span>
                  )}
                  <span className={`flex items-center gap-1.5 px-2.5 py-1 text-xs font-bold rounded-md border ${viewPlaybook.enabled ? 'bg-emerald-50 dark:bg-emerald-900/20 text-emerald-600 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800/50' : 'bg-slate-50 dark:bg-slate-800/50 text-slate-500 border-slate-200 dark:border-slate-700'}`}>
                    <ToggleRight className="w-3.5 h-3.5" />{viewPlaybook.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                  <span className="px-2.5 py-1 text-xs font-bold rounded-md bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400 border border-slate-200 dark:border-slate-700">ID: {viewPlaybook.id}</span>
                </div>
              </div>

              <div className="border-t border-slate-200 dark:border-slate-800 pt-6">
                <h4 className="text-sm font-bold text-slate-900 dark:text-white mb-4">Steps</h4>
                <ol className="space-y-3">
                  {viewPlaybook.commands.map((cmd, idx) => {
                    const scriptName = cmd.script_id ? catalog?.scripts.find(s => s.id === cmd.script_id)?.name : undefined;
                    return (
                      <li key={idx} className="flex items-start gap-3 bg-white dark:bg-slate-800 p-4 rounded-xl border border-slate-200 dark:border-slate-700/60">
                        <span className="flex items-center justify-center w-7 h-7 rounded-full bg-indigo-100 dark:bg-indigo-900 text-indigo-600 dark:text-indigo-400 font-bold text-xs shrink-0">{idx + 1}</span>
                        <div className="min-w-0">
                          <div className="font-bold text-slate-900 dark:text-white text-sm">{actionLabel(canonicalType(cmd.type))}</div>
                          {cmd.description && <div className="text-xs text-slate-500 dark:text-slate-400">{cmd.description}</div>}
                          {scriptName && <div className="text-xs font-mono text-indigo-600 dark:text-indigo-400 mt-1">{scriptName}</div>}
                          {Object.keys(cmd.params).length > 0 && (
                            <div className="mt-1 text-xs font-mono text-slate-600 dark:text-slate-300 break-all">
                              {Object.entries(cmd.params).map(([k, v]) => <div key={k}>{k}: {v}</div>)}
                            </div>
                          )}
                          <div className="mt-2 text-[10px] uppercase font-bold text-indigo-500">
                            Timeout: {cmd.timeout}s · On failure: {cmd.on_failure === 'continue' ? 'continue' : 'stop'}
                          </div>
                        </div>
                      </li>
                    );
                  })}
                </ol>
              </div>
            </div>

            <div className="p-6 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/30 flex justify-end gap-3 shrink-0">
              <button onClick={() => openEditPlaybook(viewPlaybook)}
                className="px-5 py-2.5 font-medium text-indigo-600 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-800 rounded-lg hover:bg-indigo-50 dark:hover:bg-indigo-900/20 flex items-center gap-2">
                <Pencil className="w-4 h-4" /> Edit
              </button>
              <button onClick={() => setViewPlaybook(null)}
                className="px-6 py-2.5 font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-800 rounded-lg transition-colors">
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
