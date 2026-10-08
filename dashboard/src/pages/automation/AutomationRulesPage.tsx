import { useState, useEffect, useCallback } from 'react';
import { useLocation } from 'react-router-dom';
import { AlertContextPanel } from '../../components/automation/AlertContextPanel';
import { UserAssistant } from '../../components/automation/UserAssistant';
import { Settings, TrendingUp, Clock, AlertTriangle, Plus, Activity, Power, X, CheckCircle, Trash2, Zap, Target } from 'lucide-react';
import { automationApi, authApi, type ResponsePlaybook } from '../../api/client';
import { apiErrorMessage } from '../../api/apiError';
import { useAutomationSettings } from '../../hooks/useAutomationSettings';

interface AutomationRule {
  id: string;
  name: string;
  description: string;
  priority: number;
  autoExecute: boolean;
  enabled: boolean;
  successRate: number;
  cooldownMinutes: number;
  lastExecution?: string;       // only set when DB has an actual last_execution
  matchesCurrentAlert?: boolean;
  playbookId?: string;
  triggerConditions?: unknown;
}

// Structured trigger conditions. This is exactly the shape evaluated by the
// connection-manager response engine (internal/response/conditions.go) against
// new Sigma alerts; all set conditions must match (AND).
interface TriggerConditions {
  severity?: string[];
  rule_patterns?: string[];
  rule_ids?: string[];
  mitre_techniques?: string[];
  logic_operator?: 'AND' | 'OR';
  min_risk_score?: number;
}

const SEVERITY_OPTIONS = [
  { value: 'critical',      label: 'Critical',      cls: 'bg-rose-600 border-rose-600' },
  { value: 'high',          label: 'High',          cls: 'bg-orange-500 border-orange-500' },
  { value: 'medium',        label: 'Medium',        cls: 'bg-amber-500 border-amber-500' },
  { value: 'low',           label: 'Low',           cls: 'bg-blue-500 border-blue-500' },
  { value: 'informational', label: 'Informational', cls: 'bg-slate-500 border-slate-500' },
];
const SEVERITY_VALUES = new Set(SEVERITY_OPTIONS.map(s => s.value));

// Returns the structured conditions, or null when the stored value is a legacy
// free-text condition (or anything the engine would not evaluate).
const isStringArray = (v: unknown): v is unknown[] => Array.isArray(v);

const parseConditions = (raw: unknown): TriggerConditions | null => {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const tc = raw as Record<string, unknown>;
  const out: TriggerConditions = {};
  if (isStringArray(tc.severity)) out.severity = tc.severity.filter((s): s is string => typeof s === 'string');
  if (isStringArray(tc.rule_patterns)) out.rule_patterns = tc.rule_patterns.filter((p): p is string => typeof p === 'string' && p !== '');
  if (isStringArray(tc.rule_ids)) out.rule_ids = tc.rule_ids.filter((p): p is string => typeof p === 'string' && p.trim() !== '');
  if (isStringArray(tc.mitre_techniques)) out.mitre_techniques = tc.mitre_techniques.filter((p): p is string => typeof p === 'string' && p.trim() !== '');
  out.logic_operator = typeof tc.logic_operator === 'string' && tc.logic_operator.toUpperCase() === 'OR' ? 'OR' : 'AND';
  if (typeof tc.min_risk_score === 'number' && tc.min_risk_score > 0) out.min_risk_score = tc.min_risk_score;
  const hasAny = (out.severity?.length || 0) > 0 || (out.rule_patterns?.length || 0) > 0 || (out.rule_ids?.length || 0) > 0 || (out.mitre_techniques?.length || 0) > 0 || !!out.min_risk_score;
  return hasAny ? out : null;
};

const describeConditions = (c: TriggerConditions): string => {
  const parts: string[] = [];
  if (c.severity?.length) parts.push(`Severity is ${c.severity.join(' or ')}`);
  if (c.rule_patterns?.length) parts.push(`Rule name contains ${c.rule_patterns.map(p => `"${p}"`).join(' or ')}`);
  if (c.rule_ids?.length) parts.push(`Sigma rule ID is ${c.rule_ids.join(' or ')}`);
  if (c.mitre_techniques?.length) parts.push(`MITRE technique is ${c.mitre_techniques.join(' or ')} (including sub-techniques)`);
  if (c.min_risk_score) parts.push(`Risk score is at least ${c.min_risk_score}`);
  return parts.join(`  ${c.logic_operator || 'AND'}  `);
};

const splitValues = (value: string): string[] => [...new Set(value.split(/[\s,]+/).map(v => v.trim()).filter(Boolean))];

const legacyConditionText = (tc: unknown): string => {
  if (tc && typeof tc === 'object') {
    const cond = (tc as Record<string, unknown>).condition;
    if (typeof cond === 'string') return cond;
  }
  if (typeof tc === 'string') return tc;
  return JSON.stringify(tc);
};

interface AlertContext {
  alertId: string;
  alertDetails: {
    severity: string;
    ruleName: string;
    agentId: string;
    title: string;
    description?: string;
    riskScore?: number;
    ruleId?: string;
    mitreTechniques?: string[];
  };
  timestamp: string;
}

export function AutomationRulesPage() {
  const location = useLocation();
  const [alertContext, setAlertContext] = useState<AlertContext | null>(null);
  const [rules, setRules] = useState<AutomationRule[]>([]);
  const [loading, setLoading] = useState(true);
  const { settings, loading: settingsLoading, error: settingsError, setCached, refresh } = useAutomationSettings();
  const [switchReason, setSwitchReason] = useState('');
  const [switchSaving, setSwitchSaving] = useState(false);
  const [switchError, setSwitchError] = useState('');
  const canChangeSettings = authApi.hasRole(['admin']);

  // Modal State
  const [isCreatingRule, setIsCreatingRule] = useState(false);
  const [newRuleName, setNewRuleName] = useState('');
  const [condSeverities, setCondSeverities] = useState<string[]>([]);
  const [condPatterns, setCondPatterns] = useState<string[]>([]);
  const [patternInput, setPatternInput] = useState('');
  const [condMinRisk, setCondMinRisk] = useState('');
  const [condRuleIDs, setCondRuleIDs] = useState('');
  const [condTechniques, setCondTechniques] = useState('');
  const [condLogic, setCondLogic] = useState<'AND' | 'OR'>('AND');
  const [editingLegacyCondition, setEditingLegacyCondition] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const [playbooks, setPlaybooks] = useState<ResponsePlaybook[]>([]);
  const [selectedPlaybookId, setSelectedPlaybookId] = useState('');
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [autoExecute, setAutoExecute] = useState(true);
  const [rulePriority, setRulePriority] = useState('5');
  const [ruleCooldown, setRuleCooldown] = useState('30');

  const fetchPlaybooks = useCallback(async () => {
    try {
      const res = await automationApi.listPlaybooks();
      const pbs = res.playbooks || [];
      
      setPlaybooks(pbs);
      if (pbs.length > 0) setSelectedPlaybookId(current => current || pbs[0].id);
    } catch (error) {
      console.error('Failed to fetch playbooks:', error);
    }
  }, []);

  const fetchRules = useCallback(async () => {
    try {
      setLoading(true);
      const res = await automationApi.listRules();
      
      const formattedRules: AutomationRule[] = (res.rules || []).map(r => ({
        id: r.id,
        name: r.name,
        description: r.description,
        priority: r.priority ?? 5,
        autoExecute: Boolean(r.auto_execute),
        enabled: Boolean(r.enabled),
        successRate: typeof r.success_rate === 'number' ? r.success_rate : 0,
        cooldownMinutes: r.cooldown_minutes ?? 30,
        // Only show lastExecution if the DB actually has a non-null last_execution field
        lastExecution: r.last_execution ?? undefined,
        matchesCurrentAlert: false,
        playbookId: r.playbook_id,
        triggerConditions: r.trigger_conditions,
      }));

      setRules(formattedRules);
    } catch (error) {
      console.error('Failed to fetch automation rules:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Extract alert context from navigation state
    const state = location.state as AlertContext | null;
    if (state?.alertId && state?.alertDetails) {
      setAlertContext({
        alertId: state.alertId,
        alertDetails: state.alertDetails,
        timestamp: new Date().toISOString(),
      });
    }

    // Fetch automation rules and playbooks
    fetchRules();
    fetchPlaybooks();
  }, [location.state, fetchRules, fetchPlaybooks]);

  const handleSuggestionAction = (action: string) => {
    console.log('Suggestion action:', action);
    if (action === 'review_automation_rules') {
        openCreateModal();
    }
  };

  const handleDeleteRule = async (ruleId: string) => {
    if (!window.confirm("Are you sure you want to delete this rule?")) return;
    
    try {
      if (ruleId) {
        await automationApi.deleteRule(ruleId);
      }
      setRules(prev => prev.filter(r => r.id !== ruleId));
    } catch (error) {
      console.error("Failed to delete rule:", error);
      alert("Failed to delete rule.");
    }
  };


  const handleRuleToggle = async (rule: AutomationRule) => {
    // Optimistic UI update
    setRules(prev => prev.map(r =>
      r.id === rule.id ? { ...r, enabled: !r.enabled } : r
    ));

    try {
      if (rule.id) {
        await automationApi.toggleRule(rule.id, !rule.enabled);
        // Re-fetch to guarantee UI matches DB state
        await fetchRules();
      }
    } catch (error) {
      console.error('Failed to toggle rule:', error);
      // Revert optimistic update on failure
      setRules(prev => prev.map(r =>
        r.id === rule.id ? { ...r, enabled: rule.enabled } : r
      ));
    }
  };

  const resetConditionForm = () => {
    setCondSeverities([]);
    setCondPatterns([]);
    setPatternInput('');
    setCondMinRisk('');
    setCondRuleIDs('');
    setCondTechniques('');
    setCondLogic('AND');
    setEditingLegacyCondition(null);
  };

  const openCreateModal = () => {
    setIsCreatingRule(true);
    setEditingRuleId(null);
    setAutoExecute(true);
    setRulePriority('5');
    setRuleCooldown('30');
    resetConditionForm();
    if (alertContext?.alertDetails?.ruleName) {
      setNewRuleName(`Response Rule for: ${alertContext.alertDetails.ruleName}`);
      setCondPatterns([alertContext.alertDetails.ruleName]);
      setCondRuleIDs(alertContext.alertDetails.ruleId || '');
      setCondTechniques((alertContext.alertDetails.mitreTechniques || []).join(', '));
      const sev = String(alertContext.alertDetails.severity || '').toLowerCase();
      if (SEVERITY_VALUES.has(sev)) setCondSeverities([sev]);
    } else {
      setNewRuleName('');
    }
  };

  const openEditModal = (rule: AutomationRule) => {
    setIsCreatingRule(true);
    setEditingRuleId(rule.id);
    setNewRuleName(rule.name);
    resetConditionForm();
    const parsed = parseConditions(rule.triggerConditions);
    if (parsed) {
      setCondSeverities(parsed.severity || []);
      setCondPatterns(parsed.rule_patterns || []);
      setCondMinRisk(parsed.min_risk_score ? String(parsed.min_risk_score) : '');
      setCondRuleIDs((parsed.rule_ids || []).join(', '));
      setCondTechniques((parsed.mitre_techniques || []).join(', '));
      setCondLogic(parsed.logic_operator || 'AND');
    } else if (rule.triggerConditions) {
      setEditingLegacyCondition(legacyConditionText(rule.triggerConditions));
    }
    setAutoExecute(rule.autoExecute);
    setRulePriority(String(rule.priority));
    setRuleCooldown(String(rule.cooldownMinutes));
    if (rule.playbookId) setSelectedPlaybookId(rule.playbookId);
  };

  const toggleSeverity = (value: string) => {
    setCondSeverities(prev => (prev.includes(value) ? prev.filter(s => s !== value) : [...prev, value]));
  };

  const addPattern = () => {
    const p = patternInput.trim();
    if (!p) return;
    setCondPatterns(prev => (prev.some(x => x.toLowerCase() === p.toLowerCase()) ? prev : [...prev, p]));
    setPatternInput('');
  };

  const confirmCreateRule = async () => {
    if (!newRuleName.trim()) {
      alert("Please enter a rule name.");
      return;
    }
    if (!selectedPlaybookId) {
      alert("Please select a target playbook.");
      return;
    }

    // Include a pattern still sitting in the input box.
    const patterns = [...condPatterns];
    const pending = patternInput.trim();
    if (pending && !patterns.some(x => x.toLowerCase() === pending.toLowerCase())) patterns.push(pending);

    const conditions: TriggerConditions = { logic_operator: condLogic };
    const ruleIDs = splitValues(condRuleIDs).map(v => v.toLowerCase());
    const techniques = splitValues(condTechniques).map(v => v.toUpperCase());
    if (ruleIDs.length > 100 || ruleIDs.some(id => id.length > 128)) {
      alert('Use at most 100 Sigma rule IDs, each at most 128 characters.');
      return;
    }
    if (techniques.length > 50 || techniques.some(t => !/^T\d{4}(\.\d{3})?$/.test(t))) {
      alert('Use at most 50 MITRE techniques, such as T1059 or T1059.001.');
      return;
    }
    if (ruleIDs.length) conditions.rule_ids = ruleIDs;
    if (techniques.length) conditions.mitre_techniques = techniques;
    if (condSeverities.length > 0) conditions.severity = condSeverities;
    if (patterns.length > 0) conditions.rule_patterns = patterns;
    if (condMinRisk.trim() !== '') {
      const n = Number(condMinRisk);
      if (!Number.isInteger(n) || n < 1 || n > 100) {
        alert("Minimum risk score must be a whole number between 1 and 100.");
        return;
      }
      conditions.min_risk_score = n;
    }
    // An empty condition set would match every alert, so require at least one.
    if (!conditions.severity && !conditions.rule_patterns && !conditions.min_risk_score && !conditions.rule_ids && !conditions.mitre_techniques) {
      alert('Add at least one trigger condition.');
      return;
    }
    const priority = Number(rulePriority);
    if (!Number.isInteger(priority) || priority < 1 || priority > 100) {
      alert("Priority must be a whole number between 1 (highest) and 100.");
      return;
    }
    const cooldown = Number(ruleCooldown);
    if (!Number.isInteger(cooldown) || cooldown < 0 || cooldown > 1440) {
      alert("Cooldown must be a whole number of minutes between 0 and 1440.");
      return;
    }

    setIsSaving(true);

    try {
      const payload = {
        name: newRuleName.trim(),
        description: `Triggers when: ${describeConditions(conditions)}`,
        trigger_conditions: conditions,
        priority,
        cooldown_minutes: cooldown,
        auto_execute: autoExecute,
        playbook_id: selectedPlaybookId || undefined
      };

      if (editingRuleId) {
        // Enabled state is changed only by the toggle, never by an edit.
        await automationApi.updateRule(editingRuleId, payload);
        alert(`Automation Rule "${newRuleName}" updated successfully!`);
      } else {
        await automationApi.createRule({ ...payload, enabled: true });
        alert(`Automation Rule "${newRuleName}" created successfully!`);
      }

      setIsSaving(false);
      setIsCreatingRule(false);

      fetchRules();
    } catch (err) {
      console.error("Failed to save rule:", err);
      alert(`Failed to save rule: ${apiErrorMessage(err)}`);
      setIsSaving(false);
    }
  };

  const getPriorityColor = (priority: number) => {
    if (priority <= 2) return 'bg-rose-100 text-rose-800 border border-rose-200 dark:bg-rose-900/30 dark:text-rose-400 dark:border-rose-800/50';
    if (priority <= 5) return 'bg-amber-100 text-amber-800 border border-amber-200 dark:bg-amber-900/30 dark:text-amber-400 dark:border-amber-800/50';
    return 'bg-slate-100 text-slate-800 border border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700/50';
  };

  const getPriorityLabel = (priority: number) => {
    if (priority <= 2) return 'Critical Priority';
    if (priority <= 5) return 'High Priority';
    if (priority <= 8) return 'Medium Priority';
    return 'Low Priority';
  };

  const getSuccessRateColor = (rate: number) => {
    if (rate >= 0.9) return 'text-emerald-600 dark:text-emerald-400';
    if (rate >= 0.7) return 'text-amber-600 dark:text-amber-400';
    return 'text-rose-600 dark:text-rose-400';
  };

  return (
    <div className="space-y-6 relative">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
            <Activity className="w-6 h-6 text-blue-600 dark:text-blue-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
              Automation Rules
            </h1>
            <p className="text-sm text-slate-500 mt-1">Configure trigger conditions to autonomously deploy playbooks.</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
            {alertContext && (
            <div className="flex items-center gap-2 text-sm text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20 px-3 py-1.5 rounded-full border border-blue-200 dark:border-blue-800/50 font-medium">
                <AlertTriangle className="w-4 h-4" />
                <span>Active Alert Context</span>
            </div>
            )}
            <button
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg flex items-center gap-2 font-medium transition-colors"
                onClick={openCreateModal}
            >
                <Plus className="w-4 h-4" />
                Create Rule
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

      <section className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-5 space-y-3" aria-label="Server automated response">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="font-semibold text-slate-900 dark:text-white">Server automated response</h2>
            <p className="text-sm text-slate-500">
              {settingsLoading ? 'Loading server state…' : settingsError ? 'Server state unavailable.' : settings?.enabled ? 'Enabled — matching automatic rules can start playbooks.' : 'Disabled — automatic playbooks will not start.'}
            </p>
          </div>
          {settingsError && <button type="button" onClick={() => refresh()} className="text-sm text-blue-600">Retry</button>}
          {canChangeSettings && <button type="button" role="switch" aria-checked={settings?.enabled || false}
            disabled={!settings || settingsError || settings.locked || switchSaving || !switchReason.trim()}
            onClick={async () => {
              if (!settings) return;
              setSwitchSaving(true); setSwitchError('');
              try {
                const next = await automationApi.updateSettings(!settings.enabled, switchReason.trim());
                setCached(next); setSwitchReason('');
              } catch (err) { setSwitchError(apiErrorMessage(err, 'Failed to change automated response.')); }
              finally { setSwitchSaving(false); }
            }} className="px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm font-semibold disabled:opacity-50">
            {switchSaving ? 'Saving…' : settings?.enabled ? 'Disable automated response' : 'Enable automated response'}
          </button>}
        </div>
        {settings?.locked && <p className="text-sm text-amber-600">Disabled by server configuration. An administrator must change the server setting before this switch can enable automation.</p>}
        {canChangeSettings && !settings?.locked && <input aria-label="Reason for automation setting change" value={switchReason} onChange={e => setSwitchReason(e.target.value)} maxLength={500} placeholder="Reason for change (recorded in the audit log)" className="w-full border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-sm bg-transparent" />}
        {!canChangeSettings && <p className="text-xs text-slate-500">Only administrators can change this setting.</p>}
        {switchError && <p role="alert" className="text-sm text-rose-600">{switchError}</p>}
        <p className="text-xs text-slate-500">Disabling prevents new automated runs. An action already dispatched can finish. Manual response and agent-local prevention remain available.</p>
      </section>

      {/* User Assistant */}
      <UserAssistant
        alertContext={alertContext || undefined}
        onSuggestionAction={handleSuggestionAction}
      />

      {/* Rules List */}
      <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 shadow-sm overflow-hidden">
        <div className="p-6 border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50">
          <h2 className="text-lg font-bold text-slate-900 dark:text-white">
            Configured Automation Rules
          </h2>
          <p className="text-sm text-slate-500 mt-1">
            Rules evaluate incoming alerts and telemetry against conditions to trigger autonomous responses.
          </p>
          <p className="text-xs text-amber-700 dark:text-amber-400 mt-2 flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            {settingsError ? 'Server automation state is unavailable. Check the server before relying on automatic response.' : settings?.enabled ? 'Enabled rules marked Auto Execute run on matching new alerts, subject to cooldowns and containment guardrails.' : 'Server automated response is disabled. Rules remain saved and manual playbook runs remain available.'}
          </p>
        </div>

        {loading ? (
          <div className="p-12 text-center">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            <p className="text-sm font-medium text-slate-500 mt-4">Loading rules...</p>
          </div>
        ) : (
          <div className="divide-y divide-slate-200 dark:divide-slate-700/80">
            {rules.map((rule) => (
              <div key={rule.id} className={`p-6 transition-colors ${rule.enabled ? 'hover:bg-slate-50 dark:hover:bg-slate-800/40' : 'bg-slate-50/50 dark:bg-slate-800/20 opacity-80'}`}>
                <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-6">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <h3 className={`font-bold text-lg ${rule.enabled ? 'text-slate-900 dark:text-white' : 'text-slate-500 dark:text-slate-400'}`}>
                        {rule.name}
                      </h3>
                      <span className={`px-2.5 py-0.5 text-[11px] uppercase tracking-wider font-bold rounded-md ${getPriorityColor(rule.priority)}`}>
                        {getPriorityLabel(rule.priority)}
                      </span>
                      {rule.matchesCurrentAlert && (
                        <span className="px-2.5 py-0.5 text-[11px] uppercase tracking-wider font-bold rounded-md bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400 border border-blue-200 dark:border-blue-800">
                          Matches Active Alert
                        </span>
                      )}
                    </div>
                    <p className={`text-sm mb-4 max-w-3xl ${rule.enabled ? 'text-slate-600 dark:text-slate-400' : 'text-slate-400 dark:text-slate-500'}`}>
                      {rule.description}
                    </p>
                    
                    {/* Metadata Badges — all driven from DB data */}
                    <div className="flex flex-wrap items-center gap-3 text-xs mb-5">
                      {/* Success Rate */}
                      <div className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-100 dark:bg-slate-800 rounded-md text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                        <TrendingUp className="w-3.5 h-3.5" />
                        <span className="font-semibold">Success: <span className={getSuccessRateColor(rule.successRate)}>{rule.successRate > 0 ? `${(rule.successRate * 100).toFixed(1)}%` : 'N/A'}</span></span>
                      </div>

                      {/* Cooldown */}
                      <div className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-100 dark:bg-slate-800 rounded-md text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                        <Clock className="w-3.5 h-3.5" />
                        <span className="font-semibold">Cooldown: {rule.cooldownMinutes === 0 ? 'None' : `${rule.cooldownMinutes} min`}</span>
                      </div>

                      {/* Auto Execute */}
                      <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md border ${rule.autoExecute ? 'bg-indigo-50 dark:bg-indigo-900/20 text-indigo-600 dark:text-indigo-400 border-indigo-200 dark:border-indigo-800/50' : 'bg-slate-50 dark:bg-slate-800/50 text-slate-500 border-slate-200 dark:border-slate-700'}`}>
                        <Zap className="w-3.5 h-3.5" />
                        <span className="font-semibold text-nowrap">{rule.autoExecute ? 'Auto Execute' : 'Manual Trigger'}</span>
                      </div>

                      {/* Linked Playbook */}
                      {rule.playbookId && (() => {
                        const pb = playbooks.find(p => p.id === rule.playbookId);
                        return pb ? (
                          <div className="flex items-center gap-1.5 px-2.5 py-1 bg-blue-50 dark:bg-blue-900/20 rounded-md text-blue-600 dark:text-blue-400 border border-blue-200 dark:border-blue-800/50">
                            <Activity className="w-3.5 h-3.5" />
                            <span className="font-semibold truncate max-w-[200px]" title={pb.name}>
                              PB: {pb.name}
                            </span>
                          </div>
                        ) : null;
                      })()}

                      {/* Last Run — only shown if DB has an actual last_execution value */}
                      {rule.lastExecution && (
                        <div className="flex items-center gap-1.5 px-2.5 py-1 text-slate-500 font-medium">
                          <Clock className="w-3.5 h-3.5" />
                          <span>Last Run: {new Date(rule.lastExecution).toLocaleDateString()}</span>
                        </div>
                      )}
                    </div>

                    {/* Trigger Conditions */}
                    {!!rule.triggerConditions && (
                      <div className="text-xs bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg p-3 font-mono text-slate-600 dark:text-slate-400 w-full overflow-hidden">
                        <div className="font-sans font-bold text-slate-700 dark:text-slate-300 mb-1.5 flex items-center gap-1.5">
                           <Target className="w-4 h-4 text-blue-500" />
                           Trigger Condition
                        </div>
                        {(() => {
                          const parsed = parseConditions(rule.triggerConditions);
                          return parsed ? (
                            <div className="pl-5 text-blue-600 dark:text-blue-400 font-semibold font-sans break-words">
                              {describeConditions(parsed)}
                            </div>
                          ) : (
                            <div className="pl-5">
                              <span className="inline-block mb-1 px-1.5 py-0.5 text-[10px] font-sans font-bold uppercase tracking-wide bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400 rounded">
                                Legacy condition — not evaluated. Click Configure to rebuild it.
                              </span>
                              <div className="text-slate-500 break-all whitespace-pre-wrap">
                                {legacyConditionText(rule.triggerConditions)}
                              </div>
                            </div>
                          );
                        })()}
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="flex lg:flex-col items-center justify-center gap-3 shrink-0 min-w-[140px]">
                    <button
                      onClick={() => handleRuleToggle(rule)}
                      className={`px-4 py-2 rounded-lg font-medium flex items-center justify-center gap-2 w-full transition-all border ${
                          rule.enabled 
                          ? 'bg-rose-50 text-rose-700 border-rose-200 hover:bg-rose-100 dark:bg-rose-900/20 dark:text-rose-400 dark:border-rose-800/50 dark:hover:bg-rose-900/40' 
                          : 'bg-emerald-50 text-emerald-700 border-emerald-200 hover:bg-emerald-100 dark:bg-emerald-900/20 dark:text-emerald-400 dark:border-emerald-800/50 dark:hover:bg-emerald-900/40'
                      }`}
                    >
                      <Power className="w-4 h-4" />
                      {rule.enabled ? 'Disable Rule' : 'Enable Rule'}
                    </button>
                    <div className="flex w-full gap-2">
                        <button
                            onClick={() => openEditModal(rule)}
                            className="flex-1 px-4 py-2 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-600 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-700 font-medium transition-colors flex items-center justify-center gap-2"
                        >
                            <Settings className="w-4 h-4" />
                            Configure
                        </button>
                        <button
                            onClick={() => handleDeleteRule(rule.id)}
                            className="px-3 py-2 bg-white dark:bg-slate-800 text-rose-600 dark:text-rose-400 border border-slate-300 dark:border-slate-600 rounded-lg hover:bg-rose-50 dark:hover:bg-rose-900/20 font-medium transition-colors flex items-center justify-center"
                            title="Delete Rule"
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

      {/* Create Rule Modal */}
      {isCreatingRule && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl w-full max-w-2xl flex flex-col border border-slate-200 dark:border-slate-800" style={{ maxHeight: '92vh' }}>
            <div className="flex items-center justify-between p-6 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/30 shrink-0">
              <div>
                <h2 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <Activity className="w-5 h-5 text-blue-500" />
                  {editingRuleId ? 'Edit Automation Rule' : 'Create Automation Rule'}
                </h2>
                <p className="text-sm text-slate-500 mt-1">Map alert telemetry to automated playbooks.</p>
              </div>
              <button 
                onClick={() => setIsCreatingRule(false)}
                className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            
            <div className="p-6 space-y-5 overflow-y-auto flex-1">
              <div>
                <label className="block text-sm font-bold text-slate-700 dark:text-slate-300 mb-2">
                  Rule Name <span className="text-rose-500">*</span>
                </label>
                <input 
                  type="text" 
                  value={newRuleName}
                  onChange={(e) => setNewRuleName(e.target.value)}
                  placeholder="e.g., Contain Ransomware Behavior"
                  className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-3 text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-shadow"
                />
              </div>

              <div>
                <label className="block text-sm font-bold text-slate-700 dark:text-slate-300 mb-1">
                  Trigger When <span className="text-rose-500">*</span>
                </label>
                <p className="text-xs text-slate-500 mb-3">
                  Set one or more conditions. Values within each list match any listed value; combine condition groups below.
                </p>

                {editingLegacyCondition && (
                  <div className="mb-3 p-3 text-xs rounded-lg border border-amber-200 dark:border-amber-800/50 bg-amber-50 dark:bg-amber-900/20 text-amber-800 dark:text-amber-300">
                    <div className="font-bold mb-1">This rule used a free-text condition that is not evaluated:</div>
                    <div className="font-mono break-all">{editingLegacyCondition}</div>
                    <div className="mt-1">Rebuild it with the options below and save.</div>
                  </div>
                )}

                <div className="space-y-4 border border-slate-200 dark:border-slate-700 rounded-xl p-4 bg-slate-50/60 dark:bg-slate-950/40">
                  {/* Severity */}
                  <div>
                    <div className="text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1.5">
                      Alert severity is any of
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {SEVERITY_OPTIONS.map(opt => {
                        const on = condSeverities.includes(opt.value);
                        return (
                          <button
                            key={opt.value} type="button" onClick={() => toggleSeverity(opt.value)}
                            className={`px-3 py-1.5 rounded-md border text-xs font-semibold transition-colors ${
                              on ? `${opt.cls} text-white` : 'bg-white dark:bg-slate-900 border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-blue-400'
                            }`}
                          >
                            {opt.label}
                          </button>
                        );
                      })}
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1">Leave all unselected to match any severity.</p>
                  </div>

                  {/* Rule name contains */}
                  <div>
                    <div className="text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1.5">
                      Detection rule name contains any of
                    </div>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={patternInput}
                        onChange={e => setPatternInput(e.target.value)}
                        onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addPattern(); } }}
                        placeholder="e.g., ransomware, lsass, mimikatz"
                        className="flex-1 bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 outline-none"
                      />
                      <button
                        type="button" onClick={addPattern}
                        className="px-3 py-2 text-sm font-medium rounded-lg border border-blue-300 dark:border-blue-700 text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20"
                      >
                        Add
                      </button>
                    </div>
                    {condPatterns.length > 0 && (
                      <div className="flex flex-wrap gap-1.5 mt-2">
                        {condPatterns.map(p => (
                          <span key={p} className="flex items-center gap-1 pl-2.5 pr-1 py-1 rounded-md bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 text-xs font-medium">
                            {p}
                            <button
                              type="button" onClick={() => setCondPatterns(prev => prev.filter(x => x !== p))}
                              className="p-0.5 rounded hover:bg-blue-200 dark:hover:bg-blue-800" title="Remove"
                            >
                              <X className="w-3 h-3" />
                            </button>
                          </span>
                        ))}
                      </div>
                    )}
                    <p className="text-[11px] text-slate-400 mt-1">Case-insensitive; matches part of the rule name.</p>
                  </div>

                  <div>
                    <label className="text-xs font-semibold text-slate-600 dark:text-slate-400">Combine condition groups
                      <select value={condLogic} onChange={e => setCondLogic(e.target.value as 'AND' | 'OR')} className="block mt-1 border rounded-lg px-3 py-2 bg-white dark:bg-slate-950">
                        <option value="AND">All groups (AND)</option><option value="OR">Any group (OR)</option>
                      </select>
                    </label>
                  </div>
                  <div>
                    <label className="text-xs font-semibold text-slate-600 dark:text-slate-400">Exact Sigma rule IDs
                      <textarea value={condRuleIDs} onChange={e => setCondRuleIDs(e.target.value)} placeholder="Comma or space separated rule IDs" className="block w-full mt-1 bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-sm" />
                    </label>
                    <p className="text-[11px] text-slate-500 mt-1">Explicitly opting a detection into automatic containment permits its response even below High severity. Review the detection first.</p>
                  </div>
                  <div>
                    <label className="text-xs font-semibold text-slate-600 dark:text-slate-400">MITRE techniques
                      <input value={condTechniques} onChange={e => setCondTechniques(e.target.value)} placeholder="T1059, T1486, T1059.001" className="block w-full mt-1 bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-sm" />
                    </label>
                  </div>
                  <p className="text-xs text-amber-600">Automatic containment requires AND groups and either exact Sigma rule IDs or severity restricted to High/Critical. A risk score or technique alone is insufficient.</p>

                  {/* Minimum risk score */}
                  <div>
                    <div className="text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1.5">
                      Risk score is at least
                    </div>
                    <input
                      type="number" min={1} max={100}
                      value={condMinRisk}
                      onChange={e => setCondMinRisk(e.target.value)}
                      placeholder="1–100 (optional)"
                      className="w-40 bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 outline-none"
                    />
                  </div>

                  {/* Live summary */}
                  {(() => {
                    const preview: TriggerConditions = { logic_operator: condLogic };
                    if (splitValues(condRuleIDs).length) preview.rule_ids = splitValues(condRuleIDs);
                    if (splitValues(condTechniques).length) preview.mitre_techniques = splitValues(condTechniques).map(t => t.toUpperCase());
                    if (condSeverities.length) preview.severity = condSeverities;
                    const pats = [...condPatterns];
                    if (patternInput.trim() && !pats.some(x => x.toLowerCase() === patternInput.trim().toLowerCase())) pats.push(patternInput.trim());
                    if (pats.length) preview.rule_patterns = pats;
                    const n = Number(condMinRisk);
                    if (condMinRisk.trim() && Number.isInteger(n) && n >= 1 && n <= 100) preview.min_risk_score = n;
                    const text = describeConditions(preview);
                    return (
                      <div className="text-xs pt-3 border-t border-slate-200 dark:border-slate-700">
                        <span className="font-semibold text-slate-600 dark:text-slate-400">Summary: </span>
                        {text
                          ? <span className="text-blue-600 dark:text-blue-400 font-semibold">{text}</span>
                          : <span className="text-rose-500">No conditions set yet.</span>}
                      </div>
                    );
                  })()}
                </div>

                {alertContext?.alertDetails?.ruleName && !editingRuleId && (
                  <p className="text-xs text-emerald-600 dark:text-emerald-400 mt-2 flex items-center gap-1.5 font-medium">
                    <CheckCircle className="w-3.5 h-3.5" />
                    Conditions pre-filled from the currently active alert.
                  </p>
                )}
              </div>

              <div>
                <label className="block text-sm font-bold text-slate-700 dark:text-slate-300 mb-2">
                  Target Playbook
                </label>
                <select 
                  value={selectedPlaybookId}
                  onChange={(e) => setSelectedPlaybookId(e.target.value)}
                  className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-3 text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none appearance-none"
                >
                  {playbooks.map(pb => (
                    <option key={pb.id} value={pb.id}>{pb.name}</option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-bold text-slate-700 dark:text-slate-300 mb-2">Priority</label>
                  <input
                    type="number" min={1} max={100}
                    value={rulePriority}
                    onChange={(e) => setRulePriority(e.target.value)}
                    className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-2.5 text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 outline-none"
                  />
                  <p className="text-xs text-slate-500 mt-1">1 runs first when several rules match.</p>
                </div>
                <div>
                  <label className="block text-sm font-bold text-slate-700 dark:text-slate-300 mb-2">Cooldown (minutes)</label>
                  <input
                    type="number" min={0} max={1440}
                    value={ruleCooldown}
                    onChange={(e) => setRuleCooldown(e.target.value)}
                    className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-2.5 text-slate-900 dark:text-white focus:ring-2 focus:ring-blue-500 outline-none"
                  />
                  <p className="text-xs text-slate-500 mt-1">Per endpoint: the rule fires at most once per window on the same host.</p>
                </div>
              </div>

              <div className="flex items-center gap-3 pt-2">
                <input
                  type="checkbox"
                  id="autoExec"
                  checked={autoExecute}
                  onChange={(e) => setAutoExecute(e.target.checked)}
                  className="w-4 h-4 text-blue-600 rounded border-gray-300 focus:ring-blue-500" 
                />
                <label htmlFor="autoExec" className="text-sm font-medium text-slate-700 dark:text-slate-300">
                  Enable Auto-Execution (No manual approval required)
                </label>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 p-6 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/30 shrink-0">
              <button 
                onClick={() => setIsCreatingRule(false)}
                className="px-5 py-2.5 font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-800 rounded-lg transition-colors"
                disabled={isSaving}
              >
                Cancel
              </button>
              <button 
                onClick={confirmCreateRule}
                disabled={isSaving}
                className="px-6 py-2.5 font-bold text-white bg-blue-600 hover:bg-blue-700 rounded-lg shadow-md transition-all flex items-center gap-2 disabled:opacity-70 disabled:cursor-not-allowed"
              >
                {isSaving ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Saving...
                  </>
                ) : (
                  <>
                    <Activity className="w-4 h-4" />
                    {editingRuleId ? 'Save Changes' : 'Create Rule'}
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
