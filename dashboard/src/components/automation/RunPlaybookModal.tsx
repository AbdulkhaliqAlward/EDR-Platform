// RunPlaybookModal — "Run Playbook" from Alert Details. Shows the server's
// suggested playbook for the alert (with the reasons it was ranked first),
// runs it on the alert's endpoint, or hands over to the Playbooks page to
// choose another one with the alert context preserved.
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Lightbulb, ListChecks, Loader2 } from 'lucide-react';
import { Modal } from '../Modal';
import { automationApi, authApi, type Alert, type PlaybookSuggestion } from '../../api/client';
import { PlaybookRunPanel } from './PlaybookRunPanel';
import { apiErrorMessage } from '../../api/apiError';

interface RunPlaybookModalProps {
    alert: Alert;
    isOpen: boolean;
    onClose: () => void;
}

export function RunPlaybookModal({ alert, isOpen, onClose }: RunPlaybookModalProps) {
    const navigate = useNavigate();
    // Mounted per opened alert (keyed by alert id), so state starts fresh.
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [suggestions, setSuggestions] = useState<PlaybookSuggestion[]>([]);
    const [selected, setSelected] = useState<PlaybookSuggestion | null>(null);
    const [running, setRunning] = useState(false);
    const canRun = authApi.canExecuteCommands();

    useEffect(() => {
        if (!isOpen) return;
        let cancelled = false;
        automationApi.getAlertSuggestions(alert.id)
            .then(res => {
                if (cancelled) return;
                const list = res.suggestions || [];
                setSuggestions(list);
                setSelected(list.find(s => s.playbook_id === res.suggested_playbook_id) || list[0] || null);
            })
            .catch(err => { if (!cancelled) setError(apiErrorMessage(err, 'Could not load playbook suggestions')); })
            .finally(() => { if (!cancelled) setLoading(false); });
        return () => { cancelled = true; };
    }, [isOpen, alert.id]);

    const chooseAnother = () => {
        onClose();
        navigate(`/itsm/playbooks?alert_id=${encodeURIComponent(alert.id)}`, {
            state: {
                alertId: alert.id,
                alertDetails: {
                    severity: alert.severity,
                    ruleName: alert.rule_title,
                    agentId: alert.agent_id,
                    title: alert.rule_title,
                    description: alert.human_summary,
                    riskScore: alert.risk_score,
                },
            },
        });
    };

    const footer = (
        <div className="flex items-center justify-between gap-3">
            <button
                type="button"
                onClick={chooseAnother}
                className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-600 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700 flex items-center gap-2"
            >
                <ListChecks className="w-4 h-4" />
                Choose Another Playbook
            </button>
            <button type="button" onClick={onClose} className="px-4 py-2 text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg">
                Close
            </button>
        </div>
    );

    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Run Playbook" size="lg" footer={footer} closeOnOverlayClick={false}>
            {loading && (
                <div className="flex items-center justify-center gap-2 py-8 text-sm text-slate-500">
                    <Loader2 className="w-4 h-4 animate-spin" /> Finding the best playbook for this alert…
                </div>
            )}
            {!loading && error && <p className="text-sm text-rose-600 dark:text-rose-400">{error}</p>}
            {!loading && !error && !selected && (
                <p className="text-sm text-slate-500">
                    No enabled playbook matches this alert. Use <span className="font-semibold">Choose Another Playbook</span> to pick one manually.
                </p>
            )}
            {!loading && selected && (
                <div className="space-y-4">
                    <div className="rounded-xl border border-indigo-200 dark:border-indigo-800/50 bg-indigo-50 dark:bg-indigo-900/10 p-4">
                        <div className="flex items-center gap-2 mb-1">
                            <Lightbulb className="w-4 h-4 text-indigo-500" />
                            <span className="text-[10px] uppercase tracking-wider font-bold text-indigo-500">Suggested playbook</span>
                        </div>
                        <div className="flex items-center justify-between gap-2">
                            <h3 className="font-bold text-indigo-900 dark:text-indigo-100">{selected.playbook_name}</h3>
                            <span className="text-[10px] uppercase font-bold text-slate-500">{selected.category}</span>
                        </div>
                        {selected.reasons && selected.reasons.length > 0 && (
                            <ul className="mt-2 text-xs text-indigo-700/80 dark:text-indigo-300/80 list-disc list-inside">
                                {selected.reasons.map((r, i) => <li key={i}>{r}</li>)}
                            </ul>
                        )}
                        {suggestions.length > 1 && !running && (
                            <select
                                value={selected.playbook_id}
                                onChange={e => setSelected(suggestions.find(s => s.playbook_id === e.target.value) || selected)}
                                className="mt-3 w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-900 dark:text-white outline-none focus:ring-2 focus:ring-indigo-500"
                            >
                                {suggestions.map(s => (
                                    <option key={s.playbook_id} value={s.playbook_id}>{s.playbook_name} (score {s.score})</option>
                                ))}
                            </select>
                        )}
                    </div>

                    {canRun ? (
                        <PlaybookRunPanel
                            key={selected.playbook_id}
                            playbookId={selected.playbook_id}
                            alertId={alert.id}
                            onStarted={() => setRunning(true)}
                            onFinished={() => setRunning(false)}
                        />
                    ) : (
                        <p className="text-sm text-slate-500">Your role cannot run response playbooks.</p>
                    )}
                </div>
            )}
        </Modal>
    );
}

export default RunPlaybookModal;
