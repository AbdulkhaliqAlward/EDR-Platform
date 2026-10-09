import { useState, useEffect } from 'react';
import {
    Moon, Sun, Bell, Mail, MessageSquare, Monitor,
    Webhook, Save, Check, Settings2, AlertCircle
} from 'lucide-react';

// ─── Types ──────────────────────────────────────────────────────────────────
interface GeneralConfig {
    timezone: string;
    dateFormat: string;
    darkMode: boolean;
}
interface NotificationConfig {
    [severity: string]: { [channel: string]: boolean };
}
interface IntegrationConfig {
    webhookUrl: string;
    slackChannel: string;
}

const TIMEZONES = [
    { value: 'UTC', label: 'UTC' },
    { value: 'America/New_York', label: 'Eastern Time (ET)' },
    { value: 'America/Chicago', label: 'Central Time (CT)' },
    { value: 'America/Los_Angeles', label: 'Pacific Time (PT)' },
    { value: 'Europe/London', label: 'London (GMT/BST)' },
    { value: 'Europe/Paris', label: 'Paris (CET)' },
    { value: 'Europe/Istanbul', label: 'Istanbul (TRT)' },
    { value: 'Asia/Dubai', label: 'Dubai (GST)' },
    { value: 'Asia/Tokyo', label: 'Tokyo (JST)' },
    { value: 'Asia/Singapore', label: 'Singapore (SGT)' },
    { value: 'Australia/Sydney', label: 'Sydney (AEST)' },
];

const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
const SEV_COLORS: Record<string, string> = { critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-amber-500', low: 'bg-blue-500' };
const CHANNELS = ['email', 'slack', 'browser'] as const;
const CHANNEL_ICONS: Record<string, React.ElementType> = { email: Mail, slack: MessageSquare, browser: Monitor };

function loadFromLS<T>(key: string, fallback: T): T {
    try { const raw = localStorage.getItem(key); return raw ? JSON.parse(raw) : fallback; } catch { return fallback; }
}

// ─── Shared Styles ──────────────────────────────────────────────────────────
const inputClass = 'w-full px-3.5 py-2.5 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-colors appearance-none';
const labelClass = 'block text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1.5';

// ─── Panel Wrapper ──────────────────────────────────────────────────────────
function Panel({ icon: Icon, iconBg, title, desc, children, onSave, saving, saved }: {
    icon: React.ElementType; iconBg: string; title: string; desc: string;
    children: React.ReactNode; onSave: () => void; saving?: boolean; saved?: boolean;
}) {
    return (
        <section className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl overflow-hidden shadow-sm">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-700">
                <div className="flex items-center gap-3">
                    <div className={`w-9 h-9 rounded-lg ${iconBg} flex items-center justify-center`}>
                        <Icon size={17} className="text-inherit" />
                    </div>
                    <div>
                        <h3 className="text-[15px] font-semibold text-slate-900 dark:text-white leading-tight">{title}</h3>
                        <p className="text-[12px] text-slate-500 dark:text-slate-400 leading-tight mt-0.5">{desc}</p>
                    </div>
                </div>
                <button
                    onClick={onSave}
                    disabled={saving}
                    className={`flex items-center gap-2 px-3.5 py-2 text-sm rounded-lg font-medium transition-colors ${
                        saved
                            ? 'bg-emerald-50 text-emerald-600 border border-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-400 dark:border-emerald-500/20'
                            : 'bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-50'
                    }`}
                >
                    {saved ? <><Check size={14} /> Saved</> : <><Save size={14} /> Save Changes</>}
                </button>
            </div>
            <div className="p-6">{children}</div>
        </section>
    );
}

// ─── Toggle ─────────────────────────────────────────────────────────────────
function Toggle({ checked, onChange, disabled }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
    return (
        <button
            onClick={() => !disabled && onChange(!checked)}
            className={`relative w-11 h-6 rounded-full transition-colors duration-200 ${
                checked ? 'bg-blue-600' : 'bg-slate-200 dark:bg-slate-700 border border-slate-300 dark:border-slate-600'
            } ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
        >
            <span className={`absolute top-0.5 w-5 h-5 rounded-full bg-white shadow-sm transition-transform duration-200 ${checked ? 'left-[22px]' : 'left-0.5'}`} />
        </button>
    );
}

// ═════════════════════════════════════════════════════════════════════════════
export default function SystemConfiguration() {
    // General
    const [general, setGeneral] = useState<GeneralConfig>(() =>
        loadFromLS('settings_general', { timezone: 'UTC', dateFormat: 'YYYY-MM-DD', darkMode: document.documentElement.classList.contains('dark') })
    );

    // Notifications
    const [notif, setNotif] = useState<NotificationConfig>(() =>
        loadFromLS('settings_notifications', {
            critical: { email: true, slack: true, browser: true },
            high: { email: true, slack: true, browser: true },
            medium: { email: false, slack: false, browser: true },
            low: { email: false, slack: false, browser: false },
        })
    );

    // Integrations
    const [integrations, setIntegrations] = useState<IntegrationConfig>(() =>
        loadFromLS('settings_integrations', { webhookUrl: '', slackChannel: '' })
    );

    const [savedPanels, setSavedPanels] = useState<Record<string, boolean>>({});
    const [feedback, setFeedback] = useState('');

    useEffect(() => {
        document.title = 'Platform preferences · Settings';
    }, []);

    useEffect(() => {
        if (feedback) { const t = setTimeout(() => setFeedback(''), 3000); return () => clearTimeout(t); }
    }, [feedback]);

    const savePanel = (key: string, data: any) => {
        localStorage.setItem(`settings_${key}`, JSON.stringify(data));
        setSavedPanels(prev => ({ ...prev, [key]: true }));
        setFeedback(
            `${key.charAt(0).toUpperCase() + key.slice(1)} preferences saved locally in this browser only — they are not synced to the platform API.`
        );
        setTimeout(() => setSavedPanels(prev => ({ ...prev, [key]: false })), 2500);
    };

    const toggleDark = () => {
        const next = !general.darkMode;
        document.documentElement.classList.toggle('dark', next);
        setGeneral(prev => ({ ...prev, darkMode: next }));
    };

    const toggleNotif = (sev: string, ch: string) => {
        setNotif(prev => ({
            ...prev,
            [sev]: { ...prev[sev], [ch]: !prev[sev]?.[ch] },
        }));
    };

    // Notification stats
    const activeChannels = Object.values(notif).reduce((acc, chans) => acc + Object.values(chans).filter(Boolean).length, 0);
    const totalChannels = SEVERITIES.length * CHANNELS.length;

    return (
        <div className="space-y-6 w-full min-w-0">
            {feedback && (
                <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-50 text-emerald-600 border border-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-400 dark:border-emerald-500/20 text-sm">
                    <Check size={14} /> {feedback}
                </div>
            )}

            <div className="bg-slate-50 border border-slate-200 text-slate-800 dark:bg-slate-900/40 dark:border-slate-700 dark:text-slate-300 rounded-xl p-4 text-sm flex gap-3">
                <AlertCircle className="w-5 h-5 shrink-0 text-cyan-600 dark:text-cyan-400" />
                <div>
                    <strong className="font-semibold text-slate-900 dark:text-white">Dashboard preferences (this browser)</strong>
                    <p className="mt-1 opacity-90 leading-relaxed">
                        Appearance, timezone, date format, and the notification matrix below are stored in{' '}
                        <code className="text-xs px-1 rounded bg-slate-200/80 dark:bg-slate-800 font-mono">localStorage</code>{' '}
                        for this dashboard session only. Other operators and browsers do not see these values. Platform-wide policies,
                        users, roles, and reliability data live under{' '}
                        <strong className="font-medium">System</strong> and <strong className="font-medium">Management</strong> in the main navigation — not here.
                        Webhook or Slack fields are placeholders until a server-side integration endpoint exists.
                    </p>
                </div>
            </div>

            {/* ═══ Panel: Appearance & Regional ═══ */}
            <Panel
                icon={Settings2} iconBg="bg-blue-100 text-blue-600 dark:bg-blue-500/20 dark:text-blue-400"
                title="Appearance & Regional" desc="Theme preference and timezone settings"
                onSave={() => savePanel('general', general)} saved={savedPanels['general']}
            >
                <div className="space-y-5 animate-slide-up-fade">
                    {/* Dark mode toggle */}
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            {general.darkMode ? <Moon size={16} className="text-indigo-400" /> : <Sun size={16} className="text-amber-500" />}
                            <div>
                                <div className="text-sm font-medium text-slate-900 dark:text-white">Dark Mode</div>
                                <div className="text-[12px] text-slate-500 dark:text-slate-400">
                                    {general.darkMode ? 'Dark theme is active' : 'Light theme is active'}
                                </div>
                            </div>
                        </div>
                        <Toggle checked={general.darkMode} onChange={toggleDark} />
                    </div>

                    {/* Timezone & Date */}
                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <label className={labelClass}>Timezone</label>
                            <select value={general.timezone} onChange={e => setGeneral(p => ({ ...p, timezone: e.target.value }))} className={inputClass}>
                                {TIMEZONES.map(tz => <option key={tz.value} value={tz.value}>{tz.label}</option>)}
                            </select>
                        </div>
                        <div>
                            <label className={labelClass}>Date Format</label>
                            <select value={general.dateFormat} onChange={e => setGeneral(p => ({ ...p, dateFormat: e.target.value }))} className={inputClass}>
                                <option value="YYYY-MM-DD">ISO — 2026-03-09</option>
                                <option value="MM/DD/YYYY">US — 03/09/2026</option>
                                <option value="DD/MM/YYYY">EU — 09/03/2026</option>
                            </select>
                        </div>
                    </div>
                </div>
            </Panel>

            {/* ═══ Panel: Notification Matrix ═══ */}
            <Panel
                icon={Bell} iconBg="bg-amber-100 text-amber-600 dark:bg-amber-500/20 dark:text-amber-400"
                title="Notification Matrix" desc={`Control delivery per severity level — ${activeChannels}/${totalChannels} channels active`}
                onSave={() => savePanel('notifications', notif)} saved={savedPanels['notifications']}
            >
                <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                        <thead>
                            <tr className="border-b border-slate-200 dark:border-slate-700">
                                <th className="text-left pb-3 text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider w-[140px]">Severity</th>
                                {CHANNELS.map(ch => {
                                    const Icon = CHANNEL_ICONS[ch];
                                    return (
                                        <th key={ch} className="text-center pb-3 min-w-[100px]">
                                            <div className="flex flex-col items-center gap-1">
                                                <div className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                                                    <Icon size={13} /> {ch}
                                                </div>
                                                <button
                                                    onClick={() => {
                                                        const allOn = SEVERITIES.every(s => notif[s]?.[ch]);
                                                        setNotif(prev => {
                                                            const next = { ...prev };
                                                            SEVERITIES.forEach(s => { next[s] = { ...next[s], [ch]: !allOn }; });
                                                            return next;
                                                        });
                                                    }}
                                                    className="text-[10px] text-blue-600 dark:text-blue-400 hover:underline"
                                                >
                                                    {SEVERITIES.every(s => notif[s]?.[ch]) ? '· Disable all' : '· Enable all'}
                                                </button>
                                            </div>
                                        </th>
                                    );
                                })}
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                            {SEVERITIES.map(sev => (
                                <tr key={sev} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                                    <td className="py-3.5">
                                        <div className="flex items-center gap-2">
                                            <span className={`w-2.5 h-2.5 rounded-full ${SEV_COLORS[sev]}`} />
                                            <span className="font-medium text-slate-900 dark:text-white capitalize">{sev}</span>
                                        </div>
                                    </td>
                                    {CHANNELS.map(ch => (
                                        <td key={ch} className="text-center py-3.5">
                                            <div className="flex justify-center">
                                                <Toggle checked={!!notif[sev]?.[ch]} onChange={() => toggleNotif(sev, ch)} />
                                            </div>
                                        </td>
                                    ))}
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </Panel>

            {/* ═══ Panel: Integrations ═══ */}
            <Panel
                icon={Webhook} iconBg="bg-purple-100 text-purple-600 dark:bg-purple-500/20 dark:text-purple-400"
                title="Integrations" desc="Configure webhook and Slack alert delivery"
                onSave={() => savePanel('integrations', integrations)} saved={savedPanels['integrations']}
            >
                <div className="space-y-4 max-w-lg">
                    <div>
                        <label className={labelClass}>Webhook URL</label>
                        <input
                            type="url" value={integrations.webhookUrl}
                            onChange={e => setIntegrations(p => ({ ...p, webhookUrl: e.target.value }))}
                            className={inputClass} placeholder="https://your-webhook-endpoint.com/alerts"
                        />
                        <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
                            Intended for future outbound alerts: values are saved locally here until the platform exposes a managed integration API.
                        </p>
                    </div>
                    <div>
                        <label className={labelClass}>Slack Channel</label>
                        <input
                            type="text" value={integrations.slackChannel}
                            onChange={e => setIntegrations(p => ({ ...p, slackChannel: e.target.value }))}
                            className={inputClass} placeholder="security-alerts"
                        />
                        <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
                            Invite your configured integration bot to the channel (for example): <code className="text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-500/10 px-1 rounded">/invite @edr-platform</code>
                        </p>
                    </div>
                </div>
            </Panel>
        </div>
    );
}
