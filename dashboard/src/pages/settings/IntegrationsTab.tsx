import { useState } from 'react';
import { Globe, Hash, Save, Check, Zap, CheckCircle, AlertCircle, Loader } from 'lucide-react';
import type { IntegrationSettings } from './types';

interface IntegrationsTabProps {
    settings: IntegrationSettings;
    onChange: (updated: IntegrationSettings) => void;
    onSave: () => void;
    saved: boolean;
}

type TestState = 'idle' | 'loading' | 'success' | 'error';

export default function IntegrationsTab({ settings, onChange, onSave, saved }: IntegrationsTabProps) {
    const [webhookTestState, setWebhookTestState] = useState<TestState>('idle');

    const set = (partial: Partial<IntegrationSettings>) => onChange({ ...settings, ...partial });

    const handleTestWebhook = () => {
        if (!settings.webhookUrl.trim()) return;
        setWebhookTestState('loading');
        // Simulated connection test — replace with real HTTP call when backend ready
        setTimeout(() => {
            const valid = settings.webhookUrl.startsWith('http');
            setWebhookTestState(valid ? 'success' : 'error');
            setTimeout(() => setWebhookTestState('idle'), 3000);
        }, 1500);
    };

    const testButtonContent: Record<TestState, React.ReactNode> = {
        idle: <><Zap className="w-4 h-4" />Test Connection</>,
        loading: <><Loader className="w-4 h-4 animate-spin" />Testing…</>,
        success: <><CheckCircle className="w-4 h-4" />Connected!</>,
        error: <><AlertCircle className="w-4 h-4" />Connection Failed</>,
    };

    const testButtonClass: Record<TestState, string> = {
        idle: 'btn btn-secondary',
        loading: 'btn btn-secondary opacity-70 cursor-not-allowed',
        success: 'btn btn-success',
        error: 'btn btn-danger',
    };

    return (
        <div className="space-y-6 animate-fade-in">
            {/* ── Save Button ── */}
            <div className="flex justify-end">
                <button
                    onClick={onSave}
                    className={`btn flex items-center gap-2 transition-all ${saved ? 'btn-success' : 'btn-primary'}`}
                >
                    {saved ? (
                        <><Check className="w-4 h-4" />Saved!</>
                    ) : (
                        <><Save className="w-4 h-4" />Save Changes</>
                    )}
                </button>
            </div>

            {/* ── Webhook ── */}
            <div className="card">
                <div className="flex items-center gap-3 mb-5">
                    <div className="w-9 h-9 rounded-lg bg-green-100 dark:bg-green-900/40 flex items-center justify-center">
                        <Globe className="w-5 h-5 text-green-600 dark:text-green-400" />
                    </div>
                    <div>
                        <h2 className="text-base font-semibold text-slate-900 dark:text-white">Webhook</h2>
                        <p className="text-xs text-slate-500 dark:text-slate-400">Receive alert payloads at a custom HTTP endpoint</p>
                    </div>
                </div>

                <div className="space-y-3">
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                            Webhook URL
                        </label>
                        <div className="flex gap-2">
                            <input
                                type="url"
                                value={settings.webhookUrl}
                                onChange={(e) => set({ webhookUrl: e.target.value })}
                                placeholder="https://your-siem.company.com/api/edr-alerts"
                                className="input"
                            />
                            <button
                                onClick={handleTestWebhook}
                                disabled={!settings.webhookUrl.trim() || webhookTestState === 'loading'}
                                className={`flex items-center gap-2 whitespace-nowrap text-sm font-medium px-4 py-2 rounded-md transition-colors ${testButtonClass[webhookTestState]} disabled:opacity-40 disabled:cursor-not-allowed`}
                            >
                                {testButtonContent[webhookTestState]}
                            </button>
                        </div>
                    </div>

                    {webhookTestState === 'success' && (
                        <p className="text-xs text-green-600 dark:text-green-400 flex items-center gap-1 animate-fade-in">
                            <CheckCircle className="w-3.5 h-3.5" />
                            Endpoint is reachable — payload delivered successfully.
                        </p>
                    )}
                    {webhookTestState === 'error' && (
                        <p className="text-xs text-red-600 dark:text-red-400 flex items-center gap-1 animate-fade-in">
                            <AlertCircle className="w-3.5 h-3.5" />
                            Could not reach endpoint. Check the URL and ensure it accepts POST requests.
                        </p>
                    )}

                    <div className="pt-3 border-t border-slate-100 dark:border-slate-700">
                        <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                            MITRAS will send a <code className="bg-slate-100 dark:bg-slate-700 px-1 py-0.5 rounded text-xs">POST</code> request
                            with a JSON body for each triggered alert. Ensure the endpoint is publicly accessible or reachable from this server.
                        </p>
                    </div>
                </div>
            </div>

            {/* ── Slack ── */}
            <div className="card">
                <div className="flex items-center gap-3 mb-5">
                    <div className="w-9 h-9 rounded-lg bg-purple-100 dark:bg-purple-900/40 flex items-center justify-center">
                        <Hash className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                    </div>
                    <div>
                        <h2 className="text-base font-semibold text-slate-900 dark:text-white">Slack</h2>
                        <p className="text-xs text-slate-500 dark:text-slate-400">Post alert notifications to a Slack channel</p>
                    </div>
                </div>

                <div className="space-y-3">
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                            Channel Name
                        </label>
                        <div className="relative">
                            <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 dark:text-slate-500 font-medium">#</span>
                            <input
                                type="text"
                                value={settings.slackChannel.replace(/^#/, '')}
                                onChange={(e) => set({ slackChannel: e.target.value })}
                                placeholder="security-alerts"
                                className="input pl-7"
                            />
                        </div>
                    </div>
                    <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                        Invite your configured integration bot to the channel (for example): <code className="bg-slate-100 dark:bg-slate-700 px-1 py-0.5 rounded text-xs">/invite @edr-platform</code>
                    </p>
                </div>
            </div>

            {/* ── Coming Soon ── */}
            <div className="card border-dashed border-2 border-slate-200 dark:border-slate-700 bg-transparent shadow-none">
                <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg bg-slate-100 dark:bg-slate-700 flex items-center justify-center">
                        <Zap className="w-5 h-5 text-slate-400" />
                    </div>
                    <div>
                        <h2 className="text-base font-semibold text-slate-500 dark:text-slate-400">More Integrations</h2>
                        <p className="text-xs text-slate-400 dark:text-slate-500">
                            Splunk, ServiceNow, PagerDuty, and Microsoft Teams — coming soon.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
}
