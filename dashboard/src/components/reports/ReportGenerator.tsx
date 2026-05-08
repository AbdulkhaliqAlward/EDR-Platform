/**
 * Report Generator Component
 * Advanced report creation with templates, formats, and data visualization
 */

import { useState, useCallback, useMemo } from 'react';
import {
    FileText, FileSpreadsheet, FileCode, Download, RefreshCw,
    Eye, AlertTriangle, Calendar, Filter,
    BarChart3, Shield, Activity, Terminal, Server, Settings
} from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import {
    alertsApi,
    agentsApi,
    commandsApi,
    vulnerabilityApi,
    auditApi,
} from '../../api/client';
import { REPORT_TEMPLATES, REPORT_FORMATS, type ReportTemplate, type ReportFormat, type ReportData } from './ReportTemplates';

/** Key used to pass report data to the standalone preview tab via localStorage. */
const SESSION_KEY = 'edr_report_preview';

/** Formats that support a visual preview page (opens in new tab). */
const PREVIEWABLE_FORMATS = new Set<ReportFormat>(['pdf', 'word', 'html']);
/** Formats that are data-only — trigger a direct download without preview. */
const DOWNLOAD_ONLY_FORMATS = new Set<ReportFormat>(['excel', 'csv', 'json']);

const TEMPLATE_ICONS: Record<string, any> = {
    BarChart3, Terminal, Shield, Activity, Settings,
};

const FORMAT_ICONS: Record<string, any> = {
    pdf: FileText,
    excel: FileSpreadsheet,
    word: FileText,
    html: FileCode,
    csv: FileSpreadsheet,
    json: FileCode,
};

export function ReportGenerator() {
    // Report configuration
    const [selectedTemplate, setSelectedTemplate] = useState<ReportTemplate>('executive');
    const [selectedFormat, setSelectedFormat] = useState<ReportFormat>('pdf');
    const [reportScope, setReportScope] = useState<'all' | 'specific'>('all');
    const [selectedAgent, setSelectedAgent] = useState<string>('');
    const [dateRange, setDateRange] = useState<{ from: string; to: string }>(() => {
        const to = new Date();
        const from = new Date();
        from.setDate(from.getDate() - 7);
        return {
            from: from.toISOString().slice(0, 16),
            to: to.toISOString().slice(0, 16),
        };
    });
    const [isGenerating, setIsGenerating] = useState(false);
    const [generatedData, setGeneratedData] = useState<ReportData | null>(null);
    const [error, setError] = useState<string | null>(null);
    // showPreview no longer needed — preview opens in a separate tab

    // Custom report sections
    const [customSections, setCustomSections] = useState<string[]>(['summary', 'kpis', 'charts', 'tables']);

    // Fetch agents list
    const agentsQuery = useQuery({
        queryKey: ['agents', 'reports-list'],
        queryFn: async () => {
            const res = await agentsApi.list({ limit: 500, sort_by: 'hostname' });
            return res.data;
        },
        staleTime: 60000,
    });

    // Generate report data
    const generateReportData = useCallback(async (): Promise<ReportData> => {
        const fromIso = new Date(dateRange.from).toISOString();
        const toIso = new Date(dateRange.to).toISOString();

        // Fetch all required data in parallel
        const [alertsRes, agentsRes, commandsRes, vulnRes, agentStatsRes, cmdStatsRes, auditRes] = await Promise.allSettled([
            alertsApi.list({
                limit: 1000,
                date_from: fromIso,
                date_to: toIso,
                agent_id: reportScope === 'specific' && selectedAgent ? selectedAgent : undefined,
                sort: 'timestamp',
                order: 'desc'
            }),
            agentsApi.list({ limit: 500 }),
            commandsApi.list({ limit: 500 }),
            vulnerabilityApi.listFindings({ limit: 200 }),
            agentsApi.stats(),
            commandsApi.stats(),
            auditApi.list({ limit: 200 }),
        ]);

        const alerts = alertsRes.status === 'fulfilled' ? (alertsRes.value.alerts || []) : [];
        const agents = agentsRes.status === 'fulfilled' ? (agentsRes.value.data || []) : [];
        const commands = commandsRes.status === 'fulfilled' ? (commandsRes.value.data || []) : [];
        const vulnFindings = vulnRes.status === 'fulfilled' ? (vulnRes.value.data || []) : [];
        const agentStats = agentStatsRes.status === 'fulfilled' ? agentStatsRes.value : null;
        const _cmdStats = cmdStatsRes.status === 'fulfilled' ? cmdStatsRes.value : null; void _cmdStats;
        const auditLogs = auditRes.status === 'fulfilled' ? (auditRes.value.data || []) : [];

        // Create agent map
        const agentMap = new Map(agents.map((a: { id: string; hostname: string }) => [a.id, a.hostname]));

        // Calculate summary
        const criticalCount = alerts.filter((a: { severity: string }) => a.severity === 'critical').length;
        const highCount = alerts.filter((a: { severity: string }) => a.severity === 'high').length;
        const mediumCount = alerts.filter((a: { severity: string }) => a.severity === 'medium').length;
        const lowCount = alerts.filter((a: { severity: string }) => a.severity === 'low').length;

        // Vulnerability stats
        const kevCount = vulnFindings.filter((v: any) => v.kev_listed).length;
        const exploitableCount = vulnFindings.filter((v: any) => v.exploit_available).length;

        // Command stats
        const completedCmds = commands.filter((c: any) => c.status === 'completed').length;
        const failedCmds = commands.filter((c: any) => c.status === 'failed').length;
        const pendingCmds = commands.filter((c: any) => c.status === 'pending' || c.status === 'sent').length;
        const cmdSuccessRate = commands.length > 0 ? Math.round((completedCmds / commands.length) * 100) : 0;

        // MTTR calculation: avg time from alert creation to resolution
        const resolvedAlerts = alerts.filter((a: any) => a.resolved_at && a.timestamp);
        let mttr: number | undefined;
        if (resolvedAlerts.length > 0) {
            const totalMinutes = resolvedAlerts.reduce((sum: number, a: any) => {
                return sum + (new Date(a.resolved_at).getTime() - new Date(a.timestamp).getTime()) / 60000;
            }, 0);
            mttr = Math.round(totalMinutes / resolvedAlerts.length);
        }

        // Calculate timeline (last 7 days)
        const timeline: ReportData['charts']['timeline'] = [];
        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            const dateStr = date.toISOString().split('T')[0];

            const dayAlerts = alerts.filter((a: { timestamp: string }) => a.timestamp.startsWith(dateStr));
            timeline.push({
                date: dateStr,
                critical: dayAlerts.filter(a => a.severity === 'critical').length,
                high: dayAlerts.filter(a => a.severity === 'high').length,
                medium: dayAlerts.filter(a => a.severity === 'medium').length,
                low: dayAlerts.filter(a => a.severity === 'low').length,
            });
        }

        // Severity distribution
        const severityDistribution = [
            { name: 'Critical', value: criticalCount, color: '#ef4444' },
            { name: 'High', value: highCount, color: '#f97316' },
            { name: 'Medium', value: mediumCount, color: '#f59e0b' },
            { name: 'Low', value: lowCount, color: '#3b82f6' },
        ].filter(s => s.value > 0);

        // Top MITRE tactics
        const tacticCounts = new Map<string, number>();
        alerts.forEach((a: { mitre_tactics?: string[] }) => {
            a.mitre_tactics?.forEach((t: string) => {
                tacticCounts.set(t, (tacticCounts.get(t) || 0) + 1);
            });
        });
        const topTactics = Array.from(tacticCounts.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([tactic, count]) => ({ tactic, count }));

        // OS distribution
        const osCounts = new Map<string, number>();
        agents.forEach((a: { os_type: string }) => {
            osCounts.set(a.os_type, (osCounts.get(a.os_type) || 0) + 1);
        });
        const osDistribution = Array.from(osCounts.entries())
            .map(([os, count]) => ({ os, count }));

        // Vulnerability severity distribution
        const vulnSevCounts = new Map<string, number>();
        vulnFindings.forEach((v: any) => {
            vulnSevCounts.set(v.severity, (vulnSevCounts.get(v.severity) || 0) + 1);
        });
        const vulnBySeverity = [
            { name: 'Critical', value: vulnSevCounts.get('critical') || 0, color: '#ef4444' },
            { name: 'High', value: vulnSevCounts.get('high') || 0, color: '#f97316' },
            { name: 'Medium', value: vulnSevCounts.get('medium') || 0, color: '#f59e0b' },
            { name: 'Low', value: vulnSevCounts.get('low') || 0, color: '#3b82f6' },
        ].filter(s => s.value > 0);

        // Top vulnerable packages
        const pkgCounts = new Map<string, number>();
        vulnFindings.forEach((v: any) => {
            if (v.package_name) pkgCounts.set(v.package_name, (pkgCounts.get(v.package_name) || 0) + 1);
        });
        const topVulnPackages = Array.from(pkgCounts.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([pkg, count]) => ({ package: pkg, count }));

        // Commands by status
        const statusCounts = new Map<string, number>();
        commands.forEach((c: any) => {
            statusCounts.set(c.status, (statusCounts.get(c.status) || 0) + 1);
        });
        const commandsByStatus = Array.from(statusCounts.entries())
            .map(([status, count]) => ({ status, count }));

        // Avg confidence
        const avgConfidence = alerts.length > 0
            ? Math.round(alerts.reduce((s: number, a: any) => s + (a.confidence || 0), 0) / alerts.length * 100) / 100
            : 0;

        // Enrich alerts with hostnames
        const enrichedAlerts = alerts.slice(0, 100).map((a: { agent_id: string }) => ({
            ...a,
            agent_hostname: agentMap.get(a.agent_id) || a.agent_id,
        }));

        return {
            generatedAt: new Date().toISOString(),
            period: { from: fromIso, to: toIso },
            filters: {
                scope: reportScope,
                agentId: selectedAgent || undefined,
            },
            summary: {
                totalAlerts: alerts.length,
                totalCommands: commands.length,
                totalDevices: agents.length,
                criticalCount,
                highCount,
                mediumCount,
                lowCount,
                mttr,
                totalVulnerabilities: vulnFindings.length,
                kevCount,
                exploitableCount,
                avgHealthScore: agentStats?.avg_health ?? 0,
                onlineDevices: agentStats?.online ?? 0,
                offlineDevices: agentStats?.offline ?? 0,
                avgConfidence,
                commandSuccessRate: cmdSuccessRate,
                pendingCommands: pendingCmds,
                failedCommands: failedCmds,
            },
            charts: {
                timeline,
                severityDistribution,
                topTactics,
                osDistribution,
                vulnBySeverity,
                commandsByStatus,
                topVulnPackages,
            },
            tables: {
                alerts: enrichedAlerts,
                commands: commands.slice(0, 100),
                devices: agents,
                risks: [],
                vulnerabilities: vulnFindings.slice(0, 100),
                auditLogs: auditLogs.slice(0, 100),
            },
        };
    }, [dateRange, reportScope, selectedAgent]);

    // Handle generate button
    const handleGenerate = async () => {
        setIsGenerating(true);
        setError(null);
        try {
            const data = await generateReportData();
            setGeneratedData(data);

            if (PREVIEWABLE_FORMATS.has(selectedFormat)) {
                // PDF / Word / HTML → store payload and open a new browser tab
                const payload = {
                    data,
                    format: selectedFormat,
                    template: selectedTemplate,
                    customSections: selectedTemplate === 'custom' ? customSections : undefined,
                };
                localStorage.setItem(SESSION_KEY, JSON.stringify(payload));
                window.open('/report-preview', '_blank');
            } else {
                // Excel / CSV / JSON → direct download without preview
                const { exportReport } = await import('./reportExport');
                await exportReport(data, selectedFormat, selectedTemplate);
            }
        } catch (err: any) {
            setError(err.message || 'Failed to generate report');
        } finally {
            setIsGenerating(false);
        }
    };

    // Handle download for already-generated data
    const handleDownload = async (format: ReportFormat) => {
        if (!generatedData) return;

        setIsGenerating(true);
        try {
            const { exportReport } = await import('./reportExport');
            await exportReport(generatedData, format, selectedTemplate);
        } catch (err: any) {
            setError(err.message || 'Failed to export report');
        } finally {
            setIsGenerating(false);
        }
    };

    // Get available sections for custom report
    const availableSections = useMemo(() => {
        return [
            { id: 'cover', name: 'Cover Page', type: 'text', description: 'Report header with title and date' },
            { id: 'summary', name: 'Executive Summary', type: 'summary', description: 'Key findings and overview' },
            { id: 'kpis', name: 'Key Metrics (KPIs)', type: 'kpi', description: 'Critical performance indicators' },
            { id: 'severity', name: 'Severity Distribution', type: 'chart', description: 'Pie chart of alert severities' },
            { id: 'trends', name: 'Trend Analysis', type: 'chart', description: '7-day alert trends' },
            { id: 'mitre', name: 'MITRE ATT&CK Tactics', type: 'chart', description: 'Tactics bar chart' },
            { id: 'os', name: 'OS Distribution', type: 'chart', description: 'Operating system breakdown' },
            { id: 'vulns', name: 'Vulnerability Summary', type: 'chart', description: 'CVE/KEV findings overview' },
            { id: 'alerts', name: 'Alerts Table', type: 'table', description: 'Detailed alerts list' },
            { id: 'devices', name: 'Devices Table', type: 'table', description: 'Endpoint inventory' },
            { id: 'commands', name: 'Commands Table', type: 'table', description: 'Response actions' },
            { id: 'auditLog', name: 'Audit Trail', type: 'table', description: 'Administrative activity log' },
        ];
    }, []);

    const toggleCustomSection = (sectionId: string) => {
        setCustomSections(prev =>
            prev.includes(sectionId)
                ? prev.filter(id => id !== sectionId)
                : [...prev, sectionId]
        );
    };

    return (
        <div className="space-y-6">
            {/* Report Builder Panel */}
            <div className="rounded-2xl border border-slate-200/90 dark:border-slate-700/80 bg-white/95 dark:bg-slate-800/90 backdrop-blur-sm shadow-md overflow-hidden">
                <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-700 bg-gradient-to-r from-violet-50/80 via-white to-slate-50/80 dark:from-violet-950/30 dark:via-slate-900/80 dark:to-slate-900/60">
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-xl bg-violet-500/12 text-violet-600 dark:text-violet-400 border border-violet-500/15 flex items-center justify-center">
                            <BarChart3 className="w-5 h-5" />
                        </div>
                        <div>
                            <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Report Generator</h2>
                            <p className="text-sm text-slate-500 dark:text-slate-400">
                                Create reports with charts and data visualizations
                            </p>
                        </div>
                    </div>
                </div>

                <div className="p-6 space-y-6">
                    {/* Template Selection */}
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">
                            Report Template
                        </label>
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
                            {(Object.keys(REPORT_TEMPLATES) as ReportTemplate[]).map((template) => {
                                const config = REPORT_TEMPLATES[template];
                                const Icon = TEMPLATE_ICONS[config.icon] || FileText;
                                const isSelected = selectedTemplate === template;

                                return (
                                    <button
                                        key={template}
                                        onClick={() => setSelectedTemplate(template)}
                                        className={`p-4 rounded-xl border-2 text-left transition-all ${isSelected
                                            ? 'border-violet-500 bg-violet-50 dark:bg-violet-950/30'
                                            : 'border-slate-200 dark:border-slate-700 hover:border-violet-300 dark:hover:border-violet-700'
                                            }`}
                                    >
                                        <Icon className={`w-6 h-6 mb-2 ${isSelected ? 'text-violet-600 dark:text-violet-400' : 'text-slate-500'}`} />
                                        <p className={`font-semibold ${isSelected ? 'text-violet-900 dark:text-violet-100' : 'text-slate-900 dark:text-white'}`}>
                                            {config.name}
                                        </p>
                                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 line-clamp-2">
                                            {config.description}
                                        </p>
                                    </button>
                                );
                            })}
                        </div>
                    </div>

                    {/* Custom Report Section Selector */}
                    {selectedTemplate === 'custom' && (
                        <div className="p-4 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-200 dark:border-slate-700">
                            <div className="flex items-center gap-2 mb-3">
                                <Settings className="w-4 h-4 text-violet-500" />
                                <label className="text-sm font-semibold text-slate-700 dark:text-slate-300">
                                    Customize Report Sections
                                </label>
                            </div>
                            <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">
                                Select which sections to include in your custom report:
                            </p>
                            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-2">
                                {availableSections.map((section) => (
                                    <button
                                        key={section.id}
                                        onClick={() => toggleCustomSection(section.id)}
                                        className={`p-2 rounded-lg border text-left transition-all ${customSections.includes(section.id)
                                            ? 'border-violet-500 bg-violet-50 dark:bg-violet-950/30 text-violet-700 dark:text-violet-300'
                                            : 'border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600 opacity-60'
                                            }`}
                                    >
                                        <div className="flex items-center gap-2">
                                            <div className={`w-4 h-4 rounded border flex items-center justify-center ${customSections.includes(section.id)
                                                ? 'bg-violet-500 border-violet-500'
                                                : 'border-slate-300 dark:border-slate-600'
                                                }`}>
                                                {customSections.includes(section.id) && (
                                                    <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                                                    </svg>
                                                )}
                                            </div>
                                            <span className="text-xs font-medium">{section.name}</span>
                                        </div>
                                    </button>
                                ))}
                            </div>
                            <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">
                                Selected: {customSections.length} sections
                            </p>
                        </div>
                    )}

                    {/* Format Selection */}
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">
                            Export Format
                        </label>
                        <div className="flex flex-wrap gap-2">
                            {REPORT_FORMATS.map((fmt) => {
                                const Icon = FORMAT_ICONS[fmt.id] || FileText;
                                const isSelected = selectedFormat === fmt.id;

                                return (
                                    <button
                                        key={fmt.id}
                                        onClick={() => setSelectedFormat(fmt.id)}
                                        className={`flex items-center gap-2 px-4 py-2 rounded-lg border transition-all ${isSelected
                                            ? 'border-cyan-500 bg-cyan-50 dark:bg-cyan-950/30 text-cyan-700 dark:text-cyan-300'
                                            : 'border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600'
                                            }`}
                                    >
                                        <Icon className="w-4 h-4" />
                                        <span className="text-sm font-medium">{fmt.name}</span>
                                    </button>
                                );
                            })}
                        </div>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">
                            {REPORT_FORMATS.find(f => f.id === selectedFormat)?.description}
                        </p>
                    </div>

                    {/* Scope & Date Range */}
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                        {/* Scope */}
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                                <Filter className="w-4 h-4 inline mr-1" />
                                Report Scope
                            </label>
                            <select
                                value={reportScope}
                                onChange={(e) => setReportScope(e.target.value as any)}
                                className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-sm"
                            >
                                <option value="all">All Endpoints</option>
                                <option value="specific">Specific Endpoint</option>
                            </select>
                        </div>

                        {/* Agent Selection */}
                        {reportScope === 'specific' && (
                            <div>
                                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                                    <Server className="w-4 h-4 inline mr-1" />
                                    Select Endpoint
                                </label>
                                <select
                                    value={selectedAgent}
                                    onChange={(e) => setSelectedAgent(e.target.value)}
                                    disabled={agentsQuery.isLoading}
                                    className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-sm"
                                >
                                    <option value="">Choose an endpoint...</option>
                                    {agentsQuery.data?.map((agent) => (
                                        <option key={agent.id} value={agent.id}>
                                            {agent.hostname} ({agent.os_type})
                                        </option>
                                    ))}
                                </select>
                                {agentsQuery.isLoading && (
                                    <p className="text-xs text-slate-500 mt-1">Loading endpoints...</p>
                                )}
                            </div>
                        )}

                        {/* Date Range */}
                        <div className={reportScope === 'specific' ? '' : 'lg:col-span-2'}>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                                <Calendar className="w-4 h-4 inline mr-1" />
                                Time Range
                            </label>
                            <div className="flex gap-2">
                                <input
                                    type="datetime-local"
                                    value={dateRange.from}
                                    onChange={(e) => setDateRange(prev => ({ ...prev, from: e.target.value }))}
                                    className="flex-1 px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-sm"
                                />
                                <span className="text-slate-500 self-center">to</span>
                                <input
                                    type="datetime-local"
                                    value={dateRange.to}
                                    onChange={(e) => setDateRange(prev => ({ ...prev, to: e.target.value }))}
                                    className="flex-1 px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-sm"
                                />
                            </div>
                        </div>
                    </div>

                    {/* Error Message */}
                    {error && (
                        <div className="rounded-lg border border-rose-200 dark:border-rose-900/50 bg-rose-50/80 dark:bg-rose-950/20 px-4 py-3 text-sm text-rose-900 dark:text-rose-200 flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4" />
                            {error}
                        </div>
                    )}

                    {/* Action Buttons */}
                    <div className="flex flex-wrap gap-3 pt-4 border-t border-slate-200 dark:border-slate-700">
                        {/* Primary action — label changes based on format type */}
                        <button
                            onClick={handleGenerate}
                            disabled={isGenerating || (reportScope === 'specific' && !selectedAgent)}
                            className="flex items-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-violet-600 to-cyan-600 hover:from-violet-700 hover:to-cyan-700 text-white font-semibold shadow-lg shadow-violet-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                        >
                            {isGenerating ? (
                                <>
                                    <RefreshCw className="w-5 h-5 animate-spin" />
                                    {PREVIEWABLE_FORMATS.has(selectedFormat) ? 'Opening Preview…' : 'Downloading…'}
                                </>
                            ) : PREVIEWABLE_FORMATS.has(selectedFormat) ? (
                                <>
                                    <Eye className="w-5 h-5" />
                                    Preview Report
                                </>
                            ) : (
                                <>
                                    <Download className="w-5 h-5" />
                                    Download {selectedFormat.toUpperCase()}
                                </>
                            )}
                        </button>

                        {/* Re-download button: shown after generation for download-only formats */}
                        {generatedData && DOWNLOAD_ONLY_FORMATS.has(selectedFormat) && (
                            <button
                                onClick={() => handleDownload(selectedFormat)}
                                disabled={isGenerating}
                                className="flex items-center gap-2 px-5 py-3 rounded-xl border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 font-semibold disabled:opacity-50 transition-all"
                            >
                                <Download className="w-4 h-4" />
                                Re-download {selectedFormat.toUpperCase()}
                            </button>
                        )}

                        {/* For previewable formats, offer a direct download too after first preview */}
                        {generatedData && PREVIEWABLE_FORMATS.has(selectedFormat) && (
                            <button
                                onClick={() => handleDownload(selectedFormat)}
                                disabled={isGenerating}
                                className="flex items-center gap-2 px-5 py-3 rounded-xl bg-slate-800 dark:bg-slate-700 hover:bg-slate-900 dark:hover:bg-slate-600 text-white font-semibold disabled:opacity-50 transition-all"
                            >
                                <Download className="w-4 h-4" />
                                Download {selectedFormat.toUpperCase()}
                            </button>
                        )}
                    </div>
                </div>
            </div>

            {/* Quick Stats */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800">
                    <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400 mb-1">
                        <Shield className="w-4 h-4" />
                        <span className="text-xs uppercase tracking-wider">Report Types</span>
                    </div>
                    <p className="text-2xl font-bold text-slate-900 dark:text-white">5 Templates</p>
                    <p className="text-xs text-slate-500 mt-1">Executive, Technical, Compliance, Operations, Custom</p>
                </div>

                <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800">
                    <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400 mb-1">
                        <FileText className="w-4 h-4" />
                        <span className="text-xs uppercase tracking-wider">Export Formats</span>
                    </div>
                    <p className="text-2xl font-bold text-slate-900 dark:text-white">6 Formats</p>
                    <p className="text-xs text-slate-500 mt-1">PDF, Excel, Word, HTML, CSV, JSON</p>
                </div>

                <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800">
                    <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400 mb-1">
                        <BarChart3 className="w-4 h-4" />
                        <span className="text-xs uppercase tracking-wider">Visualizations</span>
                    </div>
                    <p className="text-2xl font-bold text-slate-900 dark:text-white">Interactive</p>
                    <p className="text-xs text-slate-500 mt-1">Charts, tables, and KPI cards</p>
                </div>
            </div>
        </div>
    );
}
