/**
 * ReportPreviewPage — Opens in a NEW browser tab.
 *
 * Data flow:
 *   ReportGenerator → localStorage['edr_report_preview'] → this page
 *
 * The page is rendered WITHOUT the main PlatformAppShell so it has its
 * own clean layout suitable for printing / saving as PDF.
 */

import { useEffect, useState, lazy, Suspense } from 'react';
import {
    ArrowLeft, Download, Loader2, FileText, AlertTriangle,
    Shield, Calendar, Printer,
} from 'lucide-react';
import type { ReportData, ReportFormat, ReportTemplate } from '../components/reports/ReportTemplates';

const SESSION_KEY = 'edr_report_preview';

/** Payload written by ReportGenerator before opening the new tab. */
interface PreviewPayload {
    data: ReportData;
    format: ReportFormat;
    template: ReportTemplate;
    customSections?: string[];
}

// Lazy-load the heavy report view
const ProfessionalReportView = lazy(() =>
    import('../components/reports/ProfessionalReportView').then(m => ({
        default: m.ProfessionalReportView,
    }))
);

function LoadingSpinner({ label }: { label: string }) {
    return (
        <div className="flex flex-col items-center justify-center min-h-screen bg-slate-50 dark:bg-slate-950 gap-4">
            <Loader2 className="w-10 h-10 text-violet-500 animate-spin" />
            <p className="text-sm text-slate-500 dark:text-slate-400">{label}</p>
        </div>
    );
}

function ErrorState({ message }: { message: string }) {
    return (
        <div className="flex flex-col items-center justify-center min-h-screen bg-slate-50 dark:bg-slate-950 gap-4 px-6">
            <div className="w-14 h-14 rounded-2xl bg-rose-100 dark:bg-rose-950/40 flex items-center justify-center">
                <AlertTriangle className="w-7 h-7 text-rose-500" />
            </div>
            <div className="text-center max-w-md">
                <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">
                    Report Preview Unavailable
                </h2>
                <p className="text-sm text-slate-500 dark:text-slate-400">{message}</p>
            </div>
            <button
                onClick={() => window.close()}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-900 text-white text-sm font-medium transition-colors"
            >
                <ArrowLeft className="w-4 h-4" />
                Close Tab
            </button>
        </div>
    );
}

export default function ReportPreviewPage() {
    const [payload, setPayload] = useState<PreviewPayload | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [isDownloading, setIsDownloading] = useState(false);

    // Sync dark mode from main window preference
    useEffect(() => {
        const stored = localStorage.getItem('theme');
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        if (stored === 'dark' || (!stored && prefersDark)) {
            document.documentElement.classList.add('dark');
        }
    }, []);

    // Read report data from localStorage
    useEffect(() => {
        try {
            const raw = localStorage.getItem(SESSION_KEY);
            if (!raw) {
                setError('No report data found. Please go back to the Reports page and generate a report first.');
                return;
            }
            const parsed: PreviewPayload = JSON.parse(raw);
            setPayload(parsed);
            document.title = `Report Preview — MITRAS`;
            
            // Optional: clean up localStorage so it doesn't persist forever
            // localStorage.removeItem(SESSION_KEY);
        } catch {
            setError('Failed to parse report data. The session may have expired.');
        }
    }, []);

    const handleDownload = async (format: ReportFormat) => {
        if (!payload) return;
        setIsDownloading(true);
        try {
            const { exportReport } = await import('../components/reports/reportExport');
            await exportReport(payload.data, format, payload.template);
        } catch (err: any) {
            console.error('Download failed:', err);
        } finally {
            setIsDownloading(false);
        }
    };

    const handlePrint = () => {
        window.print();
    };

    const handleGoBack = () => {
        window.close();
    };

    if (error) return <ErrorState message={error} />;
    if (!payload) return <LoadingSpinner label="Loading report data…" />;

    const formatLabel = payload.format.toUpperCase();
    const generatedAt = payload.data.generatedAt
        ? new Date(payload.data.generatedAt).toLocaleString()
        : '';

    return (
        <div className="min-h-screen h-screen overflow-y-auto bg-slate-100 dark:bg-slate-950 print:bg-white print:h-auto print:overflow-visible">

            {/* ── Top action bar (hidden on print) ─────────────────────────── */}
            <div className="print:hidden sticky top-0 z-50 bg-white/95 dark:bg-slate-900/95 backdrop-blur border-b border-slate-200 dark:border-slate-800 shadow-sm">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3 flex items-center gap-3">

                    {/* Back / close */}
                    <button
                        onClick={handleGoBack}
                        className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                        title="Close this tab and return to Reports"
                    >
                        <ArrowLeft className="w-4 h-4" />
                        <span className="hidden sm:inline">Back to Reports</span>
                    </button>

                    {/* Divider */}
                    <div className="w-px h-6 bg-slate-200 dark:bg-slate-700" />

                    {/* Report meta */}
                    <div className="flex items-center gap-2 flex-1 min-w-0">
                        <div className="w-8 h-8 rounded-lg bg-violet-500/10 border border-violet-500/20 flex items-center justify-center shrink-0">
                            <Shield className="w-4 h-4 text-violet-500" />
                        </div>
                        <div className="min-w-0">
                            <p className="text-sm font-semibold text-slate-900 dark:text-white truncate">
                                MITRAS Report Preview
                            </p>
                            {generatedAt && (
                                <p className="text-xs text-slate-400 dark:text-slate-500 flex items-center gap-1">
                                    <Calendar className="w-3 h-3" />
                                    Generated {generatedAt}
                                </p>
                            )}
                        </div>
                    </div>

                    {/* Action buttons */}
                    <div className="flex items-center gap-2 shrink-0">
                        {/* Print */}
                        <button
                            onClick={handlePrint}
                            className="flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
                        >
                            <Printer className="w-4 h-4" />
                            <span className="hidden sm:inline">Print</span>
                        </button>

                        {/* Download same format */}
                        <button
                            onClick={() => handleDownload(payload.format)}
                            disabled={isDownloading}
                            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-violet-600 to-cyan-600 hover:from-violet-700 hover:to-cyan-700 text-white text-sm font-semibold shadow-sm shadow-violet-500/20 disabled:opacity-60 transition-all"
                        >
                            {isDownloading ? (
                                <Loader2 className="w-4 h-4 animate-spin" />
                            ) : (
                                <Download className="w-4 h-4" />
                            )}
                            Download {formatLabel}
                        </button>

                        {/* Other format quick-download (PDF if current isn't PDF) */}
                        {payload.format !== 'pdf' && (
                            <button
                                onClick={() => handleDownload('pdf')}
                                disabled={isDownloading}
                                className="flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-60 transition-colors"
                            >
                                <FileText className="w-4 h-4" />
                                <span className="hidden sm:inline">Save as PDF</span>
                            </button>
                        )}
                    </div>
                </div>
            </div>

            {/* ── Report content ──────────────────────────────────────────── */}
            <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6 print:px-0 print:py-0 print:max-w-none">
                <Suspense fallback={<LoadingSpinner label="Rendering report…" />}>
                    <ProfessionalReportView
                        data={payload.data}
                        template={payload.template}
                        format={payload.format}
                        onDownload={handleDownload}
                        isGenerating={isDownloading}
                        customSections={payload.template === 'custom' ? payload.customSections : undefined}
                        /* Hide the internal download bar since we have our own top bar */
                        hideActionBar
                    />
                </Suspense>
            </div>
        </div>
    );
}
