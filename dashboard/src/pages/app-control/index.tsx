import React, { useState, useEffect, Suspense, lazy } from 'react';
import { Layers, Activity, ShieldAlert, Package, RefreshCw, Wifi, Wrench } from 'lucide-react';
import InsightHero from '../../components/InsightHero';

// ────────────────────────────────────────────────────────────────────────────
// Application Control — main page
//
// Five tabs (aligned with WatchGuard Application Control Dashboard):
//  1. Process Analytics  — IT Applications: what's running across the fleet
//  2. Vulnerability Findings — Vulnerable Applications: CVE scan results
//  3. Bandwidth Analytics — Bandwidth-Consuming Applications: per-app traffic
//  4. Special Apps & Tools — Scripting, remote access, admin tools drill-down
//  5. Software Inventory — Installed applications from WMI/Registry
// ────────────────────────────────────────────────────────────────────────────

// Lazy-load tabs for code-splitting
const ProcessAnalyticsTab = lazy(() => import('./ProcessAnalyticsTab'));
const VulnerabilityOverviewTab = lazy(() => import('./VulnerabilityOverviewTab'));
const BandwidthAnalyticsTab = lazy(() => import('./BandwidthAnalyticsTab'));
const SpecialAppsToolsTab = lazy(() => import('./SpecialAppsToolsTab'));
const SoftwareInventoryTab = lazy(() => import('./SoftwareInventoryTab'));

type TabId = 'processes' | 'vulnerabilities' | 'bandwidth' | 'special' | 'inventory';

const TABS: { id: TabId; label: string; icon: React.ElementType; description: string }[] = [
    {
        id: 'processes',
        label: 'IT Applications',
        icon: Activity,
        description: 'Execution visibility across fleet endpoints',
    },
    {
        id: 'vulnerabilities',
        label: 'Vulnerable Applications',
        icon: ShieldAlert,
        description: 'CVE exposure from Trivy scans',
    },
    {
        id: 'bandwidth',
        label: 'Bandwidth Consuming',
        icon: Wifi,
        description: 'Network traffic per application',
    },
    {
        id: 'special',
        label: 'Special Apps & Tools',
        icon: Wrench,
        description: 'Scripting, remote access, admin tools',
    },
    {
        id: 'inventory',
        label: 'Software Inventory',
        icon: Package,
        description: 'Installed applications from registry',
    },
];

function TabSkeleton() {
    return (
        <div className="flex items-center justify-center py-20 text-slate-500 gap-2">
            <RefreshCw className="w-5 h-5 animate-spin" /> Loading…
        </div>
    );
}

export default function ApplicationControlPage() {
    const [activeTab, setActiveTab] = useState<TabId>('processes');

    useEffect(() => {
        document.title = 'Application Control | MITRAS';
    }, []);

    return (
        <div className="space-y-6 w-full min-w-0 animate-slide-up-fade">
            {/* Hero */}
            <InsightHero
                icon={Layers}
                accent="violet"
                eyebrow="Management"
                title="Application Control"
                lead={
                    <>
                        Fleet-wide application analytics: executions, vulnerabilities, network activity, special tools, and installed software.
                        Use the tabs below to drill into each dataset.
                    </>
                }
            />

            {/* Tab bar */}
            <div className="flex items-center gap-1 border-b border-slate-200 dark:border-slate-700 overflow-x-auto">
                {TABS.map(tab => {
                    const isActive = activeTab === tab.id;
                    const Icon = tab.icon;
                    return (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={`group flex items-center gap-2 px-4 py-3 text-sm font-semibold whitespace-nowrap border-b-2 transition-all ${
                                isActive
                                    ? 'border-violet-500 text-violet-700 dark:text-violet-300'
                                    : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:border-slate-300'
                            }`}
                        >
                            <Icon className={`w-4 h-4 ${isActive ? 'text-violet-500' : 'text-slate-400 group-hover:text-slate-500'}`} />
                            {tab.label}
                        </button>
                    );
                })}
            </div>

            {/* Active tab content */}
            <Suspense fallback={<TabSkeleton />}>
                {activeTab === 'processes' && <ProcessAnalyticsTab />}
                {activeTab === 'vulnerabilities' && <VulnerabilityOverviewTab />}
                {activeTab === 'bandwidth' && <BandwidthAnalyticsTab />}
                {activeTab === 'special' && <SpecialAppsToolsTab />}
                {activeTab === 'inventory' && <SoftwareInventoryTab />}
            </Suspense>
        </div>
    );
}
