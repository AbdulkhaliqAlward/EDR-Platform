/** Context (second-row) tabs + path helpers for Standard shell. */

export type ContextTab = { to: string; label: string; end?: boolean };

export const SOC_PATHS = [
    '/stats',
    '/alerts',
    '/events',
    '/endpoints',
    '/endpoint-risk',
    '/threats',
    '/rules',
    '/responses',
    '/soc',
] as const;

export function isSocPath(pathname: string): boolean {
    return SOC_PATHS.some((p) => pathname === p || pathname.startsWith(`${p}/`));
}

export const SYSTEM_PATHS = [
    '/system',
    '/audit',
] as const;

export function isSystemPath(pathname: string): boolean {
    return SYSTEM_PATHS.some((p) => pathname === p || pathname.startsWith(`${p}/`));
}

/** Hub tabs — Cloud / Verdict SaaS views omitted for self-hosted endpoint focus (routes may still exist). */
export const DASHBOARD_MAIN_TABS: ContextTab[] = [
    { to: '/dashboards/service', label: 'Security Posture' },
    { to: '/dashboards/endpoint', label: 'Endpoint Summary' },
    { to: '/dashboards/endpoint-compliance', label: 'Endpoint Compliance' },
    { to: '/dashboards/reports', label: 'Reports' },
];

export const DASHBOARD_MORE_TABS: ContextTab[] = [
    // Intentionally empty: “More” menu removed; tabs are shown directly.
];

export const SECURITY_MODULE_TABS: ContextTab[] = [
    { to: '/security/endpoint-zero-trust', label: 'Endpoint Zero Trust' },
    { to: '/security/siem-x', label: 'SIEM — X' },
    { to: '/security/tokens', label: 'Enrollment Tokens' },
    { to: '/security/events', label: 'Security Events' },
];

export const SOC_CONTEXT_TABS: ContextTab[] = [
    { to: '/stats', label: 'Statistics' },
    { to: '/alerts', label: 'Alerts (Triage)' },
    { to: '/events', label: 'Telemetry Search' },
    { to: '/endpoint-risk', label: 'Endpoint Risk' },
    { to: '/threats', label: 'ATT&CK Analytics' },
    { to: '/rules', label: 'Detection Rules' },
    { to: '/responses', label: 'Command Center' },
    { to: '/soc/vulnerability', label: 'Vulnerability' },
    { to: '/soc/correlation', label: 'Correlation' },
];

/** Managed detection & response (MDR): service-level posture + incident queue — distinct from Security modules. */
export const MANAGED_SECURITY_TABS: ContextTab[] = [
    { to: '/managed-security/overview', label: 'Operations overview' },
    { to: '/managed-security/incidents', label: 'Incident queue' },
];

export const ITSM_TABS: ContextTab[] = [
    { to: '/itsm/playbooks', label: 'Response Playbooks' },
    { to: '/itsm/automations', label: 'Response Automations' },
    { to: '/itsm/scripts', label: 'Script Library' },
    { to: '/itsm/exceptions', label: 'Detection Exceptions' },
];

export const SYSTEM_CONTEXT_TABS: ContextTab[] = [
    { to: '/system/profile', label: 'Profile' },
    { to: '/system/access/users', label: 'Users' },
    { to: '/system/access/roles', label: 'Roles & Permissions' },
    { to: '/system/audit-logs', label: 'Audit Logs' },
    { to: '/system/account', label: 'Account' },
    { to: '/system/signatures', label: 'Signatures' },
    { to: '/system/reliability-health', label: 'Reliability Health' },
];

/** RMM / licenses / billing / staff removed from nav — not in self-hosted MVP scope (URLs unchanged for bookmarks). */
export const MANAGEMENT_TABS: ContextTab[] = [
    { to: '/management/devices', label: 'Devices (Fleet)' },
    { to: '/management/network', label: 'Fleet Connectivity' },
    { to: '/management/app-control', label: 'Application Control' },
    { to: '/management/agent-deploy', label: 'Agent Deployment' },
    { to: '/management/context-policies', label: 'Context Policies' },
];

export function isDashboardMorePath(_pathname: string): boolean {
    return false;
}

