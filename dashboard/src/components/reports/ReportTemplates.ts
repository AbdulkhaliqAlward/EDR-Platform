/**
 * Professional Report Templates Configuration
 * Pre-defined report templates with charts, tables, and executive summaries
 */

export type ReportFormat = 'pdf' | 'excel' | 'word' | 'html' | 'csv' | 'json';
export type ReportTemplate = 'executive' | 'technical' | 'compliance' | 'operations' | 'custom';

export interface ReportTemplateConfig {
    id: ReportTemplate;
    name: string;
    description: string;
    icon: string;
    sections: ReportSection[];
    defaultFormat: ReportFormat;
    colorScheme: {
        primary: string;
        secondary: string;
        accent: string;
        danger: string;
        warning: string;
        success: string;
    };
}

export interface ReportSection {
    id: string;
    name: string;
    type: 'summary' | 'chart' | 'table' | 'text' | 'kpi';
    description: string;
    enabled: boolean;
    order: number;
}

export const REPORT_TEMPLATES: Record<ReportTemplate, ReportTemplateConfig> = {
    executive: {
        id: 'executive',
        name: 'Executive Summary',
        description: 'Overview for leadership showing KPIs and trends',
        icon: 'BarChart3',
        defaultFormat: 'pdf',
        colorScheme: {
            primary: '#0891b2',
            secondary: '#64748b',
            accent: '#8b5cf6',
            danger: '#dc2626',
            warning: '#f59e0b',
            success: '#10b981',
        },
        sections: [
            { id: 'cover', name: 'Cover Page', type: 'text', description: 'Title, date, and company branding', enabled: true, order: 1 },
            { id: 'summary', name: 'Executive Summary', type: 'summary', description: 'Key findings and recommendations', enabled: true, order: 2 },
            { id: 'kpis', name: 'Key Metrics', type: 'kpi', description: 'Critical KPI cards with trends', enabled: true, order: 3 },
            { id: 'trends', name: 'Trend Analysis', type: 'chart', description: '7-day trend charts', enabled: true, order: 4 },
            { id: 'risks', name: 'Risk Overview', type: 'table', description: 'Top 10 risks by severity', enabled: true, order: 5 },
            { id: 'vulns', name: 'Vulnerability Overview', type: 'chart', description: 'CVE/KEV summary and top packages', enabled: true, order: 6 },
            { id: 'recommendations', name: 'Recommendations', type: 'text', description: 'Actionable next steps', enabled: true, order: 7 },
        ],
    },
    technical: {
        id: 'technical',
        name: 'Technical Analysis',
        description: 'Technical report with MITRE ATT&CK mapping',
        icon: 'Terminal',
        defaultFormat: 'pdf',
        colorScheme: {
            primary: '#7c3aed',
            secondary: '#475569',
            accent: '#06b6d4',
            danger: '#ef4444',
            warning: '#f97316',
            success: '#22c55e',
        },
        sections: [
            { id: 'cover', name: 'Cover Page', type: 'text', description: 'Technical report header', enabled: true, order: 1 },
            { id: 'scope', name: 'Analysis Scope', type: 'text', description: 'Time range and filters applied', enabled: true, order: 2 },
            { id: 'alerts', name: 'Alert Details', type: 'table', description: 'Full alert inventory', enabled: true, order: 3 },
            { id: 'mitre', name: 'MITRE Mapping', type: 'chart', description: 'Tactics and techniques matrix', enabled: true, order: 4 },
            { id: 'endpoints', name: 'Endpoint Analysis', type: 'table', description: 'Per-endpoint breakdown', enabled: true, order: 5 },
            { id: 'endpointRisk', name: 'Endpoint Risk Posture', type: 'table', description: 'Per-endpoint risk scores and alert counts', enabled: true, order: 6 },
            { id: 'vulns', name: 'Vulnerability Findings', type: 'table', description: 'CVE list with KEV and exploit flags', enabled: true, order: 7 },
            { id: 'commands', name: 'Command History', type: 'table', description: 'Executed response actions', enabled: true, order: 8 },
            { id: 'raw', name: 'Raw Data Appendix', type: 'table', description: 'Complete dataset for further analysis', enabled: false, order: 9 },
        ],
    },
    compliance: {
        id: 'compliance',
        name: 'Compliance Report',
        description: 'Security compliance and policy adherence report',
        icon: 'Shield',
        defaultFormat: 'word',
        colorScheme: {
            primary: '#059669',
            secondary: '#52525b',
            accent: '#0ea5e9',
            danger: '#b91c1c',
            warning: '#d97706',
            success: '#16a34a',
        },
        sections: [
            { id: 'cover', name: 'Compliance Cover', type: 'text', description: 'Report title and period', enabled: true, order: 1 },
            { id: 'summary', name: 'Compliance Summary', type: 'summary', description: 'Overall compliance score', enabled: true, order: 2 },
            { id: 'policies', name: 'Policy Checks', type: 'table', description: 'Policy compliance results', enabled: true, order: 3 },
            { id: 'vulns', name: 'Vulnerability Compliance', type: 'table', description: 'Open CVEs and KEV overdue items', enabled: true, order: 4 },
            { id: 'auditLog', name: 'Audit Trail', type: 'table', description: 'Administrative and security audit events', enabled: true, order: 5 },
            { id: 'certificates', name: 'Certificate Status', type: 'table', description: 'mTLS certificate health', enabled: true, order: 6 },
            { id: 'isolations', name: 'Isolation Events', type: 'table', description: 'Network isolation log', enabled: true, order: 7 },
            { id: 'remediation', name: 'Remediation Plan', type: 'text', description: 'Required actions', enabled: true, order: 8 },
        ],
    },
    operations: {
        id: 'operations',
        name: 'Operations Dashboard',
        description: 'SOC operations and incident response metrics',
        icon: 'Activity',
        defaultFormat: 'excel',
        colorScheme: {
            primary: '#0284c7',
            secondary: '#475569',
            accent: '#f59e0b',
            danger: '#e11d48',
            warning: '#fbbf24',
            success: '#10b981',
        },
        sections: [
            { id: 'summary', name: 'Ops Summary', type: 'kpi', description: 'MTTD, MTTR, alert volume', enabled: true, order: 1 },
            { id: 'commandStats', name: 'Command Execution', type: 'kpi', description: 'Success rate, pending, failed', enabled: true, order: 2 },
            { id: 'performance', name: 'SLA Performance', type: 'table', description: 'Response time metrics', enabled: true, order: 3 },
            { id: 'topAlerts', name: 'Top Alerts', type: 'table', description: 'Most frequent alerts', enabled: true, order: 4 },
            { id: 'automation', name: 'Automation Rate', type: 'chart', description: 'Automated vs manual responses', enabled: true, order: 5 },
            { id: 'fleetHealth', name: 'Fleet Health', type: 'kpi', description: 'Online/offline devices, avg health', enabled: true, order: 6 },
        ],
    },
    custom: {
        id: 'custom',
        name: 'Custom Report',
        description: 'Build your own report with selected sections',
        icon: 'Settings',
        defaultFormat: 'pdf',
        colorScheme: {
            primary: '#6366f1',
            secondary: '#64748b',
            accent: '#ec4899',
            danger: '#dc2626',
            warning: '#f59e0b',
            success: '#10b981',
        },
        sections: [
            { id: 'cover', name: 'Cover Page', type: 'text', description: 'Report header', enabled: true, order: 1 },
            { id: 'summary', name: 'Summary', type: 'summary', description: 'Executive overview', enabled: true, order: 2 },
            { id: 'kpis', name: 'KPIs', type: 'kpi', description: 'Key metrics', enabled: true, order: 3 },
            { id: 'charts', name: 'Charts', type: 'chart', description: 'Visualizations', enabled: true, order: 4 },
            { id: 'tables', name: 'Data Tables', type: 'table', description: 'Detailed tables', enabled: true, order: 5 },
        ],
    },
};

export const REPORT_FORMATS: { id: ReportFormat; name: string; extension: string; mimeType: string; description: string; icon: string }[] = [
    { id: 'pdf', name: 'PDF Document', extension: 'pdf', mimeType: 'application/pdf', description: 'Professional formatted document with charts', icon: 'FileText' },
    { id: 'excel', name: 'Excel Workbook', extension: 'xlsx', mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', description: 'Multi-sheet workbook with data and charts', icon: 'Table' },
    { id: 'word', name: 'Word Document', extension: 'docx', mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', description: 'Editable document with embedded charts', icon: 'FileEdit' },
    { id: 'html', name: 'HTML Report', extension: 'html', mimeType: 'text/html', description: 'Interactive web-based report', icon: 'Globe' },
    { id: 'csv', name: 'CSV Data', extension: 'csv', mimeType: 'text/csv', description: 'Raw data for import into other tools', icon: 'Database' },
    { id: 'json', name: 'JSON Data', extension: 'json', mimeType: 'application/json', description: 'Structured data for API integration', icon: 'Code' },
];

export interface ReportData {
    generatedAt: string;
    period: {
        from: string;
        to: string;
    };
    filters: {
        scope: string;
        agentId?: string;
        severity?: string[];
        status?: string[];
    };
    summary: {
        totalAlerts: number;
        totalCommands: number;
        totalDevices: number;
        criticalCount: number;
        highCount: number;
        mediumCount: number;
        lowCount: number;
        avgResponseTime?: number;
        mttr?: number;
        // Vulnerability metrics
        totalVulnerabilities: number;
        kevCount: number;
        exploitableCount: number;
        // Fleet health
        avgHealthScore: number;
        onlineDevices: number;
        offlineDevices: number;
        // Detection quality
        avgConfidence: number;
        // Command execution
        commandSuccessRate: number;
        pendingCommands: number;
        failedCommands: number;
    };
    charts: {
        timeline: Array<{ date: string; critical: number; high: number; medium: number; low: number }>;
        severityDistribution: Array<{ name: string; value: number; color: string }>;
        topTactics: Array<{ tactic: string; count: number }>;
        osDistribution: Array<{ os: string; count: number }>;
        vulnBySeverity: Array<{ name: string; value: number; color: string }>;
        commandsByStatus: Array<{ status: string; count: number }>;
        topVulnPackages: Array<{ package: string; count: number }>;
    };
    tables: {
        alerts: any[];
        commands: any[];
        devices: any[];
        risks: any[];
        vulnerabilities: any[];
        auditLogs: any[];
    };
}
