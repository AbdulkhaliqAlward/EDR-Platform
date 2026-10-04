# EDR Professional Reports System

## Overview

The new Professional Reports system replaces the basic JSON/CSV export with a comprehensive report generation platform featuring:

- **5 Report Templates**: Executive, Technical, Compliance, Operations, Custom
- **6 Export Formats**: PDF, Excel, Word, HTML, CSV, JSON
- **Interactive Charts**: Real-time preview with Recharts visualizations
- **Professional Styling**: Consistent, branded report design

## Components

### ReportGenerator.tsx
Main report builder interface with:
- Template selection cards
- Format selection buttons
- Date range picker
- Endpoint scope selector
- Live preview

### ProfessionalReportView.tsx
Interactive preview component showing:
- Executive summary with KPI cards
- Trend analysis charts (AreaChart)
- Severity distribution (PieChart)
- MITRE ATT&CK tactics (BarChart)
- Data tables with filtering

### ReportTemplates.ts
Configuration for all report types:
- Template definitions
- Section layouts
- Color schemes
- Format specifications

### reportExport.ts
Export engine supporting:
- PDF (browser print to PDF)
- Excel (XLSX with SheetJS)
- Word (HTML-based)
- HTML (styled document)
- CSV (structured data)
- JSON (raw data)

## Usage

```tsx
import { ReportGenerator } from './components/reports';

// In your page component:
function ReportsPage() {
    return <ReportGenerator />;
}
```

## Report Templates

### Executive Summary
- High-level KPIs for leadership
- 7-day trend visualization
- Risk overview table
- Actionable recommendations

### Technical Analysis
- Full alert inventory
- MITRE ATT&CK mapping
- Per-endpoint breakdown
- Command history

### Compliance Report
- Policy compliance status
- Certificate health
- Isolation events log
- Remediation plan

### Operations Dashboard
- SOC metrics (MTTD, MTTR)
- Team workload analysis
- SLA performance
- Automation rate

### Custom Report
- User-selectable sections
- Flexible layout
- Multiple data sources

## Export Formats

| Format | Use Case | Features |
|--------|----------|----------|
| PDF | Sharing/Printing | Professional layout, charts |
| Excel | Data Analysis | Multi-sheet, formulas, charts |
| Word | Editing | Editable document |
| HTML | Web Publishing | Interactive, styled |
| CSV | Data Import | Universal compatibility |
| JSON | API Integration | Structured data |

## Data Sources

Reports pull data from:
- `alertsApi` - Security alerts and events
- `agentsApi` - Endpoint inventory and status
- `commandsApi` - Response actions
- `statsApi` - Aggregated statistics

## Styling

All reports use:
- Tailwind CSS classes
- Dark mode support
- Consistent color scheme per template
- Professional typography
- Responsive layouts

## Dependencies

```bash
npm install xlsx
```

## Browser Compatibility

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Print-to-PDF works in all modern browsers
