# Sigma Engine - User Guide

## Getting Started

### First Login
1. Open dashboard at `https://sigma.company.com`
2. Enter credentials provided by admin
3. Complete MFA setup (if enabled)

### Dashboard Overview

The main dashboard displays:
- **KPIs**: Total alerts, critical count, open alerts
- **Live Feed**: Real-time alert stream
- **Charts**: Trending data, severity distribution

## Alert Management

### Viewing Alerts
- Navigate to **Alerts** page
- Use filters: severity, status, date range
- Click alert row for details

### Alert Actions
| Action | Description |
|--------|-------------|
| Acknowledge | Mark as being investigated |
| Resolve | Close as handled |
| Escalate | Notify manager |
| Comment | Add investigation notes |

### Filtering
```
severity:critical status:open agent:workstation-*
```

## Rules Management

### Viewing Rules
- Navigate to **Rules** page
- See enabled/disabled status
- View rule statistics

### Creating Custom Rules
1. Click **Create Rule**
2. Add conditions (AND/OR logic)
3. Set severity and actions
4. Test against sample data
5. Save and enable

### Condition Operators
- `equals`, `not_equals`
- `contains`, `not_contains`
- `matches` (regex)
- `exists`, `not_exists`

## Playbooks

### Creating Playbooks
1. Navigate to **Playbooks**
2. Click **New Playbook**
3. Set trigger conditions
4. Add workflow steps
5. Configure notifications
6. Test and publish

### Step Types
- Notify Slack/Teams/Email
- Create ServiceNow ticket
- Wait (delay)
- Acknowledge/Resolve alert
- Conditional logic

## Integrations

### Webhooks
1. Go to **Settings > Integrations**
2. Add webhook URL
3. Configure headers
4. Set filters (severity, rules)
5. Test delivery

### Splunk
1. Enter HEC endpoint
2. Add HEC token
3. Configure index
4. Test connection

### ServiceNow
1. Enter instance URL
2. Add credentials
3. Set assignment group
4. Test connection

## User Preferences

### Alert Profiles
- Set minimum severity
- Choose notification channels
- Configure quiet hours
- Set alert routing rules

### Notification Channels
- Slack: Channel or DM
- Email: Direct or team
- Teams: Channel notifications

---
**Need Help?** Contact: soc-support@company.com
