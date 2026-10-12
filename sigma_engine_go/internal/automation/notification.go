// Package automation provides notification system for Slack, Teams, and Email.
package automation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"sync"
	"time"

	"github.com/edr-platform/shared/tzdetect"

	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
	"github.com/google/uuid"
)

// NotificationConfig holds notification settings.
type NotificationConfig struct {
	SlackWebhookURL   string   `json:"slack_webhook_url"`
	TeamsWebhookURL   string   `json:"teams_webhook_url"`
	SMTPServer        string   `json:"smtp_server"`
	SMTPPort          int      `json:"smtp_port"`
	SMTPUser          string   `json:"smtp_user"`
	SMTPPassword      string   `json:"smtp_password"`
	EmailFrom         string   `json:"email_from"`
	DefaultChannel    string   `json:"default_channel"`
	DefaultRecipients []string `json:"default_recipients"`
}

// NotificationLog tracks sent notifications.
type NotificationLog struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // slack, teams, email
	Recipient string    `json:"recipient"`
	Subject   string    `json:"subject,omitempty"`
	Message   string    `json:"message"`
	AlertID   string    `json:"alert_id"`
	Status    string    `json:"status"` // sent, failed
	Error     string    `json:"error,omitempty"`
	SentAt    time.Time `json:"sent_at"`
}

// NotificationManager handles all notification channels.
type NotificationManager struct {
	mu     sync.RWMutex
	config NotificationConfig
	client *http.Client
	logs   []NotificationLog
}

// NewNotificationManager creates a notification manager.
func NewNotificationManager() *NotificationManager {
	return &NotificationManager{
		client: &http.Client{Timeout: 10 * time.Second},
		logs:   make([]NotificationLog, 0),
	}
}

// Configure updates notification settings.
func (n *NotificationManager) Configure(config NotificationConfig) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config = config
	logger.Info("Notification manager configured")
}

// GetConfig returns current configuration.
func (n *NotificationManager) GetConfig() NotificationConfig {
	n.mu.RLock()
	defer n.mu.RUnlock()
	cfg := n.config
	cfg.SMTPPassword = "********" // Mask password
	return cfg
}

// SendSlack sends a Slack notification.
func (n *NotificationManager) SendSlack(ctx context.Context, alert *domain.Alert, config map[string]interface{}) error {
	n.mu.RLock()
	webhookURL := n.config.SlackWebhookURL
	n.mu.RUnlock()

	if webhookURL == "" {
		if url, ok := config["webhook_url"].(string); ok {
			webhookURL = url
		}
	}
	if webhookURL == "" {
		return fmt.Errorf("slack webhook URL not configured")
	}

	channel := n.config.DefaultChannel
	if ch, ok := config["channel"].(string); ok {
		channel = ch
	}

	// Build Slack message
	message := n.buildSlackMessage(alert, config)

	payload := map[string]interface{}{
		"channel": channel,
		"text":    fmt.Sprintf("[%s] %s", alert.Severity.String(), alert.RuleTitle),
		"blocks":  message,
	}

	// Send request
	err := n.sendWebhook(ctx, webhookURL, payload)

	// Log notification
	log := NotificationLog{
		ID:        uuid.New().String(),
		Type:      "slack",
		Recipient: channel,
		Message:   alert.RuleTitle,
		AlertID:   alert.ID,
		SentAt:    time.Now(),
	}
	if err != nil {
		log.Status = "failed"
		log.Error = err.Error()
	} else {
		log.Status = "sent"
	}
	n.saveLog(log)

	return err
}

// buildSlackMessage creates Slack blocks.
func (n *NotificationManager) buildSlackMessage(alert *domain.Alert, config map[string]interface{}) []map[string]interface{} {
	severityEmoji := map[string]string{
		"critical": "🔴",
		"high":     "🟠",
		"medium":   "🟡",
		"low":      "🔵",
	}

	emoji := severityEmoji[alert.Severity.String()]
	if emoji == "" {
		emoji = "⚪"
	}

	blocks := []map[string]interface{}{
		{
			"type": "header",
			"text": map[string]interface{}{
				"type":  "plain_text",
				"text":  fmt.Sprintf("%s %s Alert", emoji, alert.Severity.String()),
				"emoji": true,
			},
		},
		{"type": "divider"},
		{
			"type": "section",
			"fields": []map[string]interface{}{
				{"type": "mrkdwn", "text": fmt.Sprintf("*Rule:*\n%s", alert.RuleTitle)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Severity:*\n%s", alert.Severity.String())},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Alert ID:*\n%s", alert.ID[:8])},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Time:*\n%s", displayTime(alert.Timestamp))},
			},
		},
	}

	return blocks
}

// SendTeams sends a Microsoft Teams notification.
func (n *NotificationManager) SendTeams(ctx context.Context, alert *domain.Alert, config map[string]interface{}) error {
	n.mu.RLock()
	webhookURL := n.config.TeamsWebhookURL
	n.mu.RUnlock()

	if webhookURL == "" {
		if url, ok := config["webhook_url"].(string); ok {
			webhookURL = url
		}
	}
	if webhookURL == "" {
		return fmt.Errorf("teams webhook URL not configured")
	}

	// Build Teams adaptive card
	card := n.buildTeamsCard(alert)

	err := n.sendWebhook(ctx, webhookURL, card)

	// Log notification
	log := NotificationLog{
		ID:        uuid.New().String(),
		Type:      "teams",
		Recipient: "teams",
		Message:   alert.RuleTitle,
		AlertID:   alert.ID,
		SentAt:    time.Now(),
	}
	if err != nil {
		log.Status = "failed"
		log.Error = err.Error()
	} else {
		log.Status = "sent"
	}
	n.saveLog(log)

	return err
}

// buildTeamsCard creates a Teams adaptive card.
func (n *NotificationManager) buildTeamsCard(alert *domain.Alert) map[string]interface{} {
	themeColor := map[string]string{
		"critical": "FF0000",
		"high":     "FF6600",
		"medium":   "FFCC00",
		"low":      "0066FF",
	}

	color := themeColor[alert.Severity.String()]
	if color == "" {
		color = "808080"
	}

	return map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "https://schema.org/extensions",
		"summary":    fmt.Sprintf("%s Alert: %s", alert.Severity.String(), alert.RuleTitle),
		"themeColor": color,
		"title":      fmt.Sprintf("[%s] Security Alert", alert.Severity.String()),
		"sections": []map[string]interface{}{
			{
				"facts": []map[string]string{
					{"name": "Rule", "value": alert.RuleTitle},
					{"name": "Severity", "value": alert.Severity.String()},
					{"name": "Alert ID", "value": alert.ID[:8]},
					{"name": "Time", "value": displayTime(alert.Timestamp)},
				},
			},
		},
	}
}

// SendEmail sends an email notification.
func (n *NotificationManager) SendEmail(ctx context.Context, alert *domain.Alert, config map[string]interface{}) error {
	n.mu.RLock()
	smtpConfig := n.config
	n.mu.RUnlock()

	if smtpConfig.SMTPServer == "" {
		return fmt.Errorf("SMTP not configured")
	}

	// Get recipients
	recipients := smtpConfig.DefaultRecipients
	if to, ok := config["to"].([]string); ok {
		recipients = to
	} else if to, ok := config["to"].(string); ok {
		recipients = []string{to}
	}

	if len(recipients) == 0 {
		return fmt.Errorf("no email recipients specified")
	}

	// Build email
	subject := fmt.Sprintf("[%s] %s", alert.Severity.String(), alert.RuleTitle)
	if subj, ok := config["subject"].(string); ok {
		subject = SubstituteVariables(subj, alert)
	}

	body := n.buildEmailBody(alert)

	// Send email
	err := n.sendSMTP(smtpConfig, recipients, subject, body)

	// Log notification
	log := NotificationLog{
		ID:        uuid.New().String(),
		Type:      "email",
		Recipient: recipients[0],
		Subject:   subject,
		Message:   body,
		AlertID:   alert.ID,
		SentAt:    time.Now(),
	}
	if err != nil {
		log.Status = "failed"
		log.Error = err.Error()
	} else {
		log.Status = "sent"
	}
	n.saveLog(log)

	return err
}

// buildEmailBody creates HTML email content.
func (n *NotificationManager) buildEmailBody(alert *domain.Alert) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head><style>
body { font-family: Arial, sans-serif; }
.alert { border-left: 4px solid #dc3545; padding: 15px; margin: 10px 0; }
.critical { border-color: #dc3545; background: #f8d7da; }
.high { border-color: #fd7e14; background: #fff3cd; }
.medium { border-color: #ffc107; background: #fff9e6; }
.low { border-color: #0d6efd; background: #cfe2ff; }
</style></head>
<body>
<h2>Security Alert</h2>
<div class="alert %s">
<p><strong>Rule:</strong> %s</p>
<p><strong>Severity:</strong> %s</p>
<p><strong>Alert ID:</strong> %s</p>
<p><strong>Timestamp:</strong> %s</p>
</div>
</body>
</html>`,
		alert.Severity.String(),
		alert.RuleTitle,
		alert.Severity.String(),
		alert.ID,
		displayTime(alert.Timestamp),
	)
}

// displayZone is the platform display time zone, detected automatically from
// the server host (shared/tzdetect) — the same zone the dashboards use.
var displayZone = tzdetect.Current

// displayTime renders a time in the platform display time zone, e.g.
// "12 Oct 2026 13:04:05 +03 (Asia/Riyadh)".
func displayTime(t time.Time) string {
	z := displayZone()
	local := t.In(z.Location)
	name := z.Name
	if name == "" { // unnamed host zone: show the UTC offset
		name = "UTC" + local.Format("-07:00")
	}
	return local.Format("02 Jan 2006 15:04:05 MST") + " (" + name + ")"
}

// sendWebhook sends HTTP POST to webhook URL.
func (n *NotificationManager) sendWebhook(ctx context.Context, url string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}

	return nil
}

// sendSMTP sends email via SMTP.
func (n *NotificationManager) sendSMTP(config NotificationConfig, to []string, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", config.SMTPServer, config.SMTPPort)

	headers := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n",
		config.EmailFrom, to[0], subject)

	message := []byte(headers + body)

	var auth smtp.Auth
	if config.SMTPUser != "" {
		auth = smtp.PlainAuth("", config.SMTPUser, config.SMTPPassword, config.SMTPServer)
	}

	return smtp.SendMail(addr, auth, config.EmailFrom, to, message)
}

// saveLog stores notification log.
func (n *NotificationManager) saveLog(log NotificationLog) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.logs = append(n.logs, log)

	// Keep last 1000 logs
	if len(n.logs) > 1000 {
		n.logs = n.logs[len(n.logs)-1000:]
	}
}

// GetLogs retrieves notification logs.
func (n *NotificationManager) GetLogs(limit int, typeFilter string) []NotificationLog {
	n.mu.RLock()
	defer n.mu.RUnlock()

	result := make([]NotificationLog, 0)
	for i := len(n.logs) - 1; i >= 0 && len(result) < limit; i-- {
		if typeFilter == "" || n.logs[i].Type == typeFilter {
			result = append(result, n.logs[i])
		}
	}
	return result
}

// GetStats returns notification statistics.
func (n *NotificationManager) GetStats() map[string]interface{} {
	n.mu.RLock()
	defer n.mu.RUnlock()

	stats := map[string]int{
		"slack_sent":   0,
		"teams_sent":   0,
		"email_sent":   0,
		"slack_failed": 0,
		"teams_failed": 0,
		"email_failed": 0,
	}

	for _, log := range n.logs {
		key := log.Type + "_" + log.Status
		stats[key]++
	}

	return map[string]interface{}{
		"total_notifications": len(n.logs),
		"by_type":             stats,
	}
}
