# Sigma Engine - Operations Runbook

## Installation

### Prerequisites
- Go 1.21+
- Node.js 18+
- PostgreSQL 15+
- Kafka 3.x
- Docker (optional)

### Quick Start

```bash
# Backend
cd sigma_engine_go
go mod download
go build -o sigma-engine ./cmd/sigma-engine-kafka/main.go

# Dashboard
cd dashboard
npm install
npm run build
```

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/sigma

# Kafka
KAFKA_BROKERS=localhost:9092
KAFKA_TOPIC=security-events

# API
API_PORT=8080
API_HOST=0.0.0.0

# JWT
JWT_SECRET=your-secret-key
JWT_EXPIRY=1h

# Integrations
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
TEAMS_WEBHOOK_URL=https://outlook.office.com/...
SPLUNK_HEC_URL=https://splunk:8088
SPLUNK_HEC_TOKEN=your-token
SERVICENOW_URL=https://instance.service-now.com
SERVICENOW_USER=admin
SERVICENOW_PASS=password
```

## Configuration

### Database Setup
```sql
CREATE DATABASE sigma;
-- Run migrations
psql -d sigma -f migrations/001_create_tables.sql
```

### Kafka Topics
```bash
kafka-topics.sh --create --topic security-events --partitions 12 --replication-factor 3
```

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Connection refused | Check service is running, ports open |
| Authentication failed | Verify JWT secret, check token expiry |
| Slow queries | Add indexes, check query plans |
| High memory | Increase limits, tune GC |
| Kafka lag | Scale consumers, increase partitions |

### Log Locations
- Backend: `./logs/sigma-engine.log`
- Dashboard: Browser console
- Nginx: `/var/log/nginx/access.log`

### Health Checks
```bash
curl http://localhost:8080/health
curl http://localhost:8080/api/v1/sigma/status
```

## Maintenance

### Backup Procedures
```bash
# Database backup
pg_dump sigma > backup_$(date +%Y%m%d).sql

# Restore
psql sigma < backup_20260321.sql
```

### Log Rotation
```bash
# /etc/logrotate.d/sigma-engine
/var/log/sigma-engine/*.log {
    daily
    rotate 14
    compress
    missingok
}
```

## Monitoring

### Key Metrics
- API response time (p95 < 100ms)
- Alert processing rate
- Memory usage
- Database connections
- Kafka consumer lag

### Prometheus Metrics
```
sigma_alerts_total
sigma_api_response_seconds
sigma_kafka_messages_processed
sigma_db_query_duration_seconds
```

## Disaster Recovery

### RTO/RPO
- Recovery Time Objective: 1 hour
- Recovery Point Objective: 15 minutes

### Failover Steps
1. Detect failure (monitoring alerts)
2. Switch DNS to standby
3. Verify database replication
4. Resume Kafka consumers
5. Validate functionality

---
**Version**: 1.0.0
