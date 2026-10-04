# Sigma Engine Operations Runbook

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Go 1.21+
- PostgreSQL 15+
- Kafka 3.x

### Start with Docker Compose
```bash
cd sigma_engine_go
docker-compose up -d
```

### Start Manually
```bash
# Build
go build -o sigma-engine ./cmd/sigma-engine-kafka/main.go

# Run
./sigma-engine \
  -brokers localhost:9092 \
  -workers 4 \
  -topic events-raw
```

## Health Checks

### HTTP Endpoints
```bash
# Liveness
curl http://localhost:8080/health

# Readiness  
curl http://localhost:8080/ready

# Metrics
curl http://localhost:8080/metrics
```

### Expected Responses
```json
{"status": "healthy"}
{"status": "ready"}
```

## Common Issues

### 1. Kafka Connection Failed
**Symptoms**: "Failed to connect to Kafka"

**Resolution**:
```bash
# Check Kafka is running
docker-compose ps kafka

# Verify brokers reachable
kafka-broker-api-versions --bootstrap-server localhost:9092

# Check configuration
echo $KAFKA_BROKERS
```

### 2. Database Connection Failed
**Symptoms**: "Failed to connect to database"

**Resolution**:
```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Test connection
psql -h localhost -U sigma -d sigma_engine

# Check URL
echo $DATABASE_URL
```

### 3. High Memory Usage
**Symptoms**: Memory >2GB

**Resolution**:
```bash
# Check current usage
docker stats sigma-engine

# Reduce workers
./sigma-engine -workers 2

# Check for leaks
curl http://localhost:8080/debug/pprof/heap > heap.prof
go tool pprof heap.prof
```

### 4. High Latency
**Symptoms**: P95 >100ms

**Resolution**:
```bash
# Check metrics
curl http://localhost:8080/metrics | grep sigma_event_processing

# Check database
docker exec -it postgres psql -U sigma -c "EXPLAIN ANALYZE SELECT * FROM sigma_alerts ORDER BY timestamp DESC LIMIT 100"

# Check Kafka lag
kafka-consumer-groups --bootstrap-server localhost:9092 --describe --group sigma-engine-group
```

## Scaling

### Horizontal Scaling (Kubernetes)
```bash
# Scale up
kubectl scale deployment sigma-engine --replicas=5

# Check status
kubectl get pods -l app=sigma-engine
```

### Vertical Scaling
```yaml
# Update resource limits
resources:
  limits:
    cpu: 4000m
    memory: 4Gi
```

## Monitoring

### Key Metrics
| Metric | Alert Threshold |
|--------|-----------------|
| `sigma_events_total` rate | <100/s = investigate |
| `sigma_errors_total` rate | >1/s = alert |
| `sigma_event_processing_seconds` p95 | >0.1s = alert |
| `sigma_kafka_lag` | >10000 = alert |

### Grafana Dashboards
Import dashboard from `grafana/sigma-engine.json`

## Backup & Recovery

### Database Backup
```bash
pg_dump -h localhost -U sigma sigma_engine > backup.sql
```

### Database Restore
```bash
psql -h localhost -U sigma sigma_engine < backup.sql
```

## Logs

### View Logs
```bash
# Docker
docker logs -f sigma-engine

# Kubernetes
kubectl logs -f -l app=sigma-engine
```

### Log Levels
```bash
export LOG_LEVEL=debug  # debug, info, warn, error
```

## Emergency Procedures

### Stop Processing
```bash
# Graceful shutdown
kubectl scale deployment sigma-engine --replicas=0

# Or
docker stop sigma-engine
```

### Restart
```bash
kubectl rollout restart deployment/sigma-engine
```
