# Sigma Engine Architecture Guide

## Overview

The Sigma Engine is a high-performance, real-time threat detection system that processes security events using Sigma rules.

## System Architecture

```
                 ┌─────────────────┐
                 │   EDR Agents    │
                 │   (1000+)       │
                 └────────┬────────┘
                          │ gRPC
                          ▼
             ┌────────────────────────┐
             │  Connection Manager    │
             │  (Event Normalization) │
             └────────────┬───────────┘
                          │ Kafka
                          ▼
             ┌────────────────────────┐
             │     Kafka Cluster      │
             │   ┌─────────────────┐  │
             │   │  events-raw     │  │
             │   │  (7-day TTL)    │  │
             │   └─────────────────┘  │
             └────────────┬───────────┘
                          │
                          ▼
    ┌─────────────────────────────────────────────┐
    │              SIGMA ENGINE                    │
    │  ┌─────────────┬─────────────┬────────────┐ │
    │  │   Kafka     │  Detection  │   Alert    │ │
    │  │  Consumer   │   Engine    │  Producer  │ │
    │  └──────┬──────┴──────┬──────┴─────┬──────┘ │
    │         │             │            │        │
    │  ┌──────▼──────┐ ┌────▼────┐ ┌─────▼─────┐ │
    │  │ PostgreSQL  │ │  Rules  │ │   Kafka   │ │
    │  │ (Alerts)    │ │ (4367)  │ │ (alerts)  │ │
    │  └─────────────┘ └─────────┘ └───────────┘ │
    │                                             │
    │  ┌─────────────────────────────────────┐   │
    │  │           REST API Layer            │   │
    │  │  • Rules (9 endpoints)              │   │
    │  │  • Alerts (5 endpoints)             │   │
    │  │  • Stats (3 endpoints)              │   │
    │  │  • WebSocket (1 endpoint)           │   │
    │  │  • Metrics (Prometheus)             │   │
    │  └─────────────────────────────────────┘   │
    └─────────────────────────────────────────────┘
```

## Components

### 1. Kafka Consumer
- **File**: `internal/infrastructure/kafka/consumer.go`
- **Purpose**: Consumes events from `events-raw` topic
- **Features**: Consumer groups, offset management, error handling

### 2. Detection Engine
- **File**: `internal/application/detection/engine.go`
- **Purpose**: Matches events against Sigma rules
- **Performance**: <1ms per rule, 4,367 rules loaded

### 3. Alert Producer
- **File**: `internal/infrastructure/kafka/producer.go`
- **Purpose**: Publishes alerts to `alerts` topic
- **Features**: Snappy compression, batching

### 4. PostgreSQL Repository
- **Files**: `internal/infrastructure/database/`
- **Purpose**: Persistent storage for alerts and rules
- **Features**: Connection pooling, deduplication

### 5. REST API
- **Files**: `internal/handlers/`
- **Endpoints**: 21 total
- **Features**: Pagination, filtering, real-time streaming

## Data Flow

1. **Event Ingestion**: Agents → Connection Manager → Kafka `events-raw`
2. **Detection**: Kafka Consumer → Detection Engine → Alerts
3. **Persistence**: Alerts → PostgreSQL (with deduplication)
4. **Output**: Alerts → Kafka `alerts` topic + WebSocket

## Performance

| Metric | Value |
|--------|-------|
| Throughput | 300+ EPS |
| Latency | <50ms |
| Rules | 4,367 |
| Per-rule | <1ms |

## Deployment

### Docker
```bash
docker build -t sigma-engine:v1.0.0 .
docker run -p 8080:8080 sigma-engine:v1.0.0
```

### Kubernetes
```bash
kubectl apply -f k8s/sigma-engine.yaml
```

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `KAFKA_BROKERS` | Kafka broker addresses | `localhost:9092` |
| `DATABASE_URL` | PostgreSQL connection | - |
| `WORKERS` | Number of workers | `4` |
| `LOG_LEVEL` | Log level | `info` |

## Monitoring

- **Prometheus**: `/metrics`
- **Health**: `/health`
- **Ready**: `/ready`
