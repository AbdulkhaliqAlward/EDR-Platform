# Sigma Engine Dashboard

Separated React dashboard for the EDR Platform.

## Project Structure

```
dashboard/
├── src/
│   ├── api/           # API clients for both backends
│   ├── pages/         # 6 pages (Dashboard, Alerts, Rules, Stats, Login, Settings)
│   ├── App.tsx        # Main app with routing
│   └── main.tsx       # Entry point
├── Dockerfile         # Multi-stage build
├── nginx.conf         # Reverse proxy config
├── .env.example       # Environment template
└── package.json       # Dependencies
```

## Quick Start

```bash
# Install dependencies
npm install

# Development (uses localhost:8080 by default)
npm run dev

# Build for production
npm run build
```

## Environment Variables

Copy `.env.example` to `.env.local` and configure:

| Variable | Description | Default |
|----------|-------------|---------|
| `VITE_API_URL` | Sigma Engine URL | `http://localhost:8080` |
| `VITE_CONNECTION_MANAGER_URL` | Connection Manager URL | `http://localhost:8082` |
| `VITE_WS_URL` | WebSocket URL | Derived from API_URL |

## Integration

### With Sigma Engine
- Alerts API: `/api/v1/sigma/alerts`
- Rules API: `/api/v1/sigma/rules`
- Stats API: `/api/v1/sigma/stats/*`
- WebSocket: `/api/v1/sigma/alerts/stream`

### With Connection Manager
- Agents API: `/api/v1/agents`

## Docker Deployment

```bash
# Build image
docker build -t sigma-dashboard \
  --build-arg VITE_API_URL=http://sigma-engine:8080 \
  --build-arg VITE_CONNECTION_MANAGER_URL=http://connection-manager:8082 \
  .

# Run container
docker run -p 3000:80 sigma-dashboard
```

## Full Stack (docker-compose)

From `EDR_Server/`:

```bash
docker-compose up -d
```

This starts:
- PostgreSQL (5432)
- Kafka (9092)
- Redis (6379)
- Sigma Engine (8080)
- Connection Manager (8082)
- Dashboard (3000)

## Tech Stack
- React 19
- TypeScript
- Vite
- TailwindCSS
- React Query
- Axios
- React Router
