# Sigma Detection Engine - Go Implementation

Production-grade Sigma rule detection engine migrated from Python to Go.

## Project Structure

```
sigma_engine_go/
├── cmd/
│   └── sigma-engine/          # CLI entry point
├── internal/
│   ├── domain/                # Core domain models (Clean Architecture)
│   │   ├── event.go
│   │   ├── event_category.go
│   │   ├── rule.go
│   │   ├── detection_result.go
│   │   └── severity.go
│   ├── application/           # Application layer (use cases)
│   │   ├── detection/         # Detection engine
│   │   ├── rules/             # Rule parsing and indexing
│   │   └── mapping/           # Field mapping
│   └── infrastructure/        # Infrastructure layer
│       ├── cache/             # Caching implementations
│       ├── io/                 # File I/O
│       └── logger/             # Logging
└── pkg/                        # Public API (if needed)
```

## Architecture

This project follows **Clean Architecture** principles:

- **Domain Layer**: Pure business logic, no dependencies
- **Application Layer**: Use cases and orchestration
- **Infrastructure Layer**: External concerns (I/O, caching, logging)

## Phase 1: Foundation ✅

- ✅ Domain models (LogEvent, SigmaRule, DetectionResult)
- ✅ Infrastructure abstractions (Cache interfaces)
- ✅ Concrete implementations (LRU cache, Regex cache)
- ✅ File I/O utilities (JSONL reader/writer, YAML loader)
- ✅ Structured logging setup

## Building

```bash
go build ./cmd/sigma-engine
```

## Running

```bash
go run ./cmd/sigma-engine
```

## Dependencies

- `github.com/hashicorp/golang-lru/v2` - LRU cache implementation
- `github.com/sirupsen/logrus` - Structured logging
- `gopkg.in/yaml.v3` - YAML parsing

## Next Steps

- Phase 2: Core Parsing (RuleParser, ModifierEngine, ConditionParser)
- Phase 3: Detection Engine
- Phase 4: Parallel Processing
- Phase 5: Alert Pipeline
- Phase 6: CLI and Polish

