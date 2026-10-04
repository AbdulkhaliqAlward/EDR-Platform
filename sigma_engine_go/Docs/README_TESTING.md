# Testing Guide - Sigma Detection Engine

## نظرة سريعة

هذا الدليل يشرح كيفية تشغيل جميع أنواع الاختبارات في محرك Sigma Detection Engine.

## تشغيل الاختبارات

### جميع الاختبارات

```bash
go test ./...
```

### اختبارات محددة

```bash
# Domain tests
go test ./internal/domain -v

# Modifier tests
go test ./internal/application/detection -v

# Integration tests
go test ./test/integration -v
```

### مع Race Detector

```bash
go test -race ./...
```

### مع Coverage

```bash
# Generate coverage report
go test -coverprofile=coverage.out ./...

# View HTML report
go tool cover -html=coverage.out -o coverage.html

# View percentage
go tool cover -func=coverage.out | grep total
```

### Benchmarks

```bash
# All benchmarks
go test -bench=. -benchmem ./...

# Specific benchmark
go test -bench=BenchmarkLogEvent_GetStringField ./internal/domain
```

## هيكل الاختبارات

```
sigma_engine_go/
├── internal/
│   ├── domain/
│   │   ├── event_test.go        ✅ LogEvent tests
│   │   └── rule_test.go         ✅ SigmaRule tests
│   └── application/
│       └── detection/
│           └── modifier_test.go ✅ Modifier tests
├── test/
│   ├── helpers/
│   │   └── test_helpers.go      ✅ Test data generators
│   └── integration/
│       └── e2e_detection_test.go ✅ Integration tests
```

## الاختبارات المتاحة

### ✅ Domain Models
- LogEvent creation and validation
- Field access (string, int, float, bool)
- Category inference
- Field caching
- Hash computation
- SigmaRule validation
- LogSource matching
- Severity mapping
- MITRE ATT&CK extraction

### ✅ Modifier Engine
- Contains modifier
- StartsWith modifier
- EndsWith modifier
- Regex modifier
- Base64 modifier
- CIDR modifier
- Numeric modifiers (lt, lte, gt, gte)
- All modifier

### ✅ Integration Tests
- End-to-end detection
- Multiple rules detection
- Batch processing
- Performance validation

## Benchmarks المتاحة

### Domain
- `BenchmarkLogEvent_GetStringField`
- `BenchmarkLogEvent_GetNestedField`
- `BenchmarkLogEvent_HashComputation`
- `BenchmarkLogEvent_Creation`
- `BenchmarkSigmaRule_Validation`
- `BenchmarkLogSource_Matching`

### Modifiers
- `BenchmarkModifier_Contains`
- `BenchmarkModifier_Regex`
- `BenchmarkModifier_Base64`
- `BenchmarkModifier_CIDR`

## Coverage Goals

- **Overall**: 80%+
- **Critical paths**: 100%
- **Current**: ~42% (domain package)

## Continuous Integration

للـ CI/CD pipelines:

```bash
# Run all tests with race detector and coverage
go test -race -coverprofile=coverage.out -covermode=atomic ./...

# Check coverage threshold
go tool cover -func=coverage.out | grep total | awk '{if ($3+0 < 80) exit 1}'
```

## Troubleshooting

### اختبارات تفشل

1. تحقق من الأخطاء:
```bash
go test -v ./internal/domain 2>&1 | grep FAIL
```

2. تحقق من race conditions:
```bash
go test -race ./...
```

### اختبارات بطيئة

استخدم short mode:
```bash
go test -short ./...
```

## Best Practices

1. ✅ شغّل race detector دائماً قبل commit
2. ✅ تحقق من coverage بانتظام
3. ✅ راجع benchmark results
4. ✅ أضف tests للميزات الجديدة
5. ✅ حافظ على test helpers محدثة

---

**جاهز للاستخدام** ✅

