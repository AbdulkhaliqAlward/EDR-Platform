# Test Guide - Sigma Detection Engine

## نظرة عامة

دليل شامل لتشغيل جميع أنواع الاختبارات في محرك Sigma Detection Engine.

## أنواع الاختبارات

### 1. Unit Tests (اختبارات الوحدة)

اختبارات للمكونات الفردية:

```bash
# جميع الاختبارات
go test ./...

# حزمة محددة
go test ./internal/domain
go test ./internal/application/detection
go test ./internal/application/rules

# اختبار محدد
go test ./internal/domain -run TestNewLogEvent

# مع verbose output
go test ./internal/domain -v
```

### 2. Integration Tests (اختبارات التكامل)

اختبارات للتدفق الكامل:

```bash
# جميع اختبارات التكامل
go test ./test/integration -v

# اختبار محدد
go test ./test/integration -run TestEndToEndDetection
```

### 3. Benchmarks (اختبارات الأداء)

```bash
# جميع benchmarks
go test -bench=. -benchmem ./...

# benchmark محدد
go test -bench=BenchmarkLogEvent_GetStringField ./internal/domain

# مع تفاصيل الذاكرة
go test -bench=. -benchmem -memprofile=mem.out ./...

# تحليل الذاكرة
go tool pprof mem.out
```

### 4. Race Condition Tests

```bash
# اختبار race conditions
go test -race ./...

# حزمة محددة
go test -race ./internal/infrastructure/processor
```

### 5. Coverage Analysis (تحليل التغطية)

```bash
# إنشاء تقرير التغطية
go test -coverprofile=coverage.out ./...

# عرض HTML
go tool cover -html=coverage.out -o coverage.html

# عرض النسبة المئوية
go tool cover -func=coverage.out | grep total
```

## تشغيل جميع الاختبارات

```bash
# جميع الاختبارات مع race detector
go test -race -coverprofile=coverage.out ./...

# مع benchmarks
go test -race -bench=. -benchmem ./...
```

## اختبارات محددة

### Domain Models

```bash
go test ./internal/domain -v
```

### Modifier Engine

```bash
go test ./internal/application/detection -v -run TestModifier
```

### Detection Engine

```bash
go test ./internal/application/detection -v -run TestDetection
```

### Integration Tests

```bash
go test ./test/integration -v
```

## Benchmarks

### Performance Benchmarks

```bash
# Detection Engine
go test -bench=BenchmarkDetectionEngine ./internal/application/detection

# Modifiers
go test -bench=BenchmarkModifier ./internal/application/detection

# Field Resolution
go test -bench=BenchmarkFieldMapper ./internal/application/mapping
```

## Load Tests

```bash
# اختبارات الحمل (تتطلب وقت أطول)
go test ./test/load -v -timeout 5m
```

## Short Mode

لتخطي الاختبارات الطويلة:

```bash
go test -short ./...
```

## Continuous Integration

للـ CI/CD:

```bash
# جميع الاختبارات مع race detector و coverage
go test -race -coverprofile=coverage.out -covermode=atomic ./...

# التحقق من التغطية
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

3. تحقق من الذاكرة:
```bash
go test -memprofile=mem.out ./...
go tool pprof mem.out
```

### اختبارات بطيئة

1. استخدم short mode:
```bash
go test -short ./...
```

2. قم بتشغيل اختبارات محددة فقط

## Best Practices

1. **شغّل race detector دائماً** قبل الـ commit
2. **تحقق من التغطية** - يجب أن تكون 80%+
3. **شغّل benchmarks** قبل إصدارات جديدة
4. **اختبر التكامل** مع بيانات حقيقية
5. **راجع النتائج** بانتظام

---

**جاهز للاستخدام** ✅

