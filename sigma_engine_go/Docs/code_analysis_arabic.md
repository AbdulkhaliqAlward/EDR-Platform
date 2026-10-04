<div dir=rtl>

# 📚 تحليل شامل لمحرك Sigma Detection Engine

## 🎯 نظرة عامة على المشروع

**Sigma Engine** هو محرك كشف تهديدات أمنية (Threat Detection Engine) مبني بلغة **Go**. يقوم باستقبال أحداث النظام (Events) من Kafka، ومقارنتها مع قواعد Sigma للكشف عن الأنشطة المشبوهة.

```
┌────────────────┐    ┌──────────────┐    ┌─────────────────┐
│  Kafka Events  │───▶│ Sigma Engine │───▶│  Alerts (Kafka) │
│  (events-raw)  │    │   (Go)       │    │                 │
└────────────────┘    └──────────────┘    └─────────────────┘
```

---

## 📁 هيكل المشروع

```
sigma_engine_go/
├── cmd/                         # نقاط الدخول (Entry Points)
│   ├── sigma-engine-kafka/      # الوضع الإنتاجي مع Kafka
│   └── sigma-engine-live/       # وضع التطوير المباشر
├── internal/                    # الكود الداخلي
│   ├── application/             # منطق الأعمال
│   │   ├── detection/           # ⭐ محرك الكشف الأساسي
│   │   ├── rules/               # تحميل وفهرسة القواعد
│   │   ├── mapping/             # تعيين الحقول
│   │   └── alert/               # توليد التنبيهات
│   ├── domain/                  # نماذج البيانات
│   └── infrastructure/          # البنية التحتية
│       ├── kafka/               # التكامل مع Kafka
│       ├── cache/               # ذاكرة التخزين المؤقت
│       └── config/              # التهيئة
└── pkg/                         # مكتبات قابلة للاستخدام الخارجي
```

---

## 🚀 1. نقطة البداية: `main.go`

**الملف**: `cmd/sigma-engine-kafka/main.go`
**الغرض**: بدء تشغيل المحرك في وضع Kafka

### المكتبات المستوردة

```go
import (
    "context"       // للتحكم في دورة حياة العمليات
    "flag"          // لقراءة معاملات سطر الأوامر
    "os/signal"     // للتعامل مع إشارات النظام (Ctrl+C)
    
    // مكتبات المشروع الداخلية
    "github.com/edr-platform/sigma-engine/internal/application/alert"
    "github.com/edr-platform/sigma-engine/internal/application/detection"
    "github.com/edr-platform/sigma-engine/internal/application/mapping"
    "github.com/edr-platform/sigma-engine/internal/application/rules"
    "github.com/edr-platform/sigma-engine/internal/infrastructure/cache"
    "github.com/edr-platform/sigma-engine/internal/infrastructure/config"
    "github.com/edr-platform/sigma-engine/internal/infrastructure/kafka"
)
```

### تسلسل التشغيل

```
1. قراءة الإعدادات من سطر الأوامر
2. تحميل ملف التهيئة (config.yaml)
3. إنشاء ذاكرة التخزين المؤقت (Caches)
4. إنشاء محرك الكشف (Detection Engine)
5. تحميل قواعد Sigma
6. إنشاء مستهلك Kafka (Consumer)
7. إنشاء منتج Kafka (Producer)
8. بدء حلقة الأحداث (Event Loop)
```

### معاملات سطر الأوامر

| المعامل | الوصف | القيمة الافتراضية |
|---------|-------|------------------|
| `-config` | مسار ملف التهيئة | `config/config.yaml` |
| `-brokers` | عناوين Kafka | `localhost:9092` |
| `-events-topic` | موضوع الأحداث الواردة | `events-raw` |
| `-alerts-topic` | موضوع التنبيهات الصادرة | `alerts` |
| `-workers` | عدد عمليات الكشف المتوازية | `4` |

---

## ⚙️ 2. محرك الكشف: `detection_engine.go`

**الملف**: `internal/application/detection/detection_engine.go`
**الحجم**: 967 سطر
**الغرض**: المسؤول عن مقارنة الأحداث مع قواعد Sigma

### البنية الأساسية (Struct)

```go
type SigmaDetectionEngine struct {
    rules           []*domain.SigmaRule      // قائمة القواعد المحملة
    ruleIndex       *rules.RuleIndexer       // فهرس للبحث السريع
    selectionEval   *SelectionEvaluator      // مقيّم الاختيارات
    conditionParser *rules.ConditionParser   // محلل الشروط المنطقية
    modifierEngine  *ModifierRegistry        // محرك المعدلات (contains, endswith, etc.)
    fieldMapper     *mapping.FieldMapper     // معيّن الحقول
    stats           *DetectionStats          // إحصائيات الأداء
    quality         QualityConfig            // إعدادات الجودة
    mu              sync.RWMutex             // قفل للتزامن (Thread-safe)
}
```

### الدالة الرئيسية: `Detect()`

```go
func (e *SigmaDetectionEngine) Detect(event *domain.LogEvent) []*domain.DetectionResult
```

**المدخلات**: حدث نظام واحد (`LogEvent`)
**المخرجات**: قائمة نتائج الكشف (`DetectionResult[]`)

**خطوات العمل**:

```
1. فحص القائمة البيضاء (Whitelist)
   └─ إذا كان الحدث من عملية/مستخدم موثوق → تجاهل

2. البحث عن القواعد المرشحة (O(1) lookup)
   └─ استخدام الفهرس للحصول على القواعد المطابقة لنوع الحدث

3. تقييم كل قاعدة مرشحة
   ├─ تقييم الاختيارات (Selections)
   ├─ تقييم الشروط المنطقية (AND/OR/NOT)
   ├─ تطبيق الفلاتر (إن وجدت)
   └─ حساب درجة الثقة (Confidence)

4. إرجاع النتائج التي تجاوزت عتبة الثقة
```

### حساب درجة الثقة

```go
func (e *SigmaDetectionEngine) calculateConfidence(...) float64 {
    // 1. الثقة الأساسية من مستوى القاعدة
    baseConf := getLevelConfidence(rule.Level)
    // critical=1.0, high=0.8, medium=0.6, low=0.4
    
    // 2. عامل الحقول المطابقة
    fieldFactor := matchedFields / totalFields
    
    // 3. عامل السياق (اختياري)
    contextScore := validateContext(rule, event)
    
    // النتيجة النهائية
    return baseConf * fieldFactor * contextScore
}
```

---

## 📋 3. نموذج قاعدة Sigma: `domain/rule.go`

**الملف**: `internal/domain/rule.go`
**الغرض**: تعريف بنية قاعدة Sigma

```go
type SigmaRule struct {
    ID          string                // معرف القاعدة الفريد
    Title       string                // عنوان القاعدة
    Description string                // وصف القاعدة
    Status      string                // الحالة (test, experimental, stable)
    Level       string                // مستوى الخطورة
    Author      string                // المؤلف
    References  []string              // مراجع خارجية
    Tags        []string              // علامات (MITRE ATT&CK, etc.)
    
    Logsource   Logsource             // مصدر السجلات
    Detection   DetectionBlock        // شروط الكشف
    
    FalsePositives []string           // السيناريوهات الإيجابية الكاذبة
}

type DetectionBlock struct {
    Selections map[string]*Selection // الاختيارات (selection_*)
    Condition  string                // الشرط المنطقي
}

type Selection struct {
    Fields []FieldMatcher            // قائمة الحقول للمقارنة
}
```

---

## 🔍 4. مقيّم الاختيارات: `selection_evaluator.go`

**الملف**: `internal/application/detection/selection_evaluator.go`
**الغرض**: تقييم ما إذا كان الحدث يطابق اختيار معين

```go
type SelectionEvaluator struct {
    fieldMapper    *mapping.FieldMapper
    modifierEngine *ModifierRegistry
    fieldCache     *cache.FieldResolutionCache
}
```

### منطق المطابقة

```
للاختيار selection:
├─ لكل حقل في الاختيار:
│   ├─ استخراج قيمة الحقل من الحدث
│   ├─ تطبيق المعدلات (contains, startswith, etc.)
│   └─ مقارنة القيمة مع القيم المتوقعة
│
└─ النتيجة: true إذا تطابقت كل الحقول (AND logic)
```

---

## 🔧 5. المعدلات: `modifier.go`

**الملف**: `internal/application/detection/modifier.go`
**الغرض**: تنفيذ معدلات Sigma (مثل `|contains`, `|endswith`)

### المعدلات المدعومة

| المعدل | الوصف | مثال |
|--------|-------|------|
| `contains` | يحتوي على النص | `CommandLine\|contains: 'powershell'` |
| `startswith` | يبدأ بالنص | `Image\|startswith: 'C:\Windows'` |
| `endswith` | ينتهي بالنص | `Image\|endswith: '.exe'` |
| `re` | تعبير منتظم | `CommandLine\|re: '.*-enc.*'` |
| `cidr` | نطاق IP | `DestinationIp\|cidr: '10.0.0.0/8'` |
| `all` | كل القيم مطلوبة | `CommandLine\|all\|contains: ['a', 'b']` |

---

## 📊 6. تدفق البيانات

```
┌─────────────────────────────────────────────────────────────┐
│                    Kafka Consumer                            │
│                   (events-raw topic)                         │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                     Event Parser                             │
│              (JSON → domain.LogEvent)                        │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  Detection Engine                            │
│  ┌─────────────┐  ┌───────────────┐  ┌─────────────────┐   │
│  │  Whitelist  │──│ Rule Indexer  │──│ Rule Evaluator  │   │
│  │   Check     │  │  (O(1))       │  │                 │   │
│  └─────────────┘  └───────────────┘  └─────────────────┘   │
│                                              │               │
│                         ┌────────────────────┘               │
│                         ▼                                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Selection Evaluator                     │   │
│  │  ┌─────────────┐  ┌────────────┐  ┌──────────────┐  │   │
│  │  │ Field       │──│ Modifier   │──│ Value        │  │   │
│  │  │ Mapper      │  │ Engine     │  │ Matcher      │  │   │
│  │  └─────────────┘  └────────────┘  └──────────────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
│                         │                                    │
│                         ▼                                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Condition Parser                        │   │
│  │     selection AND NOT filter | (sel1 OR sel2)       │   │
│  └─────────────────────────────────────────────────────┘   │
│                         │                                    │
│                         ▼                                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Confidence Calculator                   │   │
│  │   baseLevel × fieldFactor × contextScore            │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  Alert Generator                             │
│              (DetectionResult → Alert)                       │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   Kafka Producer                             │
│                    (alerts topic)                            │
└─────────────────────────────────────────────────────────────┘
```

---

## 🏗️ 7. المكونات الرئيسية

### 7.1 Rule Indexer (فهرس القواعد)

```go
// تخزين القواعد بحسب Logsource للبحث السريع
type RuleIndexer struct {
    byProduct  map[string][]*SigmaRule  // حسب المنتج (windows, linux)
    byCategory map[string][]*SigmaRule  // حسب الفئة (process_creation)
    byService  map[string][]*SigmaRule  // حسب الخدمة (sysmon)
}
```

**لماذا الفهرسة؟**
- بدون فهرسة: فحص 7000 قاعدة لكل حدث ❌
- مع فهرسة: فحص ~50 قاعدة فقط (المطابقة للنوع) ✅

### 7.2 Field Mapper (معيّن الحقول)

```go
// تحويل أسماء حقول Sigma إلى أسماء الحقول الفعلية
type FieldMapper struct {
    mappings map[string]string
    cache    *FieldResolutionCache
}
```

**مثال**:
```
Sigma Field: Image
Windows Field: EventData.Image
Linux Field: comm
```

### 7.3 Cache (ذاكرة التخزين المؤقت)

```go
// تخزين نتائج التحليل لتسريع العمليات المتكررة
type FieldResolutionCache struct {
    cache *lru.Cache  // LRU Cache للحقول
}

type RegexCache struct {
    cache *lru.Cache  // LRU Cache للتعبيرات المنتظمة المترجمة
}
```

---

## 📈 8. مقاييس الأداء

| المقياس | الهدف | القيمة الفعلية |
|---------|-------|----------------|
| معالجة حدث واحد | <1ms | ~0.3ms |
| الإنتاجية | 10,000 EPS | 12,000+ EPS |
| استخدام الذاكرة | مستقر | ~200MB |

---

## 🔒 9. آليات تقليل الإيجابيات الكاذبة

### القائمة البيضاء (Whitelist)
```yaml
filtering:
  enabled: true
  whitelisted_processes:
    - C:\Windows\System32\svchost.exe
    - C:\Windows\System32\services.exe
  whitelisted_users:
    - SYSTEM
    - NT AUTHORITY\SYSTEM
```

### عتبة الثقة (Confidence Threshold)
```yaml
detection:
  min_confidence: 0.6  # 60% minimum
```

### فلترة حالة القاعدة
```yaml
rules:
  skip_experimental: true
  allowed_status: [stable, test]
  min_level: medium
```

---

## 📝 ملخص

**Sigma Engine** هو محرك كشف تهديدات عالي الأداء:

1. **يستقبل** أحداث من Kafka بشكل مستمر
2. **يفهرس** القواعد للبحث السريع O(1)
3. **يقيّم** الأحداث ضد القواعد المناسبة
4. **يحسب** درجة الثقة لتقليل الإيجابيات الكاذبة
5. **ينتج** تنبيهات للتهديدات المكتشفة

**التقنيات المستخدمة**:
- Go (للأداء العالي)
- Kafka (لمعالجة الأحداث)
- LRU Cache (للتخزين المؤقت)
- Sigma Rules (معيار صناعي للكشف)

---

## 🧠 10. محلل الشروط المنطقية: `condition_parser.go`

**الملف**: `internal/application/rules/condition_parser.go`
**الحجم**: 600 سطر
**الغرض**: تحويل شروط Sigma النصية إلى شجرة AST قابلة للتقييم

### كيف يعمل المحلل؟

```
المدخل: "selection AND NOT filter"
                ↓
          ┌─────────────┐
          │  Tokenizer  │
          └─────────────┘
                ↓
    Tokens: [selection, AND, NOT, filter]
                ↓
          ┌─────────────┐
          │   Parser    │
          └─────────────┘
                ↓
              AST:
           ┌───AND───┐
           │         │
       selection   NOT
                    │
                 filter
```

### أنواع العقد (Node Types)

| العقدة | الوصف | المنطق |
|--------|-------|--------|
| `AndNode` | عملية AND | `left && right` |
| `OrNode` | عملية OR | `left \|\| right` |
| `NotNode` | عملية NOT | `!child` |
| `SelectionNode` | مرجع اختيار | `selections[name]` |
| `PatternNode` | نمط مثل "1 of X" | عدد المطابقات ≥ N |

### الكلمات المحجوزة

```go
switch lower {
case "and":  return TokenAnd
case "or":   return TokenOr
case "not":  return TokenNot
case "of":   return TokenOf
case "them": return TokenThem
case "all":  return TokenAll
case "any":  return TokenAny
}
```

### أمثلة على الشروط المدعومة

```yaml
# شرط بسيط
condition: selection

# AND
condition: selection AND not_filter

# OR
condition: selection1 OR selection2

# معقد
condition: (selection1 OR selection2) AND NOT filter

# أنماط
condition: 1 of selection_*
condition: all of them
condition: any of selection_network_*
```

---

## 🔄 11. حلقة أحداث Kafka: `event_loop.go`

**الملف**: `internal/infrastructure/kafka/event_loop.go`
**الحجم**: 313 سطر
**الغرض**: تنسيق المستهلك والمنتج ومحرك الكشف

### البنية

```go
type EventLoop struct {
    consumer        *EventConsumer           // مستهلك الأحداث
    producer        *AlertProducer           // منتج التنبيهات
    detectionEngine *SigmaDetectionEngine    // محرك الكشف
    alertGenerator  *AlertGenerator          // مولد التنبيهات
    config          EventLoopConfig          // التهيئة
    metrics         *EventLoopMetrics        // الإحصائيات
    alertChan       chan *domain.Alert       // قناة التنبيهات
    running         atomic.Bool              // حالة التشغيل
}
```

### تدفق المعالجة

```
┌────────────────────────────────────────────────────────────┐
│                     Event Loop                              │
├────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌──────────────┐    ┌──────────────┐    ┌────────────┐  │
│   │   Consumer   │───▶│   Worker 1   │───▶│            │  │
│   │  (Kafka)     │    └──────────────┘    │            │  │
│   │              │    ┌──────────────┐    │  Alert     │  │
│   │    events    │───▶│   Worker 2   │───▶│  Channel   │  │
│   │    channel   │    └──────────────┘    │            │  │
│   │              │    ┌──────────────┐    │            │  │
│   │              │───▶│   Worker 3   │───▶│            │  │
│   │              │    └──────────────┘    │            │  │
│   │              │    ┌──────────────┐    │            │  │
│   │              │───▶│   Worker 4   │───▶│            │  │
│   └──────────────┘    └──────────────┘    └─────┬──────┘  │
│                                                   │         │
│                                           ┌───────▼──────┐ │
│                                           │   Alert      │ │
│                                           │   Publisher  │ │
│                                           │   (Kafka)    │ │
│                                           └──────────────┘ │
└────────────────────────────────────────────────────────────┘
```

### العامل (Detection Worker)

```go
func (el *EventLoop) detectionWorker(ctx context.Context, workerID int) {
    for {
        select {
        case event := <-eventChan:
            // 1. استقبال الحدث
            
            // 2. تشغيل الكشف
            matchResult := el.detectionEngine.DetectAggregated(event)
            
            // 3. توليد تنبيه إذا تطابق
            if matchResult.HasMatches() {
                alert := el.alertGenerator.GenerateAggregatedAlert(matchResult)
                el.alertChan <- alert
            }
        }
    }
}
```

### الإحصائيات المتتبعة

| المقياس | الوصف |
|---------|-------|
| `EventsReceived` | عدد الأحداث المستلمة |
| `EventsProcessed` | عدد الأحداث المعالجة |
| `AlertsGenerated` | عدد التنبيهات المولدة |
| `AlertsPublished` | عدد التنبيهات المنشورة |
| `CurrentEPS` | معدل الأحداث/ثانية الحالي |
| `AverageLatencyMs` | متوسط زمن المعالجة |

---

## 📦 12. نموذج الحدث: `event.go`

**الملف**: `internal/domain/event.go`
**الحجم**: 427 سطر
**الغرض**: تمثيل حدث النظام الموحد

### البنية

```go
type LogEvent struct {
    RawData    map[string]interface{} // البيانات الخام
    EventID    *string                // معرف الحدث
    Category   EventCategory          // فئة الحدث
    Product    string                 // المنتج (windows, linux)
    Service    string                 // الخدمة
    Timestamp  time.Time              // الوقت
    
    fieldCache map[string]interface{} // ذاكرة مؤقتة للحقول
    hash       *string                // التجزئة للإزالة المكررة
}
```

### استنتاج الفئة التلقائي

```go
func (e *LogEvent) inferCategory() EventCategory {
    // 1. من EventID
    // Event 1 (Sysmon) → ProcessCreation
    // Event 3 (Sysmon) → NetworkConnection
    // Event 11 (Sysmon) → FileEvent
    
    // 2. من event.action
    // "start", "create", "exec" → ProcessCreation
    // "connect", "network" → NetworkConnection
    
    // 3. من الحقول الموجودة
    // Image + CommandLine → ProcessCreation
    // DestinationIp → NetworkConnection
    // TargetFilename → FileEvent
}
```

### فئات الأحداث المدعومة

| الفئة | الوصف | أمثلة EventID |
|-------|-------|--------------|
| `ProcessCreation` | إنشاء عملية | Sysmon 1, Windows 4688 |
| `NetworkConnection` | اتصال شبكة | Sysmon 3 |
| `FileEvent` | عمليات الملفات | Sysmon 11, 23 |
| `RegistryEvent` | عمليات السجل | Sysmon 12, 13, 14 |
| `DNSQuery` | استعلام DNS | Sysmon 22 |
| `Authentication` | المصادقة | Windows 4624, 4625 |
| `ImageLoad` | تحميل DLL | Sysmon 7 |

### الوصول للحقول

```go
// الوصول المباشر
event.GetField("CommandLine")

// الوصول المتداخل
event.GetField("process.command_line")

// مع نوع محدد
event.GetStringField("Image")
event.GetInt64Field("ProcessId")
event.GetBoolField("elevated")

// مع قيمة افتراضية
event.GetFieldWithDefault("User", "UNKNOWN")
```

---

## 📊 13. ملخص المكونات

| المكون | الملف | الحجم | الغرض |
|--------|-------|-------|--------|
| نقطة الدخول | `cmd/sigma-engine-kafka/main.go` | 206 LOC | بدء النظام |
| محرك الكشف | `detection_engine.go` | 967 LOC | مطابقة القواعد |
| محلل الشروط | `condition_parser.go` | 600 LOC | تحليل AST |
| مقيّم الاختيارات | `selection_evaluator.go` | ~280 LOC | تقييم الحقول |
| حلقة الأحداث | `event_loop.go` | 313 LOC | تنسيق Kafka |
| نموذج الحدث | `event.go` | 427 LOC | بنية الحدث |
| نموذج القاعدة | `rule.go` | ~350 LOC | بنية القاعدة |

### إجمالي الكود

- **الكود الأساسي**: ~7,000 سطر Go
- **الاختبارات**: ~2,500 سطر
- **عدد القواعد**: 4,000+ قاعدة Sigma

---
**التحليل بتاريخ**: January 11, 2026
