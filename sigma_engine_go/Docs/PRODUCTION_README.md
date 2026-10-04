# Sigma Detection Engine - Production Application

## نظرة عامة

تطبيق جاهز للإنتاج لمعالجة أحداث EDR باستخدام قواعد Sigma الحقيقية. التطبيق يقرأ الأحداث من ملف JSONL، يحمل قواعد Sigma من المجلد، ويعالجها لإنشاء التنبيهات.

## الميزات

- ✅ **تحميل قواعد Sigma الحقيقية**: يقرأ 3,085+ قاعدة من مجلد `sigma_rules/rules/`
- ✅ **معالجة الأحداث**: يقرأ الأحداث من ملف JSONL (ECS format)
- ✅ **معالجة متوازية**: يستخدم worker pools لمعالجة عالية الأداء
- ✅ **إزالة التكرار**: يزيل التنبيهات المكررة ضمن نافذة زمنية
- ✅ **إخراج منظم**: يحفظ التنبيهات في ملف JSONL
- ✅ **إحصائيات**: تقارير دورية عن الأداء
- ✅ **إغلاق آمن**: إغلاق سلس عند استلام إشارة الإيقاف

## الاستخدام

### البناء

```bash
cd sigma_engine_go
go build -o sigma-engine.exe ./cmd/sigma-engine
```

### التشغيل الأساسي

```bash
./sigma-engine.exe
```

### مع خيارات مخصصة

```bash
./sigma-engine.exe \
  -rules sigma_rules/rules \
  -events data/agent_ecs-events/normalized_logs.jsonl \
  -output data/alerts.jsonl \
  -workers 8 \
  -batch-size 200 \
  -log-level info
```

## الخيارات المتاحة

| الخيار | الوصف | القيمة الافتراضية |
|--------|-------|-------------------|
| `-rules` | مسار مجلد قواعد Sigma | `sigma_rules/rules` |
| `-events` | مسار ملف الأحداث JSONL | `data/agent_ecs-events/normalized_logs.jsonl` |
| `-output` | مسار ملف التنبيهات JSONL | `data/alerts.jsonl` |
| `-log-level` | مستوى السجل (debug, info, warn, error) | `info` |
| `-workers` | عدد العمال المتوازيين | عدد المعالجات |
| `-batch-size` | حجم الدفعة للمعالجة | `100` |
| `-cache-size` | حجم الذاكرة المؤقتة | `10000` |
| `-stats-interval` | فترة تقارير الإحصائيات | `10s` |

## مثال على الاستخدام

```bash
# معالجة الأحداث الحقيقية
./sigma-engine.exe \
  -events data/agent_ecs-events/normalized_logs.jsonl \
  -output data/alerts.jsonl \
  -workers 4 \
  -log-level info

# مع معالجة متقدمة
./sigma-engine.exe \
  -rules sigma_rules/rules \
  -events data/agent_ecs-events/normalized_logs.jsonl \
  -output data/alerts.jsonl \
  -workers 8 \
  -batch-size 500 \
  -cache-size 50000 \
  -stats-interval 5s \
  -log-level debug
```

## تنسيق الأحداث المدخلة

التطبيق يتوقع أحداث بتنسيق ECS (Elastic Common Schema):

```json
{
  "@timestamp": "2025-12-26T20:04:05.9745478+03:00",
  "event.code": 1,
  "event.category": "process",
  "event.action": "start",
  "host.name": "NullByte",
  "process.executable": "C:\\Windows\\System32\\cmd.exe",
  "process.name": "cmd.exe",
  "process.command_line": "cmd.exe /c dir",
  "process.pid": 1234,
  "process.parent.executable": "C:\\Windows\\explorer.exe",
  "user.domain": "DOMAIN",
  "user.name": "user"
}
```

## تنسيق التنبيهات المخرجة

التنبيهات تُحفظ في ملف JSONL:

```json
{
  "id": "alert-...",
  "rule_id": "...",
  "rule_title": "...",
  "severity": "high",
  "confidence": 0.95,
  "timestamp": "2025-12-26T20:04:05Z",
  "event_id": "...",
  "event_category": "process",
  "product": "windows",
  "mitre_tactics": ["Execution"],
  "mitre_techniques": ["T1059"],
  "matched_fields": {
    "process.command_line": "cmd.exe /c dir"
  },
  "event_data": {...}
}
```

## الأداء

### الأهداف

- **معالجة الأحداث**: 300-500+ حدث/ثانية
- **زمن الاستجابة**: < 1ms لكل حدث
- **تحميل القواعد**: < 100ms لـ 3,085 قاعدة
- **الذاكرة**: < 500MB لمعالجة مليون حدث

### التحسين

- استخدم `-workers` لزيادة عدد العمال
- استخدم `-batch-size` لتحسين الأداء
- استخدم `-cache-size` لتحسين سرعة البحث
- راقب الإحصائيات لتحديد الاختناقات

## الإحصائيات

التطبيق يطبع إحصائيات دورية:

```
Statistics - Events: 1000, Alerts: 15, Throughput: 450.25 events/sec, Latency: 2.1ms
```

## الإغلاق الآمن

التطبيق يدعم الإغلاق الآمن:
- اضغط `Ctrl+C` لإرسال إشارة الإيقاف
- التطبيق يكمل معالجة الأحداث الجارية
- يحفظ جميع التنبيهات قبل الإغلاق
- مهلة زمنية: 30 ثانية

## السجلات

مستويات السجل:
- `debug`: تفاصيل كاملة (للتطوير)
- `info`: معلومات عامة (للإنتاج)
- `warn`: تحذيرات فقط
- `error`: أخطاء فقط

## هيكل الملفات

```
sigma_engine_go/
├── cmd/sigma-engine/
│   └── main.go          # التطبيق الرئيسي
├── sigma_rules/
│   └── rules/           # قواعد Sigma الحقيقية
├── data/
│   ├── agent_ecs-events/
│   │   └── normalized_logs.jsonl  # الأحداث المدخلة
│   └── alerts.jsonl     # التنبيهات المخرجة
└── sigma-engine.exe     # الملف التنفيذي
```

## استكشاف الأخطاء

### لا توجد قواعد محملة

```
Error: no rules loaded from sigma_rules/rules
```

**الحل**: تأكد من وجود مجلد `sigma_rules/rules/` وأنه يحتوي على ملفات `.yml`

### فشل في فتح ملف الأحداث

```
Error: events file does not exist: data/agent_ecs-events/normalized_logs.jsonl
```

**الحل**: تأكد من وجود ملف الأحداث في المسار المحدد

### أداء منخفض

**الحل**:
- زد عدد العمال: `-workers 8`
- زد حجم الدفعة: `-batch-size 500`
- زد حجم الذاكرة المؤقتة: `-cache-size 50000`

### أخطاء في تحليل JSON

```
Warn: Failed to parse event JSON
```

**الحل**: تحقق من تنسيق الأحداث - يجب أن تكون JSON صالح في كل سطر

## أمثلة على السيناريوهات

### معالجة ملف كبير

```bash
./sigma-engine.exe \
  -events large_events.jsonl \
  -output large_alerts.jsonl \
  -workers 16 \
  -batch-size 1000 \
  -cache-size 100000
```

### معالجة في الوقت الفعلي

```bash
# قراءة من stdin
cat events.jsonl | ./sigma-engine.exe -events /dev/stdin
```

### وضع التطوير

```bash
./sigma-engine.exe \
  -log-level debug \
  -stats-interval 1s \
  -workers 2
```

## الإنتاج

### متطلبات الإنتاج

1. **الذاكرة**: 2GB+ RAM
2. **المعالج**: 4+ cores
3. **التخزين**: مساحة كافية للتنبيهات
4. **الشبكة**: إذا كان الإخراج عبر webhook

### التوصيات

- استخدم `-log-level info` في الإنتاج
- راقب استخدام الذاكرة والمعالج
- احفظ السجلات في ملفات منفصلة
- استخدم monitoring tools لتتبع الأداء
- راجع التنبيهات بانتظام

## الدعم

للمساعدة أو الإبلاغ عن مشاكل:
1. راجع السجلات: `-log-level debug`
2. تحقق من الإحصائيات
3. راجع ملفات التنبيهات المخرجة

---

**جاهز للإنتاج** ✅

التطبيق جاهز للاستخدام في بيئة الإنتاج مع قواعد Sigma الحقيقية وأحداث EDR الحقيقية.

