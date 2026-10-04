# 🚀 Quick Start - Live Monitoring System

## ✅ ما تم إنجازه

تم تنفيذ نظام مراقبة مباشر كامل مع:

1. ✅ **نظام تكوين YAML شامل** - جميع الإعدادات قابلة للتغيير من `config/config.yaml`
2. ✅ **مراقبة الملفات المباشرة** - مراقبة `data/agent_ecs-events/normalized_logs.jsonl`
3. ✅ **حفظ التنبيهات** - في `data/alerts.jsonl` (يُنشأ تلقائياً)
4. ✅ **إنشاء الملفات تلقائياً** - لا حاجة لإنشاء الملفات يدوياً

---

## 🎯 التشغيل السريع

### 1. بناء التطبيق

```bash
cd sigma_engine_go
go build -o sigma-engine-live.exe ./cmd/sigma-engine-live
```

### 2. التحقق من ملف التكوين

الملف موجود في: `config/config.yaml`

**الإعدادات الافتراضية:**
- **مراقبة:** `data/agent_ecs-events` (ملفات `*.jsonl`)
- **إخراج:** `data/alerts.jsonl`
- **قواعد:** `sigma_rules/rules`

### 3. التشغيل

```bash
# استخدام التكوين الافتراضي (config/config.yaml)
.\sigma-engine-live.exe

# استخدام تكوين مخصص
.\sigma-engine-live.exe -config path/to/config.yaml
```

---

## ⚙️ تعديل الإعدادات

### تعديل مسار الملفات

افتح `config/config.yaml` وعدّل:

```yaml
file_monitoring:
  watch_directory: "data/agent_ecs-events"  # مجلد المراقبة
  file_pattern: "*.jsonl"                   # نمط الملفات

output:
  output_file: "data/alerts.jsonl"          # ملف التنبيهات
```

### تعديل إعدادات المحرك

```yaml
detection:
  workers: 8                                 # عدد العمال (0 = عدد المعالجات)
  batch_size: 100                            # حجم الدفعة
  cache_size: 10000                          # حجم الذاكرة المؤقتة
```

### تعديل إعدادات المراقبة

```yaml
event_counting:
  window_size_minutes: 5                    # نافذة العد (دقائق)
  alert_threshold: 10                        # عتبة التنبيه
  rate_threshold_per_minute: 5.0            # عتبة المعدل

escalation:
  count_threshold: 100                       # عتبة التصعيد
  rate_threshold_per_minute: 10.0           # عتبة معدل التصعيد
```

---

## 📁 الملفات المستخدمة

### الإدخال (الأحداث)
- **المسار:** `data/agent_ecs-events/normalized_logs.jsonl`
- **التكوين:** `file_monitoring.watch_directory` + `file_monitoring.file_pattern`
- **التنسيق:** JSONL (سطر واحد لكل حدث)

### الإخراج (التنبيهات)
- **المسار:** `data/alerts.jsonl`
- **التكوين:** `output.output_file`
- **التنسيق:** JSONL (سطر واحد لكل تنبيه محسّن)
- **الإنشاء:** تلقائي إذا لم يكن موجوداً

---

## 🔍 مثال على التنبيه المحسّن

```json
{
  "alert_id": "alert-...",
  "rule_title": "Suspicious PowerShell Command",
  "severity": 4,
  "confidence": 0.95,
  "event_count": 45,
  "first_seen": "2026-01-06T22:10:00Z",
  "last_seen": "2026-01-06T22:15:25Z",
  "rate_per_minute": 9.0,
  "count_trend": "↑",
  "should_escalate": true,
  "escalation_reason": "high event count; rapid escalation",
  "source_file": "data/agent_ecs-events/normalized_logs.jsonl"
}
```

---

## 📊 الإحصائيات

التطبيق يطبع إحصائيات كل 30 ثانية:

```
Statistics - Files: 1, Events: 1250, Groups: 45, Alerts: 12, Errors: 0
```

---

## 🛠️ استكشاف الأخطاء

### خطأ: ملف التكوين غير موجود

**الحل:**
```bash
# إنشاء ملف التكوين من المثال
cp config.example.yaml config/config.yaml
```

### خطأ: ملف الإخراج لا يمكن إنشاؤه

**الحل:**
- تحقق من صلاحيات المجلد
- تأكد من وجود مساحة كافية

### خطأ: مجلد المراقبة غير موجود

**الحل:**
- النظام سينشئه تلقائياً
- أو أنشئه يدوياً: `mkdir -p data/agent_ecs-events`

---

## 📚 الوثائق الكاملة

- `CONFIGURATION_GUIDE.md` - دليل التكوين الشامل
- `LIVE_MONITORING_GUIDE.md` - دليل المراقبة المباشرة
- `config.example.yaml` - مثال على التكوين

---

## ✅ جاهز للاستخدام!

```bash
# بناء
go build -o sigma-engine-live.exe ./cmd/sigma-engine-live

# تشغيل
.\sigma-engine-live.exe
```

**النظام جاهز للإنتاج!** 🎉

