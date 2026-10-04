# 🚀 دليل التشغيل السريع - محرك كشف Sigma

## 📋 المتطلبات الأساسية

1. **Go 1.21+** مثبت على النظام
2. **قواعد Sigma** موجودة في `sigma_rules/rules/`
3. **ملف الأحداث** بتنسيق JSONL

---

## 🔨 خطوة 1: بناء البرنامج

افتح Terminal/PowerShell في مجلد المشروع:

```bash
cd sigma_engine_go
go build -o sigma-engine.exe ./cmd/sigma-engine
```

**ملاحظة:** على Linux/Mac استخدم:
```bash
go build -o sigma-engine ./cmd/sigma-engine
```

---

## ✅ خطوة 2: التحقق من الملفات المطلوبة

### 1. قواعد Sigma
تأكد من وجود مجلد القواعد:
```bash
# Windows PowerShell
Test-Path sigma_rules\rules

# Linux/Mac
ls sigma_rules/rules
```

يجب أن يحتوي المجلد على ملفات `.yml` (يوجد 3,085+ قاعدة)

### 2. ملف الأحداث
تأكد من وجود ملف الأحداث:
```bash
# Windows PowerShell
Test-Path data\agent_ecs-events\normalized_logs.jsonl

# Linux/Mac
ls data/agent_ecs-events/normalized_logs.jsonl
```

**إذا لم يكن موجوداً:** أنشئ ملف تجريبي:
```bash
# Windows PowerShell
New-Item -ItemType Directory -Force -Path data\agent_ecs-events
```

---

## 🎯 خطوة 3: التشغيل

### الطريقة 1: التشغيل الأساسي (باستخدام القيم الافتراضية)

```bash
# Windows
.\sigma-engine.exe

# Linux/Mac
./sigma-engine
```

**القيم الافتراضية:**
- القواعد: `sigma_rules/rules`
- الأحداث: `data/agent_ecs-events/normalized_logs.jsonl`
- الإخراج: `data/alerts.jsonl`
- العمال: عدد المعالجات في النظام
- حجم الدفعة: 100

---

### الطريقة 2: التشغيل مع خيارات مخصصة

```bash
# Windows PowerShell
.\sigma-engine.exe `
  -rules sigma_rules\rules `
  -events data\agent_ecs-events\normalized_logs.jsonl `
  -output data\alerts.jsonl `
  -workers 8 `
  -batch-size 200 `
  -log-level info

# Linux/Mac
./sigma-engine \
  -rules sigma_rules/rules \
  -events data/agent_ecs-events/normalized_logs.jsonl \
  -output data/alerts.jsonl \
  -workers 8 \
  -batch-size 200 \
  -log-level info
```

---

## 📊 الخيارات المتاحة

| الخيار | الوصف | القيمة الافتراضية | مثال |
|--------|-------|-------------------|------|
| `-rules` | مسار مجلد قواعد Sigma | `sigma_rules/rules` | `-rules sigma_rules/rules` |
| `-events` | مسار ملف الأحداث JSONL | `data/agent_ecs-events/normalized_logs.jsonl` | `-events events.jsonl` |
| `-output` | مسار ملف التنبيهات JSONL | `data/alerts.jsonl` | `-output alerts.jsonl` |
| `-log-level` | مستوى السجل | `info` | `-log-level debug` |
| `-workers` | عدد العمال المتوازيين | عدد المعالجات | `-workers 4` |
| `-batch-size` | حجم الدفعة | `100` | `-batch-size 500` |
| `-cache-size` | حجم الذاكرة المؤقتة | `10000` | `-cache-size 50000` |
| `-stats-interval` | فترة تقارير الإحصائيات | `10s` | `-stats-interval 5s` |

---

## 📝 أمثلة عملية

### مثال 1: التشغيل الأساسي

```bash
.\sigma-engine.exe
```

**النتيجة المتوقعة:**
```
==========================================
Sigma Detection Engine - Production Mode
==========================================
Rules Directory: sigma_rules/rules
Events File: data/agent_ecs-events/normalized_logs.jsonl
Output File: data/alerts.jsonl
Workers: 8
Cache Size: 10000
Loading Sigma rules...
Loaded 3085 rules successfully
Processing events...
Processed 1000 events, generated 15 alerts
Statistics - Events: 1000, Alerts: 15, Throughput: 450.25 events/sec, Latency: 2.1ms
==========================================
Processing Complete
==========================================
Events Processed: 1000
Alerts Generated: 15
Duration: 2.22s
Throughput: 450.45 events/second
```

---

### مثال 2: وضع التطوير (مع تفاصيل أكثر)

```bash
.\sigma-engine.exe `
  -log-level debug `
  -stats-interval 5s `
  -workers 4
```

**مستوى `debug` يعرض:**
- تفاصيل تحميل القواعد
- تفاصيل معالجة كل حدث
- معلومات عن Cache hits/misses
- تفاصيل تطابق القواعد

---

### مثال 3: معالجة ملف كبير (أداء عالي)

```bash
.\sigma-engine.exe `
  -events large_events.jsonl `
  -output large_alerts.jsonl `
  -workers 16 `
  -batch-size 1000 `
  -cache-size 100000
```

**للملفات الكبيرة:**
- زد عدد العمال (`-workers`)
- زد حجم الدفعة (`-batch-size`)
- زد حجم الذاكرة المؤقتة (`-cache-size`)

---

### مثال 4: استخدام مسارات مخصصة

```bash
.\sigma-engine.exe `
  -rules C:\sigma\rules `
  -events D:\events\logs.jsonl `
  -output D:\alerts\output.jsonl
```

---

## 🔍 مراقبة الأداء

### الإحصائيات الدورية

التطبيق يطبع إحصائيات كل 10 ثوانٍ (افتراضياً):

```
Statistics - Events: 5000, Alerts: 75, Throughput: 485.50 events/sec, Latency: 1.8ms
```

**المعلومات المعروضة:**
- **Events**: عدد الأحداث المعالجة
- **Alerts**: عدد التنبيهات المولدة
- **Throughput**: الأحداث في الثانية
- **Latency**: متوسط زمن المعالجة

---

### تغيير فترة الإحصائيات

```bash
.\sigma-engine.exe -stats-interval 5s
```

---

## 🛑 الإغلاق الآمن

### إيقاف البرنامج

اضغط `Ctrl+C` لإيقاف البرنامج بشكل آمن.

**ما يحدث:**
1. التطبيق يتلقى إشارة الإيقاف
2. يكمل معالجة الأحداث الجارية
3. يحفظ جميع التنبيهات
4. يغلق بشكل نظيف

**المهلة الزمنية:** 30 ثانية (إذا لم يكمل، يتم الإغلاق القسري)

---

## 📂 تنسيق الأحداث المدخلة

ملف الأحداث يجب أن يكون **JSONL** (JSON Lines) - كل سطر هو JSON منفصل:

```json
{"@timestamp":"2025-12-26T20:04:05Z","event.code":1,"process.name":"cmd.exe","process.command_line":"cmd.exe /c dir"}
{"@timestamp":"2025-12-26T20:04:06Z","event.code":3,"destination.ip":"10.1.2.3","destination.port":4444}
{"@timestamp":"2025-12-26T20:04:07Z","event.code":11,"file.path":"C:\\temp\\suspicious.exe"}
```

**تنسيق ECS المطلوب:**
```json
{
  "@timestamp": "2025-12-26T20:04:05.9745478+03:00",
  "event.code": 1,
  "event.category": "process",
  "event.action": "start",
  "host.name": "HOSTNAME",
  "process.executable": "C:\\Windows\\System32\\cmd.exe",
  "process.name": "cmd.exe",
  "process.command_line": "cmd.exe /c dir",
  "process.pid": 1234,
  "process.parent.executable": "C:\\Windows\\explorer.exe",
  "user.domain": "DOMAIN",
  "user.name": "username"
}
```

---

## 📤 تنسيق التنبيهات المخرجة

التنبيهات تُحفظ في ملف JSONL:

```json
{
  "id": "alert-1735234567890123456",
  "rule_id": "abc123...",
  "rule_title": "Suspicious PowerShell Command",
  "severity": 4,
  "confidence": 0.95,
  "timestamp": "2025-12-26T20:04:05Z",
  "event_id": "1",
  "event_category": "process",
  "product": "windows",
  "mitre_tactics": ["Execution"],
  "mitre_techniques": ["T1059.001"],
  "matched_fields": {
    "process.command_line": "powershell.exe -encodedcommand ..."
  },
  "matched_selections": ["selection"],
  "event_data": {
    "process": {
      "name": "powershell.exe",
      "command_line": "powershell.exe -encodedcommand ..."
    }
  },
  "suppressed": false,
  "false_positive_risk": 0.0
}
```

---

## ⚠️ استكشاف الأخطاء

### خطأ 1: لا توجد قواعد محملة

```
Error: no rules loaded from sigma_rules/rules
```

**الحل:**
```bash
# تحقق من وجود المجلد
ls sigma_rules/rules

# تحقق من وجود ملفات .yml
ls sigma_rules/rules/*.yml | Select-Object -First 5
```

---

### خطأ 2: ملف الأحداث غير موجود

```
Error: events file does not exist: data/agent_ecs-events/normalized_logs.jsonl
```

**الحل 1:** أنشئ ملف تجريبي:
```bash
# Windows PowerShell
New-Item -ItemType File -Path data\agent_ecs-events\normalized_logs.jsonl -Force
```

**الحل 2:** استخدم مسار مختلف:
```bash
.\sigma-engine.exe -events path\to\your\events.jsonl
```

---

### خطأ 3: فشل في تحليل JSON

```
Warn: Failed to parse event JSON: ...
```

**الحل:**
- تحقق من تنسيق JSON (يجب أن يكون صالح)
- كل سطر يجب أن يكون JSON منفصل
- استخدم `-log-level debug` لرؤية السطر المحدد

---

### خطأ 4: أداء منخفض

**الأعراض:**
- Throughput أقل من 100 حدث/ثانية
- Latency أعلى من 10ms

**الحل:**
```bash
# زد عدد العمال
.\sigma-engine.exe -workers 16

# زد حجم الدفعة
.\sigma-engine.exe -batch-size 500

# زد حجم الذاكرة المؤقتة
.\sigma-engine.exe -cache-size 50000
```

---

### خطأ 5: استخدام ذاكرة عالي

**الحل:**
- قلل `-cache-size` إذا كان كبيراً جداً
- قلل `-batch-size`
- راقب استخدام الذاكرة

---

## 🧪 اختبار سريع

### إنشاء ملف أحداث تجريبي

```bash
# Windows PowerShell
@"
{"@timestamp":"2025-12-26T20:04:05Z","event.code":1,"process.name":"powershell.exe","process.command_line":"powershell.exe -encodedcommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0","host.name":"TEST-HOST"}
{"@timestamp":"2025-12-26T20:04:06Z","event.code":1,"process.name":"cmd.exe","process.command_line":"cmd.exe /c dir","host.name":"TEST-HOST"}
"@ | Out-File -FilePath data\agent_ecs-events\test_events.jsonl -Encoding utf8
```

### تشغيل الاختبار

```bash
.\sigma-engine.exe `
  -events data\agent_ecs-events\test_events.jsonl `
  -output data\test_alerts.jsonl `
  -log-level debug
```

### التحقق من النتائج

```bash
# عرض التنبيهات
Get-Content data\test_alerts.jsonl | ConvertFrom-Json | Format-List
```

---

## 📈 نصائح للأداء الأمثل

### 1. عدد العمال
- **قاعدة عامة:** عدد العمال = عدد المعالجات
- **للأداء العالي:** عدد العمال = عدد المعالجات × 2

```bash
.\sigma-engine.exe -workers 16
```

### 2. حجم الدفعة
- **صغير (100):** لاستجابة أسرع
- **كبير (500-1000):** لمعالجة أسرع

```bash
.\sigma-engine.exe -batch-size 500
```

### 3. حجم الذاكرة المؤقتة
- **صغير (10000):** لاستخدام ذاكرة أقل
- **كبير (50000+):** لأداء أفضل (Cache hit rate أعلى)

```bash
.\sigma-engine.exe -cache-size 50000
```

### 4. مستوى السجل
- **الإنتاج:** `info` (أسرع)
- **التطوير:** `debug` (أبطأ، تفاصيل أكثر)

```bash
.\sigma-engine.exe -log-level info
```

---

## 🎓 أمثلة متقدمة

### مثال 1: معالجة في الوقت الفعلي (من stdin)

```bash
# Windows PowerShell
Get-Content events.jsonl | .\sigma-engine.exe -events /dev/stdin

# Linux/Mac
cat events.jsonl | ./sigma-engine -events /dev/stdin
```

### مثال 2: إخراج إلى ملفات متعددة

```bash
# معالجة وإخراج إلى ملف
.\sigma-engine.exe -output alerts_$(Get-Date -Format 'yyyyMMdd').jsonl
```

### مثال 3: معالجة مع مراقبة

```bash
# تشغيل في الخلفية مع حفظ السجلات
.\sigma-engine.exe -log-level info > logs.txt 2>&1
```

---

## 📚 المراجع

- `PRODUCTION_README.md` - دليل الإنتاج الكامل
- `SYSTEM_ARCHITECTURE_AR.md` - شرح معماري شامل
- `TEST_GUIDE.md` - دليل الاختبارات

---

## ✅ قائمة التحقق السريعة

قبل التشغيل، تأكد من:

- [ ] Go 1.21+ مثبت
- [ ] مجلد `sigma_rules/rules/` موجود ويحتوي على ملفات `.yml`
- [ ] ملف الأحداث موجود (أو أنشئ ملف تجريبي)
- [ ] مجلد الإخراج موجود (سيتم إنشاؤه تلقائياً)
- [ ] مساحة كافية على القرص

---

## 🚀 ابدأ الآن!

```bash
# بناء البرنامج
go build -o sigma-engine.exe ./cmd/sigma-engine

# تشغيل
.\sigma-engine.exe
```

**جاهز للاستخدام!** 🎉

---

**تم إنشاء هذا الدليل بواسطة:** Sigma Detection Engine Team  
**التاريخ:** 2025  
**الإصدار:** 1.0

