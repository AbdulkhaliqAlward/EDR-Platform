الريبو وصل للسيرفر، وكل المتطلبات موجودة. Docker 29.4.0 يأتي مع Compose v2 مدمج تلقائياً. اتبع هذا بالترتيب:

## خطوة 1 — تأكيد Docker Compose وclone المشروع

```bash
docker compose version
git clone https://github.com/ProtoSoftDev/protosoftdev-supabase.git
cd protosoftdev-supabase
```

## خطوة 2 — تنزيل utils من Supabase

[setup.sh](cci:7://file:///c:/Users/Administrator/ProtoSoftDev.Org/protosoftdev-supabase/scripts/setup.sh:0:0-0:0) يحتاجها لتوليد الأسرار — نُنزلها مباشرة من GitHub:

```bash
mkdir -p utils
curl -fsSL -o utils/generate-keys.sh \
  https://raw.githubusercontent.com/supabase/supabase/master/docker/utils/generate-keys.sh
curl -fsSL -o utils/add-new-auth-keys.sh \
  https://raw.githubusercontent.com/supabase/supabase/master/docker/utils/add-new-auth-keys.sh
curl -fsSL -o utils/db-passwd.sh \
  https://raw.githubusercontent.com/supabase/supabase/master/docker/utils/db-passwd.sh
chmod +x utils/*.sh
```

## خطوة 3 — تشغيل Setup (ينشئ .env ويولّد الأسرار)

```bash
sh scripts/setup.sh
```

## خطوة 4 — تعديل .env (الأهم)

```bash
nano .env
```

القيم التي **يجب** تغييرها الآن:

```bash
# IP السيرفر أو الدومين
SUPABASE_PUBLIC_URL=http://<SERVER_IP>:8000
API_EXTERNAL_URL=http://<SERVER_IP>:8000
SITE_URL=http://<SERVER_IP>:3000

# كلمة مرور قوية للداشبورد
DASHBOARD_PASSWORD=MyStr0ngPassword!

# إذا عندك SMTP جاهز — اضبطه الآن، وإلا اتركه
```

> **تنبيه أمني:** قمت بتعليق `.env` في [.gitignore](cci:7://file:///c:/Users/Administrator/ProtoSoftDev.Org/protosoftdev-supabase/.gitignore:0:0-0:0) — يعني إذا أضفت `.env` للـ commit، ستُرفع الأسرار لـ GitHub. **لا تفعل ذلك في الإنتاج.** الـ `.env` يبقى على السيرفر فقط.

## خطوة 5 — تشغيل الخدمات

```bash
docker compose up -d
```

## خطوة 6 — انتظر التهيئة ثم تحقق

```bash
# انتظر ~60 ثانية ثم
docker compose ps
```

كل الخدمات يجب أن تكون `healthy` أو `running`.

## خطوة 7 — تطبيق Migrations

```bash
sh scripts/migrate.sh
```

## خطوة 8 — فتح Studio

افتح `http://<SERVER_IP>:8000` في المتصفح وسجّل دخول بـ `DASHBOARD_USERNAME` و `DASHBOARD_PASSWORD`.

---

بعد نجاح كل شيء، لإضافة أول عميل حقيقي:

```bash
sh scripts/new-tenant.sh --slug acme_corp --name "Acme Corp" --plan pro --crm
```

أرسل output الخطوات وأساعدك في أي مشكلة تظهر.


DASHBOARD_USERNAME=protosoftdev
DASHBOARD_PASSWORD=4d94b7e30fe95959201559bf381e9ed9