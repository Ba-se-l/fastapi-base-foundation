# 🧪 الدليل المعماري والهندسي لحزمة الاختبارات (`tests/`)

[![Tests](https://img.shields.io/badge/pytest-115%20passed-brightgreen.svg?style=flat-square&logo=pytest)](.)
[![Python](https://img.shields.io/badge/python-3.13-blue.svg?style=flat-square&logo=python)](pyproject.toml)
[![Architecture](https://img.shields.io/badge/architecture-mirrored%20modular-orange.svg?style=flat-square)](tests)

يحتوي هذا المجلد على حزمة الاختبارات الآلية الشاملة لبنية **FastAPI Base Foundation**. تم تنظيم الاختبارات وفق هيكلية هرمية متطابقة (Mirrored Modular Hierarchy) تعكس بنية الكود المصدري في `src/`، متوافقة 100% مع أحدث توصيات مطوري `pytest` ومعايير صمامات الأمان المعمارية (Zero-Regression Guardrails).

---

## فهرس المحتويات
1. [الفلسفة الهندسية لحزمة الاختبارات](#1-الفلسفة-الهندسية-لحزمة-الاختبارات)
2. [الهيكل المعماري المتطابق (Mirrored Structure)](#2-الهيكل-المعماري-المتطابق-mirrored-structure)
3. [البنية التحتية المشتركة والفيكستشرز المركزية](#3-البنية-التحتية-المشتركة-والفيكستشرز-المركزية)
   - [`tests/support/`](#testssupport-الأدوات-المساعدة-المستقلة)
   - [`tests/conftest.py`](#testsconftestpy-الفيكستشرز-العامة)
4. [علامات التصنيف وبوابات التحقق (Test Markers & Gates)](#4-علامات-التصنيف-وبوابات-التحقق-test-markers--gates)
5. [التشريح الفني التفصيلي للملفات المقسمة](#5-التشريح-الفني-التفصيلي-للملفات-المقسمة)
6. [دليل أوامر التشغيل عبر سطر الأوامر (CLI Guide)](#6-دليل-أوامر-التشغيل-عبر-سطر-الأوامر-cli-guide)
7. [عقود البيانات ونماذج الطلبات والردود](#7-عقود-البيانات-ونماذج-الطلبات-والردود)
8. [معايير كتابة اختبارات جديدة وأفضل الممارسات](#8-معايير-كتابة-اختبارات-جديدة-وأفضل-الممارسات)

---

## 1. الفلسفة الهندسية لحزمة الاختبارات

تستند حزمة الاختبارات على 4 ركائز معمارية رئيسية:

1. **التطابق المعماري مع عزل النطاقات (Mirrored Domain Isolation):**
   * يعكس مجلد الاختبارات هيكلية الكود المصدري تماماً (مثلاً: `src/modules/auth/` يقابله `tests/modules/auth/`).
   * تقسيم دقيق وشامل: فصول المصادقة، تحصين الجلسات، ونقل الكوكيز/CSRF تم فصلها في وحدات اختبارية مستقلة ومركزة.

2. **العزل التام لقاعدة البيانات في الذاكرة (`sqlite+aiosqlite:///:memory:`):**
   * تعمل جميع اختبارات قواعد البيانات على قاعدة بيانات معزولة بالذاكرة العشوائية.
   * **صفر تلوث:** قاعدة بيانات التطوير المحلية (`database.db`) لا يتم المساس بها أو فتحها نهائياً.
   * تُبنى الجداول وتُحذف دورياً مع كل اختبار فردي لضمان بيئة نظيفة ونقية 100%.

3. **معالجة الشبكة داخلياً بدون فتح منافذ (`httpx.AsyncClient`):**
   * تُدار كافة طلبات HTTP داخل عملية التشغيل عبر `ASGITransport(app=app)`.
   * انعدام استهلاك المنافذ (Zero Port Binding) وسرعة استجابة فائقة (تُنفذ كامل الحزمة المكونة من 115 اختباراً في نحو 3 ثوانٍ فقط).

4. **بنية تحتية مستقلة تماماً (Decoupled Support):**
   * تلتزم ملفات الاختبارات بمنع الاستيراد المباشر من ملف `conftest` (تجنباً للممارسات السيئة في بيئات Pytest المعاصرة).
   * يتم تصدير كائنات المحرك وجلسات قواعد البيانات والمسارات المطلقة حصراً من حزمة `tests.support`.

---

## 2. الهيكل المعماري المتطابق (Mirrored Structure)

```
tests/
├── app/                              # اختبارات دورة حياة التطبيق، والواجهة، والوسطاء
│   ├── test_error_envelopes.py       # أغلفة أخطاء RFC 7807 والأخطاء المخصصة
│   ├── test_health.py                # فحوصات الحياة (/health) والجاهزية للبيانات (/health/ready)
│   ├── test_input_hardening.py       # تجريد المدخلات الحساسة وضبط الحدود القصوى (Pydantic v2)
│   ├── test_middleware.py            # معالجة عناوين البروكسي الموثوقة وحجب التوثيق (SEC-17/18)
│   └── test_ui_workbench.py          # ربط الملفات الساكنة لـ /ui وحماية الأصول (SEC-08/09)
├── cli/                              # الأوامر الإدارية لسطر الأوامر
│   └── test_manage.py                # أمر إنشاء المشرف manage.py create-admin وحماية SEC-16
├── contracts/                        # عقود بوابات الإصدار المعمارية
│   └── test_release_gate.py          # اختبارات ثوابت الإصدار الصارمة (RG-01 حتى RG-15)
├── database/                         # سلوكيات البنية التحتية لقواعد البيانات
│   └── test_base_repo.py             # الترتيب الحتمي للتصفح بالصفحات في المستودع الأساسي
├── migrations/                       # اختبارات تطور مخطط قاعدة البيانات
│   └── test_migrations.py           # التحقق من رأس Alembic الأحادي وانعدام انحراف المخطط
├── modules/                          # الوحدات الوظيفية للنظام
│   ├── audit/                        # سجلات التدقيق والمراقبة
│   │   ├── test_audit_db_disabled.py # التحقق من استمرار النظام بسلاسة عند تعطيل تدقيق القاعدة
│   │   ├── test_audit_logging.py     # عمليات الخدمة، وحقن السياق، واستعلام سجلات المستخدم
│   │   └── test_audit_model.py       # قيود نموذج التدقيق وتنسيقات التصدير (JSON, TXT, MD)
│   ├── auth/                         # آليات المصادقة وإدارة الجلسات
│   │   ├── test_auth_flow.py         # دورة المصادقة الكاملة: تسجيل، دخول، تحديث، خروج
│   │   ├── test_events.py            # إطلاق أحداث UserLoggedIn و UserRegistered
│   │   ├── test_password_change.py   # تغيير كلمة المرور والترقية الذرية لـ security_version
│   │   ├── test_session_hardening.py # إغلاق أمان العائلات (SEC-02)، وكشف التكرار، وإلغاء CAS
│   │   └── test_transport_and_csrf.py# نقل الكوكيز (SEC-01)، وحجب التوكن (SEC-03)، وتأمين CSRF
│   └── user/                         # إدارة المستخدمين والصلاحيات
│       ├── test_events.py            # إطلاق أحداث تعديل وحذف المستخدمين على ناقل الأحداث
│       ├── test_pagination.py        # حالات حواف التصفح الحتمي والصفحات
│       ├── test_user_crud.py         # عمليات استرجاع وتعديل وحذف حسابات المستخدمين
│       └── test_user_rbac.py         # حدود الصلاحيات المبنية على الأدوار (مشرف مقابل مستخدم)
├── security/                         # التشفير وإدارة الأذونات
│   ├── test_authorization.py         # صلاحيات Casbin الرباعية، والرموز الشاملة، وذاكرة SEC-10
│   ├── test_guards.py                # حظر التسجيل العام ديناميكياً (SEC-15)
│   └── test_security.py              # تشفير Argon2id، وبناء وفك توكنات JWT، ومنع خلط الأنواع
├── settings/                         # صمامات أمان التهيئة وإعدادات البيئة
│   └── test_settings.py              # ضوابط الإنتاج، إنتروبيا المفاتيح، والبروكسي (SEC-04..07)
├── share/                            # الأدوات المشتركة عبر الوحدات
│   ├── test_event_bus.py             # عزل أخطاء المعالجات في ناقل الأحداث EventBus
│   ├── test_helpers.py               # دوال الترتيب والتجزئة الحتمية ومساعدات التاريخ
│   └── test_rate_limit.py            # محدد المعدل في الذاكرة وسياسة إخلاء الذاكرة LRU (SEC-14)
├── support/                          # حزمة الدعم المستقلة (خالية من استيرادات conftest)
│   ├── __init__.py                   # علامة الحزمة
│   ├── database.py                   # تصدير TEST_DATABASE_URL و test_engine و TestSessionLocal
│   └── paths.py                      # تصدير المسارات المطلقة PROJECT_ROOT و ALEMBIC_INI و STATIC_DIR
├── conftest.py                       # الفيكستشرز العامة وتجاوز التبعيات
├── README.md                         # الدليل المعماري للاختبارات باللغة الإنجليزية
└── README_AR.md                      # الدليل المعماري للاختبارات باللغة العربية (هذا الملف)
```

---

## 3. البنية التحتية المشتركة والفيكستشرز المركزية

### `tests/support/` الأدوات المساعدة المستقلة

لتفادي التبعيات الدائرية والالتزام بتوصيات Pytest التي تمنع الاستيراد المباشر من ملفات `conftest`، جرى تجميع أدوات الاختبار في حزمة `tests/support/`:

* **[`tests/support/database.py`](support/database.py)**:
  * `TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"`
  * `test_engine`: كائن محرك SQLAlchemy غير المتزامن مهيأ بـ `echo=False`.
  * `TestSessionLocal`: مصنع الجلسات `async_sessionmaker` مع تعطيل `expire_on_commit` و `autoflush`.
* **[`tests/support/paths.py`](support/paths.py)**:
  * `PROJECT_ROOT`: المسار المطلق لجذر المشروع.
  * `ALEMBIC_INI`: المسار المطلق لملف `alembic.ini`.
  * `STATIC_DIR`: المسار المطلق لمجلد الأصول الثابتة `static/`.

### `tests/conftest.py` الفيكستشرز العامة

الملف: [`tests/conftest.py`](conftest.py)

| اسم الفيكستشر | النطاق (Scope) | الوظيفة والدور المعماري |
|---|---|---|
| `init_test_database` | Function (`autouse=True`) | يقوم تلقائياً بإنشاء كافة الجداول (`BaseModel.metadata.create_all`) قبل كل اختبار ثم يحذفها بالكامل فور انتهائه. |
| `db_session` | Function | يوفر كائن جلسة `AsyncSession` متصل بقاعدة بيانات الذاكرة لتنفيذ عمليات البذر المباشر للبيانات (Seeding). |
| `client` | Function | يوفر عميل الاختبارات `httpx.AsyncClient` مربوطاً بتطبيق FastAPI مع تفعيل تجاوز جلسة قاعدة البيانات الإنتاجية تلقائياً. |
| `make_access_token` | Function | **فيكستشر مصنع (Factory Fixture)** يعيد دالة غير متزامنة `_make(user_id, security_version=1)` لتوليد توكنات JWT صالحة مباشرة دون الحاجة لاستعلامات قاعدة بيانات. |

---

## 4. علامات التصنيف وبوابات التحقق (Test Markers & Gates)

تم تسجيل علامات التصنيف الصارمة داخل `pyproject.toml` مع تفعيل خيار `--strict-markers`:

| العلامة (Marker) | أمر التشغيل المباشر | عدد الاختبارات | النطاق والهدف |
|---|---|---|---|
| `release_gate` | `uv run --frozen pytest -m release_gate` | **15 اختباراً** | التحقق من عقود الإصدار المعمارية الإلزامية (`RG-01` حتى `RG-15`). |
| `security_audit` | `uv run --frozen pytest -m security_audit` | **18 اختباراً** | التحقق من صمامات الأمان العميقة ومقاومة الثغرات (`SEC-01` حتى `SEC-18`). |
| *كافة الاختبارات* | `uv run --frozen pytest` | **115 اختباراً** | تنفيذ كامل الحزمة التأكيدية للمشروع بنجاح 100%. |

---

## 5. التشريح الفني التفصيلي للملفات المقسمة

### العقود الأساسية والبنية التحتية
* **`tests/contracts/test_release_gate.py` (15 اختباراً):**
  * يتحقق من ثوابت بوابات الإصدار `RG-01` حتى `RG-15`: الجلسات غير المتزامنة، إغلاق نظام Casbin عند الخطأ، إبطال الجلسات عبر `security_version`، تدوير التوكن مع منع التكرار، رأس Alembic الوحيد، وانعدام أخطاء 500 غير المعالجة.
* **`tests/migrations/test_migrations.py` (اختباران):**
  * يضمن أن تاريخ الهجرات ينتهي برأس خطي وحيد معتمد (`6aa8f9bfed61`).
  * ينفذ فحص `alembic check` للتأكد من انعدام أي انحراف بين نماذج بايثون ومخطط الجداول.
* **`tests/cli/test_manage.py` (3 اختبارات):**
  * يختبر أمر سطر الأوامر لإنشاء حساب المشرف (`manage.py create-admin`).
  * يتحقق من صحة البريد، قوة كلمة المرور، ودعم التشغيل الآلي غير التفاعلي عبر `--password-stdin` (`SEC-16`).

### الأمان والتشفير والإعدادات
* **`tests/security/test_security.py` (4 اختبارات):**
  * يتحقق من تشفير وفحص كلمات المرور بخوارزمية Argon2id.
  * يتحقق من تشفير وفك توكنات JWT والتأكد من ادعاءات `sub` و `jti` و `exp` ومنع استبدال أنواع التوكنات.
* **`tests/security/test_authorization.py` (9 اختبارات):**
  * يتحقق من تقييم محرك Casbin لسياسات الصلاحيات، وراثة الأدوار، والصلاحيات الشاملة (`*`).
  * يتحقق من ذاكرة التخزين المؤقت للسياسات وتحديثها التلقائي (`SEC-10`).
* **`tests/security/test_guards.py` (اختبار واحد):**
  * يتحقق من حظر مسار التسجيل العام ديناميكياً (`SEC-15`) عند تعطيل `ALLOW_PUBLIC_REGISTRATION`.
* **`tests/settings/test_settings.py` (10 اختبارات):**
  * يتحقق من صمامات الإنتاج (`SEC-04` حتى `SEC-07`): رفض المفاتيح الضعيفة، تباين المفاتيح، وحظر نجوم CORS الشاملة.
  * يتحقق من استخراج عنوان العميل الحقيقي عبر نطاقات البروكسي الموثوقة وكتل CIDR.

### المصادقة والجلسات
* **`tests/modules/auth/test_auth_flow.py` (8 اختبارات):**
  * دورة المصادقة المتكاملة: إنشاء الحساب، منع التكرار، فحص قوة كلمة المرور، تسجيل الدخول، وتدوير التوكن.
* **`tests/modules/auth/test_session_hardening.py` (5 اختبارات):**
  * يختبر إغلاق عائلة الجلسات عند الشك (`SEC-02`).
  * يتحقق من إبطال الجلسات الذري (CAS Revocation) عند حدوث طلبات تدوير متزامنة.
  * يختبر حماية التوقيت عبر كلمة مرور تجريبية (Dummy Password Verification) لمنع حصر أسماء المستخدمين.
* **`tests/modules/auth/test_transport_and_csrf.py` (4 اختبارات):**
  * يتحقق من نمط الكوكيز المحصن وحماية CSRF عبر ترويسة `X-CSRF-Token` (`SEC-01`).
  * يتحقق من حجب التوكنات (`SEC-03`): إعادة `null` للتوكنات داخل جسم الاستجابة عند تفعيل وضع الكوكيز.
* **`tests/modules/auth/test_password_change.py` (3 اختبارات):**
  * يختبر تحديث كلمة المرور، والتحقق من كلمة المرور الحالية، والإبطال الشامل للجلسات فوراً.

### نطاق المستخدم وسجلات التدقيق
* **`tests/modules/user/test_user_rbac.py` و `test_user_crud.py` (اختباران):**
  * يختبر استعراض الملف الشخصي (`/api/v1/users/me`)، وتعديل وحذف الحسابات، وحدود رتبة المشرف.
* **`tests/modules/user/test_pagination.py` (اختباران):**
  * يختبر استقرار الترتيب الحتمي للتصفح بالصفحات في المستودع الأساسي.
* **`tests/modules/audit/test_audit_logging.py` و `test_audit_model.py` (9 اختبارات):**
  * يختبر عمليات طبقة التدقيق، وفلترة سجلات المستخدم، والتصدير بتنسيقات JSON و TXT و Markdown.
  * يتحقق من حقن السياق (`client_ip`, `user_agent`, `request_id`) وحجب بيانات الاعتماد وكلمات المرور.
* **`tests/modules/audit/test_audit_db_disabled.py` (اختبار واحد):**
  * يتحقق من استمرار عمل التطبيق بكفاءة تامة دون أخطاء عند ضبط `AUDIT_LOG_TO_DB=False`.

---

## 6. دليل أوامر التشغيل عبر سطر الأوامر (CLI Guide)

تُنفذ كافة الأوامر حصراً عبر `uv`:

### التشغيل القياسي لكافة الاختبارات
```bash
uv run --frozen pytest
```

### التشغيل بالنمط المفصل مع قياس الوقت
```bash
uv run --frozen pytest -v
```

### تشغيل اختبارات بوابات الإصدار المعمارية فقط
```bash
uv run --frozen pytest -m release_gate -v
```

### تشغيل اختبارات التدقيق الأمني وصمامات الأمان فقط
```bash
uv run --frozen pytest -m security_audit -v
```

### تشغيل مجلد أو ملف اختباري محدد
```bash
# تشغيل كافة اختبارات المصادقة
uv run --frozen pytest tests/modules/auth/ -v

# تشغيل اختبارات عقود بوابات الإصدار
uv run --frozen pytest tests/contracts/test_release_gate.py -v

# تشغيل اختبارات الإعدادات والأمان
uv run --frozen pytest tests/settings/ tests/security/ -v
```

### فلترة وتشغيل الاختبارات بالاسم (`-k`)
```bash
uv run --frozen pytest -k "csrf or cookie" -v
uv run --frozen pytest -k "casbin" -v
```

---

## 7. عقود البيانات ونماذج الطلبات والردود

### تسجيل الحساب (`POST /api/v1/auth/register`)

#### الحالة الإيجابية (نجاح)
* **جسم الطلب (JSON):**
  ```json
  {
    "name": "Basel Developer",
    "email": "basel@example.com",
    "password": "StrongP@ssw0rd!"
  }
  ```
* **رمز الاستجابة:** `201 Created`
* **جسم الرد (`UserResponse`):**
  ```json
  {
    "id": 1,
    "name": "Basel Developer",
    "email": "basel@example.com",
    "role": "user",
    "is_active": true,
    "created_at": "2026-11-04T12:00:00Z",
    "updated_at": "2026-11-04T12:00:00Z"
  }
  ```

#### الحالة السلبية (تكرار البريد الإلكتروني)
* **رمز الاستجابة:** `409 Conflict`
* **جسم الرد (`ErrorResponse`):**
  ```json
  {
    "success": false,
    "error": {
      "code": "USER_ALREADY_EXISTS",
      "message": "User with email 'basel@example.com' already exists.",
      "details": null
    },
    "request_id": "c1f7a4b8..."
  }
  ```

### تسجيل الدخول (`POST /api/v1/auth/login`)

#### الحالة الإيجابية (نمط Bearer القياسي)
* **رمز الاستجابة:** `200 OK`
* **جسم الرد (`TokenResponse`):**
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsIn...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsIn...",
    "token_type": "bearer"
  }
  ```

#### الحالة الإيجابية (نمط الكوكيز المحصن `SEC-03`)
* **رمز الاستجابة:** `200 OK`
* **ترويسات Set-Cookie:** إرسال `access_token` و `refresh_token` مع سمات `HttpOnly; Secure; SameSite=Lax`.
* **جسم الرد (`TokenResponse`):**
  ```json
  {
    "access_token": null,
    "refresh_token": null,
    "token_type": "bearer"
  }
  ```

---

## 8. معايير كتابة اختبارات جديدة وأفضل الممارسات

عند إضافة اختبارات جديدة إلى المشروع، يجب الالتزام الصارم بالإرشادات المعمارية التالية:

1. **وضع الاختبار في المجلد المتطابق:**
   * عند إضافة ميزة إلى `src/modules/billing/`، تُكتب اختباراتها في `tests/modules/billing/test_billing_flow.py`.
2. **الامتناع التام عن استيراد `conftest`:**
   * استخدم `tests.support.database` لجلب `TestSessionLocal` أو `test_engine`.
   * استخدم `tests.support.paths` للوصول إلى مسارات المشروع.
3. **الاعتماد على فيكستشر المصنع `make_access_token`:**
   * عند الحاجة لتوثيق مستخدم، استخدم `await make_access_token(user_id=1)` لتوليد توكن صالح دون كلفة قاعدة بيانات.
4. **تحديد نص الخطأ المتوقع بدقة داخل `pytest.raises`:**
   ```python
   with pytest.raises(ValidationException, match="must contain at least one uppercase letter"):
       ...
   ```
5. **تعيين معرفات صريحة لمعاملات الاختبار (`ids`):**
   ```python
   @pytest.mark.parametrize(
       ("payload", "expected_code"),
       [
           ({"email": "valid@example.com"}, 200),
           ({"email": "bad-email"}, 422),
       ],
       ids=["valid-email", "malformed-email"],
   )
   ```
6. **استخدام `monkeypatch` لتجاوز الإعدادات:**
   * قم بتعديل الإعدادات والبيئة حصراً عبر فيكستشر `monkeypatch` المدمج في Pytest لضمان استعادة الحالة الأصلية تلقائياً بعد انتهاء الاختبار.
