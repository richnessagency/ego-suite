# خطة الأدوات ودمجها (Tools Architecture & Integration Plan)

---

## 1. مصفوفة الأدوات المختارة (Selected Tools Matrix)
*(تم التحديث تلقائياً من [selected-tools.json](file:///home/omar/Working/Richness/Sec/selected-tools.json) — إجمالي 19 أداة)*

| الأداة (`id`) | التصنيف | وضع التشغيل (`URL` / `Local`) | طريقة التشغيل المخططة (`Docker` / `CLI`) | الأولوية |
| :--- | :--- | :--- | :--- | :--- |
| `owasp-zap` | DAST | `url` | Docker (`zaproxy:stable`) | عالية |
| `nuclei` | DAST | `url` | CLI (`go install`) | عالية |
| `testssl` | DAST | `url` | CLI (`git clone`) | عالية |
| `nikto` | DAST | `url` | CLI (`apt`) / Docker | متوسطة |
| `nmap` | DAST | `url` | CLI (`apt`) | متوسطة |
| `wapiti` | DAST | `url` | CLI (`pip`) | متوسطة |
| `httpx-headers` | DAST | `url` | CLI (`go install`) | عالية |
| `semgrep` | SAST | `local` | CLI (`pip`) | عالية |
| `bandit` | SAST | `local` | CLI (`pip`) | عالية |
| `eslint-security` | SAST | `local` | CLI (`npm`) | عالية |
| `bearer` | SAST | `local` | CLI (`install.sh`) | متوسطة |
| `sonarqube-scanner` | SAST | `local` | Docker (`sonarqube:community`) | متوسطة |
| `trivy` | SCA | `local` | CLI (`apt`) / Docker | عالية |
| `osv-scanner` | SCA | `local` | CLI (`go install`) | عالية |
| `retirejs` | SCA | `both` | CLI (`npm`) | متوسطة |
| `pip-npm-audit` | SCA | `local` | CLI (`pip` / `npm`) | عالية |
| `gitleaks` | Secrets | `local` | Docker / CLI | عالية |
| `trufflehog` | Secrets | `local` | Docker / CLI | متوسطة |
| `checkov` | IaC | `local` | CLI (`pip`) | متوسطة |

---

## 2. استراتيجية التشغيل حسب الفئة

### أ. أدوات فحص الروابط والمواقع الحية (`DAST`)
- **المدخل:** رابط الموقع (`https://example.com`) + إعدادات الأمان (مثل: ترويسات مصادقة/Cookies اختيارية، نطاق الفحص `Scope` لمنع فحص روابط خارجية).
- **ضوابط الأمان (Safe Scanning Policy):**
  - في `Nuclei`: تقييد التشغيل بوسوم غير تخريبية (استبعاد قوالب `dos`, `fuzzing` الثقيل، أو القوالب التجريبية) والعمل بمعدل طلبات (`rate-limit`) آمن لا يسبب ضغطاً على موقعك.
  - في `OWASP ZAP`: دعم وضعين؛ **Baseline Scan** (فحص سلبي سريع وآمن للمواقع الحية) و**Full Scan** (لبيئة التجربة Staging).
  - في `testssl.sh` و`httpx` و`Nmap`: فحص قراءة فقط (Read-only inspection) للتحقق من الشهادات والترويسات والمنافذ.

### ب. أدوات تحليل الكود المصدري (`SAST`)
- **المدخل:** مسار المجلد المحلي للمشروع (`/path/to/project`).
- **آلية التشغيل:**
  - اكتشاف لغة المشروع تلقائياً (وجود `package.json`, `requirements.txt`, `composer.json`, `go.mod`) لتشغيل الأدوات المناسبة فقط دون إضاعة وقت.
  - دعم ملف استثناءات (`.secignore` أو احترام `.gitignore`) لتجاهل مجلدات مثل `node_modules`, `venv`, `dist`.

### ج. أدوات فحص المكتبات والاعتماديات (`SCA`)
- **المدخل:** مجلد المشروع المحلي (أو صورة Docker).
- **آلية التشغيل:** استخدام `Trivy` و/أو `OSV-Scanner` لقراءة ملفات الـ Lockfiles (`package-lock.json`, `poetry.lock`, ...) وإخراج الثغرات مع رقم `CVE` والنسخة الآمنة المقترحة للترقية.

### د. أدوات كشف الأسرار (`Secrets`)
- **المدخل:** مجلد المشروع + سجل Git (`.git`).
- **آلية التشغيل:** تشغيل `Gitleaks` / `TruffleHog` مع إخفاء القيمة الفعلية للمفتاح في التقرير النهائي (`Masking`) والاكتفاء بذكر اسم الملف ورقم السطر ونوع المفتاح.

### هـ. أدوات البنية التحتية (`IaC`)
- **المدخل:** ملفات `Dockerfile`, `docker-compose.yml`, `Terraform`, وملفات CI/CD.

---

## 3. معيار التعديل والتخصيص (Customizability)
بما أن أحد شروطك الأساسية هو القدرة على التعديل على الأدوات:
- **أدوات القواعد (Rule-based):** مثل `Semgrep` و`Nuclei` تسمح بإضافة قواعد YAML مخصصة لمشاريعك دون تعديل كود الأداة نفسها.
- **أدوات مفتوحة الكود (Source-modifiable):** مثل `Wapiti`, `Bandit`, `Checkov` (Python) و`Retire.js` (JS) و`Gitleaks`, `Trivy` (Go) يمكن عمل Fork لها وتعديلها مباشرة إذا احتجت منطق فحص خاص.
- **طبقة التغليف (Wrapper Plugins):** في البرنامج الموحد، ستكون كل أداة معزولة في **Adapter/Plugin** مستقل، بحيث يسهل استبدالها أو تعديل وسائط تشغيلها (CLI Flags) من ملف إعدادات واحد.

