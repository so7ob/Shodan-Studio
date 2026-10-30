## Independent execution spaces — Issue #35 (2026-10-30)

- Python: **364 passed**, no skips, including two simultaneous real offline
  workers, live discovery seeding before extraction finishes, per-kind claims,
  independent VPN/browser control, shared-account exclusion, restart/checkpoint
  compatibility and host page verification. [Log](docs/enrichment-spaces-evidence/python-tests.txt).
- JavaScript: **33 passed**, no skips. [Log](docs/enrichment-spaces-evidence/node-tests.txt).
- Browser: `/extraction` and `/enrichment`, RTL 375/1280, keyboard, reload,
  separate tables, VPN/diagnostics space selection, zero axe violations.
  [Report](docs/enrichment-spaces-evidence/spaces-browser.json).
  Inventory/dialog regressions also passed; [report](docs/enrichment-spaces-evidence/browser.json).
- Live database copy: 22 jobs, 1463 targets, 2107 IP links, 2165 discovery rows;
  all retained, contracts unchanged, integrity `ok`. Schedulers were disabled
  and no external requests were made. [Report](docs/enrichment-spaces-evidence/migration-copy.json).
- UI states and host HTML layouts are fixtures; they do not prove live Shodan
  acceptance. Installation, two live VPN connections and interactive recovery
  require separate local service evidence. CI evidence is tracked in the pull request linked to #35.

# Shodan Studio 1.1.0 — تحقق مؤشر IP

النتائج الفعلية بتاريخ **2026-10-24** على **Debian 12، Python 3.11.2، systemd 252**.
الأدلة في الجدول تخص الاختبارات المعزولة؛ حالة النشر الفعلية تُوثّق في سجل منفصل.
لم تُرسل هذه الاختبارات استعلامات حية إلى Shodan. اختبار الخدمة شغّل نسخة معزولة
من وحدة النشر تحت اسم وبيانات منفصلين ثم أزالها، وتحقق من بقاء PID ووقت بدء
الخدمة الأصلية كما كانا ومن تطابق إصدار فحص الصحة مع إصدار الحزمة.

| الفحص | النتيجة والدليل |
|---|---|
| Python وحدة وتكامل | **108/108** خلال **41.231 ثانية**، بلا تجاوزات: [السجل](docs/ip-progress-evidence/python-tests.txt) |
| JavaScript | **11/11**، بلا تجاوزات: [السجل](docs/ip-progress-evidence/js-tests.txt) |
| Debian/systemd | الخدمة active؛ إعادتان للتشغيل مع بقاء البيانات: [السجل](docs/ip-progress-evidence/service-test.txt) |
| المتصفح | دخول فعلي، تفاصيل بلوحة المفاتيح، القائمة والتفاصيل 65% للمثال، RTL بعرضي 375 و1280، بلا أخطاء JavaScript: [النتيجة](docs/ip-progress-evidence/browser.json) |
| axe | صفر مخالفات في **مكوّنات المؤشر المعدلة** على العرضين؛ ليس تدقيقًا شاملًا للتطبيق |
| سلامة البيانات | `PRAGMA integrity_check = ok`؛ بقيت 98 IP بعد restart ثم 292 بعد resume، دون تضاعف |
| الاتصال | 9 طلبات DemoData محلية معتادة للوصول إلى 292 IP؛ صفر طلبات Shodan في الاختبار |
| التثبيت والتركيب | `install-debian.sh --check`، Bash syntax، `node --check`، وقواعد Python 3.11 ناجحة |

[صورة 1280](docs/ip-progress-evidence/rtl-1280.png) ·
[صورة 375](docs/ip-progress-evidence/rtl-375.png). جميع العناوين والأعداد في الصور
بيانات اختبار اصطناعية، وليست تقديرًا لأي مهمة للمستخدم.

غطت الاختبارات: 512/782 = 65% مع بقاء 16/77 مستقلًا؛ تخطيط غير مكتمل؛ مقام مجهول؛
تكرار IP بين الخدمات؛ إعادة IPC والاستكمال وIPv6 المكافئ؛ عدم جمع الأب والأبناء؛
تحفظ التداخل بين product/version؛ صف API جزئي محفوظ؛ سجلات بلا IDs وصفحات قصيرة
ومكررة؛ توقف العامل بعد checkpoint وقبل وصول IPC؛ HTML/API وتبديل المصدر؛ 0 IP؛
الترقية من التخزين القديم وإعادة الترقية بعد كتابة إصدار سابق للملفات؛ وخطة كبيرة
من 60,010 ورقة تبقى مدخلاتها أصغر من 1000 بايت دون تغيير الأعداد.

نُفذت إصلاحات قبل هذه الجولة النهائية: إنشاء BrowserContext صريح لأداة axe،
واحتواء labels الجدول المطلقة داخل scroller لمنع امتداد RTL على الهاتف.
كشفت إعادة الفحوص قراءة اختبار الأحداث قبل وصول الحدث النهائي؛ أُضيف انتظار محدود
للحدث النهائي مع إبقاء فحص محتواه. كما وُحّد رقم إصدار الخادم والحزمة بعد أن كشف
فحص النشر قيمة قديمة في `/health`. الجولة النهائية المذكورة أعلاه ناجحة.
لم يُعطّل اختبار ولم يُخفّض معيار النجاح. لم يُنفذ اختبار قارئ شاشة يدوي أو إعادة
إقلاع الجهاز كاملًا أو اختبار حساب Shodan حي. المثبت
فُحص بـ`--check`؛ وحدة الخدمة اختُبرت فعليًا بمسارات ومستخدم اختبار غير مميزين.

إعادة الاختبار (المتصفح يحتاج Playwright وChromium و@axe-core/playwright في بيئة
الاختبارات فقط، وليست اعتماديات تشغيل التطبيق):

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
node --test tests/test_ip_progress.mjs
bash install-debian.sh --check
# نفّذ من checkout اختباري بصلاحيات root، ولا تغيّر أسماء العزل في السكربت:
sudo env NODE_PATH=/usr/lib/node_modules PYTHONDONTWRITEBYTECODE=1 \
  python3 tools/verify_ip_progress_service.py --browser
```

المصدر الأساسي المحلي: `27685a9`. محرك `studio/engine.py` لم يتغير، وبصمته مطابقة
للأصل: `f6621de8be85f02981246b20cd65b51cf178d1669b40a0332a1e9a98e707551a`.
حزمة الإدخال `ShodanStudio-IP-Progress-Integration-Kit-v1.zip`:
`ab1e18a16b3c5b955876d1ddc73b5cfa97c3df4cd55eb580df0c0c7a8e483cb3`.

السجل التالي يخص الإصدار القديم فقط؛ حدوده ونسبة الفروع فيه لا تصف الإصدار 1.1.0.

---

## سجل التحقق التاريخي للإصدار 1.0.0

## النتيجة المسجلة

اجتاز الإصدار **69 اختبارًا محليًا في 30.470 ثانية**، دون إخفاق أو اختبارات متجاوزة في هذه المجموعة. يوجد سجل التشغيل الكامل في `docs/test-run.txt`.

الأمر المستخدم من مجلد التطبيق:

```bash
python3 -m unittest discover -s tests -v
```

| المجموعة | عدد الاختبارات | أهم ما تغطيه |
|---|---:|---|
| `test_server.py` | 34 | التهيئة، تسجيل الدخول والجلسات، CSRF وOrigin وHost، تنزيل الملفات، التخزين، وربط الخادم بمدير المهام والعامل الحقيقي |
| `test_jobs.py` | 14 | التخطيط، الطابور، النتائج، الإيقاف والاستكمال، الميزانية، الاستيراد، المفاتيح، وتغيير المصدر |
| `test_deployment.py` | 10 | تركيب Bash، التحقق من الحزمة، خيارات المثبّت، حدود المدخلات، خدمة systemd، وقواعد Python 3.11 |
| `test_lifecycle.py` | 8 | السباقات عند الإيقاف والإلغاء، التحقق من مسارات المخرجات، واستعادة التقدم بعد توقف مفاجئ |
| `test_worker.py` | 3 | الرجوع من API إلى HTML، فشل المصدرين، وحفظ موعد Retry-After |
| **المجموع** | **69** | **اجتازت جميعها** |

## حالات تحقق فعلية

- نفّذ مدير المهام عاملًا معزولًا بعملية Python مستقلة، مع بيانات محلية بديلة. أعاد المثال **292 عنوانًا اصطناعيًا فريدًا** في **9 طلبات محاكاة** و**5 فروع**. ترتيب الاستخراج كان `98 → 54 → 51 → 49 → 40`.
- احتفظ الإيقاف والاستكمال بالعناوين السابقة واستفاد من الصفحات المحفوظة. استكمال المهمة بعد بلوغ ميزانية الجولة لا يعيدها إلى الصفر.
- أبقى تغيير المصدر من API إلى HTML على التقدم، وسجّل تغير المصدر في التقرير.
- عند محاكاة API 403، حدث رجوع واحد إلى HTML، وانتهى الجمع بـ292 عنوانًا في 10 محاولات إجمالية. عند فشل API وHTML معًا، أصبحت الحالة `waiting_input` بعد محاولتين.
- عند محاكاة API 429 مع `Retry-After: 3600`، حُفظ موعد الانتظار. الاستكمال الفوري لم يرسل أي طلب إضافي ولم يدخل الاختبار في انتظار ساعة.
- حاكى اختبار توقفًا مفاجئًا بعد كتابة النتائج وقبل تثبيت بصمتها في نقطة الحفظ. نجح الاستكمال مع بقاء 292 عنوانًا ودون طلبات جديدة إلى المصدر.
- رُفضت المسارات الخارجة عن مجلد المهمة، والروابط الرمزية للمخرجات، وخيارات الأوامر غير المسموح بها. الاستعلامات تُمرّر بيانات ولا تُنفّذ كأوامر shell.
- تحققت الاختبارات من عدم وجود المفتاح البديل المستخدم فيها في قاعدة البيانات أو ملفات المهام أو التقارير والتصدير. لم تُستخدم المفاتيح التي ظهرت في المحادثة.
- رُفضت طلبات التعديل دون جلسة وCSRF صالحين، والطلبات ذات Origin أو Host غير المسموح. خُزّنت كلمات المرور والجلسات بصيغ مشتقة، وليس كنصوصها الأصلية.
- تحققت سلامة تركيب JavaScript بواسطة `node --check`، وتركيب Bash، ومراجع عناصر الواجهة. جرى التحقق من ملف خدمة systemd بأداة `systemd-analyze verify` المتاحة في بيئة البناء.

## مراجعة الواجهة في المتصفح

فُتحت صفحة التهيئة الفعلية في متصفح. كما روجعت لوحة التحكم، تفاصيل المهمة، التقدم، النتائج والبحث داخلها، ونموذج إنشاء المهمة وإعداداته باستخدام استجابات محلية ثابتة مأخوذة من تنفيذ المهمة التجريبية.

هذه المعاينة الثانية كانت **واجهة قراءة ببيانات بديلة**؛ لا تُعد اختبار تسجيل دخول وتنفيذ مهمة حقيقية عبر متصفح متصل بـShodan. تدفق تسجيل الدخول وإنشاء المهام وتنفيذ العامل وتنزيل النتائج اختُبر برمجيًا عبر واجهة WSGI داخل العملية مع عامل مستقل.

الصورة `docs/dashboard-demo.jpg` تعرض بيانات اصطناعية موسومة في الواجهة. لم يُختبر مقاس هاتف فعلي في هذه الجولة.

## بيئة التحقق وحدوده

- بيئة الاختبارات الفعلية: **Ubuntu 24.04.3، Python 3.12.14**.
- الهدف التشغيلي: **Debian 12، Python 3.11**. اجتاز الكود فحص قواعد Python 3.11، ولا يعتمد التطبيق على حزم pip أو Node.js وقت التشغيل.
- لم يتوفر جهاز Debian 12 أو حاوية Debian في بيئة البناء؛ **لم يُجرَ تثبيت فعلي للخدمة على Debian 12**. التحقق من القواعد وملف الخدمة لا يعادل اختبار تشغيل على نظام الهدف.
- لم تُرسل هذه الاختبارات استعلامات حية إلى Shodan، ولم يُختبر اشتراك المستخدم أو رصيده أو مسار اتصاله أو شهاداته أو الجدار الناري لديه.
- خادم HTTP المرفق مبني على `wsgiref` ومخصص هنا للاستخدام الفردي أو شبكة داخلية موثوقة أو نفق SSH. لا يُقدَّم كإعداد عام مقوّى للاستضافة على الإنترنت.
- نسبة التقدم تخص الفروع المعروفة. اكتمال المهمة لا يثبت الحصول على كل نتائج Shodan، وعدّ سجلات الـfacets لا يساوي بالضرورة عدد IP الفريد.

محرك `studio/engine.py` مأخوذ من الإصدار المستقل ShodanSpider 7.1.0 دون تعديل في هذه الحزمة. عدد 69 أعلاه يخص اختبارات التطبيق المرفقة هنا، ولا يجمع أرقام اختبارات إصدار السكربت السابق.

## فحص الحزمة عند الاستلام

من مجلد الحزمة بعد فك الضغط:

```bash
sha256sum -c SHA256SUMS
bash install-debian.sh --check
```

ملف البصمات يخص ملفات حزمة المصدر كما تم تسليمها. لا يتضمن بيانات تشغيل أو مفاتيح أو قاعدة بيانات مستخدم.

## Patchright recovery 1.6.0 — 2026-10-29

Local full gate: 243 Python tests passed with zero skips; 20 Node tests passed.
Installer checks, JavaScript syntax and git diff checks passed. Both native
browser backends passed in disconnected namespaces. Patchright additionally
proved persistent cookies after restart, malformed-facet rejection, private
JSON-pipe lifecycle and no challenge reloads. The simulated Arabic interface
passed keyboard/axe and overflow checks at 375/1280, with no page errors.

Evidence is in `docs/patchright-evidence/`. Native lab and UI fixtures do not
prove live Shodan acceptance. A deployment receipt records the production check
separately. The originally selected task became cancelled during implementation;
the user selected a separate test job and the original task's 566 IPs must remain
unchanged.

Production deployment: source commit `ea7ca4b5abe1b1379e09725b9b240290835aadeb`,
version 1.6.0, active application/helper, matching live health, verified backup
and preserved original job IP sets. The approved separate test job
`8d336ce1ee780b73e455a135280fdd9a` received HTTP 200 in Patchright, passed exact
facet verification, extracted 3 IPs in one worker request and was left paused.
Its browser was closed. The original task remains cancelled with 566 IPs.

Live preflight recorded a missing manually selected tunnel, a test-directory
ownership error (corrected before retry as the application user), and a transient
VPN health hold. These held runs sent zero extraction requests. The final run
passed the unchanged health checks. Receipts retain each observation separately.
GitHub CI 40902906990 passed on the deployed implementation commit.

## Task pacing and estimated progress — Issue #29, 2026-10-29

Local full gate: 311 Python tests passed in 152.444 seconds, zero skips; 28 Node
tests passed. Installer/helper/browser checks, JavaScript syntax and diff checks
passed. Worker tests include cancellation cleanup and persistence overhead within
the published delay. Clock tests cover browser skew, reloads, changing wall time,
stale/slow responses, network jitter, and independent Retry-After waits.

The authenticated loopback UI fixture used a task interval of 18 seconds and
100 persisted unique IPs against 579 source records during incomplete planning.
Both list and detail displayed 17% estimated. With the browser clock five seconds
behind, the countdown started at 18; later clock jumps of +1 hour and -2 hours and
a reload did not reset it. Recorded samples reached 13, 12, ... 1, 0, then retained
the configured interval without hiding the timer line. Keyboard entry, RTL at
375/1280, horizontal overflow checks and axe all passed, with zero page errors.
Manual screen-reader testing was not performed.

Evidence: `docs/pacing-progress-evidence/issue29-ui.json` and the two screenshots.
Reproduce with `python3 tests/serve_vpn_fixture.py --pacing-progress --port 8799`,
then `node tests/browser_pacing_progress.cjs` with Playwright/axe available and
`STUDIO_TEST_CHROMIUM` pointing to the test Chromium binary. The fixture uses a
temporary database and sends no Shodan queries. This records local validation,
not a deployment or live source acceptance result.

## Query attempts and results — Issue #31, 2026-10-30

The local full Python gate passed 325 tests in 175.294 seconds. The 14 request
history tests also passed after final API-page detail and HTML verification-state
adjustments. All 31 Node tests passed; JavaScript syntax, installer/helper/browser
checks and diff checks passed. Exact-head CI runs the full gate again before merge.

Coverage includes HTML/API pagination, distinct empty/unavailable/verification
states, parse/connection failures, 429 retry identities, pacing-excluded durations,
cache observations without additional source calls, actual SQLite IP additions,
replay safety, interrupted results and restart recovery. Large-detail tests stream
10,000 facet values in bounded messages, including an oversized source label.
Authenticated routes reject anonymous and cross-job detail access. Secret fields
and raw responses are excluded. Existing worker/lifecycle tests retain pause,
resume and cancellation checks.

An isolated copy of the live SQLite database recovered 270 legacy attempts and
177 explicitly labelled checkpoint snapshots across 12 jobs, with 4,996 values.
Repeating the import created no duplicates; job documents remained identical and
SQLite integrity passed. The live database was not modified and no Shodan query
was sent. Evidence: `docs/request-history-evidence/offline-migration.json`.

The authenticated local browser fixture exercised 70 attempts, 250 values loaded
in 100-item pages, an in-flight result completing during polling, old-attempt
pagination, all-events switching, reload and unsafe markup displayed as text.
Expanded details and keyboard focus survived refreshes. RTL at 375/1280, overflow
checks and axe passed with zero page errors. Manual screen-reader testing was not
performed. Evidence: `docs/request-history-evidence/browser.json` and screenshots.
Reproduce with `python3 tests/serve_vpn_fixture.py --request-history --port 8801`
and `node tests/browser_requests.cjs` with Playwright/axe and Chromium available.
These are fixture and offline migration checks; rollout evidence is recorded
separately after backup, deployment and live service/API verification.

## Target repository and enrichment jobs — Issue #33, 2026-10-30

The final local Python gate passed 349 tests in 305.405 seconds, with no skips.
The final 16 focused enrichment/security tests also passed after adding source-echo
redaction at the metadata sidecar boundary. All 33 Node tests passed. Installer/helper/browser dry-run checks, JavaScript
syntax and diff checks passed. Coverage includes cross-job IP identity, correlated
filters, timestamps and replay, services and snapshots, deletion retention,
authenticated/CSRF routes, encrypted optional keys, shared job controls, schedule
and runtime settings, checkpoints/import/recovery, API/HTML fallback, exact-host
browser verification/RPC, malformed responses and persisted Retry-After holds.

The isolated live-data-copy migration preserved 12 source jobs and 2,107 task/IP
links, producing 1,463 inventory targets and 2,165 discovery records. Of those,
1,795 have explicitly unknown historical times. It created 9 enrichment jobs and
1,463 automatic claims; repeating seeding changed neither. Original task contracts
and SQLite integrity passed. The scheduler never started, socket creation was
blocked, and keys/browser profiles were not copied. The original service/state
was not modified. Evidence: `docs/target-repository-evidence/migration.json`.

The authenticated temporary UI fixture covers 120 synthetic IPs, filters,
pagination, selection/focus retention, source/history details, enrichment creation,
runtime settings and clearing a secret input on dialog close. RTL at 375/1280,
keyboard navigation and axe passed with zero violations in the inventory and
target/enrichment/create/runtime dialogs. No manual screen-reader audit was done.
Evidence: `docs/target-repository-evidence/browser.json` and screenshots.

These results are local/offline evidence. No original-service deployment or live
enrichment was performed. A direct public example fetch from the development
environment failed with `NETWORK_UNREACHABLE`; HTML parsing and browser acceptance
use isolated fixtures and do not establish live Shodan/Cloudflare acceptance.
Reproduction instructions: `docs/TARGET_REPOSITORY_AR.md`.
