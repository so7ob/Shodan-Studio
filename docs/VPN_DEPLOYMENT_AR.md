# تثبيت وترقية VPN Manager على Debian 12

المسارات أدناه تحققت في هذا الخادم. لا تنقل بيانات خادم آخر إليها بلا فحص.
الترقية تضيف جدولين وتغيّر `PRAGMA user_version` من 0 إلى 1، دون حذف جداول
أو إعادة إنشاء المهام. الترقية من 1.2 إلى 1.3 تبقي المخطط عند النسخة 1.
تشغيل أداة التركيب لا يتصل بأي ملف VPN.

## المتطلبات والأدوات

لـPremium يلزم python3-cryptography؛ راجع [ربط الاشتراك](VPN_PREMIUM_AR.md).
Python 3.11 وiproute2 وnftables وutil-linux وcurl وca-certificates.
للـAmneziaWG: daemon الموجود في `/opt/AmneziaVPN/bin/amneziawg-go` وأداة awg
الرسمية. لم تُستخدم awg-quick لأنها قد تنفذ hooks وتعدل شبكة المضيف.
للـWireGuard: أداة `/usr/bin/wg` ودعم kernel wireguard؛ هذا المسار مدعوم
بالكود لكنه لم يُختبر كنفق Premium في هذا التسليم.

تثبيت awg من المصدر الرسمي المثبت بالإصدار المستخدم في الاختبار:

```bash
sudo apt install build-essential git iproute2 nftables util-linux curl ca-certificates python3-cryptography
git clone https://github.com/amnezia-vpn/amneziawg-tools.git /tmp/studio-awg-tools
git -C /tmp/studio-awg-tools checkout ee0f0a9aa34ff0a0da4b3433b9512781cfe02843
make -C /tmp/studio-awg-tools/src -j2
sudo install -d -o root -g root -m 0755 /usr/local/libexec/shodan-studio
sudo install -o root -g root -m 0755 /tmp/studio-awg-tools/src/wg /usr/local/libexec/shodan-studio/awg
```

هذه خطوة إدارة صريحة. لا تنزل خدمة الويب أدوات أو كودًا وتنفذه كـroot.
لا تثبّت kernel module جديدًا أو تستبدل عميل Amnezia الحالي لهذا التكامل.

## قبل الترقية

تحقق من Git والنسخة النشطة وحالة الطابور؛ انتظر العامل أو أوقفه مؤقتًا مع
حفظ Checkpoint. نفذ فحوص الحزمة والمحاكاة قبل إيقاف الخدمات:

```bash
bash install-debian.sh --check
bash tools/install_vpn_helper.sh --check
python3 -m unittest discover -s tests
node --test tests/test_ip_progress.mjs
```

الاختبار الحقيقي المحلي اختياري، يحتاج root، ويستخدم مفاتيح وهمية مستقلة
ونفقًا محليًا ثم يستعيد موارده. لا يتصل بـPremium أو يبحث في Shodan:

```bash
sudo python3 tools/verify_vpn_isolation.py --run-root-lab \
  --awg /usr/local/libexec/shodan-studio/awg
```

## نسخة احتياطية متسقة وترقية

عند نقطة الصيانة احفظ الرابط القديم وحالة الخدمة، ثم أوقف خدمات التطبيق فقط.
لا توقف AmneziaVPN أو SSH أو systemd-resolved. أسماء ملفات النسخ الاحتياطية
فريدة ولا تعيد الكتابة على نسخة سابقة.

```bash
sudo systemctl stop shodan-studio
# إذا كانت الخدمة المساعدة مثبتة بالفعل:
sudo systemctl stop shodan-studio-vpn
sudo install -d -m 0700 /var/backups/shodan-studio
sudo bash -c 'umask 077; tar -C / -czf /var/backups/shodan-studio/pre-vpn-$(date +%Y%m%d-%H%M%S).tar.gz var/lib/shodan-studio etc/default/shodan-studio'
readlink -f /opt/shodan-studio/current
sudo bash install-debian.sh --no-start
sudo bash tools/install_vpn_helper.sh --no-start
sudo systemctl enable --now shodan-studio-vpn
sudo systemctl start shodan-studio
```

عند أول ترحيل من الإصدار صفر يُمسك المهاجر قفل كتابة قبل فحص الإصدار، ويأخذ
نسخة SQLite عبر backup API من اتصال قراءة مستقل. يقارن المخطط وجميع الصفوف
بالمصدر، ثم يستعيد النسخة إلى قاعدة مؤقتة مستقلة ويتحقق منها قبل تعديل المخطط.
لا يكفي نجاح integrity_check وحده. فشل النسخ أو التحقق يمنع الترحيل، وفشل
تعديل المخطط يعيد المعاملة إلى حالتها السابقة.

تُنشر النسخة المكتملة بصلاحية 0600 دون استبدال أي ملف موجود. الاسم الافتراضي:
`/var/lib/shodan-studio/studio.pre-vpn-v0.sqlite3`. إذا كان موجودًا، حتى لو كان
فارغًا أو تالفًا أو قديمًا، يبقى دون تعديل وتُنشأ نسخة جديدة باسم
`studio.pre-vpn-v0.<معرّف فريد>.sqlite3`. تُرجع دالة migrate مسار النسخة الجديدة؛
لا تفترض أن الملف ذا الاسم الافتراضي هو نسخة المحاولة الأخيرة. الملفات
المؤقتة المتبقية من انقطاع سابق لا تُستخدم كنسخ موثقة. هذا مكمل لنسخة الملفات
الكاملة وليس بديلًا عن حفظ Checkpoints والنتائج والإعدادات. القواعد التي
سبق ترحيلها لا تُغيّر ولا تُعاد كتابة نسخها القديمة تلقائيًا.

إذا كانت ملفات VPN موجودة قبل الترقية، أدرج `/etc/shodan-studio/vpn` في
الأرشيف الخاص نفسه قبل استبدال أي مكون. يجب أن يبقى الأرشيف بصلاحية 0600.

تحقق من الخدمة والحالة ومن بقاء أعداد المهام والنتائج والمستخدمين. استخدم
عنوان Host المسموح في `/etc/default/shodan-studio`:

```bash
systemctl is-active shodan-studio shodan-studio-vpn
curl --fail http://127.0.0.1:8787/health
```

ثم سجّل الدخول: القسم متاح، سجل الملفات صادق، والمهام القديمة موجودة.
لا تغيّر ملفًا محميًا أو تحاول استكماله إلا بعد نجاح فحص العامل المعزول.
الحساب غير المميز يمكنه إرسال عمليات محددة إلى socket، ولا يستطيع قراءة
مفاتيح `/etc/shodan-studio/vpn/profiles`.

## التراجع

مرجع ما قبل Premium محفوظ في `vpn-evidence/premium-baseline.json`، ومرجع
آخر ترقية في `vpn-evidence/premium-deployment.json`. لا تعتمد على اسم
`previous` دون فحص وجهته؛ قد يشير إلى نسخة 1.3 سابقة لا إلى 1.2.

تراجع الكود يحافظ على جداول VPN الإضافية ونتائج ما بعد الترقية. أوقف
الخدمتين أولًا، وتحقق أن `previous` يشير للإصدار المقصود قبل تبديل الرابط:

```bash
sudo systemctl stop shodan-studio shodan-studio-vpn
readlink -f /opt/shodan-studio/previous
sudo ln -sfn "$(readlink -f /opt/shodan-studio/previous)" /opt/shodan-studio/current
sudo systemctl disable shodan-studio-vpn
```

**عند الرجوع إلى إصدار قبل 1.2**: لأنه لا يفهم سياسة VPN، لا تسمح له بتشغيل مهام
VPN مصطفة. على النسخة الجديدة، أوقف هذه المهام قبل التراجع. إذا وقع فشل
قبل ذلك، نفذ الأمر الآتي بعد إيقاف الخدمات؛ يحوّلها إلى paused ويحتفظ
بالسياسة والنتائج. لا يستخدم قاعدة بيانات أخرى:

```bash
sudo python3 tools/pause_vpn_jobs.py /var/lib/shodan-studio/studio.sqlite3
```

شغّل الأداة من checkout أو حزمة الإصدار الجديد؛ لا تبحث عنها داخل الإصدار
القديم. لا تطبع الأداة بيانات المهام أو مفاتيحها.
لا تستكمل مهام VPN باستخدام إصدار قبل 1.2: لن يعزل اتصالها.
عند الرجوع إلى 1.2، تبقى ملفات WG/AWG المستوردة مدعومة، لكن مهام مواقع
Premium الديناميكية يجب أن تبقى متوقفة إلى إعادة 1.3؛ لا يوجد ملف ثابت لها.

ثم `sudo systemctl start shodan-studio`. راجع المهام مباشرة. أعد الترقية
لتشغيل المهام المحمية. لا تزل مفاتيح VPN أو بيانات المهام أثناء التراجع.

استعادة نسخة البيانات الكاملة خيار أخير **يلغي التغييرات اللاحقة للنسخة**:
أوقف الخدمات، احفظ نسخة الحالة الحالية أولًا، استعد الأرشيف في مكان تجريبي،
تحقق من integrity_check والأعداد والملكية shodan-studio:shodan-studio، ثم
استبدل مجلد البيانات عند توقف الخدمتين. لا تضع SQLite قديمة فوق WAL/SHM
من قاعدة أخرى. استعادة SQLite وحدها تحتاج كذلك Checkpoints المتزامنة معها.

## حدود الدليل

نجاح CI ليس نشرًا، ونجاح المختبر ليس اتصال Premium. أدلة كل مرحلة والقيود
الحالية موثقة في `VPN_VALIDATION.md`. لا يُنشأ tag أو إصدار GitHub ولا يُدمج PR
كجزء ضمني من هذه الترقية.
