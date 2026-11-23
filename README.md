# Cyber Toolkit

## العربية

أداة سطر أوامر تعليمية تجمع فحوصات أساسية للمواقع والشبكات في قائمة واحدة. تحفظ نتائج الفحوصات في `report.txt`، ويمكنها إنشاء صفحة HTML محلية بتصميم داكن عبر الخيار 6 أو تلقائيًا بعد الفحص الشامل.

### المتطلبات والتشغيل على Kali Linux

- Python 3.8 أو أحدث.
- لا تحتاج الأداة إلى تثبيت مكتبات خارجية؛ كل الاعتمادات من مكتبات Python القياسية.

من داخل المجلد:

```bash
python3 cyber_toolkit.py
```

اختر رقمًا من القائمة واتبع التعليمات. عند تنفيذ فحص، تُضاف النتيجة إلى `report.txt`. الخيار 6 يحوّل التقرير الحالي إلى `report.html`، ويمكن فتحه في أي متصفح.

### الوظائف الـ 12

1. **فحص المنافذ:** يفحص TCP للمنافذ 21 و22 و80 و443 على اسم موقع أو IP.
2. **استخراج الروابط والنماذج:** يقرأ HTML للصفحة ويعرض روابطها وحقول النماذج.
3. **فحص إعدادات الأمان:** يعرض ترويسات HTTP المهمة، مثل CSP وHSTS وX-Frame-Options.
4. **اكتشاف التقنيات:** يبحث عن مؤشرات في الترويسات وHTML، مثل نوع الخادم وWordPress وPHP.
5. **فحص المسارات المهمة:** يفحص استجابات مسارات محددة مثل `robots.txt` و`admin` و`/.git/config`.
6. **تصدير التقرير إلى HTML:** ينشئ `report.html` بتنسيق عربي واتجاه RTL وتصميم داكن وجداول.
7. **اكتشاف النطاقات الفرعية:** يستعلم من سجلات الشهادات العامة `crt.sh` ويجرّب أسماء شائعة، ثم يعرض الأسماء التي تحل عبر DNS.
8. **فحص شهادة SSL/TLS:** يعرض الجهة المصدرة وتاريخ الانتهاء وأسماء DNS البديلة للشهادة على المنفذ 443.
9. **الفحص الشامل التلقائي:** يشغّل فحص المنافذ، والترويسات، والتقنيات، والمسارات، والشهادة، وIP Info، وقراءة `robots.txt` و`security.txt`، ثم يصدر HTML تلقائيًا.
10. **فحص مبدئي للمدخلات:** يجري طلبي GET محدودين لرصد مؤشرات أخطاء SQL وانعكاس علامة نصية؛ لا يثبت غياب الثغرات.
11. **IP Info:** يحل اسم الموقع إلى IP ويطلب معلومات الدولة والمدينة وISP وOrg من `ip-api.com`.
12. **قراءة ملفات الموقع:** يعرض توجيهات مهمة من `/robots.txt` وحقولًا من `/.well-known/security.txt`.

### ملاحظات وحدود

- نتائج تحديد التقنيات والموقع الجغرافي استدلالية وقد تكون غير مكتملة أو تقريبية.
- خيار 2 يقرأ HTML الذي يرسله الخادم، ولا ينفّذ JavaScript في المتصفح.
- خيار 7 يعتمد على توفر `crt.sh` وDNS. ظهور عنوان IP يعني أن الاسم يحل عبر DNS، وليس بالضرورة أن خدمة ويب تعمل عليه.
- واجهة `ip-api.com` المجانية تستخدم HTTP غير مشفر؛ يرسل الخيار عنوان IP المستهدف إلى الخدمة.
- `requirements.txt` موجود للتوثيق، ولا توجد حزم خارجية مطلوبة.

### إخلاء المسؤولية القانونية

هذه الأداة مخصصة **للتعلم والاختبار المصرح به فقط**. استخدمها على أنظمة تملكها أو لديك إذن صريح بفحصها، والتزم بالقوانين وسياسات الشبكات المعمول بها. أنت مسؤول عن استخدام الأداة والنتائج الناتجة عنها. لا تضمن الأداة اكتشاف جميع المشكلات أو صحة كل استنتاج.

---

## English

Cyber Toolkit is an educational command-line utility that groups basic website and network checks in one menu. Scan output is appended to `report.txt`. Option 6 exports the current report to a local dark-themed HTML page; Full Recon exports it automatically.

### Requirements and Kali Linux usage

- Python 3.8 or newer.
- No third-party packages are required; the program uses Python's standard library.

From the project directory, run:

```bash
python3 cyber_toolkit.py
```

Choose an item from the menu and follow its prompts. Scan results are appended to `report.txt`. Option 6 creates `report.html`, which can be opened in any web browser.

### The 12 features

1. **Port scan:** Checks TCP ports 21, 22, 80, and 443 on a hostname or IP address.
2. **Links and forms:** Reads the page HTML and lists links and form fields.
3. **Security headers:** Reports important HTTP headers such as CSP, HSTS, and X-Frame-Options.
4. **Technology clues:** Looks for server, WordPress, PHP, and similar clues in headers and HTML.
5. **Important paths:** Checks responses for selected paths such as `robots.txt`, `admin`, and `/.git/config`.
6. **HTML report export:** Creates an Arabic, RTL, dark-themed `report.html` with tables.
7. **Subdomain discovery:** Queries public certificate records at `crt.sh`, tries common names, and lists names that resolve in DNS.
8. **SSL/TLS certificate:** Shows the issuer, expiration date, and DNS subject alternative names for the certificate on port 443.
9. **Full Recon:** Runs the port, header, technology, path, certificate, IP Info, and robots/security.txt checks, then exports HTML automatically.
10. **Basic input checks:** Sends two limited GET requests to look for SQL error clues and reflected text. This does not prove that a site is free of vulnerabilities.
11. **IP Info:** Resolves a hostname and requests country, city, ISP, and organization information from `ip-api.com`.
12. **Site policy files:** Displays relevant directives from `/robots.txt` and fields from `/.well-known/security.txt`.

### Notes and limitations

- Technology and geolocation results are clues and may be incomplete or approximate.
- Option 2 reads the HTML returned by the server; it does not run JavaScript in a browser.
- Option 7 depends on `crt.sh` and DNS. An IP address confirms DNS resolution, not that a web service is running.
- The free `ip-api.com` endpoint uses unencrypted HTTP; the target IP is sent to that service.
- `requirements.txt` is included for documentation; no external packages are needed.

### Legal disclaimer

This tool is for **educational use and authorized testing only**. Use it only on systems you own or have explicit permission to assess, and follow applicable laws and network policies. You are responsible for how you use the tool and its results. The tool does not guarantee that it will find every issue or that every inference is correct.
