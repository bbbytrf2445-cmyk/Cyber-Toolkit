"""A small menu-driven toolkit for basic website checks."""

import builtins
import html
import ipaddress
import json
import re
import secrets
import socket
import ssl
import sys
from contextlib import redirect_stdout
from datetime import datetime
from html.parser import HTMLParser
from io import StringIO
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen


PORTS = (21, 22, 80, 443)
IMPORTANT_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/admin",
    "/login",
    "/wp-login.php",
    "/.git/config",
)
COMMON_SUBDOMAINS = (
    "www", "mail", "dev", "test", "api", "blog", "admin",
    "webmail", "staging", "shop", "ftp", "vpn", "portal", "app",
)
SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "يساعد المتصفح على استخدام HTTPS دائمًا."),
    "content-security-policy": ("CSP", "يحدد مصادر المحتوى المسموح بها."),
    "x-frame-options": ("X-Frame-Options", "يقلل عرض الموقع داخل إطار لخداع المستخدم."),
    "x-content-type-options": ("X-Content-Type-Options", "يمنع تخمين نوع المحتوى."),
    "referrer-policy": ("Referrer-Policy", "يتحكم في المعلومات المرسلة عن الصفحة السابقة."),
    "permissions-policy": ("Permissions-Policy", "يتحكم في ميزات المتصفح المتاحة للصفحة."),
}


class PageParser(HTMLParser):
    """Collect links and fields belonging to forms from HTML."""

    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        elif tag == "form":
            self.current_form = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "GET").upper(),
                "fields": [],
            }
            self.forms.append(self.current_form)
        elif tag == "input" and self.current_form is not None:
            self.current_form["fields"].append(
                ("input", attrs.get("type", "text"), attrs.get("name", "(بدون اسم)"))
            )
        elif tag in ("textarea", "select") and self.current_form is not None:
            self.current_form["fields"].append(
                (tag, tag, attrs.get("name", "(بدون اسم)"))
            )

    def handle_endtag(self, tag):
        if tag == "form":
            self.current_form = None


def normalize_url(value):
    value = value.strip()
    if value and not urlparse(value).scheme:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("اكتب رابطًا صحيحًا يبدأ بـ http أو https.")
    return value


def scan_ports(target=None):
    if target is None:
        target = input("اكتب اسم الموقع أو عنوان IP: ").strip()
    if not target:
        print("لازم تدخل اسم موقع أو عنوان IP.")
        return
    try:
        addresses = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        print(f"تعذّر العثور على الهدف: {error}")
        return

    for port in PORTS:
        is_open = False
        for family, socktype, proto, _, sockaddr in addresses:
            try:
                with socket.socket(family, socktype, proto) as connection:
                    connection.settimeout(3)
                    if connection.connect_ex((sockaddr[0], port)) == 0:
                        is_open = True
                        break
            except OSError:
                continue
        state = "مفتوح" if is_open else "مقفل أو لا يستجيب"
        print(f"المنفذ {port}: {state}")


def extract_links_and_forms():
    try:
        url = normalize_url(input("اكتب رابط الموقع: "))
    except ValueError as error:
        print(error)
        return

    request = Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; CyberToolkit/1.0)"})
    try:
        with urlopen(request, timeout=10) as response:
            page_url = response.geturl()
            charset = response.headers.get_content_charset() or "utf-8"
            html = response.read().decode(charset, errors="replace")
    except (HTTPError, URLError, TimeoutError, OSError) as error:
        print(f"تعذّر قراءة الصفحة: {error}")
        return

    parser = PageParser()
    parser.feed(html)
    print("\nالروابط:")
    if parser.links:
        for number, link in enumerate(parser.links, 1):
            print(f"{number}. {urljoin(page_url, link)}")
    else:
        print("مفيش روابط في الصفحة.")

    print("\nالنماذج وخانات الإدخال:")
    if not parser.forms:
        print("مفيش نماذج في الصفحة.")
    for number, form in enumerate(parser.forms, 1):
        action = urljoin(page_url, form["action"] or page_url)
        print(f"{number}. {form['method']} {action}")
        if form["fields"]:
            for tag, field_type, name in form["fields"]:
                print(f"   - {tag} ({field_type}): {name}")
        else:
            print("   - مفيش خانات إدخال.")


def check_security_headers(target_url=None):
    try:
        url = normalize_url(target_url if target_url is not None else input("اكتب رابط الموقع: "))
    except ValueError as error:
        print(error)
        return

    request = Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; CyberToolkit/1.0)"},
        method="HEAD",
    )
    try:
        try:
            response = urlopen(request, timeout=10)
        except HTTPError as error:
            response = error
        if response.status in (400, 403, 405, 501):
            response.close()
            request = Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; CyberToolkit/1.0)"},
                method="GET",
            )
            response = urlopen(request, timeout=10)
        with response:
            headers = response.headers
            final_url = response.geturl()
            status = response.status
            header_items = list(headers.items())
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
        print(f"تعذّر جلب الترويسات: {error}")
        return

    print(f"\nالموقع: {final_url}\nحالة الاستجابة: {status}")
    print("\nملخص إعدادات الأمان:")
    for key, (name, explanation) in SECURITY_HEADERS.items():
        value = headers.get(key)
        if key == "strict-transport-security" and urlparse(final_url).scheme != "https":
            print(f"- {name}: غير مطبّق لأن الرابط يستخدم HTTP. {explanation}")
        elif value:
            print(f"- {name}: موجود ({value}). {explanation}")
        else:
            print(f"- {name}: غير موجود في الاستجابة. {explanation}")

    print("\nكل ترويسات الاستجابة:")
    for name, value in header_items:
        print(f"{name}: {value}")


def detect_technologies(target_url=None):
    try:
        url = normalize_url(target_url if target_url is not None else input("اكتب رابط الموقع: "))
    except ValueError as error:
        print(error)
        return

    request = Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; CyberToolkit/1.0)"},
    )
    try:
        with urlopen(request, timeout=10) as response:
            final_url = response.geturl()
            headers = response.headers
            charset = headers.get_content_charset() or "utf-8"
            html = response.read(1_000_000).decode(charset, errors="replace")
            header_items = list(headers.items())
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
        print(f"تعذّر قراءة الموقع لاكتشاف التقنيات: {error}")
        return

    header_map = {name.lower(): value for name, value in header_items}
    page_lower = html.lower()
    clues = []

    server = header_map.get("server")
    if server:
        clues.append(("نوع الخادم", server))
    powered_by = header_map.get("x-powered-by")
    if powered_by:
        clues.append(("تقنية مذكورة في X-Powered-By", powered_by))

    if "wordpress" in page_lower or "wp-content/" in page_lower or "wp-includes/" in page_lower:
        clues.append(("نظام إدارة المحتوى", "توجد مؤشرات على WordPress"))
    if "drupal" in page_lower or "/sites/default/" in page_lower:
        clues.append(("نظام إدارة المحتوى", "توجد مؤشرات على Drupal"))
    if "joomla" in page_lower or "/media/system/js/" in page_lower:
        clues.append(("نظام إدارة المحتوى", "توجد مؤشرات على Joomla"))

    if powered_by and "php" in powered_by.lower():
        clues.append(("لغة/بيئة الخادم", "PHP (حسب ترويسة X-Powered-By)"))
    elif "phpsessid" in header_map.get("set-cookie", "").lower():
        clues.append(("لغة/بيئة الخادم", "قد يكون PHP مستخدمًا (حسب اسم ملف الارتباط)"))
    if "asp.net" in (powered_by or "").lower() or "asp.net" in page_lower:
        clues.append(("لغة/بيئة الخادم", "توجد مؤشرات على ASP.NET"))

    print(f"الموقع: {final_url}")
    print("مؤشرات التقنيات:")
    if clues:
        for category, value in clues:
            print(f"- {category}: {value}")
    else:
        print("- لم تظهر مؤشرات واضحة في ترويسات الاستجابة أو HTML.")
    print("\nالمؤشرات تقريبية؛ قد تخفي إعدادات الموقع بعض التقنيات أو تعرض ترويسات غير دقيقة.")


class NoRedirectHandler(HTTPRedirectHandler):
    """Keep redirects visible so a redirect to the homepage isn't a false match."""

    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def check_important_paths(target_url=None):
    try:
        base_url = normalize_url(target_url if target_url is not None else input("اكتب رابط الموقع: "))
    except ValueError as error:
        print(error)
        return

    opener = build_opener(NoRedirectHandler())
    print(f"نتيجة فحص المسارات على {base_url}:")
    for path in IMPORTANT_PATHS:
        target_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        request = Request(
            target_url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; CyberToolkit/1.0)"},
        )
        try:
            # Read only the response status and headers; don't fetch the page body.
            with opener.open(request, timeout=5) as response:
                status = response.status
        except HTTPError as error:
            status = error.code
            error.close()
        except (URLError, TimeoutError, OSError, ValueError) as error:
            print(f"- {path}: تعذّر الفحص ({error})")
            continue

        if status == 200:
            result = "موجود ويستجيب (200)"
        elif status == 403:
            result = "المسار موجود أو محمي، والوصول مرفوض (403)"
        elif 300 <= status < 400:
            result = f"إعادة توجيه (HTTP {status})؛ لم نتابعها"
        elif status == 404:
            result = "غير موجود حسب استجابة الموقع (404)"
        else:
            result = f"استجابة HTTP {status}"
        print(f"- {path}: {result}")


def discover_subdomains():
    """Find DNS-resolving subdomains from crt.sh and a small common-name list."""
    raw_domain = input("اكتب اسم الدومين (مثال: example.com): ").strip()
    parsed = urlparse(raw_domain if "://" in raw_domain else "//" + raw_domain)
    domain = (parsed.hostname or "").lower().rstrip(".")
    if not domain or "." not in domain or any(char.isspace() for char in domain):
        print("اكتب اسم دومين صحيح مثل example.com.")
        return

    found_names = set()
    crt_url = f"https://crt.sh/?q=%25.{quote(domain, safe='.-')}&output=json"
    print("جارٍ البحث في سجلات الشهادات العامة crt.sh...")
    request = Request(crt_url, headers={"User-Agent": "CyberToolkit/1.0"})
    try:
        with urlopen(request, timeout=15) as response:
            entries = json.loads(response.read(5_000_000).decode("utf-8", errors="replace"))
        for entry in entries:
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lower().lstrip("*.").rstrip(".")
                if name.endswith("." + domain) and name != domain:
                    found_names.add(name)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"تعذّر جلب سجلات crt.sh ({error})؛ هنجرب الأسماء الشائعة.")

    for label in COMMON_SUBDOMAINS:
        found_names.add(f"{label}.{domain}")

    print("النطاقات الفرعية التي لها سجلات DNS:")
    active = []
    for hostname in sorted(found_names):
        try:
            results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            addresses = sorted({result[4][0] for result in results})
            if addresses:
                active.append((hostname, addresses))
        except socket.gaierror:
            continue

    if active:
        for hostname, addresses in active:
            print(f"- {hostname}: {', '.join(addresses)}")
    else:
        print("مفيش نطاقات فرعية من النتائج اللي اتجمعت رجّعت عنوان IP.")
    print("\nملحوظة: وجود DNS يعني إن الاسم بيحلّ لعنوان IP، مش بالضرورة إن عليه موقع أو خدمة شغالة.")


def inspect_ssl_certificate(target_host=None):
    """Read and display the verified TLS certificate presented on port 443."""
    raw_host = target_host if target_host is not None else input("اكتب اسم الموقع (مثال: google.com): ").strip()
    if not raw_host:
        print("لازم تدخل اسم موقع.")
        return
    parsed = urlparse(raw_host if "://" in raw_host else "//" + raw_host)
    hostname = parsed.hostname
    if not hostname:
        print("اسم الموقع غير صحيح.")
        return

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=10) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                certificate = tls_socket.getpeercert()
    except (OSError, ssl.SSLError, ValueError) as error:
        print(f"تعذّر الاتصال الآمن أو قراءة الشهادة: {error}")
        return

    issuer_parts = []
    for group in certificate.get("issuer", ()):
        for key, value in group:
            if key in ("organizationName", "commonName"):
                issuer_parts.append(f"{key}: {value}")
    issuer = "; ".join(issuer_parts) or "غير متاحة"

    expiration_text = certificate.get("notAfter")
    if expiration_text:
        expires_at = datetime.fromtimestamp(
            ssl.cert_time_to_seconds(expiration_text), datetime.now().astimezone().tzinfo
        )
        days_left = (expires_at.date() - datetime.now().astimezone().date()).days
        expiration = f"{expires_at.strftime('%Y-%m-%d %H:%M:%S %Z')} (متبقي {days_left} يوم)"
    else:
        expiration = "غير متاح"

    alternative_names = [
        value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"
    ]

    print(f"اسم الموقع: {hostname}")
    print(f"الجهة المصدرة: {issuer}")
    print(f"تاريخ انتهاء الشهادة: {expiration}")
    print("أسماء النطاقات البديلة (SAN):")
    if alternative_names:
        for name in alternative_names:
            print(f"- {name}")
    else:
        print("- لا توجد أسماء DNS بديلة مسجلة.")


def full_recon():
    """Run the main checks against one target, in the requested order."""
    try:
        target_url = normalize_url(input("اكتب اسم الموقع أو رابطه (مثال: google.com): "))
    except ValueError as error:
        print(error)
        return
    target_host = urlparse(target_url).hostname

    checks = (
        ("1/7 فحص المنافذ", lambda: scan_ports(target_host)),
        ("2/7 فحص إعدادات الأمان (Headers)", lambda: check_security_headers(target_url)),
        ("3/7 اكتشاف التقنيات", lambda: detect_technologies(target_url)),
        ("4/7 فحص المسارات المهمة", lambda: check_important_paths(target_url)),
        ("5/7 فحص شهادة الأمان SSL", lambda: inspect_ssl_certificate(target_host)),
        ("6/7 كشف هوية السيرفر (IP Info)", lambda: lookup_ip_info(target_host)),
        ("7/7 قراءة robots.txt و security.txt", lambda: read_site_policy_files(target_url)),
    )
    for title, check in checks:
        print(f"\n--- {title} ---")
        check()


def check_input_safety():
    """Run two small GET-only checks for SQL error clues and reflected input."""
    try:
        target_url = normalize_url(input("اكتب رابط الصفحة (مثال: http://vulnweb.com): "))
    except ValueError as error:
        print(error)
        return

    print("تنبيه: استخدم الفحص على موقع تدريبي تملكه أو لديك تصريح بفحصه فقط.")
    parsed = urlparse(target_url)
    query_parameters = parse_qsl(parsed.query, keep_blank_values=True)
    parameter_name = query_parameters[0][0] if query_parameters else "q"

    def make_probe_url(value):
        parameters = list(query_parameters) or [(parameter_name, "")]
        parameters[0] = (parameter_name, value)
        return parsed._replace(query=urlencode(parameters, doseq=True)).geturl()

    def fetch_probe(value):
        request = Request(
            make_probe_url(value),
            headers={"User-Agent": "Mozilla/5.0 (compatible; CyberToolkit/1.0)"},
            method="GET",
        )
        try:
            response = urlopen(request, timeout=8)
        except HTTPError as error:
            response = error
        with response:
            status = response.status
            charset = response.headers.get_content_charset() or "utf-8"
            body = response.read(1_000_000).decode(charset, errors="replace")
        return status, body

    sql_signatures = (
        "sql syntax", "mysql", "sqlstate", "ora-", "sqlite error",
        "postgresql", "unclosed quotation mark", "unterminated quoted string",
        "odbc sql", "you have an error in your sql",
    )

    print(f"\nالصفحة المستهدفة: {target_url}")
    print(f"اسم المتغير الذي تم اختياره: {parameter_name}")
    try:
        sql_status, sql_body = fetch_probe("'")
        sql_lower = sql_body.lower()
        sql_matches = [signature for signature in sql_signatures if signature in sql_lower]
        if sql_matches:
            print(f"فحص أخطاء قواعد البيانات: ظهرت مؤشرات محتملة (HTTP {sql_status}).")
            print(f"المؤشرات: {', '.join(sql_matches)}")
        else:
            print(f"فحص أخطاء قواعد البيانات: لم تظهر رسائل خطأ معروفة (HTTP {sql_status}).")
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
        print(f"فحص أخطاء قواعد البيانات: تعذّر إكمال الطلب ({error}).")

    marker = "CT_REFLECT_" + secrets.token_hex(6)
    try:
        reflect_status, reflect_body = fetch_probe(marker)
        if marker in html.unescape(reflect_body):
            print(f"فحص انعكاس المدخلات: ظهرت العلامة النصية في الاستجابة (HTTP {reflect_status}).")
            print("ده مؤشر على انعكاس النص فقط، ومش دليل بمفرده على وجود ثغرة تنفيذية.")
        else:
            print(f"فحص انعكاس المدخلات: لم تظهر العلامة في الاستجابة (HTTP {reflect_status}).")
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
        print(f"فحص انعكاس المدخلات: تعذّر إكمال الطلب ({error}).")

    print("\nنصائح حماية:")
    print("- استخدم الاستعلامات المعلّمة (Parameterized Queries) بدل تركيب SQL من مدخلات المستخدم.")
    print("- اعرض رسائل عامة للمستخدم وسجّل تفاصيل أخطاء قواعد البيانات داخليًا فقط.")
    print("- اعمل ترميزًا للمخرجات حسب سياقها (HTML أو JavaScript) قبل عرض مدخلات المستخدم.")
    print("- تحقّق من المدخلات حسب نوعها، ولا تعتمد على حذف علامات بعينها كوسيلة حماية.")
    print("النتيجة استكشافية ومحدودة؛ عدم ظهور مؤشر لا يثبت خلو الموقع من الثغرات.")


def read_site_policy_files(target_url=None):
    """Fetch robots.txt and security.txt and display useful directives."""
    try:
        url = normalize_url(
            target_url if target_url is not None else input("اكتب رابط الموقع: ")
        )
    except ValueError as error:
        print(error)
        return

    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    files = (
        (
            "robots.txt",
            f"{origin}/robots.txt",
            {"user-agent", "disallow", "allow", "sitemap", "crawl-delay"},
        ),
        (
            "security.txt",
            f"{origin}/.well-known/security.txt",
            {
                "contact", "expires", "encryption", "policy", "canonical",
                "preferred-languages", "acknowledgments", "hiring",
            },
        ),
    )

    for label, file_url, relevant_fields in files:
        print(f"\n--- {label}: {file_url} ---")
        request = Request(
            file_url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; CyberToolkit/1.0)"},
        )
        try:
            with urlopen(request, timeout=10) as response:
                status = response.status
                charset = response.headers.get_content_charset() or "utf-8"
                content = response.read(256_000).decode(charset, errors="replace")
        except HTTPError as error:
            status = error.code
            content = ""
            error.close()
        except (URLError, TimeoutError, OSError, ValueError) as error:
            print(f"تعذّر قراءة الملف: {error}")
            continue

        print(f"حالة HTTP: {status}")
        if status != 200:
            print("الملف غير متاح أو لم يرجع استجابة ناجحة.")
            continue

        important_lines = []
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or ":" not in stripped:
                continue
            field = stripped.split(":", 1)[0].strip().lower()
            if field in relevant_fields:
                important_lines.append(stripped)

        if important_lines:
            for line in important_lines:
                print(f"- {line}")
        else:
            print("لم يتم العثور على سطور مهمة معروفة في الملف.")


def lookup_ip_info(target=None):
    """Resolve a hostname if needed and query ip-api.com for public IP details."""
    raw_target = (target if target is not None else input("اكتب اسم موقع أو عنوان IP: ")).strip()
    if not raw_target:
        print("لازم تدخل اسم موقع أو عنوان IP.")
        return

    try:
        address = str(ipaddress.ip_address(raw_target.strip("[]")))
        hostname = None
    except ValueError:
        parsed = urlparse(raw_target if "://" in raw_target else "//" + raw_target)
        hostname = parsed.hostname
        if not hostname:
            print("اسم الموقع أو عنوان IP غير صحيح.")
            return
        try:
            records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            addresses = sorted(
                {record[4][0] for record in records},
                key=lambda item: (ipaddress.ip_address(item).version != 4, item),
            )
            address = addresses[0]
        except (socket.gaierror, ValueError, IndexError) as error:
            print(f"تعذّر تحويل اسم الموقع إلى عنوان IP: {error}")
            return

    fields = "status,message,query,country,city,isp,org"
    api_url = (
        f"http://ip-api.com/json/{quote(address, safe=':')}?"
        f"{urlencode({'fields': fields, 'lang': 'en'})}"
    )
    request = Request(api_url, headers={"User-Agent": "CyberToolkit/1.0"})
    try:
        with urlopen(request, timeout=10) as response:
            data = json.loads(response.read(128_000).decode("utf-8", errors="replace"))
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"تعذّر الاستعلام من خدمة معلومات IP: {error}")
        return

    if data.get("status") != "success":
        print(f"الخدمة لم تستطع تحديد معلومات العنوان: {data.get('message', 'سبب غير معروف')}")
        return

    print(f"الهدف: {raw_target}")
    if hostname:
        print(f"عنوان IP الذي تم اختياره: {data.get('query', address)}")
    else:
        print(f"عنوان IP: {data.get('query', address)}")
    print(f"الدولة: {data.get('country') or 'غير متاحة'}")
    print(f"المدينة: {data.get('city') or 'غير متاحة'}")
    print(f"مزود الخدمة (ISP): {data.get('isp') or 'غير متاح'}")
    print(f"الجهة/الشركة (Org): {data.get('org') or 'غير متاحة'}")
    print("ملاحظة: تحديد الموقع الجغرافي تقريبي وقد يشير إلى موقع مزود الخدمة.")
    print("تنبيه اتصال: الواجهة المجانية من ip-api.com تستخدم HTTP غير مشفر.")


def run_and_save_report(title, function):
    """Run a scan, show its output, and append it to report.txt."""
    output = StringIO()
    console = sys.stdout
    original_input = builtins.input

    def visible_input(prompt=""):
        print(prompt, end="", file=console, flush=True)
        return original_input()

    builtins.input = visible_input
    try:
        with redirect_stdout(output):
            function()
    finally:
        builtins.input = original_input
    result = output.getvalue()
    print(result, end="")

    timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    report_entry = f"\n{'=' * 60}\n{title} | {timestamp}\n{'=' * 60}\n{result}"
    try:
        report_path = Path(__file__).resolve().with_name("report.txt")
        with report_path.open("a", encoding="utf-8") as report:
            report.write(report_entry)
            if not result.endswith("\n"):
                report.write("\n")
        print("\nتم حفظ نتيجة الفحص في report.txt")
    except OSError as error:
        print(f"تعذّر حفظ التقرير: {error}")


def export_html_report():
    """Convert report.txt into a standalone, dark-themed HTML report."""
    folder = Path(__file__).resolve().parent
    source_path = folder / "report.txt"
    output_path = folder / "report.html"

    try:
        report_text = source_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print("ملف report.txt مش موجود لسه. شغّل فحصًا الأول عشان يتسجل تقرير.")
        return
    except OSError as error:
        print(f"تعذّر قراءة report.txt: {error}")
        return

    if not report_text.strip():
        print("ملف report.txt فاضي؛ مفيش نتائج للتصدير.")
        return

    blocks = [
        block.strip()
        for block in re.split(r"\n={10,}\s*\n", report_text)
        if block.strip()
    ]
    sections = []
    for index in range(0, len(blocks), 2):
        heading = blocks[index].splitlines()[0].strip() or "نتائج الفحص"
        content = blocks[index + 1] if index + 1 < len(blocks) else ""
        rows = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            normalized = line.lstrip("- ").strip()
            if ": " in normalized:
                label, value = normalized.split(": ", 1)
                rows.append((label, value))
            else:
                rows.append(("النتيجة", line))

        table_rows = "\n".join(
            f"<tr><th>{html.escape(label)}</th><td>{html.escape(value)}</td></tr>"
            for label, value in rows
        )
        sections.append(
            f'<section class="report-card"><h2>{html.escape(heading)}</h2>'
            f"<table><tbody>{table_rows}</tbody></table></section>"
        )

    generated_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    document = f"""<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>تقرير Cyber Toolkit</title>
  <style>
    :root {{ color-scheme: dark; --bg:#0b1120; --panel:#131d2e; --line:#26364d; --text:#e7eef8; --muted:#9aabc2; --accent:#62d6c5; --header:#1a2940; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:radial-gradient(ellipse at top,#172a40 0,#0b1120 55%); color:var(--text); font-family:"Segoe UI",Tahoma,Arial,sans-serif; line-height:1.7; }}
    main {{ width:min(100% - 32px,1000px); margin:48px auto; }}
    .hero {{ padding:28px 32px; border:1px solid var(--line); border-radius:20px; background:linear-gradient(135deg,#17263b,#101a2a); box-shadow:0 18px 50px #0005; }}
    .eyebrow {{ color:var(--accent); font-size:.85rem; font-weight:700; letter-spacing:.08em; }}
    h1 {{ margin:4px 0; font-size:clamp(1.8rem,4vw,2.6rem); }}
    .meta {{ color:var(--muted); margin:0; }}
    .report-card {{ margin-top:22px; overflow:hidden; border:1px solid var(--line); border-radius:16px; background:var(--panel); box-shadow:0 12px 32px #0003; }}
    h2 {{ margin:0; padding:16px 20px; background:var(--header); color:var(--accent); font-size:1.1rem; overflow-wrap:anywhere; }}
    table {{ width:100%; border-collapse:collapse; }}
    th,td {{ padding:12px 18px; border-top:1px solid var(--line); text-align:right; vertical-align:top; overflow-wrap:anywhere; }}
    th {{ width:30%; color:#b7c7dc; font-weight:600; }} td {{ color:var(--text); }}
    tr:nth-child(even) {{ background:#ffffff05; }}
    footer {{ margin:28px 0; color:var(--muted); text-align:center; font-size:.9rem; }}
    @media(max-width:600px) {{ main {{ width:min(100% - 20px,1000px); margin:20px auto; }} .hero {{ padding:22px; }} th,td {{ padding:10px; }} th {{ width:36%; }} }}
  </style>
</head>
<body><main>
  <header class="hero"><div class="eyebrow">CYBER TOOLKIT</div><h1>تقرير نتائج الفحوصات</h1><p class="meta">تاريخ إنشاء الصفحة: {html.escape(generated_at)}</p></header>
  {''.join(sections)}
  <footer>تم إنشاء هذا التقرير محليًا من report.txt</footer>
</main></body>
</html>
"""

    try:
        output_path.write_text(document, encoding="utf-8")
        print(f"تم تصدير التقرير بنجاح إلى: {output_path}")
    except OSError as error:
        print(f"تعذّر حفظ report.html: {error}")


def main():
    while True:
        print("\n=== Cyber Toolkit ===")
        print("1- فحص المنافذ (21، 22، 80، 443)")
        print("2- استخراج روابط ونماذج الموقع")
        print("3- فحص إعدادات الأمان (Headers)")
        print("4- اكتشاف تقنيات الموقع")
        print("5- فحص المسارات والملفات المهمة")
        print("6- تصدير التقرير كصفحة HTML احترافية")
        print("7- اكتشاف النطاقات الفرعية (Subdomains)")
        print("8- فحص شهادة الأمان (SSL Certificate)")
        print("9- فحص شامل تلقائي (Full Recon)")
        print("10- فحص مبدئي لأمان الروابط والمدخلات (للمواقع التدريبية)")
        print("11- كشف هوية السيرفر والموقع الجغرافي (IP Info)")
        print("12- قراءة ملفات robots.txt و security.txt")
        print("0- خروج")
        choice = input("اختار رقم: ").strip()

        if choice == "1":
            run_and_save_report("فحص المنافذ", scan_ports)
        elif choice == "2":
            run_and_save_report("استخراج الروابط والنماذج", extract_links_and_forms)
        elif choice == "3":
            run_and_save_report("فحص ترويسات الأمان", check_security_headers)
        elif choice == "4":
            run_and_save_report("اكتشاف تقنيات الموقع", detect_technologies)
        elif choice == "5":
            run_and_save_report("فحص المسارات والملفات المهمة", check_important_paths)
        elif choice == "6":
            export_html_report()
        elif choice == "7":
            run_and_save_report("اكتشاف النطاقات الفرعية", discover_subdomains)
        elif choice == "8":
            run_and_save_report("فحص شهادة الأمان SSL", inspect_ssl_certificate)
        elif choice == "9":
            run_and_save_report("فحص شامل تلقائي (Full Recon)", full_recon)
            export_html_report()
            print("اكتمل الفحص الشامل وتم تصدير التقرير إلى report.html.")
        elif choice == "10":
            run_and_save_report("فحص مبدئي لأمان الروابط والمدخلات", check_input_safety)
        elif choice == "11":
            run_and_save_report("كشف هوية السيرفر والموقع الجغرافي (IP Info)", lookup_ip_info)
        elif choice == "12":
            run_and_save_report("قراءة ملفات robots.txt و security.txt", read_site_policy_files)
        elif choice == "0":
            print("مع السلامة!")
            break
        else:
            print("اختيار غير صحيح. اختار رقمًا من 0 إلى 12.")


if __name__ == "__main__":
    main()
