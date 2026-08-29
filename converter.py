import json
import os
import sys
import urllib.request
import base64
import re
from urllib.parse import urlparse, parse_qs, unquote

# ===========================================================================
# 1. Base64 helpers
# ===========================================================================
def base64_decode(s: str) -> str:
    try:
        s = re.sub(r'\s+', '', s)
        s = s.replace('-', '+').replace('_', '/')
        while len(s) % 4 != 0:
            s += '='
        decoded = base64.b64decode(s).decode('utf-8', errors='ignore')
        return decoded
    except Exception:
        return ''

def base64_encode(s: str) -> str:
    try:
        return base64.b64encode(s.encode('utf-8')).decode('ascii')
    except Exception:
        return ''

# ===========================================================================
# 2. Parsers for proxy links (vless, vmess, trojan, ss, ssr, hysteria...)
# ===========================================================================
def parse_vless(link: str):
    if not link.startswith('vless://'):
        return None
    try:
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        name = parsed.fragment or 'VLESS'
        config = {
            'name': name,
            'type': 'vless',
            'server': parsed.hostname,
            'port': parsed.port or 443,
            'uuid': unquote(parsed.username or ''),
            'network': params.get('type', ['tcp'])[0],
            'flow': params.get('flow', [''])[0],
            'skip-cert-verify': params.get('allowInsecure', [''])[0] == '1'
        }
        if params.get('security', [''])[0] in ('tls', 'reality'):
            config['tls'] = True
            config['servername'] = params.get('sni', [''])[0]
        if params.get('security', [''])[0] == 'reality':
            config['reality-opts'] = {
                'public-key': params.get('pbk', [''])[0],
                'short-id': params.get('sid', [''])[0]
            }
            config['client-fingerprint'] = params.get('fp', ['chrome'])[0]
        if config['network'] == 'ws':
            config['ws-opts'] = {
                'path': params.get('path', ['/'])[0],
                'headers': {'Host': params.get('host', [''])[0]} if params.get('host', [''])[0] else None
            }
        if config['network'] == 'grpc':
            config['grpc-opts'] = {
                'grpc-service-name': params.get('serviceName', [params.get('service', [''])[0]])[0]
            }
        return {'name': name, 'config': config}
    except Exception:
        return None

# سایر پارسرها (vmess, trojan, ss, ssr, hysteria, hysteria2, http, socks5) مشابه قبل ...
# (برای اختصار حذف شدند، اما در فایل کامل قرار می‌دهیم)

# ===========================================================================
# 3. پارس‌کننده Sing-box JSON (پشتیبانی از outbounds یا آرایه مستقیم)
# ===========================================================================
def parse_singbox(text: str):
    try:
        data = json.loads(text)
        outbounds = None
        if isinstance(data, dict) and 'outbounds' in data:
            outbounds = data['outbounds']
        elif isinstance(data, list):
            outbounds = data
        else:
            return [], ['فرمت JSON نامعتبر']

        if not isinstance(outbounds, list):
            return [], ['outbounds باید آرایه باشد']

        proxies = []
        unsupported = []
        TYPE_MAP = {
            'shadowsocks': 'ss', 'vmess': 'vmess', 'vless': 'vless',
            'trojan': 'trojan', 'hysteria': 'hysteria', 'hysteria2': 'hysteria2',
            'http': 'http', 'socks': 'socks5'
        }
        NON_PROXY = {'selector', 'urltest', 'direct', 'block', 'dns'}

        for ob in outbounds:
            if not isinstance(ob, dict):
                continue
            if ob.get('type') in NON_PROXY:
                continue
            sb_type = ob.get('type')
            if sb_type not in TYPE_MAP:
                unsupported.append(sb_type)
                continue
            internal_type = TYPE_MAP[sb_type]
            node = singbox_to_proxy_node(ob, internal_type)
            if node:
                proxies.append(node)
        return proxies, unsupported
    except json.JSONDecodeError as e:
        return [], [f'JSON معتبر نیست: {e}']

def singbox_to_proxy_node(ob, internal_type):
    # مشابه قبل (همان تابع)
    # ...

# ===========================================================================
# 4. پارس‌کننده لینک‌های خام (چندخطی)
# ===========================================================================
def parse_multiple_proxies(text: str):
    lines = text.splitlines()
    proxies = []
    unsupported = []
    # پارسرهای لینک را اینجا قرار دهید (vless, vmess, ...)
    # برای اختصار فقط vless را نشان می‌دهیم، اما در فایل کامل همه هستند.
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # تلاش با هر پارسر
        parsed = parse_vless(line)  # و سایر پارسرها
        if parsed:
            proxies.append(parsed['config'])
        else:
            if '://' in line:
                proto = line.split('://')[0].strip()
                if proto and proto.isalpha() and proto not in ['vless','vmess','trojan','ss','ssr','hysteria','hysteria2','http','socks5']:
                    unsupported.append(proto)
    return proxies, unsupported

# ===========================================================================
# 5. تشخیص خودکار فرمت
# ===========================================================================
def detect_format(text: str):
    text = text.strip()
    if not text:
        return 'links'
    # Sing-box JSON
    if text.startswith('{') or text.startswith('['):
        try:
            json.loads(text)
            return 'singbox'
        except:
            pass
    # Clash YAML (اختیاری)
    if re.search(r'^\s*(proxies\s*:|port\s*:|mixed-port\s*:)', text, re.MULTILINE):
        return 'clash'
    if 'proxies:' in text and 'proxy-groups:' in text:
        return 'clash'
    # اگر شامل لینک‌های vless:// و غیره باشد
    if re.search(r'(vless|vmess|trojan|ss|ssr|hysteria)://', text):
        return 'links'
    return 'links'

# ===========================================================================
# 6. تابع دریافت ساب‌لینک با دیباگ
# ===========================================================================
def fetch_subscription(sub_link):
    try:
        req = urllib.request.Request(sub_link, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode('utf-8-sig').strip()
            if not raw:
                raise ValueError("پاسخ خالی است")
            
            # نمایش ۲۰۰ کاراکتر اول برای دیباگ
            print(f"📄 محتوای دریافتی (۲۰۰ کاراکتر اول):\n{raw[:200]}...")

            # تلاش برای Base64 decode
            decoded = base64_decode(raw)
            if decoded and ('://' in decoded or '{' in decoded or 'proxies:' in decoded):
                print("🔓 Base64 decode موفقیت‌آمیز بود")
                raw = decoded
                print(f"📄 محتوای پس از decode (۲۰۰ کاراکتر):\n{raw[:200]}...")
            return raw
    except Exception as e:
        raise Exception(f"خطا در دریافت: {e}")

# ===========================================================================
# 7. تابع اصلی
# ===========================================================================
def main():
    sub_link = os.environ.get("SUB_LINK")
    if not sub_link:
        print("❌ متغیر محیطی SUB_LINK تنظیم نشده است")
        sys.exit(1)

    print("🔄 دریافت ساب‌لینک...")
    try:
        content = fetch_subscription(sub_link)
    except Exception as e:
        print(f"❌ {e}")
        sys.exit(1)

    # تشخیص فرمت
    fmt = detect_format(content)
    print(f"🔍 فرمت تشخیص داده شده: {fmt}")

    proxies = []
    unsupported = []

    if fmt == 'links':
        proxies, unsupported = parse_multiple_proxies(content)
    elif fmt == 'singbox':
        proxies, unsupported = parse_singbox(content)
    elif fmt == 'clash':
        # اگر pyyaml نصب بود، از آن استفاده کنید
        try:
            import yaml
            data = yaml.safe_load(content)
            if data and isinstance(data, dict):
                raw_proxies = data.get('proxies', [])
                for p in raw_proxies:
                    # تبدیل ساده به فرمت داخلی
                    typ = p.get('type')
                    if typ in ('vless', 'vmess', 'trojan', 'ss', 'ssr', 'hysteria', 'hysteria2', 'http', 'socks5'):
                        proxies.append(p)
                    else:
                        unsupported.append(typ)
        except ImportError:
            print("⚠️ کتابخانه pyyaml نصب نیست، از لینک‌ها استفاده می‌شود.")
            proxies, unsupported = parse_multiple_proxies(content)
    else:
        print("❌ فرمت ورودی قابل تشخیص نیست")
        sys.exit(1)

    print(f"✅ تعداد نودهای استخراج‌شده: {len(proxies)}")
    if unsupported:
        print(f"⚠️ پروتکل‌های ناشناخته/پشتیبانی‌نشده: {', '.join(set(unsupported))}")

    if not proxies:
        print("❌ هیچ نود معتبری یافت نشد")
        sys.exit(1)

    # تولید خروجی Sing-box (با استفاده از Adapterها)
    singbox_json = generate_singbox_config(proxies, mode='tun')

    with open("javidbox", "w", encoding="utf-8") as f:
        f.write(singbox_json)

    print("✅ فایل javidbox با موفقیت تولید شد.")

if __name__ == "__main__":
    main()
