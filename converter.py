import json
import os
import sys
import urllib.request
import base64
import re
from urllib.parse import urlparse, parse_qs, unquote

# ===========================================================================
# 1. Base64 helpers with validation
# ===========================================================================
def is_base64(s: str) -> bool:
    """بررسی می‌کند که آیا رشته یک Base64 معتبر است یا خیر"""
    s = re.sub(r'\s+', '', s)
    # طول باید مضرب ۴ باشد
    if len(s) % 4 != 0:
        return False
    # کاراکترهای مجاز Base64: A-Z a-z 0-9 + / =
    if not re.match(r'^[A-Za-z0-9+/=]+$', s):
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False

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
    except Exception as e:
        print(f"⚠️ خطا در parse_vless: {e}")
        return None

# سایر پارسرها (vmess, trojan, ss, ssr, hysteria, hysteria2, http, socks5) مشابه قبل ...
# برای جلوگیری از طولانی شدن کد، فقط parse_vless را اینجا گذاشته‌ام.
# در فایل کامل تمام پارسرها وجود دارند.

# ===========================================================================
# 3. Parse multiple lines (links) with deduplication
# ===========================================================================
def parse_multiple_proxies(text: str):
    lines = text.splitlines()
    proxies = []
    unsupported = []
    seen = set()
    default_names = {'SS', 'SSR', 'Vmess', 'Trojan', 'Hysteria', 'Hysteria2', 'VLESS', 'HTTP', 'SOCKS5'}
    default_counter = 0

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        res = parse_proxy_link(line)
        if res:
            config = res['config']
            name = config['name']
            if name in default_names:
                default_counter += 1
                config['name'] = f"defaultName_{default_counter}"
            base_name = config['name']
            if base_name in seen:
                dup_counter = 1
                while f"{base_name}_{dup_counter}" in seen:
                    dup_counter += 1
                config['name'] = f"{base_name}_{dup_counter}"
            seen.add(config['name'])
            proxies.append(config)
        else:
            if '://' in line:
                proto = line.split('://')[0].strip()
                if proto and proto.isalpha() and proto not in ['vless', 'vmess', 'trojan', 'ss', 'ssr', 'hysteria', 'hysteria2', 'http', 'https', 'socks', 'socks5']:
                    unsupported.append(proto)
    return proxies, unsupported

# ===========================================================================
# 4. Parse Sing-box JSON (مشابه قبل)
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
            'shadowsocks': 'ss',
            'vmess': 'vmess',
            'vless': 'vless',
            'trojan': 'trojan',
            'hysteria': 'hysteria',
            'hysteria2': 'hysteria2',
            'http': 'http',
            'socks': 'socks5'
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
    base = {
        'name': ob.get('tag', ob.get('name', 'unnamed')),
        'type': internal_type,
        'server': ob.get('server', ''),
        'port': ob.get('server_port', ob.get('port', 0))
    }
    if not base['server'] or base['port'] == 0:
        return None

    if internal_type == 'ss':
        base.update({
            'cipher': ob.get('method', 'aes-128-gcm'),
            'password': ob.get('password', '')
        })
    elif internal_type == 'vmess':
        base.update({
            'uuid': ob.get('uuid', ''),
            'alterId': ob.get('alter_id', 0),
            'cipher': ob.get('security', 'auto'),
            'network': 'tcp'
        })
        if ob.get('transport', {}).get('type') == 'ws':
            base['network'] = 'ws'
            if ob['transport'].get('path'):
                base['ws-opts'] = {'path': ob['transport']['path']}
                if ob['transport'].get('headers'):
                    base['ws-opts']['headers'] = ob['transport']['headers']
        if ob.get('transport', {}).get('type') == 'grpc':
            base['network'] = 'grpc'
            base['grpc-opts'] = {'grpc-service-name': ob['transport'].get('service_name', '')}
        if ob.get('tls'):
            base['tls'] = ob['tls'].get('enabled', False)
            if ob['tls'].get('server_name'):
                base['servername'] = ob['tls']['server_name']
            if ob['tls'].get('insecure') is not None:
                base['skip-cert-verify'] = ob['tls']['insecure']
    elif internal_type == 'vless':
        base.update({
            'uuid': ob.get('uuid', ''),
            'network': 'tcp'
        })
        if ob.get('flow'):
            base['flow'] = ob['flow']
        tls = ob.get('tls')
        if tls and (tls.get('enabled') or tls.get('servername')):
            base['tls'] = True
            if tls.get('server_name'):
                base['servername'] = tls['server_name']
            if tls.get('insecure') is not None:
                base['skip-cert-verify'] = tls['insecure']
            if tls.get('reality', {}).get('enabled'):
                reality = tls['reality']
                base['reality-opts'] = {
                    'public-key': reality.get('public_key', ''),
                    'short-id': reality.get('short_id', '')
                }
        if ob.get('transport', {}).get('type') == 'ws':
            base['network'] = 'ws'
            base['ws-opts'] = {
                'path': ob['transport'].get('path', '/'),
                'headers': ob['transport'].get('headers')
            }
        elif ob.get('transport', {}).get('type') == 'grpc':
            base['network'] = 'grpc'
            base['grpc-opts'] = {
                'grpc-service-name': ob['transport'].get('service_name', '')
            }
    elif internal_type == 'trojan':
        base.update({
            'password': ob.get('password', ''),
            'network': 'tcp',
            'tls': True
        })
        if ob.get('tls'):
            if ob['tls'].get('insecure') is not None:
                base['skip-cert-verify'] = ob['tls']['insecure']
            if ob['tls'].get('server_name'):
                base['sni'] = ob['tls']['server_name']
        if ob.get('transport', {}).get('type') == 'ws':
            base['network'] = 'ws'
            base['ws-opts'] = {
                'path': ob['transport'].get('path', '/'),
                'headers': ob['transport'].get('headers')
            }
    elif internal_type == 'hysteria':
        base.update({
            'auth_str': ob.get('auth', ob.get('auth_str', '')),
            'protocol': ob.get('protocol', 'udp'),
            'up': int(ob.get('up_mbps', 10)),
            'down': int(ob.get('down_mbps', 50)),
            'sni': ob.get('server_name', ob.get('sni', '')),
            'skip-cert-verify': ob.get('tls', {}).get('insecure', False)
        })
    elif internal_type == 'hysteria2':
        base.update({
            'password': ob.get('password', ''),
            'skip-cert-verify': ob.get('tls', {}).get('insecure', False),
            'sni': ob.get('tls', {}).get('server_name', ob.get('server_name', '')),
            'obfs': ob.get('obfs', {}).get('type', ''),
            'obfs-password': ob.get('obfs', {}).get('password', '')
        })
    elif internal_type in ('http', 'socks5'):
        users = ob.get('users', [])
        if users:
            base['username'] = users[0].get('username', '')
            base['password'] = users[0].get('password', '')
        else:
            base['username'] = ''
            base['password'] = ''
    return base

# ===========================================================================
# 5. Detect format
# ===========================================================================
def detect_format(text: str):
    text = text.strip()
    if not text:
        return 'links'
    if text.startswith('{') or text.startswith('['):
        try:
            json.loads(text)
            return 'singbox'
        except:
            pass
    if re.search(r'^\s*(proxies\s*:|port\s*:|mixed-port\s*:)', text, re.MULTILINE):
        return 'clash'
    if 'proxies:' in text and 'proxy-groups:' in text:
        return 'clash'
    if re.search(r'(vless|vmess|trojan|ss|ssr|hysteria)://', text):
        return 'links'
    return 'links'

# ===========================================================================
# 6. Adapters for Sing-box generation (همانند قبل)
# ===========================================================================
# ... (Adapters را از کد قبلی کپی کنید)

# ===========================================================================
# 7. Generate Sing-box JSON (همانند قبل)
# ===========================================================================
# ... (تابع generate_singbox_config را از کد قبلی کپی کنید)

# ===========================================================================
# 8. Fetch subscription with smart Base64 detection
# ===========================================================================
def fetch_subscription(sub_link):
    try:
        req = urllib.request.Request(sub_link, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode('utf-8-sig').strip()
            if not raw:
                raise ValueError("پاسخ خالی است")
            
            print(f"📄 محتوای دریافتی (۲۰۰ کاراکتر اول):\n{raw[:200]}...")

            # فقط اگر محتوا Base64 باشد، decode می‌کنیم
            if is_base64(raw):
                decoded = base64_decode(raw)
                if decoded and ('://' in decoded or '{' in decoded or 'proxies:' in decoded):
                    print("🔓 Base64 decode موفقیت‌آمیز بود")
                    raw = decoded
                    print(f"📄 محتوای پس از decode (۲۰۰ کاراکتر):\n{raw[:200]}...")
                else:
                    print("⚠️ Base64 decode نتیجه معقولی نداشت، از محتوای اصلی استفاده می‌شود.")
            else:
                print("ℹ️ محتوای ورودی Base64 نیست، بدون تغییر استفاده می‌شود.")

            return raw
    except Exception as e:
        raise Exception(f"خطا در دریافت: {e}")

# ===========================================================================
# 9. Main
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

    fmt = detect_format(content)
    print(f"🔍 فرمت تشخیص داده شده: {fmt}")

    proxies = []
    unsupported = []

    if fmt == 'links':
        proxies, unsupported = parse_multiple_proxies(content)
    elif fmt == 'singbox':
        proxies, unsupported = parse_singbox(content)
    elif fmt == 'clash':
        try:
            import yaml
            data = yaml.safe_load(content)
            if data and isinstance(data, dict):
                raw_proxies = data.get('proxies', [])
                for p in raw_proxies:
                    typ = p.get('type')
                    if typ in ('vless', 'vmess', 'trojan', 'ss', 'ssr', 'hysteria', 'hysteria2', 'http', 'socks5'):
                        proxies.append({
                            'name': p.get('name', 'ClashProxy'),
                            'type': typ,
                            'server': p.get('server', ''),
                            'port': p.get('port', 0),
                            **{k: v for k, v in p.items() if k not in ['name', 'type', 'server', 'port']}
                        })
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

    singbox_json = generate_singbox_config(proxies, mode='tun')

    with open("javidbox", "w", encoding="utf-8") as f:
        f.write(singbox_json)

    print("✅ فایل javidbox با موفقیت تولید شد.")

if __name__ == "__main__":
    main()
