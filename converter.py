#!/usr/bin/env python3
"""
Javidbox - Subscription to Sing-Box Config Converter
تبدیل لینک اشتراک به کانفیگ Sing-Box با ساختار مشخص
"""

import os
import sys
import base64
import json
import urllib.parse
import re
from typing import Dict, List, Any, Optional

# ==============================
# پارسرهای پروتکل‌ها
# ==============================

def parse_vless(uri: str) -> Optional[Dict[str, Any]]:
    """پارس URI با پروتکل vless"""
    if not uri.startswith('vless://'):
        return None
    # حذف پروتکل
    uri = uri[8:]
    # جدا کردن بخش remark (بعد از #)
    if '#' in uri:
        uri, remark = uri.split('#', 1)
        remark = urllib.parse.unquote(remark)
    else:
        remark = ''
    # جدا کردن userinfo و host/port و params
    if '@' not in uri:
        return None
    userinfo, rest = uri.split('@', 1)
    # rest شامل host:port?params
    if '?' in rest:
        host_port, params_str = rest.split('?', 1)
        params = urllib.parse.parse_qs(params_str)
        # params values are lists, take first
        params = {k: v[0] for k, v in params.items()}
    else:
        host_port = rest
        params = {}
    if ':' not in host_port:
        return None
    server, port_str = host_port.split(':', 1)
    try:
        port = int(port_str)
    except ValueError:
        port = 443

    uuid = userinfo
    # استخراج پارامترها
    security = params.get('security', '')
    sni = params.get('sni', '')
    host = params.get('host', '')
    path = params.get('path', '/')
    type_ = params.get('type', 'ws')  # معمولاً ws

    # ساخت outbound
    outbound = {
        "tag": remark if remark else f"{server}_{port}",
        "type": "vless",
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "transport": {
            "type": type_,
            "path": path,
            "headers": {
                "Host": host or server
            }
        },
        "domain_resolver": "dns-direct"
    }

    # اگر TLS فعال باشد
    if security and security.lower() in ['tls', 'reality']:
        outbound["tls"] = {
            "enabled": True,
            "server_name": sni or host or server,
            "utls": {
                "enabled": True,
                "fingerprint": "chrome"
            }
        }
    return outbound


def parse_vmess(uri: str) -> Optional[Dict[str, Any]]:
    """پارس URI با پروتکل vmess (base64 json)"""
    if not uri.startswith('vmess://'):
        return None
    b64 = uri[8:]
    # ممکن است padding نیاز داشته باشد
    b64 += '=' * (4 - len(b64) % 4)
    try:
        data = json.loads(base64.b64decode(b64).decode('utf-8'))
    except Exception:
        return None
    # ساخت outbound
    outbound = {
        "tag": data.get('ps', f"{data.get('add', '')}_{data.get('port', 0)}"),
        "type": "vmess",
        "server": data.get('add', ''),
        "server_port": int(data.get('port', 0)),
        "uuid": data.get('id', ''),
        "security": data.get('scy', 'auto'),
        "transport": {
            "type": data.get('net', 'tcp'),
            "path": data.get('path', '/'),
            "headers": {
                "Host": data.get('host', '')
            }
        },
        "domain_resolver": "dns-direct"
    }
    # TLS
    if data.get('tls', '') == 'tls':
        outbound["tls"] = {
            "enabled": True,
            "server_name": data.get('sni', ''),
            "utls": {
                "enabled": True,
                "fingerprint": "chrome"
            }
        }
    return outbound


def parse_ss(uri: str) -> Optional[Dict[str, Any]]:
    """پارس URI با پروتکل Shadowsocks"""
    if not uri.startswith('ss://'):
        return None
    # فرمت‌های مختلف: ss://base64@server:port#remark  یا ss://base64?params#remark
    # ساده‌ترین: ss://method:password@server:port#remark
    # برخی از uri ها کل قسمت بعد از ss:// را base64 می‌کنند.
    # برای سادگی، فقط فرمت ساده را پشتیبانی می‌کنیم.
    uri = uri[5:]
    if '#' in uri:
        uri, remark = uri.split('#', 1)
        remark = urllib.parse.unquote(remark)
    else:
        remark = ''
    if '@' not in uri:
        return None
    userinfo, host_port = uri.split('@', 1)
    # userinfo ممکن است base64 باشد یا plain
    try:
        # decode base64
        decoded = base64.b64decode(userinfo + '=' * (4 - len(userinfo) % 4)).decode('utf-8')
        method, password = decoded.split(':', 1)
    except Exception:
        # فرض می‌کنیم plain است
        if ':' not in userinfo:
            return None
        method, password = userinfo.split(':', 1)
    if ':' not in host_port:
        return None
    server, port_str = host_port.split(':', 1)
    try:
        port = int(port_str)
    except ValueError:
        port = 1080

    outbound = {
        "tag": remark if remark else f"{server}_{port}",
        "type": "shadowsocks",
        "server": server,
        "server_port": port,
        "method": method,
        "password": password,
        "domain_resolver": "dns-direct"
    }
    return outbound


def parse_trojan(uri: str) -> Optional[Dict[str, Any]]:
    """پارس URI با پروتکل Trojan"""
    if not uri.startswith('trojan://'):
        return None
    uri = uri[9:]
    if '#' in uri:
        uri, remark = uri.split('#', 1)
        remark = urllib.parse.unquote(remark)
    else:
        remark = ''
    if '@' not in uri:
        return None
    userinfo, rest = uri.split('@', 1)
    if '?' in rest:
        host_port, params_str = rest.split('?', 1)
        params = urllib.parse.parse_qs(params_str)
        params = {k: v[0] for k, v in params.items()}
    else:
        host_port = rest
        params = {}
    if ':' not in host_port:
        return None
    server, port_str = host_port.split(':', 1)
    try:
        port = int(port_str)
    except ValueError:
        port = 443
    password = userinfo
    sni = params.get('sni', '')
    host = params.get('host', '')

    outbound = {
        "tag": remark if remark else f"{server}_{port}",
        "type": "trojan",
        "server": server,
        "server_port": port,
        "password": password,
        "tls": {
            "enabled": True,
            "server_name": sni or host or server,
            "utls": {
                "enabled": True,
                "fingerprint": "chrome"
            }
        },
        "transport": {
            "type": "ws",
            "path": params.get('path', '/'),
            "headers": {
                "Host": host or server
            }
        },
        "domain_resolver": "dns-direct"
    }
    return outbound


def parse_hysteria2(uri: str) -> Optional[Dict[str, Any]]:
    """پارس URI با پروتکل Hysteria2"""
    if not uri.startswith('hysteria2://'):
        return None
    # مشابه vless
    uri = uri[11:]
    if '#' in uri:
        uri, remark = uri.split('#', 1)
        remark = urllib.parse.unquote(remark)
    else:
        remark = ''
    if '@' not in uri:
        return None
    userinfo, rest = uri.split('@', 1)
    if '?' in rest:
        host_port, params_str = rest.split('?', 1)
        params = urllib.parse.parse_qs(params_str)
        params = {k: v[0] for k, v in params.items()}
    else:
        host_port = rest
        params = {}
    if ':' not in host_port:
        return None
    server, port_str = host_port.split(':', 1)
    try:
        port = int(port_str)
    except ValueError:
        port = 443
    auth = userinfo  # معمولاً به شکل "" یا base64

    outbound = {
        "tag": remark if remark else f"{server}_{port}",
        "type": "hysteria2",
        "server": server,
        "server_port": port,
        "password": auth,
        "tls": {
            "enabled": True,
            "server_name": params.get('sni', server),
            "utls": {
                "enabled": True,
                "fingerprint": "chrome"
            }
        },
        "transport": {
            "type": "udp"
        },
        "domain_resolver": "dns-direct"
    }
    return outbound


def parse_tuic(uri: str) -> Optional[Dict[str, Any]]:
    """پارس URI با پروتکل TUIC"""
    if not uri.startswith('tuic://'):
        return None
    uri = uri[7:]
    if '#' in uri:
        uri, remark = uri.split('#', 1)
        remark = urllib.parse.unquote(remark)
    else:
        remark = ''
    if '@' not in uri:
        return None
    userinfo, rest = uri.split('@', 1)
    if '?' in rest:
        host_port, params_str = rest.split('?', 1)
        params = urllib.parse.parse_qs(params_str)
        params = {k: v[0] for k, v in params.items()}
    else:
        host_port = rest
        params = {}
    if ':' not in host_port:
        return None
    server, port_str = host_port.split(':', 1)
    try:
        port = int(port_str)
    except ValueError:
        port = 443
    uuid = userinfo

    outbound = {
        "tag": remark if remark else f"{server}_{port}",
        "type": "tuic",
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "tls": {
            "enabled": True,
            "server_name": params.get('sni', server),
            "utls": {
                "enabled": True,
                "fingerprint": "chrome"
            }
        },
        "domain_resolver": "dns-direct"
    }
    return outbound


# ==============================
# تابع اصلی پردازش
# ==============================

PARSERS = [
    parse_vless,
    parse_vmess,
    parse_ss,
    parse_trojan,
    parse_hysteria2,
    parse_tuic,
]

def parse_subscription(content: str) -> List[Dict[str, Any]]:
    """دریافت محتوای دیکود شده اشتراک و استخراج گره‌ها"""
    outbounds = []
    lines = content.strip().splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parsed = None
        for parser in PARSERS:
            parsed = parser(line)
            if parsed:
                break
        if parsed:
            outbounds.append(parsed)
    return outbounds


def build_config(outbounds: List[Dict[str, Any]]) -> Dict[str, Any]:
    """ساختار نهایی کانفیگ با بخش‌های ثابت"""
    # لیست تگ‌های همه گره‌ها
    tags = [ob['tag'] for ob in outbounds]

    # ساختار ثابت
    config = {
        "log": {
            "disabled": False,
            "level": "warn",
            "timestamp": True
        },
        "dns": {
            "servers": [
                {
                    "type": "https",
                    "tag": "dns-remote",
                    "server": "8.8.8.8",
                    "detour": "✅  Select"
                },
                {
                    "type": "udp",
                    "tag": "dns-direct",
                    "server": "8.8.8.8"
                }
            ],
            "rules": [
                {
                    "clash_mode": "Direct",
                    "server": "dns-direct"
                },
                {
                    "clash_mode": "Global",
                    "server": "dns-remote"
                }
            ],
            "strategy": "prefer_ipv4"
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "address": ["172.19.0.1/28"],
                "mtu": 9000,
                "auto_route": True,
                "strict_route": True,
                "stack": "mixed"
            },
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2334
            },
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": 2333
            }
        ],
        "outbounds": [
            {
                "type": "selector",
                "tag": "✅  Select",
                "outbounds": tags.copy(),
                "interrupt_exist_connections": False
            },
            {
                "type": "urltest",
                "tag": "Best Ping 🚀",
                "outbounds": tags.copy(),
                "url": "https://www.gstatic.com/generate_204",
                "interval": "30s",
                "interrupt_exist_connections": False
            },
            {
                "type": "direct",
                "tag": "direct",
                "domain_resolver": "dns-direct"
            }
        ] + outbounds,  # گره‌ها بعد از direct

        "route": {
            "rules": [
                {
                    "ip_cidr": "172.19.0.2",
                    "action": "hijack-dns"
                },
                {
                    "clash_mode": "Direct",
                    "outbound": "direct"
                },
                {
                    "clash_mode": "Global",
                    "outbound": "✅  Select"
                },
                {
                    "action": "sniff"
                },
                {
                    "protocol": "dns",
                    "action": "hijack-dns"
                },
                {
                    "ip_is_private": True,
                    "outbound": "direct"
                },
                {
                    "network": "udp",
                    "action": "reject"
                }
            ],
            "auto_detect_interface": True,
            "final": "✅  Select"
        },
        "ntp": {
            "enabled": True,
            "server": "time.cloudflare.com",
            "server_port": 123,
            "domain_resolver": "dns-direct",
            "interval": "30m",
            "write_to_system": False
        },
        "experimental": {
            "cache_file": {
                "enabled": True,
                "store_fakeip": True
            },
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "external_ui": "ui",
                "default_mode": "Rule",
                "external_ui_download_url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
                "external_ui_download_detour": "direct"
            }
        }
    }
    return config


# ==============================
# اجرای اصلی
# ==============================

def main():
    sub_link = os.environ.get('SUB_LINK')
    if not sub_link:
        print("ERROR: SUB_LINK environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    # دریافت محتوای اشتراک (با inja requests)
    try:
        import requests
        resp = requests.get(sub_link, timeout=30)
        resp.raise_for_status()
        content = resp.text
    except ImportError:
        print("ERROR: requests library not installed. Please install it.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to fetch subscription: {e}", file=sys.stderr)
        sys.exit(1)

    # دیکود Base64
    try:
        # ممکن است محتوا base64 باشد یا plain text
        # سعی می‌کنیم دیکود کنیم
        decoded = base64.b64decode(content).decode('utf-8')
    except Exception:
        # اگر دیکود نشد، فرض می‌کنیم خودش plain است
        decoded = content

    # Parse گره‌ها
    outbounds = parse_subscription(decoded)
    if not outbounds:
        print("WARNING: No valid nodes found in subscription.", file=sys.stderr)

    # ساخت کانفیگ نهایی
    config = build_config(outbounds)

    # ذخیره در فایل
    with open('javidbox.json', 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    print(f"✅ Successfully generated javidbox.json with {len(outbounds)} nodes.")


if __name__ == '__main__':
    main()
