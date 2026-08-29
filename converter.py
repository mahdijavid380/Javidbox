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
    s = re.sub(r'\s+', '', s)
    if len(s) % 4 != 0:
        return False
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
# 2. Parsers for proxy links
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

def parse_vmess(link: str):
    if not link.startswith('vmess://'):
        return None
    try:
        rest = link[8:]
        if '#' in rest:
            main, name_raw = rest.split('#', 1)
            name = unquote(name_raw)
        else:
            main = rest
            name = 'Vmess'
        decoded = base64_decode(main)
        if not decoded:
            return None
        cfg = json.loads(decoded)
        node_name = name or cfg.get('ps', 'Vmess')
        config = {
            'name': node_name,
            'type': 'vmess',
            'server': cfg.get('add', ''),
            'port': int(cfg.get('port', 0)),
            'uuid': cfg.get('id', ''),
            'alterId': int(cfg.get('aid', '0')),
            'cipher': cfg.get('scy', 'auto'),
            'network': cfg.get('net', 'tcp'),
            'tls': cfg.get('tls') == 'tls' or cfg.get('tls') == '1',
            'udp': True,
            'skip-cert-verify': cfg.get('allowInsecure') in ('true', '1', True),
            'servername': cfg.get('sni', '') or cfg.get('host', '')
        }
        if config['network'] == 'ws':
            config['ws-opts'] = {
                'path': cfg.get('path', '/'),
                'headers': {'Host': cfg.get('host', '')} if cfg.get('host') else None
            }
        if config['network'] == 'grpc':
            config['grpc-opts'] = {'grpc-service-name': cfg.get('path', '')}
        return {'name': node_name, 'config': config}
    except Exception:
        return None

def parse_trojan(link: str):
    if not link.startswith('trojan://'):
        return None
    try:
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        name = parsed.fragment or 'Trojan'
        config = {
            'name': name,
            'type': 'trojan',
            'server': parsed.hostname,
            'port': parsed.port or 443,
            'password': unquote(parsed.username or ''),
            'udp': True,
            'skip-cert-verify': params.get('allowInsecure', [''])[0] in ('1', 'true'),
            'sni': params.get('sni', [params.get('peer', [''])[0]])[0],
            'network': params.get('type', ['tcp'])[0]
        }
        return {'name': name, 'config': config}
    except Exception:
        return None

def parse_ss(link: str):
    if not link.startswith('ss://'):
        return None
    try:
        rest = link[5:]
        if '#' in rest:
            main, name_b64 = rest.split('#', 1)
            name = unquote(name_b64)
        else:
            main = rest
            name = 'SS'
        decoded = base64_decode(main)
        if decoded and '@' in decoded:
            user_info, server_info = decoded.split('@', 1)
            if ':' in user_info:
                method, password = user_info.split(':', 1)
                server, port_str = server_info.split(':')
                port = int(port_str)
                config = {
                    'name': name,
                    'type': 'ss',
                    'server': server,
                    'port': port,
                    'cipher': method,
                    'password': password,
                    'udp': True
                }
                return {'name': name, 'config': config}
        if '@' in main:
            user_b64, server_info = main.split('@', 1)
            user_dec = base64_decode(user_b64)
            if user_dec and ':' in user_dec:
                method, password = user_dec.split(':', 1)
                server, port_str = server_info.split(':')
                port = int(port_str)
                config = {
                    'name': name,
                    'type': 'ss',
                    'server': server,
                    'port': port,
                    'cipher': method,
                    'password': password,
                    'udp': True
                }
                return {'name': name, 'config': config}
        return None
    except Exception:
        return None

def parse_ssr(link: str):
    if not link.startswith('ssr://'):
        return None
    try:
        rest = link[6:]
        if '#' in rest:
            main, name_raw = rest.split('#', 1)
            name = unquote(name_raw)
        else:
            main = rest
            name = 'SSR'
        decoded = base64_decode(main)
        if not decoded:
            return None
        parts = decoded.split('/?', 1)
        main_part = parts[0]
        params_str = parts[1] if len(parts) > 1 else ''
        params = {}
        for p in params_str.split('&'):
            if '=' in p:
                k, v = p.split('=', 1)
                params[k] = v
        segs = main_part.split(':')
        if len(segs) < 6:
            return None
        server = segs[0]
        port = int(segs[1])
        protocol = segs[2]
        method = segs[3]
        obfs = segs[4]
        password_b64 = ':'.join(segs[5:])
        password = base64_decode(password_b64)
        if not password:
            password = password_b64
        node_name = name
        if 'remarks' in params:
            rem = base64_decode(params['remarks'])
            if rem:
                node_name = rem
        config = {
            'name': node_name,
            'type': 'ssr',
            'server': server,
            'port': port,
            'cipher': method,
            'password': password,
            'protocol': protocol,
            'obfs': obfs
        }
        if 'protoparam' in params:
            config['protocolparam'] = base64_decode(params['protoparam']) or params['protoparam']
        if 'obfsparam' in params:
            config['obfsparam'] = base64_decode(params['obfsparam']) or params['obfsparam']
        if 'group' in params:
            config['group'] = base64_decode(params['group']) or params['group']
        return {'name': node_name, 'config': config}
    except Exception:
        return None

def parse_hysteria2(link: str):
    if not link.startswith('hysteria2://'):
        return None
    try:
        rest = link[12:]
        if '#' in rest:
            main, name_raw = rest.split('#', 1)
            name = unquote(name_raw)
        else:
            main = rest
            name = 'Hysteria2'
        if '?' in main:
            main, query_str = main.split('?', 1)
            params = parse_qs(query_str)
        else:
            params = {}
        if '@' in main:
            user_part, server_part = main.split('@', 1)
            password = unquote(user_part)
        else:
            return None
        server, port_str = server_part.split(':')
        port = int(port_str)
        config = {
            'name': name,
            'type': 'hysteria2',
            'server': server,
            'port': port,
            'password': password,
            'skip-cert-verify': params.get('insecure', [''])[0] == '1',
            'sni': params.get('sni', [''])[0],
            'obfs': params.get('obfs', [''])[0],
            'obfs-password': params.get('obfs-password', [''])[0]
        }
        return {'name': name, 'config': config}
    except Exception:
        return None

def parse_hysteria(link: str):
    if not link.startswith('hysteria://'):
        return None
    try:
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        name = parsed.fragment or 'Hysteria'
        config = {
            'name': name,
            'type': 'hysteria',
            'server': parsed.hostname,
            'port': parsed.port or 443,
            'auth_str': params.get('auth', [''])[0],
            'protocol': params.get('protocol', ['udp'])[0],
            'skip-cert-verify': params.get('insecure', [''])[0] == '1',
            'sni': params.get('peer', [''])[0],
            'up': int(params.get('upmbps', ['10'])[0]),
            'down': int(params.get('downmbps', ['50'])[0]),
            'alpn': [params.get('alpn', ['h3'])[0]]
        }
        return {'name': name, 'config': config}
    except Exception:
        return None

def parse_http(link: str):
    if not link.startswith(('http://', 'https://')):
        return None
    try:
        parsed = urlparse(link)
        name = parsed.fragment or 'HTTP'
        config = {
            'name': name,
            'type': 'http',
            'server': parsed.hostname,
            'port': parsed.port or (443 if parsed.scheme == 'https' else 80),
            'username': unquote(parsed.username or ''),
            'password': unquote(parsed.password or ''),
            'tls': parsed.scheme == 'https'
        }
        return {'name': name, 'config': config}
    except Exception:
        return None

def parse_socks5(link: str):
    if not link.startswith(('socks5://', 'socks://')):
        return None
    try:
        parsed = urlparse(link)
        name = parsed.fragment or 'SOCKS5'
        config = {
            'name': name,
            'type': 'socks5',
            'server': parsed.hostname,
            'port': parsed.port or 1080,
            'username': unquote(parsed.username or ''),
            'password': unquote(parsed.password or '')
        }
        return {'name': name, 'config': config}
    except Exception:
        return None

def parse_telegram(link: str):
    if not link.startswith('https://t.me/socks') and not link.startswith('https://t.me/http'):
        return None
    try:
        params = parse_qs(urlparse(link).query)
        server = params.get('server', [''])[0]
        port = params.get('port', [''])[0]
        if not server or not port:
            return None
        is_socks = 'socks' in link
        type_ = 'socks5' if is_socks else 'http'
        name = 'SOCKS5' if is_socks else 'HTTP'
        config = {
            'name': name,
            'type': type_,
            'server': server,
            'port': int(port),
            'username': params.get('user', [''])[0],
            'password': params.get('pass', [''])[0]
        }
        return {'name': name, 'config': config}
    except Exception:
        return None

# ===========================================================================
# 3. Define PARSERS list and parse_proxy_link
# ===========================================================================
PARSERS = [
    parse_vless,
    parse_vmess,
    parse_trojan,
    parse_ss,
    parse_ssr,
    parse_hysteria2,
    parse_hysteria,
    parse_http,
    parse_socks5,
    parse_telegram
]

def parse_proxy_link(link: str):
    link = link.strip()
    if not link:
        return None
    for parser in PARSERS:
        res = parser(link)
        if res:
            return res
    return None

# ===========================================================================
# 4. Parse multiple lines (links) with deduplication
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
# 5. Parse Sing-box JSON
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
# 6. Detect format
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
# 7. Adapters for Sing-box generation
# ===========================================================================
class SSAdapter:
    @staticmethod
    def to_singbox(node):
        return {
            "tag": node['name'],
            "type": "shadowsocks",
            "server": node['server'],
            "server_port": node['port'],
            "method": node.get('cipher', 'aes-128-gcm'),
            "password": node.get('password', '')
        }

class SSRAdapter:
    @staticmethod
    def to_singbox(node):
        return {
            "tag": node['name'],
            "type": "shadowsocks",
            "server": node['server'],
            "server_port": node['port'],
            "method": node.get('cipher', 'aes-128-gcm'),
            "password": node.get('password', '')
        }

class VmessAdapter:
    @staticmethod
    def to_singbox(node):
        out = {
            "tag": node['name'],
            "type": "vmess",
            "server": node['server'],
            "server_port": node['port'],
            "uuid": node.get('uuid', ''),
            "packet_encoding": "xudp",
            "security": node.get('cipher', 'auto'),
            "alter_id": 0
        }
        if node.get('network') == 'ws' and 'ws-opts' in node:
            out["transport"] = {
                "type": "ws",
                "path": node['ws-opts'].get('path', '/'),
                "headers": node['ws-opts'].get('headers')
            }
        if node.get('network') == 'grpc' and 'grpc-opts' in node:
            out["transport"] = {
                "type": "grpc",
                "service_name": node['grpc-opts'].get('grpc-service-name', '')
            }
        if node.get('tls') or node.get('servername'):
            out["tls"] = {"enabled": True}
            if node.get('servername'):
                out["tls"]["server_name"] = node['servername']
            if node.get('skip-cert-verify'):
                out["tls"]["insecure"] = node['skip-cert-verify']
        return out

class VlessAdapter:
    @staticmethod
    def to_singbox(node):
        out = {
            "tag": node['name'],
            "type": "vless",
            "server": node['server'],
            "server_port": node['port'],
            "uuid": node.get('uuid', '')
        }
        if node.get('flow'):
            out["flow"] = node['flow']
        if node.get('tls') or node.get('servername'):
            out["tls"] = {"enabled": True}
            if node.get('servername'):
                out["tls"]["server_name"] = node['servername']
            if node.get('skip-cert-verify'):
                out["tls"]["insecure"] = node['skip-cert-verify']
        if 'reality-opts' in node:
            out["tls"] = out.get("tls", {"enabled": True})
            out["tls"]["reality"] = {
                "enabled": True,
                "public_key": node['reality-opts'].get('public-key', ''),
                "short_id": node['reality-opts'].get('short-id', '')
            }
        if out.get("tls"):
            out["tls"]["utls"] = {"enabled": True, "fingerprint": "chrome"}
        if node.get('network') == 'ws' and 'ws-opts' in node:
            out["transport"] = {
                "type": "ws",
                "path": node['ws-opts'].get('path', '/'),
                "headers": node['ws-opts'].get('headers')
            }
        elif node.get('network') == 'grpc' and 'grpc-opts' in node:
            out["transport"] = {
                "type": "grpc",
                "service_name": node['grpc-opts'].get('grpc-service-name', '')
            }
        if not re.match(r'^[\d.]+$', node['server']) and not node['server'].startswith('['):
            out["domain_resolver"] = "dns-direct"
        return out

class TrojanAdapter:
    @staticmethod
    def to_singbox(node):
        out = {
            "tag": node['name'],
            "type": "trojan",
            "server": node['server'],
            "server_port": node['port'],
            "password": node.get('password', ''),
            "tls": {
                "enabled": True,
                "utls": {"enabled": True, "fingerprint": "chrome"}
            }
        }
        if node.get('skip-cert-verify'):
            out["tls"]["insecure"] = node['skip-cert-verify']
        if node.get('sni'):
            out["tls"]["server_name"] = node['sni']
        if node.get('network') == 'ws' and 'ws-opts' in node:
            out["transport"] = {
                "type": "ws",
                "path": node['ws-opts'].get('path', '/'),
                "headers": node['ws-opts'].get('headers')
            }
        if not re.match(r'^[\d.]+$', node['server']) and not node['server'].startswith('['):
            out["domain_resolver"] = "dns-direct"
        return out

class HysteriaAdapter:
    @staticmethod
    def to_singbox(node):
        return {
            "tag": node['name'],
            "type": "hysteria",
            "server": node['server'],
            "server_port": node['port'],
            "auth": node.get('auth_str', ''),
            "up_mbps": node.get('up', 10),
            "down_mbps": node.get('down', 50),
            "server_name": node.get('sni', '')
        }

class Hysteria2Adapter:
    @staticmethod
    def to_singbox(node):
        out = {
            "tag": node['name'],
            "type": "hysteria2",
            "server": node['server'],
            "server_port": node['port'],
            "password": node.get('password', ''),
            "tls": {"enabled": True}
        }
        if node.get('sni'):
            out["tls"]["server_name"] = node['sni']
        if node.get('skip-cert-verify'):
            out["tls"]["insecure"] = node['skip-cert-verify']
        if node.get('obfs'):
            out["obfs"] = {
                "type": node['obfs'],
                "password": node.get('obfs-password', '')
            }
        return out

class HttpAdapter:
    @staticmethod
    def to_singbox(node):
        return {
            "tag": node['name'],
            "type": "http",
            "server": node['server'],
            "server_port": node['port'],
            "users": [{"username": node.get('username', ''), "password": node.get('password', '')}]
        }

class Socks5Adapter:
    @staticmethod
    def to_singbox(node):
        return {
            "tag": node['name'],
            "type": "socks",
            "server": node['server'],
            "server_port": node['port'],
            "version": "5",
            "username": node.get('username', ''),
            "password": node.get('password', '')
        }

def get_adapter(proto):
    mapping = {
        'ss': SSAdapter,
        'ssr': SSRAdapter,
        'vmess': VmessAdapter,
        'vless': VlessAdapter,
        'trojan': TrojanAdapter,
        'hysteria': HysteriaAdapter,
        'hysteria2': Hysteria2Adapter,
        'http': HttpAdapter,
        'socks5': Socks5Adapter
    }
    return mapping.get(proto)

# ===========================================================================
# 8. Generate Sing-box JSON
# ===========================================================================
def generate_singbox_config(proxies, mode='tun'):
    if not proxies:
        return json.dumps({"error": "هیچ نودی پیدا نشد"}, indent=2, ensure_ascii=False)

    supported_types = {'ss', 'vmess', 'vless', 'trojan', 'hysteria', 'hysteria2', 'http', 'socks5'}
    proxies = [p for p in proxies if p.get('type') in supported_types]

    if not proxies:
        return json.dumps({"error": "هیچ نود پشتیبانی‌شده‌ای برای Sing-box یافت نشد"}, indent=2, ensure_ascii=False)

    proxy_names = [p['name'] for p in proxies]

    outbounds = []
    for p in proxies:
        adapter = get_adapter(p['type'])
        if adapter:
            outbound = adapter.to_singbox(p)
            if outbound:
                outbounds.append(outbound)

    selector_tag = "✅  Select"

    config = {
        "log": {
            "disabled": False,
            "level": "warn",
            "timestamp": True
        },
        "dns": {
            "servers": [
                {"type": "https", "tag": "dns-remote", "server": "8.8.8.8", "detour": selector_tag},
                {"type": "udp", "tag": "dns-direct", "server": "8.8.8.8"}
            ],
            "rules": [
                {"clash_mode": "Direct", "server": "dns-direct"},
                {"clash_mode": "Global", "server": "dns-remote"}
            ],
            "strategy": "prefer_ipv4"
        },
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/28"], "mtu": 9000,
             "auto_route": True, "strict_route": True, "stack": "mixed"},
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2334},
            {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 2333}
        ],
        "outbounds": [
            {
                "type": "selector",
                "tag": selector_tag,
                "outbounds": ["Best Ping 🚀"] + proxy_names,
                "interrupt_exist_connections": False
            },
            {
                "type": "urltest",
                "tag": "Best Ping 🚀",
                "outbounds": proxy_names,
                "url": "https://www.gstatic.com/generate_204",
                "interval": "30s",
                "interrupt_exist_connections": False
            },
            {"type": "direct", "tag": "direct", "domain_resolver": "dns-direct"}
        ] + outbounds,
        "route": {
            "rules": [
                {"ip_cidr": "172.19.0.2", "action": "hijack-dns"},
                {"clash_mode": "Direct", "outbound": "direct"},
                {"clash_mode": "Global", "outbound": selector_tag},
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_is_private": True, "outbound": "direct"},
                {"network": "udp", "action": "reject"}
            ],
            "auto_detect_interface": True,
            "final": selector_tag
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
            "cache_file": {"enabled": True, "store_fakeip": True},
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "external_ui": "ui",
                "default_mode": "Rule",
                "external_ui_download_url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
                "external_ui_download_detour": "direct"
            }
        }
    }
    return json.dumps(config, indent=2, ensure_ascii=False)

# ===========================================================================
# 9. Fetch subscription with smart Base64 detection
# ===========================================================================
def fetch_subscription(sub_link):
    try:
        req = urllib.request.Request(sub_link, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode('utf-8-sig').strip()
            if not raw:
                raise ValueError("پاسخ خالی است")
            
            print(f"📄 محتوای دریافتی (۲۰۰ کاراکتر اول):\n{raw[:200]}...")

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
# 10. Main
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
