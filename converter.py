#!/usr/bin/env python3
"""
Sing-Box Subscription Converter (v7 - Final stable version)
Supports: VLESS, VMess, Shadowsocks, Trojan, Hysteria2, TUIC
Features: URLTest for best ping, Modern DNS (1.14+), Rule Actions (1.11+)
"""

import base64
import json
import logging
import os
import sys
from urllib.parse import urlparse, parse_qs, unquote

import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

OUTPUT_FILE = "javidbox.json"


def fetch_subscription(sub_url: str) -> str:
    try:
        response = requests.get(
            sub_url, timeout=30,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        response.raise_for_status()
        content = response.text.strip()
        
        try:
            padding = 4 - len(content) % 4
            if padding != 4:
                content += '=' * padding
            return base64.b64decode(content).decode('utf-8')
        except Exception:
            return content
    except Exception as e:
        logger.error(f"Failed to fetch subscription: {e}")
        raise


def parse_vless(url: str) -> dict:
    parsed = urlparse(url)
    uuid = parsed.username
    server = parsed.hostname
    port = int(parsed.port) if parsed.port else 443
    params = parse_qs(parsed.query)
    name = unquote(parsed.fragment) if parsed.fragment else f"vless-{server}-{port}"
    
    outbound = {
        "type": "vless", "tag": name,
        "server": server, "server_port": port, "uuid": uuid,
    }
    
    security = params.get('security', ['none'])[0]
    if security == 'tls':
        tls_config = {"enabled": True}
        if 'sni' in params: tls_config["server_name"] = params['sni'][0]
        if 'alpn' in params: tls_config["alpn"] = params['alpn'][0].split(',')
        if 'fp' in params: tls_config["utls"] = {"enabled": True, "fingerprint": params['fp'][0]}
        outbound["tls"] = tls_config
    elif security == 'reality':
        reality_config = {"enabled": True}
        if 'sni' in params: reality_config["server_name"] = params['sni'][0]
        if 'pbk' in params: reality_config["public_key"] = params['pbk'][0]
        if 'sid' in params: reality_config["short_id"] = params['sid'][0]
        if 'fp' in params: reality_config["utls"] = {"enabled": True, "fingerprint": params['fp'][0]}
        outbound["tls"] = reality_config
    
    flow = params.get('flow', [''])[0]
    if flow: outbound["flow"] = flow
    
    network = params.get('type', ['tcp'])[0]
    if network == 'ws':
        transport = {"type": "ws"}
        if 'path' in params: transport["path"] = params['path'][0]
        if 'host' in params: transport["headers"] = {"Host": params['host'][0]}
        outbound["transport"] = transport
    elif network == 'grpc':
        transport = {"type": "grpc"}
        if 'serviceName' in params: transport["service_name"] = params['serviceName'][0]
        outbound["transport"] = transport
    elif network == 'httpupgrade':
        transport = {"type": "httpupgrade"}
        if 'path' in params: transport["path"] = params['path'][0]
        if 'host' in params: transport["host"] = params['host'][0]
        outbound["transport"] = transport
    
    return outbound


def parse_vmess(url: str) -> dict:
    encoded = url.split('://')[1]
    name = None
    if '#' in encoded:
        encoded, name_fragment = encoded.split('#', 1)
        name = unquote(name_fragment)
    
    padding = 4 - len(encoded) % 4
    if padding != 4:
        encoded += '=' * padding
    
    config = json.loads(base64.b64decode(encoded).decode('utf-8'))
    server = config.get('add', '')
    port = int(config.get('port', 443))
    uuid = config.get('id', '')
    if not name: name = config.get('ps', f"vmess-{server}-{port}")
    
    outbound = {
        "type": "vmess", "tag": name,
        "server": server, "server_port": port, "uuid": uuid,
        "alter_id": int(config.get('aid', 0)),
    }
    
    if config.get('tls') == 'tls':
        tls_config = {"enabled": True}
        if config.get('sni'): tls_config["server_name"] = config['sni']
        elif config.get('host'): tls_config["server_name"] = config['host']
        if config.get('fp'): tls_config["utls"] = {"enabled": True, "fingerprint": config['fp']}
        outbound["tls"] = tls_config
    
    network = config.get('net', 'tcp')
    if network == 'ws':
        transport = {"type": "ws"}
        if config.get('path'): transport["path"] = config['path']
        if config.get('host'): transport["headers"] = {"Host": config['host']}
        outbound["transport"] = transport
    elif network == 'grpc':
        transport = {"type": "grpc"}
        if config.get('path'): transport["service_name"] = config['path']
        outbound["transport"] = transport
    
    return outbound


def parse_ss(url: str) -> dict:
    parsed = urlparse(url)
    name = unquote(parsed.fragment) if parsed.fragment else f"ss-{parsed.hostname}-{parsed.port}"
    
    userinfo = parsed.username
    if ':' not in userinfo:
        try:
            padding = 4 - len(userinfo) % 4
            if padding != 4: userinfo += '=' * padding
            userinfo = base64.b64decode(userinfo).decode('utf-8')
        except Exception: pass
    
    method, password = userinfo.split(':', 1)
    return {
        "type": "shadowsocks", "tag": name,
        "server": parsed.hostname,
        "server_port": int(parsed.port) if parsed.port else 8388,
        "method": method, "password": password,
    }


def parse_trojan(url: str) -> dict:
    parsed = urlparse(url)
    password = parsed.username
    server = parsed.hostname
    port = int(parsed.port) if parsed.port else 443
    params = parse_qs(parsed.query)
    name = unquote(parsed.fragment) if parsed.fragment else f"trojan-{server}-{port}"
    
    outbound = {
        "type": "trojan", "tag": name,
        "server": server, "server_port": port, "password": password,
    }
    
    tls_config = {"enabled": True}
    if 'sni' in params: tls_config["server_name"] = params['sni'][0]
    if 'fp' in params: tls_config["utls"] = {"enabled": True, "fingerprint": params['fp'][0]}
    if params.get('allowInsecure', ['0'])[0] == '1': tls_config["insecure"] = True
    outbound["tls"] = tls_config
    
    network = params.get('type', ['tcp'])[0]
    if network == 'ws':
        transport = {"type": "ws"}
        if 'path' in params: transport["path"] = params['path'][0]
        if 'host' in params: transport["headers"] = {"Host": params['host'][0]}
        outbound["transport"] = transport
    elif network == 'grpc':
        transport = {"type": "grpc"}
        if 'serviceName' in params: transport["service_name"] = params['serviceName'][0]
        outbound["transport"] = transport
    
    return outbound


def parse_hysteria2(url: str) -> dict:
    parsed = urlparse(url)
    password = parsed.username
    server = parsed.hostname
    port = int(parsed.port) if parsed.port else 443
    params = parse_qs(parsed.query)
    name = unquote(parsed.fragment) if parsed.fragment else f"hysteria2-{server}-{port}"
    
    outbound = {
        "type": "hysteria2", "tag": name,
        "server": server, "server_port": port, "password": password,
    }
    
    tls_config = {"enabled": True}
    if 'sni' in params: tls_config["server_name"] = params['sni'][0]
    if params.get('insecure', ['0'])[0] == '1': tls_config["insecure"] = True
    outbound["tls"] = tls_config
    
    if 'obfs' in params:
        outbound["obfs"] = {"type": params['obfs'][0]}
        if 'obfs-password' in params:
            outbound["obfs"]["password"] = params['obfs-password'][0]
    
    return outbound


def parse_tuic(url: str) -> dict:
    parsed = urlparse(url)
    uuid = parsed.username
    password = parsed.password or ''
    server = parsed.hostname
    port = int(parsed.port) if parsed.port else 443
    params = parse_qs(parsed.query)
    name = unquote(parsed.fragment) if parsed.fragment else f"tuic-{server}-{port}"
    
    outbound = {
        "type": "tuic", "tag": name,
        "server": server, "server_port": port,
        "uuid": uuid, "password": password,
    }
    
    tls_config = {"enabled": True}
    if 'sni' in params: tls_config["server_name"] = params['sni'][0]
    if params.get('allow_insecure', ['0'])[0] == '1': tls_config["insecure"] = True
    outbound["tls"] = tls_config
    
    if 'congestion_control' in params: outbound["congestion_control"] = params['congestion_control'][0]
    if 'udp_relay_mode' in params: outbound["udp_relay_mode"] = params['udp_relay_mode'][0]
    
    return outbound


def parse_line(line: str):
    line = line.strip()
    if not line or line.startswith('#'): return None
    
    try:
        if line.startswith('vless://'): return parse_vless(line)
        elif line.startswith('vmess://'): return parse_vmess(line)
        elif line.startswith('ss://'): return parse_ss(line)
        elif line.startswith('trojan://'): return parse_trojan(line)
        elif line.startswith('hysteria2://') or line.startswith('hy2://'): return parse_hysteria2(line)
        elif line.startswith('tuic://'): return parse_tuic(line)
    except Exception as e:
        logger.warning(f"Failed to parse line: {line[:50]}... Error: {e}")
        return None


def deduplicate_servers(servers: list) -> list:
    seen = set()
    unique = []
    
    for s in servers:
        key = f"{s.get('type', '')}-{s.get('server', '')}-{s.get('server_port', '')}"
        if s.get('type') == 'vless': key += f"-{s.get('uuid', '')}"
        elif s.get('type') in ('vmess', 'shadowsocks', 'trojan', 'hysteria2'):
            key += f"-{s.get('password', '') or s.get('uuid', '')}"
        elif s.get('type') == 'tuic': key += f"-{s.get('uuid', '')}-{s.get('password', '')}"
        
        if key not in seen:
            seen.add(key)
            unique.append(s)
    
    return unique


def build_config(servers: list) -> dict:
    server_tags = [s['tag'] for s in servers]
    
    # ⚡ URLTest: انتخاب خودکار بهترین سرور با کمترین ping
    urltest = {
        "type": "urltest",
        "tag": "⚡ Auto Best",
        "outbounds": server_tags,
        "url": "https://www.gstatic.com/generate_204",
        "interval": "5m",
        "tolerance": 50,
    }
    
    # 🎯 Selector: انتخاب دستی یا خودکار
    selector = {
        "type": "selector",
        "tag": "🎯 Proxy",
        "outbounds": ["⚡ Auto Best", "direct"] + server_tags,
        "default": "⚡ Auto Best",
    }
    
    outbounds = [
        selector,
        urltest,
    ] + servers + [
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
        {"type": "dns", "tag": "dns-out"},
    ]
    
    config = {
        "$schema": "https://sing-box.sagernet.org/schema.json",
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "remote", "type": "tls", "server": "8.8.8.8", "server_port": 853, "detour": "proxy"},
                {"tag": "remote-backup", "type": "https", "server": "1.1.1.1", "server_port": 443, "detour": "proxy"},
                {"tag": "local", "type": "udp", "server": "1.1.1.1", "server_port": 53, "detour": "direct"},
            ],
            "rules": [
                {"rule_set": "geosite-ads", "action": "predefined", "rcode": "REFUSED"},
                {"outbound": "any", "server": "remote"},
                {"rule_set": "geosite-private", "server": "local"},
            ],
            "final": "remote",
            "strategy": "prefer_ipv4",
        },
        "ntp": {
            "enabled": True, "server": "time.apple.com",
            "server_port": 123, "interval": "30m",
        },
        "certificate": {},
        "certificate_providers": [],
        "http_clients": [],
        "network_namespaces": [],
        "endpoints": [],
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                "auto_route": True,
                "strict_route": True,
                "stack": "system",
            },
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 7890,
            },
        ],
        "outbounds": outbounds,
        "route": {
            "rules": [
                {
                    "inbound": ["tun-in", "mixed-in"],
                    "action": "resolve",
                    "strategy": "prefer_ipv4",
                },
                {
                    "inbound": ["tun-in", "mixed-in"],
                    "action": "sniff",
                    "timeout": "1s",
                },
                {"protocol": "dns", "outbound": "dns-out"},
                {
                    "rule_set": ["geosite-ir", "geoip-ir", "geosite-private"],
                    "outbound": "direct",
                },
            ],
            "rule_set": [
                {
                    "type": "remote", "tag": "geosite-ir", "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs",
                    "download_detour": "proxy", "update_interval": "1d",
                },
                {
                    "type": "remote", "tag": "geoip-ir", "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs",
                    "download_detour": "proxy", "update_interval": "1d",
                },
                {
                    "type": "remote", "tag": "geosite-private", "format": "binary",
                    "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-private.srs",
                    "download_detour": "proxy", "update_interval": "1d",
                },
                {
                    "type": "remote", "tag": "geosite-ads", "format": "binary",
                    "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
                    "download_detour": "proxy", "update_interval": "1d",
                },
            ],
            "auto_detect_interface": True,
        },
        "services": [],
        "experimental": {
            "cache_file": {
                "enabled": True, "path": "cache.db",
                "store_fakeip": True, "store_rdrc": True,
            },
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "external_ui": "ui",
                "external_ui_download_url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
                "external_ui_download_detour": "proxy",
                "default_mode": "rule",
            },
        },
    }
    
    return config


def main():
    sub_url = os.environ.get('SUB_LINK')
    if not sub_url:
        logger.error("SUB_LINK environment variable is not set.")
        sys.exit(1)
    
    try:
        logger.info(f"Fetching subscription from: {sub_url[:50]}...")
        content = fetch_subscription(sub_url)
        
        servers = []
        for line in content.splitlines():
            outbound = parse_line(line)
            if outbound:
                servers.append(outbound)
        
        logger.info(f"Parsed {len(servers)} servers.")
        
        if not servers:
            logger.error("No valid servers found.")
            sys.exit(0)
        
        servers = deduplicate_servers(servers)
        logger.info(f"After deduplication: {len(servers)} unique servers.")
        
        config = build_config(servers)
        new_content = json.dumps(config, indent=2, ensure_ascii=False)
        
        if os.path.exists(OUTPUT_FILE):
            with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
                if f.read().strip() == new_content.strip():
                    logger.info("No changes detected.")
                    return
        
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        logger.info(f"Successfully wrote {OUTPUT_FILE} with {len(servers)} servers.")
        
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
