#!/usr/bin/env python3
"""
converter.py

Download a Base64 subscription (V2Ray/V2RayN style), parse known link types and
generate a sing-box config file (javidbox.json) compatible with schema ~1.11+.

- Reads subscription URL from env var SUB_LINK or first CLI argument.
- Supports vmess, vless, ss, trojan, hysteria2, tuic (best-effort).
- Deduplicates servers by server+port+credential.
- Writes javidbox.json only if content changed.
- Extensive logging and error handling.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import typing
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, unquote, urlparse

import pybase64
import requests

# -----------------------
# Configuration & types
# -----------------------

OUTFILE = Path("javidbox.json")
USER_AGENT = "javidbox-converter/1.0"
REQ_TIMEOUT = 30  # seconds

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
)

# Type alias for outbound object (structured dict for sing-box)
Outbound = Dict[str, typing.Any]


# -----------------------
# Utilities
# -----------------------

def safe_b64decode(data: str) -> bytes:
    """
    Robust base64 decode: add padding if missing and try urlsafe variants.
    """
    if not data:
        return b""
    s = data.strip()
    # Remove newlines and spaces
    s = s.replace("\n", "").replace("\r", "").strip()
    # Add missing padding
    padding = (-len(s)) % 4
    if padding:
        s += "=" * padding
    try:
        return pybase64.b64decode(s)
    except Exception:
        # Try urlsafe
        try:
            return pybase64.urlsafe_b64decode(s)
        except Exception as e:
            logging.debug("Base64 decode failed: %s", e)
            raise


def download_subscription(url: str) -> str:
    """
    Download the subscription content. Return text (may be base64).
    Raise requests.RequestException on failure.
    """
    headers = {"User-Agent": USER_AGENT}
    resp = requests.get(url, headers=headers, timeout=REQ_TIMEOUT)
    resp.raise_for_status()
    return resp.text


def normalize_host_port(host: str, port: Optional[str]) -> Tuple[str, Optional[int]]:
    host = host.strip()
    port_i: Optional[int] = None
    if port:
        try:
            port_i = int(port)
        except Exception:
            port_i = None
    return host, port_i


def outbound_tag_from_name(name: Optional[str], idx: int, scheme: str) -> str:
    base = (name or "").strip()
    if base:
        # Keep safe characters for tag
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in base)
        return f"{safe}-{scheme}"
    return f"{scheme}-{idx}"


# -----------------------
# Parsers per-protocol
# -----------------------

def parse_vmess(link: str, idx: int) -> Optional[Outbound]:
    """
    vmess://BASE64JSON
    The base64-decoded JSON typically contains fields like:
      { "v": "2", "ps": "name", "add": "host", "port": "443",
        "id": "uuid", "aid": "0", "net": "ws", "type": "none",
        "host": "example.com", "path": "/ws", "tls": "tls" }
    """
    try:
        payload = link[len("vmess://") :]
        raw = safe_b64decode(payload).decode("utf-8", errors="ignore")
        data = json.loads(raw)
    except Exception as e:
        logging.debug("vmess parse failed for %s: %s", link, e)
        return None

    server = data.get("add") or data.get("address") or data.get("host")
    port = int(data.get("port") or 0)
    tag = outbound_tag_from_name(data.get("ps") or data.get("remark"), idx, "vmess")

    outbound: Outbound = {
        "type": "vmess",
        "tag": tag,
        "server": server,
        "server_port": port,
        "uuid": data.get("id"),
        "alter_id": int(data.get("aid") or 0),
        "security": data.get("scy", data.get("security", "auto")),
    }

    transport = data.get("net") or data.get("network")
    if transport:
        if transport == "ws":
            outbound["transport"] = {
                "type": "ws",
                "path": data.get("path") or data.get("ps", "/"),
                "header": {"type": data.get("type", "none"), "Host": data.get("host")},
            }
        elif transport in ("tcp", "kcp", "h2", "grpc", "quic"):
            outbound["transport"] = {"type": transport}
    if data.get("tls") and data.get("tls") != "none":
        outbound["tls"] = True

    return outbound


def parse_vless(link: str, idx: int) -> Optional[Outbound]:
    """
    vless://<uuid>@host:port?param=...#name
    Handle reality, ws, grpc, xtls as best-effort.
    """
    try:
        parsed = urlparse(link)
        # parsed.netloc may include credentials: <uuid>@host:port
        userinfo, at, hostport = parsed.netloc.rpartition("@")
        if at:
            uuid = userinfo
            host_port = hostport
        else:
            # In some forms vless://host:port?encryption=none&uuid=...
            uuid = parsed.username or ""
            host_port = parsed.hostname or ""
        host = parsed.hostname or ""
        port = parsed.port or (int(parsed.path) if parsed.path and parsed.path.isdigit() else None)
        query = parse_qs(parsed.query)
        name = unquote(parsed.fragment) if parsed.fragment else None

        tag = outbound_tag_from_name(name, idx, "vless")

        outbound: Outbound = {
            "type": "vless",
            "tag": tag,
            "server": host,
            "server_port": int(port or 0),
            "uuid": uuid or (query.get("uuid", [None])[0]),
        }

        # Transport handling
        net = (query.get("type") or query.get("transport") or query.get("net") or [None])[0]
        if net:
            net = net.lower()
            if net == "ws":
                outbound["transport"] = {
                    "type": "ws",
                    "path": (query.get("path") or ["/"])[0],
                    "header": {"Host": (query.get("host") or [parsed.hostname])[0]},
                }
            elif net == "grpc":
                outbound["transport"] = {"type": "grpc", "service_name": (query.get("serviceName") or [None])[0]}
            elif net == "tcp":
                outbound["transport"] = {"type": "tcp"}
            # reality specifics
        if "reality" in parsed.scheme or query.get("security", [""])[0] == "reality" or query.get("reality_public_key"):
            # Best-effort mapping for reality
            reality = {}
            if query.get("reality_public_key"):
                reality["public_key"] = query["reality_public_key"][0]
            if query.get("short_id"):
                reality["short_id"] = query["short_id"][0]
            if reality:
                outbound["reality"] = reality
        if query.get("security") and query.get("security")[0] != "none":
            outbound["tls"] = True

        return outbound
    except Exception as e:
        logging.debug("vless parse failed for %s: %s", link, e)
        return None


def parse_ss(link: str, idx: int) -> Optional[Outbound]:
    """
    Shadowsocks: ss://<base64- or method:password>@host:port#name
    Accepts both old and newer forms.
    """
    try:
        stripped = link[len("ss://") :]
        # If contains '@' then form may be ss://BASE64@host:port or ss://method:passwd@host:port
        if "@" in stripped:
            left, right = stripped.rsplit("@", 1)
            # left could be base64 (method:password) or method:password directly
            try:
                left_decoded = safe_b64decode(left).decode("utf-8", errors="ignore")
                method, password = left_decoded.split(":", 1)
            except Exception:
                # try raw
                if ":" in left:
                    method, password = left.split(":", 1)
                else:
                    method, password = left, ""
            # right may include #fragment
            if "#" in right:
                hostport, _, frag = right.partition("#")
                name = unquote(frag)
            else:
                hostport = right
                name = None
            if ":" in hostport:
                host, port_s = hostport.split(":", 1)
                port = int(port_s)
            else:
                host, port = hostport, 0
        else:
            # Form: ss://BASE64 (where base64 decodes to method:password@host:port) or other variants
            try:
                decoded = safe_b64decode(stripped).decode("utf-8", errors="ignore")
                # decoded is like method:password@host:port
                if "@" in decoded:
                    left, right = decoded.rsplit("@", 1)
                    method, password = left.split(":", 1)
                    if "#" in right:
                        hostport, _, frag = right.partition("#")
                        name = unquote(frag)
                    else:
                        hostport = right
                        name = None
                    if ":" in hostport:
                        host, port_s = hostport.split(":", 1)
                        port = int(port_s)
                    else:
                        host, port = hostport, 0
                else:
                    return None
            except Exception:
                return None

        tag = outbound_tag_from_name(name, idx, "ss")
        outbound: Outbound = {
            "type": "shadowsocks",
            "tag": tag,
            "server": host,
            "server_port": int(port or 0),
            "method": method,
            "password": password,
        }
        return outbound
    except Exception as e:
        logging.debug("ss parse failed for %s: %s", link, e)
        return None


def parse_trojan(link: str, idx: int) -> Optional[Outbound]:
    """
    trojan://password@host:port?params#name
    """
    try:
        parsed = urlparse(link)
        password = parsed.username or parsed.netloc.split("@")[0] if "@" in parsed.netloc else None
        host = parsed.hostname or ""
        port = parsed.port or 0
        name = unquote(parsed.fragment) if parsed.fragment else None
        tag = outbound_tag_from_name(name, idx, "trojan")
        outbound: Outbound = {
            "type": "trojan",
            "tag": tag,
            "server": host,
            "server_port": int(port),
            "password": password,
            # trojan often supports sni/tls
        }
        qs = parse_qs(parsed.query)
        if qs.get("sni"):
            outbound.setdefault("tls", True)
            outbound["sni"] = qs["sni"][0]
        elif qs.get("security") and qs["security"][0] != "none":
            outbound["tls"] = True
        return outbound
    except Exception as e:
        logging.debug("trojan parse failed for %s: %s", link, e)
        return None


def parse_hysteria2(link: str, idx: int) -> Optional[Outbound]:
    """
    Try to parse hysteria2 links: hysteria2://user:pass@host:port?params#name
    This is best-effort mapping to sing-box hysteria outbound.
    """
    try:
        parsed = urlparse(link)
        host = parsed.hostname or ""
        port = parsed.port or 0
        username = parsed.username
        password = parsed.password
        name = unquote(parsed.fragment) if parsed.fragment else None
        qs = parse_qs(parsed.query)
        tag = outbound_tag_from_name(name, idx, "hysteria2")
        outbound: Outbound = {
            "type": "hysteria",
            "tag": tag,
            "server": host,
            "server_port": int(port),
            # hysteria plugin-specific fields
            "up_mbps": int(qs.get("up", ["0"])[0]) if qs.get("up") else None,
            "down_mbps": int(qs.get("down", ["0"])[0]) if qs.get("down") else None,
        }
        if username or password:
            outbound["auth"] = {"user": username, "pass": password}
        if qs.get("obfs"):
            outbound["obfs"] = qs["obfs"][0]
        return outbound
    except Exception as e:
        logging.debug("hysteria2 parse failed for %s: %s", link, e)
        return None


def parse_tuic(link: str, idx: int) -> Optional[Outbound]:
    """
    TUIC parsing (best-effort).
    Example generic forms exist; we try to extract host/port/password/params.
    """
    try:
        parsed = urlparse(link)
        qs = parse_qs(parsed.query)
        host = parsed.hostname or ""
        port = parsed.port or 0
        name = unquote(parsed.fragment) if parsed.fragment else None
        tag = outbound_tag_from_name(name, idx, "tuic")
        outbound: Outbound = {
            "type": "tuic",
            "tag": tag,
            "server": host,
            "server_port": int(port),
            # tuic specifics: transport, password, obfs, etc.
        }
        if qs.get("password"):
            outbound["password"] = qs["password"][0]
        if qs.get("transport"):
            outbound["transport"] = {"type": qs["transport"][0]}
        return outbound
    except Exception as e:
        logging.debug("tuic parse failed for %s: %s", link, e)
        return None


PARSERS = {
    "vmess": parse_vmess,
    "vless": parse_vless,
    "ss": parse_ss,
    "trojan": parse_trojan,
    "hysteria2": parse_hysteria2,
    "tuic": parse_tuic,
}


def parse_link(link: str, idx: int) -> Optional[Outbound]:
    link = link.strip()
    if not link:
        return None
    # Some lines may still be base64 of a block of links
    if link.startswith("vmess://") or link.startswith("vless://") or link.startswith("ss://") or link.startswith("trojan://") or link.startswith("hysteria2://") or link.startswith("tuic://"):
        scheme = link.split("://", 1)[0].lower()
        parser = PARSERS.get(scheme)
        if parser:
            return parser(link, idx)
    # If the link appears to be base64 encoded inner content that contains links, caller handles splitting
    return None


# -----------------------
# Build sing-box config
# -----------------------

def build_base_config(outbounds: List[Outbound]) -> Dict[str, typing.Any]:
    """
    Construct the full config structure required by the prompt.
    outbounds should already contain all parsed server outbounds.
    We'll append the helper outbounds at the end.
    """
    # Helper outbounds
    helper_outbounds = [
        # selector "proxy" to let user pick manually (example)
        {
            "type": "selector",
            "tag": "proxy",
            "target": [o["tag"] for o in outbounds] or [],
            "strategy": "order",
        },
        # auto urltest
        {
            "type": "urltest",
            "tag": "auto",
            "url": "https://www.gstatic.com/generate_204",
            "timeout": 5,
            "interval": "30s",
            "probes": [o["tag"] for o in outbounds] or [],
        },
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
        {"type": "dns-out", "tag": "dns-out"},
    ]

    combined_outbounds = outbounds + helper_outbounds

    cfg: Dict[str, typing.Any] = {
        "$schema": "https://sing-box.sagernet.org/schema.json",
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "remote", "address": "tls://8.8.8.8", "detour": "proxy"},
                {"tag": "local", "address": "1.1.1.1", "detour": "direct"},
                {"tag": "block", "address": "rcode://success"},
            ],
            "rules": [{"outbound": "any", "server": "remote"}],
            "final": "remote",
            "strategy": "prefer_ipv4",
        },
        "ntp": {"enabled": True, "server": "time.apple.com", "server_port": 123, "interval": "30m"},
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                "auto_route": True,
                "strict_route": True,
                "stack": "system",
                "sniff": True,
            },
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 7890,
                "sniff": True,
            },
        ],
        "outbounds": combined_outbounds,
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"rule_set": ["geosite-ir", "geoip-ir", "geosite-private"], "outbound": "direct"},
                {"rule_set": "geosite-ads", "outbound": "block"},
            ],
            "rule_set": [
                {
                    "type": "remote",
                    "tag": "geosite-ir",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs",
                    "download_detour": "proxy",
                    "update_interval": "1d",
                },
                {
                    "type": "remote",
                    "tag": "geoip-ir",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs",
                    "download_detour": "proxy",
                    "update_interval": "1d",
                },
                {
                    "type": "remote",
                    "tag": "geosite-private",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-private.srs",
                    "download_detour": "proxy",
                    "update_interval": "1d",
                },
                {
                    "type": "remote",
                    "tag": "geosite-ads",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
                    "download_detour": "proxy",
                    "update_interval": "1d",
                },
            ],
            "auto_detect_interface": True,
        },
        "experimental": {
            "cache_file": {"enabled": True, "path": "cache.db", "store_fakeip": True},
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "external_ui": "ui",
                "external_ui_download_url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
                "external_ui_download_detour": "proxy",
                "default_mode": "rule",
            },
        },
    }
    return cfg


# -----------------------
# Main flow
# -----------------------

def dedupe_outbounds(outbounds: List[Outbound]) -> List[Outbound]:
    """
    Deduplicate outbounds based on server + server_port + credential fields (uuid/password).
    Returns filtered list preserving first occurrence order.
    """
    seen = set()
    unique = []
    for o in outbounds:
        server = o.get("server", "")
        port = o.get("server_port", 0)
        # Identify credential: prefer uuid, then password, then auth or method+password
        cred = o.get("uuid") or o.get("password") or json.dumps(o.get("auth", {}), sort_keys=True)
        key = (server, int(port or 0), str(cred))
        if key in seen:
            continue
        seen.add(key)
        unique.append(o)
    return unique


def parse_subscription_content(decoded_text: str) -> List[Outbound]:
    """
    Given decoded subscription text, split into lines and parse each supported link.
    The subscription may itself be a newline separated list of links, or base64 content which we already decoded.
    """
    outbounds: List[Outbound] = []
    lines = [ln.strip() for ln in decoded_text.splitlines() if ln.strip()]
    idx = 0
    for ln in lines:
        # Sometimes the subscription is a single long line containing another base64 block.
        # If line looks like base64 and decodes to text containing protocols, decode and flatten.
        try:
            if not any(ln.startswith(s) for s in ("vmess://", "vless://", "ss://", "trojan://", "hysteria2://", "tuic://")):
                # try base64 decode and see if contained text has known links
                decoded = safe_b64decode(ln).decode("utf-8", errors="ignore")
                if any(k in decoded for k in ("vmess://", "vless://", "ss://", "trojan://", "hysteria2://", "tuic://")):
                    # extend lines with inner lines
                    inner = [l.strip() for l in decoded.splitlines() if l.strip()]
                    lines.extend(inner)
                    continue
            parsed = parse_link(ln, idx)
            if parsed:
                outbounds.append(parsed)
                idx += 1
            else:
                logging.debug("Unsupported or unparsed link: %s", ln[:80])
        except Exception as e:
            logging.debug("Error parsing line: %s ; %s", ln[:80], e)
    return outbounds


def load_existing_output() -> Optional[str]:
    if OUTFILE.exists():
        try:
            return OUTFILE.read_text(encoding="utf-8")
        except Exception:
            return None
    return None


def write_output_if_changed(cfg: Dict[str, typing.Any]) -> bool:
    """
    Dump cfg to JSON file if changed compared to existing file.
    Returns True if wrote the file, False if unchanged.
    """
    new_text = json.dumps(cfg, indent=2, ensure_ascii=False, sort_keys=False)
    old_text = load_existing_output()
    if old_text is not None and old_text.strip() == new_text.strip():
        logging.info("Output unchanged, not writing file.")
        return False
    OUTFILE.write_text(new_text + "\n", encoding="utf-8")
    logging.info("Wrote output to %s", OUTFILE)
    return True


def main(argv: Optional[List[str]] = None) -> int:
    argv = argv or sys.argv[1:]
    parser = argparse.ArgumentParser(description="Convert subscription to sing-box javidbox.json")
    parser.add_argument("--url", "-u", help="Subscription URL (falls back to SUB_LINK env var)")
    args = parser.parse_args(argv)

    sub_link = args.url or os.environ.get("SUB_LINK")
    if not sub_link:
        logging.error("No subscription link provided. Set SUB_LINK env or pass --url.")
        return 2

    try:
        logging.info("Downloading subscription from %s", sub_link if len(sub_link) < 120 else sub_link[:120] + "...")
        raw = download_subscription(sub_link)
    except Exception as e:
        logging.error("Failed to download subscription: %s", e)
        logging.error("Keeping existing %s (if any).", OUTFILE)
        return 3

    # The downloaded content may itself be base64; try decode once.
    content_text = raw.strip()
    decoded_text = ""
    try:
        # If it looks like base64 blob (no spaces, many base64 chars), try decoding
        if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r" for c in content_text.replace("\n", "").replace("\r", "")) and len(content_text) > 0:
            try:
                decoded_text = safe_b64decode(content_text).decode("utf-8", errors="ignore")
            except Exception:
                decoded_text = content_text
        else:
            # If includes vmess:// or other schemes directly, keep raw
            decoded_text = content_text
    except Exception:
        decoded_text = content_text

    # If decoded_text still base64-like, attempt another decode pass (some providers double-encode)
    if not any(s in decoded_text for s in ("vmess://", "vless://", "ss://", "trojan://", "hysteria2://", "tuic://")):
        # second attempt
        try:
            dd = safe_b64decode(decoded_text).decode("utf-8", errors="ignore")
            if any(s in dd for s in ("vmess://", "vless://", "ss://", "trojan://", "hysteria2://", "tuic://")):
                decoded_text = dd
        except Exception:
            pass

    outbounds = parse_subscription_content(decoded_text)
    if not outbounds:
        logging.error("No valid servers parsed from subscription. Aborting without writing file.")
        return 4

    # Deduplicate
    before = len(outbounds)
    outbounds = dedupe_outbounds(outbounds)
    after = len(outbounds)
    logging.info("Parsed %d servers, %d after deduplication.", before, after)

    cfg = build_base_config(outbounds)

    try:
        wrote = write_output_if_changed(cfg)
        if wrote:
            logging.info("Config updated successfully. Servers: %d", len(outbounds))
        else:
            logging.info("No update needed.")
        return 0
    except Exception as e:
        logging.error("Failed to write config file: %s", e)
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
