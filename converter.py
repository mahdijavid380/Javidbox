import json
import os
import urllib.request
import sys

# قالب ثابت (بر اساس فایل نمونه)
BASE_CONFIG = {
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
            {"clash_mode": "Direct", "server": "dns-direct"},
            {"clash_mode": "Global", "server": "dns-remote"}
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
    "route": {
        "rules": [
            {"ip_cidr": "172.19.0.2", "action": "hijack-dns"},
            {"clash_mode": "Direct", "outbound": "direct"},
            {"clash_mode": "Global", "outbound": "✅  Select"},
            {"action": "sniff"},
            {"protocol": "dns", "action": "hijack-dns"},
            {"ip_is_private": True, "outbound": "direct"},
            {"network": "udp", "action": "reject"}
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


def fetch_subscription(sub_link):
    """دریافت محتوای ساب‌لینک (فرض بر JSON با کلید 'outbounds')"""
    try:
        with urllib.request.urlopen(sub_link, timeout=30) as response:
            data = json.load(response)
            # اگر کلید outbounds وجود داشته باشد
            if "outbounds" in data:
                return data["outbounds"]
            # در غیر این صورت کل محتوا را به عنوان outbounds فرض می‌کنیم (آرایه)
            elif isinstance(data, list):
                return data
            else:
                raise ValueError("فرمت ساب‌لینک نامعتبر است")
    except Exception as e:
        print(f"خطا در دریافت ساب‌لینک: {e}")
        sys.exit(1)


def build_outbounds(remote_outbounds):
    """ساختار outbounds نهایی با افزودن Selector و Urltest"""
    # فیلتر کردن outboundهای اضافی (در صورت وجود selector/urltest)
    filtered = []
    for ob in remote_outbounds:
        if ob.get("type") not in ["selector", "urltest"]:
            filtered.append(ob)

    # لیست tagهای تمام outboundهای واقعی
    tags = [ob["tag"] for ob in filtered if "tag" in ob]

    # ساخت Selector
    selector = {
        "type": "selector",
        "tag": "✅  Select",
        "outbounds": tags.copy(),
        "interrupt_exist_connections": False
    }

    # ساخت Urltest
    urltest = {
        "type": "urltest",
        "tag": "Best Ping 🚀",
        "outbounds": tags.copy(),
        "url": "https://www.gstatic.com/generate_204",
        "interval": "30s",
        "interrupt_exist_connections": False
    }

    # outboundهای نهایی: selector, urltest, سپس بقیه
    final_outbounds = [selector, urltest] + filtered
    return final_outbounds


def main():
    sub_link = os.environ.get("SUB_LINK")
    if not sub_link:
        print("متغیر محیطی SUB_LINK تنظیم نشده است")
        sys.exit(1)

    print("دریافت ساب‌لینک...")
    remote_outbounds = fetch_subscription(sub_link)
    print(f"تعداد outbound دریافت شده: {len(remote_outbounds)}")

    # ساخت outbounds جدید
    new_outbounds = build_outbounds(remote_outbounds)

    # به‌روزرسانی قالب
    config = BASE_CONFIG.copy()
    config["outbounds"] = new_outbounds

    # ذخیره در فایل javidbox
    with open("javidbox", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
        f.write("\n")  # افزودن newline در انتها

    print("فایل javidbox با موفقیت تولید شد.")


if __name__ == "__main__":
    main()
