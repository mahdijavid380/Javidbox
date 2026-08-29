import json
import os
import urllib.request
import sys
import base64

# ===== قالب ثابت (همان فایل نمونه) =====
BASE_CONFIG = {
    "log": {
        "disabled": False,
        "level": "warn",
        "timestamp": True
    },
    "dns": {
        "servers": [
            {"type": "https", "tag": "dns-remote", "server": "8.8.8.8", "detour": "✅  Select"},
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

def fetch_subscription(sub_link):
    """
    دریافت محتوا از لینک و تلاش برای استخراج آرایه outboundها.
    فرمت‌های پشتیبانی‌شده:
      - JSON خام حاوی کلید "outbounds" یا خود یک آرایه
      - Base64 از JSON (با همان ساختار)
    اگر هیچکدام کار نکرد، خطا با نمایش محتوای دریافتی (۲۰۰ کاراکتر اول) صادر می‌شود.
    """
    try:
        req = urllib.request.Request(sub_link, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read().decode('utf-8-sig').strip()
            if not raw:
                raise ValueError("پاسخ دریافتی خالی است.")

            # 1. تلاش برای JSON مستقیم
            try:
                data = json.loads(raw)
                if "outbounds" in data:
                    return data["outbounds"]
                if isinstance(data, list):
                    return data
                # اگر یک شیء دیگر بود، شاید کلید دیگری داشته باشد – می‌توانید کلیدهای احتمالی را اضافه کنید
            except json.JSONDecodeError:
                pass

            # 2. تلاش برای Base64
            try:
                decoded = base64.b64decode(raw).decode('utf-8')
                data = json.loads(decoded)
                if "outbounds" in data:
                    return data["outbounds"]
                if isinstance(data, list):
                    return data
            except Exception:
                pass

            # اگر هیچکدام موفق نشد، خطا با نمایش بخشی از محتوا
            preview = raw[:200] + ("..." if len(raw) > 200 else "")
            raise ValueError(f"فرمت پشتیبانی نمی‌شود. محتوای دریافتی:\n{preview}")

    except Exception as e:
        print(f"❌ خطا در دریافت ساب‌لینک: {e}")
        sys.exit(1)

def build_outbounds(remote_outbounds):
    """ساخت Selector و Urltest و فیلتر کردن outboundهای تکراری"""
    # حذف outboundهای از نوع selector/urltest (اگر در ساب وجود داشته باشند)
    filtered = [ob for ob in remote_outbounds if ob.get("type") not in ["selector", "urltest"]]
    # استخراج tagها
    tags = [ob["tag"] for ob in filtered if "tag" in ob]
    if not tags:
        print("⚠️ هشدار: هیچ outbound با tag معتبر پیدا نشد. ممکن است ساختار ساب‌لینک نامناسب باشد.")

    selector = {
        "type": "selector",
        "tag": "✅  Select",
        "outbounds": tags.copy(),
        "interrupt_exist_connections": False
    }
    urltest = {
        "type": "urltest",
        "tag": "Best Ping 🚀",
        "outbounds": tags.copy(),
        "url": "https://www.gstatic.com/generate_204",
        "interval": "30s",
        "interrupt_exist_connections": False
    }
    # قرار دادن selector و urltest در ابتدا، سپس بقیه
    return [selector, urltest] + filtered

def main():
    sub_link = os.environ.get("SUB_LINK")
    if not sub_link:
        print("❌ متغیر محیطی SUB_LINK تنظیم نشده است.")
        sys.exit(1)

    print("🔄 دریافت ساب‌لینک...")
    remote_outbounds = fetch_subscription(sub_link)
    print(f"✅ تعداد outbound دریافت شده: {len(remote_outbounds)}")

    new_outbounds = build_outbounds(remote_outbounds)
    config = BASE_CONFIG.copy()
    config["outbounds"] = new_outbounds

    with open("javidbox", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print("✅ فایل javidbox با موفقیت تولید شد.")

if __name__ == "__main__":
    main()
