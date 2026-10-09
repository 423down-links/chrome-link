#!/usr/bin/env python3
"""探测 Google Chrome 全部通道版本（稳定/Beta/Dev/Canary/Win7/企业版MSI），更新 index.html 内嵌数据

数据源：
- 消费版：Google Update API（update.googleapis.com/service/update2，XML 协议）
  · x64/x86 各通道：os arch=x64 + ap=x64-{chan}/x86-{chan}
  · arm64 仅 stable 通道有官方构建（os arch=arm64 + ap=arm64-stable）
  · canary 使用独立 appguid {4EA16AC7-FD5A-47C3-875B-DBF4A2008C20}
- 企业版 MSI：Google 官方静态直链 dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise*.msi
  （直链始终指向最新企业版，无静态 SHA256，版本与当前 stable 同步）
- Win7：Chrome 109 为最后支持版本（2023-01），最终 build 109.0.5414.121，
  官方已停止提供 109 离线包直链，入口指向官方系统要求说明页
"""
import json
import re
import urllib.request
from datetime import datetime, timezone

APPID_STABLE = "{8A69D345-D564-463C-AFF1-A69D9E530F96}"
APPID_CANARY = "{4EA16AC7-FD5A-47C3-875B-DBF4A2008C20}"
UA = "Chrome/155.0.8059.40"

# (key, appid, os_arch, ap, channel_label, arch)
TARGETS = [
    ("stable-x64",   APPID_STABLE, "x64",   "x64-stable",   "稳定版", "x64"),
    ("stable-x86",   APPID_STABLE, "x64",   "x86-stable",   "稳定版", "x86"),
    ("stable-arm64", APPID_STABLE, "arm64", "arm64-stable", "稳定版", "arm64"),
    ("beta-x64",     APPID_STABLE, "x64",   "x64-beta",     "Beta",   "x64"),
    ("beta-x86",     APPID_STABLE, "x64",   "x86-beta",     "Beta",   "x86"),
    ("dev-x64",      APPID_STABLE, "x64",   "x64-dev",      "Dev",    "x64"),
    ("dev-x86",      APPID_STABLE, "x64",   "x86-dev",      "Dev",    "x86"),
    ("canary-x64",   APPID_CANARY, "x64",   "x64-canary",   "Canary", "x64"),
    ("canary-x86",   APPID_CANARY, "x64",   "x86-canary",   "Canary", "x86"),
]

# 企业版 MSI（官方静态直链，始终指向最新版）
ENTERPRISE_TEMPLATES = [
    {"key": "enterprise-x64", "channel": "企业版MSI", "arch": "x64",
     "fileName": "GoogleChromeStandaloneEnterprise64.msi",
     "downloadURL": "https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi"},
    {"key": "enterprise-x86", "channel": "企业版MSI", "arch": "x86",
     "fileName": "GoogleChromeStandaloneEnterprise.msi",
     "downloadURL": "https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise.msi"},
]

# Win7 固定条目（官方最终版 109.0.5414.121，官方已停供直链）
WIN7_ITEMS = [
    {"key": "win7-x64", "channel": "Win7/2008R2", "arch": "x64",
     "version": "109.0.5414.121", "size": "—",
     "fileName": "Chrome-109-x64（官方最终版，已停供直链）", "sha256": "",
     "downloadURL": "https://support.google.com/chrome/a/answer/7100626"},
    {"key": "win7-x86", "channel": "Win7/2008R2", "arch": "x86",
     "version": "109.0.5414.121", "size": "—",
     "fileName": "Chrome-109-x86（官方最终版，已停供直链）", "sha256": "",
     "downloadURL": "https://support.google.com/chrome/a/answer/7100626"},
]


def probe(appid: str, os_arch: str, ap: str):
    """Google Update XML 探测最新版完整安装包"""
    # arm64 通道要求 Windows 11（10.0.22631），x64/x86 用 Windows 10
    osver = "10.0.22631" if os_arch == "arm64" else "10.0.19045"
    xml_body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<request protocol="3.0" version="Chrome/155.0.8059.40" ismachine="1" installsource="ondemandcheckforupdate" dedup="cr">'
        f'<os platform="win" version="{osver}" arch="{os_arch}" sp=""/>'
        f'<app appid="{appid}" ap="{ap}" version="" lang="zh-CN" brand="GCEA" installage="1">'
        '<updatecheck/></app></request>'
    )
    req = urllib.request.Request("https://update.googleapis.com/service/update2",
                                 data=xml_body.encode(),
                                 headers={"Content-Type": "application/xml", "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=25) as resp:
        text = resp.read().decode("utf-8", errors="ignore")

    ver = re.search(r'<manifest version="([^"]+)"', text)
    name = re.search(r'<package[^>]*name="([^"]+)"', text)
    size = re.search(r'<package[^>]*size="(\d+)"', text)
    h = re.search(r'hash_sha256="([^"]+)"', text)
    cb = re.search(r'<url codebase="(https://[^"]+)"', text)
    if not (ver and name and cb):
        raise RuntimeError(f"{ap} 解析失败")
    return {
        "version": ver.group(1),
        "size": f"{int(size.group(1)) / 1048576:.0f}MB" if size else "?",
        "downloadURL": cb.group(1) + name.group(1),
        "sha256": h.group(1).lower() if h else "",
        "fileName": name.group(1),
    }


def head_size(url: str) -> int:
    req = urllib.request.Request(url, method="HEAD")
    with urllib.request.urlopen(req, timeout=20) as resp:
        return int(resp.headers.get("Content-Length", 0))


def ver_key(v: str):
    return tuple(int(x) for x in v.split("."))


def probe_stable(appid: str, os_arch: str, ap: str, key: str):
    """多次探测取最新稳定包：过滤异常大小（标准 uncompressed 包 200~600MB），版本号取最高"""
    best = None
    for _ in range(3):
        try:
            r = probe(appid, os_arch, ap)
            size_mb = int(r["size"].rstrip("MB"))
            if size_mb < 200 or size_mb > 600:
                continue  # 异常包（如 beta 多语言变体 717MB），重试
            if best is None or ver_key(r["version"]) > ver_key(best["version"]):
                best = r
        except Exception:
            continue
    if best is None:
        raise RuntimeError(f"{key} 无稳定结果")
    return best


def main():
    items = []
    stable_version = ""
    for key, appid, os_arch, ap, label, arch in TARGETS:
        try:
            info = probe_stable(appid, os_arch, ap, key)
            info["key"] = key
            info["channel"] = label
            info["arch"] = arch
            items.append(info)
            print(f"{key:14s} v{info['version']:18s} {info['size']:6s} sha={info['sha256'][:12] or '-':12s} {info['fileName'][:45]}")
            if key == "stable-x64":
                stable_version = info["version"]
        except Exception as e:
            print(f"{key:14s} 探测失败: {e}")

    # 企业版 MSI：版本与 stable 同步，动态直链无静态 SHA
    for t in ENTERPRISE_TEMPLATES:
        try:
            size = f"{head_size(t['downloadURL']) / 1048576:.0f}MB"
        except Exception:
            size = "?"
        items.append({**t, "version": stable_version or "最新企业版", "size": size, "sha256": ""})
        print(f"{t['key']:14s} v{stable_version or '最新':18s} {size:6s}（动态直链）")

    items.extend(WIN7_ITEMS)
    for w in WIN7_ITEMS:
        print(f"{w['key']:14s} v{w['version']}（官方最终版，已停供直链）")

    new_data = {
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "items": items,
    }

    with open("index.html", "r", encoding="utf-8") as f:
        html = f.read()
    pattern = re.compile(r"var EMBEDDED_DATA = \{.*?\};", re.S)
    block = "var EMBEDDED_DATA = " + json.dumps(new_data, ensure_ascii=False, indent=2) + ";"
    new_html, n = pattern.subn(block, html)
    if n == 0:
        raise RuntimeError("未找到 EMBEDDED_DATA 块")
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(new_html)
    print(f"\nindex.html 已更新（{len(items)} 个版本条目）")


if __name__ == "__main__":
    main()
