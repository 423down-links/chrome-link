#!/usr/bin/env python3
"""探测 Google Chrome 全部通道版本（稳定/Beta/Dev/Canary/Win7/企业版MSI），更新 index.html 内嵌数据

数据源（全部为 Google 官方接口/官方镜像，不依赖任何第三方仓库，可长期运行）：
- 消费版：Google Update API（update.googleapis.com/service/update2，XML 协议）
  · x64/x86 各通道：os arch=x64 + ap=x64-{chan}/x86-{chan}
  · arm64 仅 stable 通道有官方构建（os arch=arm64 + ap=arm64-stable，os 须报 Win11）
  · canary 使用独立 appguid {4EA16AC7-FD5A-47C3-875B-DBF4A2008C20}
  · 下载域名统一走 Google 官方镜像 edgedl.me.gvt1.com/edgedl/release2/chrome
- 企业版 MSI：Google 官方镜像 edgedl.me.gvt1.com/dl/chrome/install/...，
  SHA256 由本脚本下载完整文件自动计算；版本与 stable 同步，版本未变时复用上一次结果
- Win7/2008R2：Chrome 109 为最后支持版本，最终 build 109.0.5414.168，
  官方镜像直链 + 固定 SHA256（永不再更新）
"""
import email.utils as eut
import hashlib
import json
import os
import re
import urllib.request
from datetime import datetime, timezone

APPID_STABLE = "{8A69D345-D564-463C-AFF1-A69D9E530F96}"
APPID_CANARY = "{4EA16AC7-FD5A-47C3-875B-DBF4A2008C20}"
UA = "Chrome/155.0.8059.40"

# 官方域名 → 官方镜像（gvt1 为 Google 自有 CDN，与 dl.google.com 内容一致）
MIRROR_MAP = [
    ("https://dl.google.com/release2/chrome/",
     "https://edgedl.me.gvt1.com/edgedl/release2/chrome/"),
]

# (key, appid, os_arch, ap, channel_label, arch) —— 消费版
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

# 企业版 MSI（Google 官方镜像，文件名小写，直链始终指向最新版）
ENTERPRISE_TEMPLATES = [
    {"key": "enterprise-x64", "arch": "x64",
     "fileName": "googlechromestandaloneenterprise64.msi",
     "downloadURL": "https://edgedl.me.gvt1.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"},
    {"key": "enterprise-x86", "arch": "x86",
     "fileName": "googlechromestandaloneenterprise.msi",
     "downloadURL": "https://edgedl.me.gvt1.com/dl/chrome/install/googlechromestandaloneenterprise.msi"},
]

# Win7 固定条目（最终 build 109.0.5414.168，官方镜像直链，永不再更新）
WIN7_ITEMS = [
    {"key": "win7-x64", "channel": "Win7/2008R2", "arch": "x64",
     "version": "109.0.5414.168", "size": "89MB",
     "fileName": "109.0.5414.168_chrome_installer.exe",
     "sha256": "5fccbc9fb42a616c06b6bda64086d045908a8e6a23ac739baa1454dbf31b091b",
     "downloadURL": "https://edgedl.me.gvt1.com/edgedl/release2/chrome/nvwf3mhcdg76ot6qwp75ovmh2u_109.0.5414.168/109.0.5414.168_chrome_installer.exe"},
    {"key": "win7-x86", "channel": "Win7/2008R2", "arch": "x86",
     "version": "109.0.5414.168", "size": "85MB",
     "fileName": "109.0.5414.168_chrome_installer.exe",
     "sha256": "373b7260e2e464759b6ae4a8133cdc4145397d7b72012b6f62f5b1fa4918188f",
     "downloadURL": "https://edgedl.me.gvt1.com/edgedl/release2/chrome/p5iizujxrjjggjfl7d4kvj5e5i_109.0.5414.168/109.0.5414.168_chrome_installer.exe"},
]


def _mirror(url: str) -> str:
    for old, new in MIRROR_MAP:
        url = url.replace(old, new)
    return url


def probe(appid: str, os_arch: str, ap: str):
    """Google Update XML 探测最新版完整安装包"""
    osver = "10.0.22631" if os_arch == "arm64" else "10.0.19045"
    xml_body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<request protocol="3.0" version="{UA}" ismachine="1" installsource="ondemandcheckforupdate" dedup="cr">'
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
        "downloadURL": _mirror(cb.group(1) + name.group(1)),
        "sha256": h.group(1).lower() if h else "",
        "fileName": name.group(1),
    }


def ver_key(v: str):
    return tuple(int(x) for x in v.split("."))


def probe_stable(appid: str, os_arch: str, ap: str, key: str):
    """多次探测取最新稳定包：过滤异常大小（标准 uncompressed 包 200~600MB），版本号取最高"""
    best = None
    for _ in range(6):  # 重试 6 次：beta x64 偶发 717MB 多语言旧变体，多试取正常最高版
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


def download_sha256(url: str, retries: int = 3):
    """流式下载完整文件，计算 SHA256 与字节数（带重试）"""
    last = None
    for _ in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            h = hashlib.sha256()
            size = 0
            with urllib.request.urlopen(req, timeout=60) as r:
                while True:
                    b = r.read(1 << 20)
                    if not b:
                        break
                    h.update(b)
                    size += len(b)
            return h.hexdigest(), size
        except Exception as e:
            last = e
    raise last


def head_last_modified(url: str) -> str:
    """HEAD 安装包取 Last-Modified（官方文件时间），返回带 Z 的 UTC ISO"""
    for _ in range(3):
        try:
            req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=25) as r:
                lm = r.headers.get("Last-Modified")
                if lm:
                    return eut.parsedate_to_datetime(lm).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            continue
    return ""


VH_PLATFORM = {"x64": "win64", "x86": "win", "arm64": "winarm64"}
VH_CHANNEL = {"稳定版": "stable", "Beta": "beta", "Dev": "dev", "Canary": "canary"}


def versionhistory_published(channel: str, arch: str, version: str) -> str:
    """Chrome 官方 Version History API：取该版本的 startTime（官方发布/开始推送时间）。
    同一版本会因分批放量出现多条记录，取最早的 startTime 才是真正的发布时刻；
    失败时由调用方回退 Last-Modified（那是文件上传时间，可能早于发布，仅作兜底）。"""
    if os.environ.get("SKIP_VH"):  # 本地沙箱代理白名单外，跳过（GitHub Actions 不设此变量）
        return ""
    plat = VH_PLATFORM.get(arch)
    ch = VH_CHANNEL.get(channel)
    if not plat or not ch:
        return ""
    url = (f"https://versionhistory.googleapis.com/v1/chrome/platforms/{plat}/channels/{ch}"
           f"/releases?order_by=starttime%20desc&page_size=15")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=25) as r:
            data = json.loads(r.read().decode())
        best = ""
        for rel in data.get("releases", []):
            if rel.get("version") != version:
                continue
            st = rel.get("startTime") or rel.get("eventTime") or ""
            if not st:
                continue
            st = st.replace("Z", "+00:00").replace("z", "+00:00")
            try:
                dt = datetime.fromisoformat(st)
            except Exception:
                continue
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            iso = dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if not best or iso < best:  # 最早的 startTime = 真正发布时刻
                best = iso
        return best
    except Exception:
        return ""


def main():
    with open("index.html", "r", encoding="utf-8") as f:
        html = f.read()

    # 解析上一次嵌入数据（企业版版本没变时复用其 SHA，避免每天下载 320MB）
    old_items = {}
    m = re.search(r"var EMBEDDED_DATA = (\{.*?\});", html, re.S)
    if m:
        try:
            for it in json.loads(m.group(1)).get("items", []):
                old_items[it["key"]] = it
        except Exception:
            pass

    items = []
    stable_version = ""
    for key, appid, os_arch, ap, label, arch in TARGETS:
        try:
            info = probe_stable(appid, os_arch, ap, key)
            info["key"] = key
            info["channel"] = label
            info["arch"] = arch
            # 官方发布时间：Version History 优先，失败回退文件 Last-Modified
            info["published"] = versionhistory_published(label, arch, info["version"]) \
                or head_last_modified(info["downloadURL"])
            items.append(info)
            print(f"{key:14s} v{info['version']:18s} {info['size']:6s} pub={info['published']}")
            if key == "stable-x64":
                stable_version = info["version"]
        except Exception as e:
            print(f"{key:14s} 探测失败: {e}")

    # 企业版 MSI：版本没变复用旧 SHA，版本变化则下载重新计算
    for t in ENTERPRISE_TEMPLATES:
        old = old_items.get(t["key"])
        if old and old.get("version") == stable_version and len(old.get("sha256", "")) == 64:
            sha = old["sha256"]
            size = old.get("size", "?")
            print(f"{t['key']:14s} v{stable_version:18s} {size:6s} SHA复用")
        else:
            sha, nbytes = download_sha256(t["downloadURL"])
            size = f"{nbytes / 1048576:.0f}MB"
            print(f"{t['key']:14s} v{stable_version:18s} {size:6s} SHA自动计算 {sha[:12]}")
        # 企业版随 stable 发布：用 stable 官方时间，失败回退 Last-Modified
        pub = versionhistory_published("稳定版", t["arch"], stable_version) \
            or head_last_modified(t["downloadURL"])
        items.append({**t, "channel": "企业版MSI", "version": stable_version,
                      "size": size, "sha256": sha, "published": pub})

    for w in WIN7_ITEMS:
        if not w.get("published"):  # Win7 终版：取官方文件 Last-Modified
            w["published"] = head_last_modified(w["downloadURL"])
    items.extend(WIN7_ITEMS)
    for w in WIN7_ITEMS:
        print(f"{w['key']:14s} v{w['version']:18s} {w['size']:6s} pub={w['published']}")

    new_data = {
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "items": items,
    }

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
