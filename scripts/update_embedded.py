#!/usr/bin/env python3
"""探测 Google Chrome 最新版本，更新 index.html 内嵌数据"""
import json
import re
import urllib.request
from datetime import datetime, timezone, timedelta

API_URL = "https://update.googleapis.com/service/update2"
APPID = "{8A69D345-D564-463C-AFF1-A69D9E530F96}"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


def probe(arch: str):
    xml_body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<request protocol="3.0" version="1.3.36.155">'
        f'<os version="10.0.22631" platform="win" sp="" arch="{arch}"/>'
        f'<app appid="{APPID}" version="" nextversion="" lang="" brand="" client="" ap="{arch}-stable">'
        '<updatecheck target="" targetchannel=""/></app></request>'
    )
    req = urllib.request.Request(API_URL, data=xml_body.encode(), headers={"Content-Type": "application/xml", "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=20) as resp:
        text = resp.read().decode("utf-8", errors="ignore")

    ver = re.search(r'<manifest version="([^"]+)"', text)
    code = re.search(r'<url codebase="(https://dl\.google\.com/[^"]+)"', text)
    pkg = re.search(r'name="([^"]+\.exe)"', text)
    size = re.search(r'required="true" size="(\d+)"', text)
    if not (ver and code and pkg):
        raise RuntimeError(f"{arch} 解析失败")
    dl = code.group(1) + pkg.group(1)
    sz = f"{int(size.group(1)) / 1048576:.0f}MB" if size else "?"
    return {"version": ver.group(1), "size": sz, "downloadURL": dl}


def main():
    new_data = {"checked_at": datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M")}
    for arch in ("x64", "arm64"):
        try:
            new_data[arch] = probe(arch)
            print(f"{arch}: v{new_data[arch]['version']} {new_data[arch]['size']}")
        except Exception as e:
            print(f"{arch} 探测失败: {e}")

    with open("index.html", "r", encoding="utf-8") as f:
        html = f.read()

    pattern = re.compile(r"var EMBEDDED_DATA = \{.*?\};", re.S)
    block = "var EMBEDDED_DATA = " + json.dumps(new_data, ensure_ascii=False, indent=2) + ";"
    new_html, n = pattern.subn(block, html)
    if n == 0:
        raise RuntimeError("未找到 EMBEDDED_DATA 块")
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(new_html)
    print("index.html 已更新")


if __name__ == "__main__":
    main()
