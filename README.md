# chrome-installer

Google Chrome 离线安装包下载页（官方 Google Update 直链）

- 数据来源：update.googleapis.com（Google Update API）
- 版本：Windows x64 / ARM64 稳定版
- 部署：Cloudflare Pages → chrome-installer.pages.dev

## 自动更新

GitHub Actions 每天自动探测最新版本，更新 index.html 内嵌数据并推送，
触发 Cloudflare Pages 自动部署。
