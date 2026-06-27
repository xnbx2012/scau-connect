# scau-connect

> [English](README.md) | 中文

通过 Selenium 无头浏览器自动完成 SCAU（华南农业大学）aTrust 网关的 CAS 登录，将认证会话转换为本地 HTTP 代理，**自带 HTTPS MITM**，使 `curl` / `wget` / `Git` / 浏览器等任何 HTTP 客户端可直接通过本地端口访问校园网资源，无需手动输入 ticket，也无需打开官方 aTrust 客户端。

---

## 功能特性

| 功能 | 状态 | 说明 |
|------|------|------|
| Selenium 无头 CAS 登录 | ✅ 已实现 | 浏览器自动填账号密码，绕过 RSA 密码加密 |
| aTrust 会话管理 | ✅ 已实现 | sid、CASTGC、csrf_token 自动维护 |
| HTTP 代理（含 HTTPS MITM） | ✅ 已实现 | `localhost:1081` — 终结 TLS 后转发到 aTrust web proxy |
| 会话保活 + 自动重连 | ✅ 已实现 | 每 45s 探活，过期自动重新登录，解决"用一会儿就 502" |
| SOCKS5 代理 | ⚠️ 实验性 | 默认关闭；仅 80 端口的 HTTP 请求可用 |
| 会话持久化 | ✅ 已实现 | `.session.json` 自动保存/加载 |
| L3 隧道 | 🚧 第二阶段 | 暂未实现 |

---

## 环境要求

- Python ≥ 3.10
- Chrome 或 Edge 浏览器（Selenium WebDriver 自动调用）
- [uv](https://github.com/astral-sh/uv) 包管理器（推荐）

---

## 安装

```bash
# 克隆项目
git clone https://github.com/your-repo/scau-connect.git
cd scau-connect

# 安装依赖（自动创建 .venv）
uv sync

# 安装浏览器 WebDriver（如果尚未安装）
# Chrome:  通常随 Chrome 自动安装
# Edge:    通常随 Edge 自动安装
```

---

## 快速开始

### 第 1 步：首次登录（创建 `.env`）

在项目根目录创建 `.env` 文件，写入账号密码：

```bash
cat > .env << 'EOF'
SCAU_USERNAME=你的学号或工号
SCAU_PASSWORD=你的密码
EOF
```

然后一条命令启动代理：

```bash
uv run scau-connect login
```

成功后会看到：
```
登录成功
会话已保存到：.session.json
代理已启动
HTTP 代理：127.0.0.1:1081
按 Ctrl+C 停止
```

### 第 2 步：用 curl 测试

保持进程运行，**另开一个终端**：

```bash
# 普通 HTTP
curl --proxy http://127.0.0.1:1081 http://www.scau.edu.cn/

# HTTPS 需要 -k（本地 MITM 用的是自签 CA）
curl -k --proxy http://127.0.0.1:1081 https://www.scau.edu.cn/
```

### 第 3 步：日常使用

会话已保存到 `.session.json`。下次启动无需重新登录：

```bash
uv run scau-connect proxy
```

### 第 4 步：会话过期时重新登录

```bash
# 选项 A：删掉会话文件后重新走 login
rm .session.json
uv run scau-connect login

# 选项 B：先尝试 proxy，若失败再重新登录
uv run scau-connect proxy
```

---

## 进阶用法

```bash
uv run scau-connect login \
    --http-proxy-port 10891 \
    --socks5-proxy-port 10892 \
    --enable-socks5-proxy \
    --debug
```

---

## 命令行参考

### `scau-connect login`

执行 CAS 登录并保存会话。

```bash
uv run scau-connect login [OPTIONS]

选项：
  --server TEXT                VPN 服务器地址 (默认: vpn.scau.edu.cn)
  --port INTEGER              HTTPS 端口 (默认: 443)
  --username TEXT             账号（学号/工号）
  --password TEXT             密码
  --http-proxy-port INT        HTTP 代理端口 (默认: 1081)
  --socks5-proxy-port INT      SOCKS5 代理端口 (默认: 1080)
  --enable-http-proxy / --no-enable-http-proxy
  --enable-socks5-proxy / --no-enable-socks5-proxy
  --session-file PATH          会话保存路径 (默认: .session.json)
  --auto-reconnect / --no-auto-reconnect
  --debug, -d                  开启调试日志
  --headless-browser / --no-headless-browser
```

### `scau-connect proxy`

启动本地代理服务（不重新登录，使用已有会话）。

```bash
uv run scau-connect proxy [OPTIONS]
```

### `scau-connect status`

查看当前会话状态。

```bash
uv run scau-connect status [--session-file .session.json]
```

---

## 环境变量列表

所有配置均可通过 `SCAU_` 前缀的环境变量设置：

| 环境变量 | 配置项 | 类型 | 默认值 |
|----------|--------|------|--------|
| `SCAU_SERVER` | 服务器地址 | str | `vpn.scau.edu.cn` |
| `SCAU_PORT` | HTTPS 端口 | int | `443` |
| `SCAU_USERNAME` | 账号 | str | - |
| `SCAU_PASSWORD` | 密码 | str | - |
| `SCAU_HTTP_PROXY_PORT` | HTTP 代理端口 | int | `1081` |
| `SCAU_SOCKS5_PROXY_PORT` | SOCKS5 代理端口 | int | `1080` |
| `SCAU_ENABLE_HTTP_PROXY` | 启用 HTTP 代理 | bool | `true` |
| `SCAU_ENABLE_SOCKS5_PROXY` | 启用 SOCKS5（实验性） | bool | `false` |
| `SCAU_SESSION_FILE` | 会话文件路径 | str | `.session.json` |
| `SCAU_AUTO_RECONNECT` | 自动重连 | bool | `true` |
| `SCAU_DEBUG` | 调试模式 | bool | `false` |
| `SCAU_SKIP_SSL_VERIFY` | 跳过 SSL 验证 | bool | `true` |
| `SCAU_HEADLESS_BROWSER` | 无头浏览器 | bool | `true` |
| `SCAU_BROWSER` | 浏览器类型 | str | `chrome` |

---

## 代理使用

代理监听在 `127.0.0.1:1081`，支持 HTTP 和 HTTPS。

### 快速参考

| 客户端 | HTTP | HTTPS |
|--------|------|-------|
| `curl` | `curl --proxy http://127.0.0.1:1081 http://...` | `curl -k --proxy http://127.0.0.1:1081 https://...` |
| `wget` | `wget -e use_proxy=yes -e http_proxy=127.0.0.1:1081 http://...` | `wget --no-check-certificate ...` |
| `git` | `git config --global http.proxy http://127.0.0.1:1081` | `git config --global https.proxy http://127.0.0.1:1081` |
| Python `requests` | `proxies={'http': 'http://127.0.0.1:1081'}` | `proxies={'https': 'http://127.0.0.1:1081'}` + verify=False |
| 浏览器 | SwitchyOmega → `127.0.0.1:1081` | 同左，需导入本地 CA |

### curl

```bash
# HTTP
curl --proxy http://127.0.0.1:1081 http://www.scau.edu.cn/

# HTTPS —— 必须加 -k（本地 MITM CA 是自签的）
curl -k --proxy http://127.0.0.1:1081 https://www.scau.edu.cn/
```

### wget

```bash
wget -e use_proxy=yes -e http_proxy=127.0.0.1:1081 \
     --no-check-certificate \
     https://www.scau.edu.cn/
```

### Git

```bash
git config --global http.proxy  http://127.0.0.1:1081
git config --global https.proxy http://127.0.0.1:1081

# 验证
git clone https://github.com/some/repo.git
```

### Python requests

```python
import requests

proxies = {
    "http":  "http://127.0.0.1:1081",
    "https": "http://127.0.0.1:1081",
}

# HTTPS 必须关掉证书校验（或把 .proxy-ca/local-ca.crt.pem 配成 verify）
r = requests.get("https://www.scau.edu.cn/", proxies=proxies, verify=False)
print(r.status_code, len(r.text))
```

### 浏览器（推荐 SwitchyOmega）

1. 安装 [SwitchyOmega](https://github.com/FelisCatus/SwitchyOmega) 扩展
2. 新建情景模式 `scau-connect`，代理协议 `HTTP`，代理服务器 `127.0.0.1`，端口 `1081`
3. （HTTPS）导入 `.proxy-ca/local-ca.crt.pem` 到系统受信任的根证书颁发机构

---

## 会话保活与自动重连

aTrust 会话在若干分钟无活动后会过期，过期后所有代理请求会被网关重定向到登录页，表现为 **502 Bad Gateway**。本项目内置保活机制：

- **保活**：后台每 45 秒向 `/passport/v1/user/onlineInfo` 发一次心跳
- **自动重连**：检测到会话过期时，自动重新走 CAS 登录，刷新 cookies 后继续转发

> 💡 只要 `.env` 或命令行里有账号密码，`proxy` 命令也会自动启用保活和重连。

---

## HTTPS MITM 原理

```
curl --proxy http://127.0.0.1:1081
            │
            ▼
  本地代理 (127.0.0.1:1081)
  ┌─────────────────────────────────────┐
  │ 1. 返回 200 Connection Established   │
  │ 2. 用本地 CA 签的证书终结 TLS         │
  │ 3. 解密后还原成明文 HTTP 请求         │
  │ 4. 重写 Host + Cookie               │
  │ 5. 转发到 aTrust web proxy          │
  │ 6. 加密响应回传给客户端              │
  └─────────────────────────────────────┘
            │
            ▼
  *.s.vpn.scau.edu.cn:443 (aTrust 反向代理)
            │
            ▼
  目标网站
```

- 本地 CA 持久化在 `.proxy-ca/local-ca.crt.pem`
- 每个目标主机的 leaf 证书缓存在 `.proxy-ca/leaf/<sha256>.crt.pem`

---

## 工作原理

### 认证流程

```
1. GET /passport/v1/public/authConfig
   → 获取 csrf_token + 初始 sid cookie

2. Selenium 无头浏览器登录
   → 打开 CAS 登录页（浏览器自动处理 RSA 密码加密）
   → 填写账号密码并提交
   → 通过 CDP 获取 CASTGC、sid 等 HttpOnly cookie

3. GET /passport/v1/auth/authCheck
   → 获取 sidTicket

4. POST /passport/v1/public/ticketExchange
   → 交换 ticket 完成会话建立

5. GET /passport/v1/user/onlineInfo
   → 确认 isOnline = true

6. POST /controller/v1/user/clientResource
   → 获取资源信息（DNS、路由等）
```

---

## 项目结构

```
scau-connect/
├── pyproject.toml           # uv 项目配置
├── .env.example             # 环境变量示例
├── LICENSE                  # MIT 协议
├── README.md                # 英文文档
├── README_zh.md             # 中文文档
├── src/scau_connect/
│   ├── __init__.py
│   ├── __main__.py          # python -m scau_connect 入口
│   ├── cli.py               # Typer CLI 定义
│   ├── config.py            # 配置管理（dataclass + 环境变量）
│   ├── session.py           # 会话状态与持久化
│   ├── main.py              # 应用入口
│   ├── protocol/
│   │   ├── atrust.py        # aTrust 主协议
│   │   ├── base.py          # ProtocolBase 抽象基类
│   │   └── auth/
│   │       ├── base.py      # AuthenticatorBase
│   │       └── cas.py       # Selenium CAS 认证实现
│   ├── proxy/
│   │   ├── base.py            # 代理基类
│   │   ├── http.py            # HTTP CONNECT + 本地 TLS 终结
│   │   ├── certificates.py    # 本地 CA + per-host leaf 证书
│   │   ├── web_proxy_dialer.py # aTrust web proxy 连接层
│   │   ├── session_manager.py # 会话保活 + 过期自动重连
│   │   └── socks5.py          # SOCKS5 代理（实验性）
│   └── utils/
│       ├── http_client.py   # aTrust HTTP 客户端
│       ├── crypto.py        # 加密工具
│       └── logger.py        # structlog 封装
└── tests/
    ├── test_config.py       # 配置单元测试
    ├── test_tunnel.py       # L3 隧道测试
    └── test_tcp_tunnel_reader.py # TCP 隧道读取器测试
```

---

## 常见问题

### 安装 / 启动

**Q: 提示 "Failed to start WebDriver" / 找不到 chrome.exe**

确保系统装了 Chrome 或 Edge：

```bash
# Windows: 直接装 Chrome 浏览器即可，WebDriver 通常自带
# macOS:   brew install --cask google-chrome
# Linux:   sudo apt install google-chrome-stable
```

**Q: uv sync 报错 / 依赖装不上**

确认 uv 版本 ≥ 0.4（`uv --version`）。必要时删除 `.venv` 后重试：

```bash
rm -rf .venv
uv sync
```

### 登录

**Q: 浏览器无法访问登录页 / 一直转圈**

检查能否直接访问 `https://vpn.scau.edu.cn/`。若学校 VPN 网关本身宕机，等几分钟后重试。

**Q: 密码里有特殊字符，命令行传不进去**

优先用 `.env` 文件，环境变量能正确处理几乎所有特殊字符。如确实要用命令行参数，用单引号包裹：

```bash
uv run scau-connect login --username 'your_id' --password 'your!pass#word'
```

**Q: 想调试浏览器操作**

加 `--no-headless-browser` 参数，浏览器窗口会显示出来：

```bash
uv run scau-connect login --no-headless-browser
```

### 代理使用

**Q: curl HTTPS 报 "SSL certificate problem"**

三种解法：

```bash
# 方案 A（最快）：忽略证书校验
curl -k --proxy http://127.0.0.1:1081 https://example.com

# 方案 B（推荐用于脚本）：把本地 CA 加进 curl 信任链
export CURL_CA_BUNDLE="$(pwd)/.proxy-ca/local-ca.crt.pem"
curl --proxy http://127.0.0.1:1081 https://example.com

# 方案 C（永久）：Windows 上加到系统信任列表
#   双击 .proxy-ca/local-ca.crt.pem → 安装证书 → 受信任的根证书颁发机构
```

**Q: 浏览器每个 HTTPS 站点都弹 `不安全`**

把 `.proxy-ca/local-ca.crt.pem` 导入到操作系统的受信任根证书颁发机构。

**Q: `.proxy-ca/` 目录可以删吗？**

可以，是缓存。删了以后程序会重新生成。

**Q: 代理连得上，但访问任何网站都返回 502**

通常是 aTrust 会话已过期。如果用 `login` 命令（带账号密码）启动，应自动重连。若仍 502：

```bash
rm .session.json
uv run scau-connect login
```

### 会话

**Q: 如何彻底退出？**

按 `Ctrl+C` 发送中断信号，程序会保存会话、关闭浏览器、释放端口。

---

## 安全注意

- `.session.json` 文件包含敏感认证信息，请妥善保管
- 不要将该文件提交到代码仓库（已加入 `.gitignore`）
- 生产环境建议使用文件权限限制：`chmod 600 .session.json`

---

## 贡献指南

欢迎贡献代码！

1. Fork 本仓库
2. 创建你的功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

---

## 开源协议

本项目采用 MIT 协议开源 — 详见 [LICENSE](LICENSE) 文件。

---

## 参考资料

- [SCAU VPN 网关](https://vpn.scau.edu.cn)
- [Selenium 文档](https://www.selenium.dev/documentation/)
- [深信服 aTrust](https://www.sangfor.com/)
- [浙江大学 zju-connect (参考实现)](https://github.com/Mythologyli/zju-connect)
