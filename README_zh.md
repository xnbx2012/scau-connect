# scau-connect

> English | [中文](README_zh.md)

通过 Selenium 无头浏览器自动完成 SCAU（华南农业大学）aTrust 网关的 CAS 登录，将认证会话转换为本地 HTTP 代理，支持 HTTPS MITM，使 `curl` / `wget` / `Git` / 浏览器等任何 HTTP 客户端可直接通过本地端口访问校园网资源。

---

## 功能特性

| 功能 | 状态 | 说明 |
|------|------|------|
| Selenium 无头 CAS 登录 | ✅ | 浏览器自动处理 RSA 密码加密 |
| aTrust 会话管理 | ✅ | sid、CASTGC、csrf_token 自动维护 |
| HTTP 代理（含 HTTPS MITM） | ✅ | `localhost:1081` — 本地终结 TLS，转发到 aTrust web proxy |
| 会话保活 + 自动重连 | ✅ | 每 45s 探活，过期自动重新登录，解决 502 问题 |
| TCP 隧道拨号器 | ✅ | 通过 node:441 连接内网 IP（如 `222.201.229.x`） |
| L3 隧道（WebSocket） | ✅ | 持久隧道用于心跳和会话保活 |
| 会话持久化 | ✅ | `.session.json` 自动保存/加载 |
| SOCKS5 代理 | ⚠️ | 实验性，默认关闭 |

---

## 环境要求

- Python ≥ 3.10
- Chrome 或 Edge 浏览器（Selenium WebDriver 自动调用）
- [uv](https://github.com/astral-sh/uv) 包管理器（推荐）

---

## 安装

### 方式一：下载 EXE（推荐大多数用户使用）

对于非技术用户，可从 GitHub Releases 下载独立可执行文件：

1. 访问 [scau-connect Releases](https://github.com/xnbx2012/scau-connect/releases)
2. 下载最新的 `scau-connect.exe`
3. 双击运行即可

**首次运行：** 程序会提示输入用户名和密码，然后启动代理。

**命令行用法：**
```bash
# 登录并启动代理
scau-connect.exe login --username 你的学号 --password 你的密码

# 使用已有会话启动（无需登录）
scau-connect.exe proxy

# 其他选项
scau-connect.exe login --http-proxy-port 1081 --debug
```

### 方式二：从源码安装

```bash
git clone https://github.com/xnbx2012/scau-connect.git
cd scau-connect
uv sync
```

---

## 快速开始

### 首次登录

在项目根目录创建 `.env` 文件，写入账号密码：

```bash
cat > .env << 'EOF'
SCAU_USERNAME=你的学号或工号
SCAU_PASSWORD=你的密码
EOF
```

然后启动代理：

```bash
uv run scau-connect login
```

输出：
```
登录成功
会话已保存到：.session.json
代理已启动
HTTP 代理：127.0.0.1:1081
按 Ctrl+C 停止
```

### 使用 curl 测试

另开一个终端：

```bash
# HTTP
curl --proxy http://127.0.0.1:1081 http://www.scau.edu.cn/

# HTTPS（需要 -k，因为 MITM 使用自签 CA）
curl -k --proxy http://127.0.0.1:1081 https://www.scau.edu.cn/
```

### 日常使用

会话已持久化，无需重新登录：

```bash
uv run scau-connect proxy
```

### 会话过期时

```bash
# 方式 A：删除会话文件后重新登录
rm .session.json
uv run scau-connect login

# 方式 B：使用 proxy 命令，如有凭证会自动重连
uv run scau-connect proxy
```

---

## 命令行参考

### `scau-connect login`

执行 CAS 登录并启动代理，保存会话。

```bash
uv run scau-connect login [OPTIONS]

选项：
  --server TEXT                VPN 服务器地址（默认：vpn.scau.edu.cn）
  --port INTEGER              HTTPS 端口（默认：443）
  --username TEXT             账号（学号/工号）
  --password TEXT             密码
  --http-proxy-host TEXT      HTTP 代理监听地址（默认：0.0.0.0）
  --http-proxy-port INT       HTTP 代理端口（默认：1081）
  --socks5-proxy-host TEXT    SOCKS5 代理监听地址（默认：0.0.0.0）
  --socks5-proxy-port INT     SOCKS5 代理端口（默认：1080）
  --enable-http-proxy / --no-enable-http-proxy
  --enable-socks5-proxy / --no-enable-socks5-proxy
  --session-file PATH          会话保存路径（默认：.session.json）
  --auto-reconnect / --no-auto-reconnect
  --debug, -d                 开启调试日志
  --headless-browser / --no-headless-browser
```

### `scau-connect proxy`

使用已有会话启动代理（不重新登录）。

```bash
uv run scau-connect proxy [OPTIONS]
```

### `scau-connect status`

查看当前会话状态。

```bash
uv run scau-connect status [--session-file .session.json]
```

---

## 环境变量

所有配置均可通过 `SCAU_` 前缀的环境变量设置：

| 环境变量 | 说明 | 默认值 |
|----------|------|--------|
| `SCAU_SERVER` | 服务器地址 | `vpn.scau.edu.cn` |
| `SCAU_PORT` | HTTPS 端口 | `443` |
| `SCAU_USERNAME` | 账号 | - |
| `SCAU_PASSWORD` | 密码 | - |
| `SCAU_HTTP_PROXY_HOST` | HTTP 代理监听地址 | `0.0.0.0` |
| `SCAU_HTTP_PROXY_PORT` | HTTP 代理端口 | `1081` |
| `SCAU_SOCKS5_PROXY_HOST` | SOCKS5 代理监听地址 | `0.0.0.0` |
| `SCAU_SOCKS5_PROXY_PORT` | SOCKS5 代理端口 | `1080` |
| `SCAU_ENABLE_HTTP_PROXY` | 启用 HTTP 代理 | `true` |
| `SCAU_ENABLE_SOCKS5_PROXY` | 启用 SOCKS5 | `false` |
| `SCAU_SESSION_FILE` | 会话文件路径 | `.session.json` |
| `SCAU_AUTO_RECONNECT` | 自动重连 | `true` |
| `SCAU_DEBUG` | 调试模式 | `false` |
| `SCAU_SKIP_SSL_VERIFY` | 跳过 SSL 验证 | `true` |
| `SCAU_HEADLESS_BROWSER` | 无头浏览器 | `true` |
| `SCAU_BROWSER` | 浏览器类型 | `chrome` |

---

## 代理使用

### 快速参考

默认代理监听在 `0.0.0.0:<端口>`，即**同一局域网内的其他设备**也可以使用。将 `<host>` 替换为机器的内网 IP（如 `192.168.1.x`），若仅本机使用则用 `127.0.0.1`。

| 客户端 | HTTP | HTTPS |
|--------|------|-------|
| `curl` | `curl --proxy http://<host>:1081 http://...` | `curl -k --proxy http://<host>:1081 https://...` |
| `wget` | `wget -e use_proxy=yes -e http_proxy=<host>:1081 http://...` | `wget --no-check-certificate ...` |
| `git` | `git config --global http.proxy http://<host>:1081` | `git config --global https.proxy http://<host>:1081` |
| Python | `proxies={'http': 'http://<host>:1081'}` | `proxies={'https': 'http://<host>:1081'}` + `verify=False` |
| 浏览器 | SwitchyOmega → `<host>:1081` | 同左，需导入本地 CA |

### 仅允许本机使用

如果你**不**希望局域网内其他设备使用代理：

```bash
scau-connect login --http-proxy-host 127.0.0.1
```

或通过环境变量：

```bash
export SCAU_HTTP_PROXY_HOST=127.0.0.1
```

### 信任本地 CA

```bash
# 方式 A：忽略证书错误（最快）
curl -k --proxy http://<host>:1081 https://example.com

# 方式 B：让 curl 信任本地 CA
export CURL_CA_BUNDLE="$(pwd)/.proxy-ca/local-ca.crt.pem"
curl --proxy http://<host>:1081 https://example.com

# 方式 C：导入 CA 到系统信任存储
#   Windows：双击 .crt → 安装 → 受信任的根证书颁发机构
```

---

## 技术架构

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
   → 获取资源信息（DNS、路由、IP 段等）
```

### HTTPS MITM 架构

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

### TCP 隧道架构

对于 web proxy 无法到达的内网 IP（如 `222.201.229.x`）：

```
客户端              TCP 隧道拨号器            aTrust 节点:441
  │                      │                         │
  │──── dial(xxx) ──────▶│                         │
  │                      │──── TLS 连接 ──────────▶│
  │                      │──── [0x05 init] ───────▶│
  │                      │──── [0x05 dest+IP+port]▶│
  │                      │◀─── [0x05][0x53 OK VIP]─│
  │                      │                         │
  │◀─── L3 心跳 ─────────│  （保持 SID "在线"）      │
  │     (每 25s)         │                         │
  │                      │◀─── 原始字节流 ─────────│
  │◀─── 原始数据 ────────▶│                         │
```

- **L3 心跳**：持久 TLS 连接，每 25s 发送 `0x15` 心跳帧
- **TCP 隧道**：数据传输专用连接，使用 `0x05` 固定 10 字节头 + 原始透传
- **会话刷新**：当节点返回错误码 `10000004` 时自动刷新 `sid`

---

## 项目结构

```
scau-connect/
├── pyproject.toml           # uv 项目配置
├── .env.example             # 环境变量示例
├── LICENSE                  # MIT 协议
├── README.md               # 英文文档
├── README_zh.md            # 中文文档
├── src/scau_connect/
│   ├── __init__.py
│   ├── __main__.py         # python -m scau_connect 入口
│   ├── cli.py              # Typer CLI 定义
│   ├── config.py           # 配置管理（dataclass + 环境变量）
│   ├── session.py          # 会话状态与持久化
│   ├── main.py             # 应用入口
│   ├── protocol/
│   │   ├── atrust.py       # aTrust 主协议
│   │   ├── base.py         # ProtocolBase 抽象基类
│   │   ├── auth/
│   │   │   ├── base.py     # AuthenticatorBase
│   │   │   └── cas.py      # Selenium CAS 认证实现
│   │   └── tunnel/
│   │       ├── crypto.py   # 隧道加密（HMAC-SHA256、device ID）
│   │       ├── dialer.py   # Dialer 抽象接口
│   │       ├── l3.py       # L3 WebSocket 隧道管理器
│   │       ├── packet.py   # 隧道包封装（0x05 帧格式）
│   │       ├── resource_parser.py  # 解析 clientResource 获取 IP 段
│   │       └── tcp_tunnel_dialer.py # TCP 隧道拨号器（node:441）
│   ├── proxy/
│   │   ├── base.py         # 代理基类
│   │   ├── http.py         # HTTP CONNECT + 本地 TLS 终结
│   │   ├── certificates.py  # 本地 CA + per-host leaf 证书
│   │   ├── web_proxy_dialer.py # aTrust web proxy 连接层
│   │   ├── session_manager.py # 会话保活 + 过期自动重连
│   │   └── socks5.py       # SOCKS5 代理（实验性）
│   └── utils/
│       ├── http_client.py  # aTrust HTTP 客户端
│       ├── crypto.py       # 加密工具
│       └── logger.py       # structlog 封装
└── tests/
    ├── test_config.py      # 配置单元测试
    ├── test_tunnel.py      # 隧道测试
    └── test_tcp_tunnel_reader.py # TCP 隧道读取器测试
```

---

## 常见问题

### 安装 / 启动

**提示 "Failed to start WebDriver" / 找不到 chrome.exe**

确保系统安装了 Chrome 或 Edge：

```bash
# Windows：直接装 Chrome 浏览器即可，WebDriver 通常自带
# macOS：  brew install --cask google-chrome
# Linux：  sudo apt install google-chrome-stable
```

**`uv sync` 报错 / 依赖装不上**

确认 uv 版本 ≥ 0.4（`uv --version`）。必要时删除 `.venv` 后重试：

```bash
rm -rf .venv && uv sync
```

### 登录

**浏览器无法访问登录页 / 一直转圈**

检查能否直接访问 `https://vpn.scau.edu.cn/`。若学校 VPN 网关本身宕机，等几分钟后重试。

**密码里有特殊字符**

优先用 `.env` 文件，环境变量能正确处理几乎所有特殊字符。

**调试浏览器操作**

```bash
uv run scau-connect login --no-headless-browser
```

### 代理使用

**curl HTTPS 报 "SSL certificate problem"**

```bash
# 方式 A：忽略证书校验
curl -k --proxy http://127.0.0.1:1081 https://example.com

# 方式 B：信任本地 CA
export CURL_CA_BUNDLE="$(pwd)/.proxy-ca/local-ca.crt.pem"
curl --proxy http://127.0.0.1:1081 https://example.com
```

**访问任何网站都返回 502**

通常是 aTrust 会话已过期。如果用 `login` 命令（带账号密码）启动，应自动重连。若仍 502：

```bash
rm .session.json && uv run scau-connect login
```

**一开始能用，过一会儿就 502**

这是 aTrust 空闲超时。工具内置了保活机制，检查日志中是否有 `session_keepalive_ok`。

---

## 安全注意

- `.session.json` 文件包含敏感认证信息，请妥善保管
- 不要将该文件提交到代码仓库（已加入 `.gitignore`）
- 生产环境建议使用文件权限限制：`chmod 600 .session.json`
- `.proxy-ca/` 目录是缓存，可以安全删除，程序会重新生成

---

## 贡献指南

欢迎贡献代码！

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
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
