# scau-connect 与 zju-connect 实现差异

本文档说明 scau-connect 与 zju-connect 在实现上的主要差异，帮助开发者将 zju-connect 的代码适配到 SCAU 的 aTrust 环境。

---

## 一、总体差异概览

| 模块 | zju-connect | scau-connect | 说明 |
|------|-------------|--------------|------|
| **CAS 认证** | 直接 HTTP 请求，密码 RSA 加密 | Selenium 浏览器自动化 | SCAU 需要浏览器处理 RSA 加密 |
| **Cookie 获取** | HTTP 响应头 Set-Cookie | CDP Network.getAllCookies | SCAU 的 CASTGC 是 HttpOnly |
| **会话刷新** | 简单重登录 | 完整浏览器重认证 | 节点需要 `online=1` cookie |
| **TCP 隧道帧格式** | Go 结构体封装 | Python 自定义解析 | SCAU 使用 0x05 固定头 |
| **心跳协议** | WebSocket | TLS 直连 + 帧 | 协议细节不同 |

---

## 二、CAS 认证适配

### 2.1 zju-connect 的实现

zju-connect 直接发送 HTTP 请求登录，手动处理 RSA 加密：

```go
// zju-connect 密码 RSA 加密逻辑
passwordBytes := []byte(password)
hash := sha256.Sum256(passwordBytes)
encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, hash[:], nil)
password = base64.StdEncoding.EncodeToString(encrypted)
```

### 2.2 scau-connect 的适配

SCAU 的 RSA 加密在 JavaScript 中完成，手动逆向困难。使用 Selenium 浏览器自动化：

```python
# scau-connect: 让浏览器处理密码加密
driver.get(login_url)  # 打开 CAS 登录页
driver.execute_script("""
    // 浏览器 JS 自动处理 RSA 加密
    var usernameField = document.querySelector('input#userName');
    var passwordField = document.querySelector('input#password');
    // ... 设置值并提交
""")
```

**适配要点：**
1. 删除 RSA 加密逻辑
2. 使用 Selenium WebDriver 打开登录页
3. 使用 JavaScript 注入填写表单
4. 通过 CDP 获取 cookie

### 2.3 登录后处理差异

**zju-connect：** CAS 登录后直接获取 cookie，调用 `/auth/ticket` 获取 sidTicket。

**scau-connect：** 需要额外访问 `/portal/shortcut.html`：
```python
# scau-connect: 触发 portal JS 会话建立
driver.get(f"{base_url}/portal/shortcut.html")
# 等待 online=1 cookie 出现
self._wait_for_portal_session(driver)
```

---

## 三、Cookie 获取适配

### 3.1 HttpOnly Cookie 问题

SCAU 的关键 cookie `CASTGC` 是 HttpOnly，Selenium 标准 API 无法读取：

```python
# Selenium 标准 API 获取不到 HttpOnly cookie
selenium_cookies = driver.get_cookies()  # 没有 CASTGC

# 需要使用 CDP
result = driver.execute_cdp_cmd("Network.getAllCookies", {})
# CDP 返回包含 HttpOnly cookie
```

**适配要点：**
```go
// zju-connect 适配：在获取 cookie 后，额外通过 CDP 或其他方式获取 HttpOnly cookie
// 或：保持现有逻辑，SCAU 的 CASTGC 可能不是 HttpOnly（需要实测）
```

### 3.2 Cookie 名称格式

CDP 返回的 cookie 名称带有域名后缀：
```
CASTGC_-_vpn.scau.edu.cn  →  CASTGC
sid_-_vpn.scau.edu.cn     →  sid
```

**适配要点：** 解析 cookie 名称时需要去除域名后缀。

---

## 四、会话刷新适配

### 4.1 节点 SID 验证

aTrust 节点要求：
1. `online=1` cookie 存在
2. `sid` 是最近签发的

**zju-connect：** 简单的 `relogin()` 重登录即可刷新 sid。

**scau-connect：** 需要完整重新认证：
```python
# scau-connect: 简单重登录不够
async def refresh_session(self, session: Session) -> Session:
    # 需要重新走浏览器认证流程
    new_session = await self.authenticate()
    # 获取完整的 CASTGC + sid + online=1
    session.cookies.clear()
    session.cookies.update(new_session.cookies)
    return session
```

**适配要点：**
```go
// zju-connect 适配：
// 1. refreshSession() 不能只是重新获取 sid
// 2. 需要重新走完整的认证流程（包括 portal/shortcut.html）
// 3. 确保获取到 online=1 cookie
```

---

## 五、API 端点差异

### 5.1 认证 API

| 操作 | zju-connect | scau-connect |
|------|-------------|--------------|
| 获取 csrf_token | `/auth/v2/authentication/.require` | `/passport/v1/public/authConfig` |
| CAS 登录回调 | `/auth/v2/authentication.consumer` | `/passport/v1/auth/cas?ticket=XXX` |
| 获取 sidTicket | `/auth/v2/authentication.ticket` | `/passport/v1/auth/authCheck` |
| 交换 ticket | `/auth/v2/authentication.session` | `/passport/v1/public/ticketExchange` |
| 查询状态 | `/auth/v2/authentication.status` | `/passport/v1/user/onlineInfo` |

### 5.2 查询参数

**zju-connect：**
```go
query := "?callback=jsonpcallback&client=VPN&os=Windows&arch=&version=&clientType=WindowsOpenVPN"
```

**scau-connect：**
```
clientType=SDPBrowserClient&platform=Windows&lang=zh-CN
```

### 5.3 clientResource API

**zju-connect：** 不需要此 API。

**scau-connect：** 获取 IP 资源范围和节点地址：
```python
POST /controller/v1/user/clientResource
Content-Type: application/json
Referer: https://vpn.scau.edu.cn/portal/service_center.html

{
    "resourceType": {
        "appList": {},
        "featureCenter": {},
        "sdpPolicy": {},
        "favoriteAppList": {},
        "uemSpace": {
            "params": {"action": "login"}
        }
    }
}
```

---

## 六、TCP 隧道帧格式适配

### 6.1 初始化帧

**zju-connect（Go）：**
```go
// Go 使用二进制写入，结构体自动对齐
type InitFrame struct {
    Version    byte
    Type       byte
    TypeHigh   byte
    Magic      byte
    TypeLow    byte
    Length     uint16
    AuthJSON   string
}
```

**scau-connect（Python）：**
```python
_INIT_PREFIX = bytes([0x05, 0x01, 0x81, 0x53, 0x03])
auth_bytes = self.auth_json.encode("utf-8")
init_frame = _INIT_PREFIX + struct.pack(">H", len(auth_bytes)) + auth_bytes
```

**差异：** 两者等效，但 Python 需要手动构建字节序列。

### 6.2 数据帧格式

**关键差异：** SCAU 使用 **0x05 固定 10 字节头**，之后直接是原始应用数据。

**zju-connect：** 使用 `[0x01, 0x00, len(2BE), data]` 格式，有长度字段。

**scau-connect：** 使用 SCAU 特有格式：
```python
# SCAU 数据帧：固定 10 字节头 + 原始数据（无长度字段）
# [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] + 原始数据
```

**适配要点：**
```go
// zju-connect 适配：修改 dataFrame 的读取逻辑
// 原逻辑：读取 2 字节类型 + 2 字节长度 + 数据
// 新逻辑（SCAU）：读取到 0x05 前缀后，再读 8 字节，然后直接透传剩余数据

// 识别 SCAU 帧
if frameType[0] == 0x05 {
    // 固定 10 字节头
    readN(8) // 跳过剩余 8 字节
    // 之后是原始数据流，直接 recv() 直到 EOF
}
```

### 6.3 心跳帧

**zju-connect：** WebSocket 发送心跳。

**scau-connect：** TLS 连接直接发送帧：
```python
# 4 字节心跳帧
HEARTBEAT_FRAME = bytes([0x05, 0x15, 0x00, 0x00])
sock.sendall(HEARTBEAT_FRAME)
```

---

## 七、适配检查清单

如果要将 zju-connect 适配到 SCAU，需要修改以下部分：

### 7.1 认证模块 (`client/atrust/auth.go`)

- [ ] **删除** RSA 加密逻辑
- [ ] **新增** Selenium 浏览器自动化登录
- [ ] **新增** CDP 获取 HttpOnly cookie
- [ ] **新增** 访问 `portal/shortcut.html` 触发会话建立
- [ ] **修改** API 端点为 SCAU 版本

### 7.2 会话管理 (`client/atrust/session.go` 或类似)

- [ ] **修改** `refreshSession()` 为完整重认证
- [ ] **确保** 获取 `online=1` cookie
- [ ] **新增** Cookie 名称后缀清理逻辑

### 7.3 API 端点配置

- [ ] `authConfig`: `/passport/v1/public/authConfig`
- [ ] `authCheck`: `/passport/v1/auth/authCheck`
- [ ] `ticketExchange`: `/passport/v1/public/ticketExchange`
- [ ] `onlineInfo`: `/passport/v1/user/onlineInfo`
- [ ] `clientResource`: `/controller/v1/user/clientResource`

### 7.4 查询参数

- [ ] 修改 `clientType` 为 `SDPBrowserClient`
- [ ] 修改 `platform` 为 `Windows`
- [ ] 新增 `lang=zh-CN`

### 7.5 TCP 隧道 (`client/atrust/tcptunnel.go`)

- [ ] **修改** 数据帧读取逻辑，识别 0x05 固定头
- [ ] **新增** raw passthrough 模式
- [ ] **保持** L3 心跳连接逻辑（可能需要调整）

### 7.6 clientResource 解析

- [ ] **新增** 解析 `/controller/v1/user/clientResource` 响应
- [ ] **提取** IP 资源范围（用于判断哪些 IP 需要走 TCP 隧道）
- [ ] **提取** 节点地址（node address）用于 TCP 隧道连接

---

## 八、实测调试建议

### 8.1 抓包获取认证序列

使用浏览器开发者工具（F12）或 Fiddler 抓取 `https://vpn.scau.edu.cn`：

1. 清除浏览器缓存和 cookie
2. 打开 Fiddler 并开始抓包
3. 正常登录一次
4. 分析 Network 面板中的请求序列
5. 记录每个请求的 URL、Headers、Body

### 8.2 检查 Cookie 类型

在浏览器开发者工具中检查各 cookie 是否有 `HttpOnly` 标记：
- 如果 `CASTGC` 是 HttpOnly，需要用 CDP 获取
- 如果不是 HttpOnly，Selenium 标准 API 即可

### 8.3 测试会话过期

1. 登录后等待约 10 分钟（无活动）
2. 观察 Web Proxy 返回的内容
3. 检查返回的是目标页面还是 aTrust 重定向页

### 8.4 测试 TCP 隧道

1. 确保 clientResource 返回包含 IP 资源范围
2. 尝试连接一个内网 IP（如教务系统地址）
3. 观察连接是成功还是失败
4. 如果失败，检查错误码是否是 10000004

---

## 九、关键区别速查

```
┌─────────────────────────────────────────────────────────────────┐
│                      快速适配指南                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ❌ 不要照搬 zju-connect 的 Go 源码                               │
│  ❌ 不要直接使用 zju-connect 的 API 端点                          │
│  ❌ 不要假设 cookie 都可以用标准方式获取                          │
│                                                                  │
│  ✅ 使用 Selenium 浏览器自动化处理 RSA 加密                        │
│  ✅ 使用 CDP 获取 HttpOnly cookie                                 │
│  ✅ 访问 portal/shortcut.html 建立会话                           │
│  ✅ 完整重认证来刷新会话（不只是重新获取 sid）                     │
│  ✅ SCAU 数据帧用 0x05 固定 10 字节头 + 原始透传                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 十、参考资料

- zju-connect 源码：https://github.com/Mythologyli/zju-connect
- SCAU VPN 网关：https://vpn.scau.edu.cn
- Selenium 文档：https://www.selenium.dev/documentation/
- Chrome DevTools Protocol：https://chromedevtools.github.io/devtools-protocol/