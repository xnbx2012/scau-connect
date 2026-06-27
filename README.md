# scau-connect

> [中文](README_zh.md) | English

A reverse-proxy tool that uses a Selenium headless browser to automate **CAS authentication** for SCAU (South China Agricultural University) aTrust VPN gateway, exposing a local HTTP(S) proxy for seamless access to campus network resources.

---

## Features

| Feature | Status | Description |
|---------|--------|-------------|
| Selenium headless CAS login | ✅ Implemented | Browser handles RSA password encryption automatically |
| aTrust session management | ✅ Implemented | Automatic sid, CASTGC, csrf_token maintenance |
| HTTP proxy (with HTTPS MITM) | ✅ Implemented | `localhost:1081` — terminates TLS locally, forwards to aTrust web proxy |
| Session keep-alive + auto-reconnect | ✅ Implemented | Heartbeat every 45s, auto re-login on session expiry, no more 502 errors |
| SOCKS5 proxy | ⚠️ Experimental | Disabled by default; HTTP/80 traffic only |
| Session persistence | ✅ Implemented | `.session.json` auto-save/load |
| L3 tunnel | 🚧 Phase 2 | Not yet implemented |

---

## Requirements

- Python ≥ 3.10
- Chrome or Edge browser (Selenium WebDriver auto-detected)
- [uv](https://github.com/astral-sh/uv) package manager (recommended)

---

## Installation

```bash
# Clone the project
git clone https://github.com/your-repo/scau-connect.git
cd scau-connect

# Install dependencies (auto-creates .venv)
uv sync

# Install browser WebDriver if not already installed
# Chrome: usually bundled with Chrome
# Edge:   usually bundled with Edge
```

---

## Quick Start

### Step 1: First Login (Create `.env`)

Create a `.env` file in the project root with your credentials:

```bash
cat > .env << 'EOF'
SCAU_USERNAME=your_student_id
SCAU_PASSWORD=your_password
EOF
```

Then start the proxy with one command:

```bash
uv run scau-connect login
```

Success output:
```
Login successful
Session saved to: .session.json
Proxy started
HTTP proxy: 127.0.0.1:1081
Press Ctrl+C to stop
```

### Step 2: Use curl to Test

Keep the process running, **open another terminal**:

```bash
# HTTP
curl --proxy http://127.0.0.1:1081 http://www.scau.edu.cn/

# HTTPS requires -k (self-signed MITM CA)
curl -k --proxy http://127.0.0.1:1081 https://www.scau.edu.cn/
```

### Step 3: Daily Use

Session is saved to `.session.json`. Next time, no login needed:

```bash
uv run scau-connect proxy
```

### Step 4: When Session Expires

```bash
# Option A: Delete session file and re-login
rm .session.json
uv run scau-connect login

# Option B: Try proxy first, re-login if it fails
uv run scau-connect proxy
```

---

## Advanced Usage

```bash
uv run scau-connect login \
    --http-proxy-port 10891 \
    --socks5-proxy-port 10892 \
    --enable-socks5-proxy \
    --debug
```

---

## Command Reference

### `scau-connect login`

Execute CAS login and save session.

```bash
uv run scau-connect login [OPTIONS]

Options:
  --server TEXT                VPN server (default: vpn.scau.edu.cn)
  --port INTEGER              HTTPS port (default: 443)
  --username TEXT             Username (student/staff ID)
  --password TEXT             Password
  --http-proxy-port INT        HTTP proxy port (default: 1081)
  --socks5-proxy-port INT      SOCKS5 proxy port (default: 1080)
  --enable-http-proxy / --no-enable-http-proxy
  --enable-socks5-proxy / --no-enable-socks5-proxy
  --session-file PATH          Session save path (default: .session.json)
  --auto-reconnect / --no-auto-reconnect
  --debug, -d                  Enable debug logging
  --headless-browser / --no-headless-browser
```

### `scau-connect proxy`

Start proxy with existing session (no login).

```bash
uv run scau-connect proxy [OPTIONS]
```

### `scau-connect status`

Check current session status.

```bash
uv run scau-connect status [--session-file .session.json]
```

---

## Environment Variables

All options support both CLI flags and `SCAU_*` environment variables:

| Variable | Description | Type | Default |
|----------|-------------|------|---------|
| `SCAU_SERVER` | VPN server | str | `vpn.scau.edu.cn` |
| `SCAU_PORT` | HTTPS port | int | `443` |
| `SCAU_USERNAME` | Username | str | - |
| `SCAU_PASSWORD` | Password | str | - |
| `SCAU_HTTP_PROXY_PORT` | HTTP proxy port | int | `1081` |
| `SCAU_SOCKS5_PROXY_PORT` | SOCKS5 proxy port | int | `1080` |
| `SCAU_ENABLE_HTTP_PROXY` | Enable HTTP proxy | bool | `true` |
| `SCAU_ENABLE_SOCKS5_PROXY` | Enable SOCKS5 | bool | `false` |
| `SCAU_SESSION_FILE` | Session file path | str | `.session.json` |
| `SCAU_AUTO_RECONNECT` | Auto reconnect | bool | `true` |
| `SCAU_DEBUG` | Debug mode | bool | `false` |
| `SCAU_SKIP_SSL_VERIFY` | Skip SSL verify | bool | `true` |
| `SCAU_HEADLESS_BROWSER` | Headless browser | bool | `true` |
| `SCAU_BROWSER` | Browser type | str | `chrome` |

---

## Using the Proxy

The proxy listens on `127.0.0.1:1081`. Any HTTP-aware client can use it.

### Quick Reference

| Client | HTTP | HTTPS |
|--------|------|-------|
| `curl` | `curl --proxy http://127.0.0.1:1081 http://...` | `curl -k --proxy http://127.0.0.1:1081 https://...` |
| `wget` | `wget -e use_proxy=yes -e http_proxy=127.0.0.1:1081 http://...` | `wget --no-check-certificate ...` |
| `git` | `git config --global http.proxy http://127.0.0.1:1081` | `git config --global https.proxy http://127.0.0.1:1081` |
| Python `requests` | `proxies={'http': 'http://127.0.0.1:1081'}` | `proxies={'https': 'http://127.0.0.1:1081'}` + verify=False |
| Browser | SwitchyOmega → `127.0.0.1:1081` | Same, import local CA |

### Trusting the Local CA (Optional)

Default curl doesn't trust the self-signed MITM CA. Options:

```bash
# Option A: Ignore cert errors (fastest)
curl -k --proxy http://127.0.0.1:1081 https://example.com

# Option B: Point curl to local CA (recommended for scripts)
export CURL_CA_BUNDLE="$(pwd)/.proxy-ca/local-ca.crt.pem"
curl --proxy http://127.0.0.1:1081 https://example.com

# Option C (permanent): Import CA to system trust store
#   Windows: Double-click .crt → Install → Trusted Root CA
#   macOS:   Keychain Access → Import
```

---

## How It Works

### Authentication Flow

```
1. GET /passport/v1/public/authConfig
   → Get csrf_token + initial sid cookie

2. Selenium headless browser login
   → Open CAS login page (RSA password encryption handled by browser)
   → Fill credentials and submit
   → Get CASTGC, sid via CDP (HttpOnly cookies)

3. GET /passport/v1/auth/authCheck
   → Get sidTicket

4. POST /passport/v1/public/ticketExchange
   → Exchange ticket to complete session

5. GET /passport/v1/user/onlineInfo
   → Confirm isOnline = true

6. POST /controller/v1/user/clientResource
   → Get resource info (DNS, routes, etc.)
```

### HTTPS MITM Architecture

```
curl --proxy http://127.0.0.1:1081
            │
            ▼
  Local Proxy (127.0.0.1:1081)
  ┌─────────────────────────────────────┐
  │ 1. Return 200 Connection Established│
  │ 2. Terminate TLS with local CA cert │
  │ 3. Decrypt to plaintext HTTP        │
  │ 4. Rewrite Host + Cookie           │
  │ 5. Forward to aTrust web proxy      │
  │ 6. Encrypt response back to client  │
  └─────────────────────────────────────┘
            │
            ▼
  *.s.vpn.scau.edu.cn:443 (aTrust reverse proxy)
            │
            ▼
  Target website
```

---

## Project Structure

```
scau-connect/
├── pyproject.toml           # uv project config
├── .env.example             # Environment variable template
├── LICENSE                  # MIT License
├── README.md                # English README
├── README_zh.md             # Chinese README
├── src/scau_connect/
│   ├── __init__.py
│   ├── __main__.py          # python -m scau_connect entry
│   ├── cli.py               # Typer CLI definitions
│   ├── config.py            # Config dataclass + env vars
│   ├── session.py           # Session state & persistence
│   ├── main.py              # Application entry
│   ├── protocol/
│   │   ├── atrust.py        # aTrust main protocol
│   │   ├── base.py          # ProtocolBase abstract class
│   │   └── auth/
│   │       ├── base.py      # AuthenticatorBase
│   │       └── cas.py       # Selenium CAS authenticator
│   ├── proxy/
│   │   ├── base.py            # Proxy base class
│   │   ├── http.py            # HTTP CONNECT + local TLS MITM
│   │   ├── certificates.py    # Local CA + per-host leaf certs
│   │   ├── web_proxy_dialer.py # aTrust web proxy connection
│   │   ├── session_manager.py # Session keep-alive + auto-reconnect
│   │   └── socks5.py          # SOCKS5 proxy (experimental)
│   └── utils/
│       ├── http_client.py   # aTrust HTTP client
│       ├── crypto.py        # Crypto utilities
│       └── logger.py        # structlog wrapper
└── tests/
    ├── test_config.py       # Config unit tests
    ├── test_tunnel.py       # L3 tunnel tests
    └── test_tcp_tunnel_reader.py # TCP tunnel reader tests
```

---

## Troubleshooting

### Installation

**Q: "Failed to start WebDriver" / Chrome not found**

```bash
# Windows: Install Chrome, WebDriver is usually bundled
# macOS:   brew install --cask google-chrome
# Linux:   sudo apt install google-chrome-stable
```

**Q: `uv sync` fails**

Check uv version ≥ 0.4 (`uv --version`). Try recreating venv:

```bash
rm -rf .venv
uv sync
```

### Login

**Q: Browser can't reach login page**

Check if you can access `https://vpn.scau.edu.cn/` directly. If the VPN gateway is down, wait and retry.

**Q: Password with special characters doesn't work**

Use `.env` file — it handles all special characters correctly. Or use single quotes:

```bash
uv run scau-connect login --username 'your_id' --password 'your!pass#word'
```

**Q: Debug browser operations**

Use `--no-headless-browser` to see the browser window:

```bash
uv run scau-connect login --no-headless-browser
```

### Proxy

**Q: "SSL certificate problem" on HTTPS**

Three solutions:

```bash
# A (fastest): Ignore cert errors
curl -k --proxy http://127.0.0.1:1081 https://example.com

# B (recommended for scripts): Trust local CA
export CURL_CA_BUNDLE="$(pwd)/.proxy-ca/local-ca.crt.pem"
curl --proxy http://127.0.0.1:1081 https://example.com

# C (permanent): Add CA to system trust store
```

**Q: Returns 502 on all requests**

Session expired. If you started with `login` (with credentials), it should auto-reconnect. Otherwise:

```bash
rm .session.json
uv run scau-connect login
```

**Q: Works at first, then 502 after a while**

This is aTrust session idle timeout. The tool has built-in keep-alive. Check for `会话保活已启用` in logs.

### Session

**Q: Auto-reconnect failed**

`--auto-reconnect` retries once on 401. For persistent issues, delete session and re-login:

```bash
rm .session.json
uv run scau-connect login
```

---

## Security Notes

- `.session.json` contains sensitive authentication data — keep it safe
- Never commit this file to version control (it's in `.gitignore`)
- For production, restrict file permissions: `chmod 600 .session.json`
- `.proxy-ca/` contains generated certificates — safe to delete, will regenerate

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## References

- [SCAU VPN Gateway](https://vpn.scau.edu.cn)
- [Selenium Documentation](https://www.selenium.dev/documentation/)
- [Sangfor aTrust](https://www.sangfor.com/)
- [zju-connect (Reference Implementation)](https://github.com/Mythologyli/zju-connect)
