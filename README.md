# scau-connect

> [中文](README_zh.md) | English

A reverse-proxy tool that automates **CAS authentication** for SCAU (South China Agricultural University) aTrust VPN gateway using a Selenium headless browser, exposing a local HTTP(S) proxy for seamless access to campus network resources.

---

## Features

| Feature | Status | Description |
|---------|--------|-------------|
| Selenium headless CAS login | ✅ | Browser handles RSA password encryption automatically |
| aTrust session management | ✅ | sid, CASTGC, csrf_token maintained automatically |
| HTTP proxy with HTTPS MITM | ✅ | `localhost:1081` — terminates TLS locally, forwards to aTrust web proxy |
| Session keep-alive + auto-reconnect | ✅ | Heartbeat every 45s, auto re-login on expiry, no more 502 errors |
| TCP tunnel dialer | ✅ | Reach internal IPs (e.g., `222.201.229.x`) via node:441 |
| L3 tunnel (WebSocket) | ✅ | Persistent tunnel for heartbeat and session hold |
| Session persistence | ✅ | `.session.json` auto-save/load |
| SOCKS5 proxy | ⚠️ | Experimental, disabled by default |

---

## Requirements

- Python ≥ 3.10
- Chrome or Edge browser (Selenium WebDriver auto-detected)
- [uv](https://github.com/astral-sh/uv) package manager (recommended)

---

## Installation

### Option A: Download EXE (Recommended for most users)

For non-technical users, download the standalone executable from GitHub Releases:

1. Go to [scau-connect Releases](https://github.com/xnbx2012/scau-connect/releases)
2. Download the latest `scau-connect.exe`
3. Double-click to run

**First run:** It will prompt for username and password, then start the proxy.

**Command line usage:**
```bash
# Login and start proxy
scau-connect.exe login --username YOUR_ID --password YOUR_PASSWORD

# Start with existing session (no login needed)
scau-connect.exe proxy

# Other options
scau-connect.exe login --http-proxy-port 1081 --debug
```

### Option B: Install from Source

```bash
git clone https://github.com/xnbx2012/scau-connect.git
cd scau-connect
uv sync
```

---

## Quick Start

### First Login

Create a `.env` file with your credentials:

```bash
cat > .env << 'EOF'
SCAU_USERNAME=your_student_id
SCAU_PASSWORD=your_password
EOF
```

Then start the proxy:

```bash
uv run scau-connect login
```

Output:
```
Login successful
Session saved to: .session.json
Proxy started
HTTP proxy: 127.0.0.1:1081
Press Ctrl+C to stop
```

### Use with curl

In another terminal:

```bash
# HTTP
curl --proxy http://127.0.0.1:1081 http://www.scau.edu.cn/

# HTTPS (requires -k for self-signed MITM CA)
curl -k --proxy http://127.0.0.1:1081 https://www.scau.edu.cn/
```

### Daily Use

Session is persisted. No login needed:

```bash
uv run scau-connect proxy
```

### Session Expiry

```bash
# Option A: Delete session and re-login
rm .session.json
uv run scau-connect login

# Option B: Use proxy, auto-reconnects if credentials available
uv run scau-connect proxy
```

---

## Command Reference

### `scau-connect login`

Execute CAS login and start proxy with session persistence.

```bash
uv run scau-connect login [OPTIONS]

Options:
  --server TEXT                VPN server (default: vpn.scau.edu.cn)
  --port INTEGER              HTTPS port (default: 443)
  --username TEXT             Username
  --password TEXT             Password
  --http-proxy-host TEXT      HTTP proxy listen host (default: 0.0.0.0)
  --http-proxy-port INT       HTTP proxy port (default: 1081)
  --socks5-proxy-host TEXT    SOCKS5 proxy listen host (default: 0.0.0.0)
  --socks5-proxy-port INT     SOCKS5 proxy port (default: 1080)
  --enable-http-proxy / --no-enable-http-proxy
  --enable-socks5-proxy / --no-enable-socks5-proxy
  --session-file PATH         Session save path (default: .session.json)
  --auto-reconnect / --no-auto-reconnect
  --debug, -d                 Enable debug logging
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

| Variable | Description | Default |
|----------|-------------|---------|
| `SCAU_SERVER` | VPN server | `vpn.scau.edu.cn` |
| `SCAU_PORT` | HTTPS port | `443` |
| `SCAU_USERNAME` | Username | - |
| `SCAU_PASSWORD` | Password | - |
| `SCAU_HTTP_PROXY_HOST` | HTTP proxy listen host | `0.0.0.0` |
| `SCAU_HTTP_PROXY_PORT` | HTTP proxy port | `1081` |
| `SCAU_SOCKS5_PROXY_HOST` | SOCKS5 proxy listen host | `0.0.0.0` |
| `SCAU_SOCKS5_PROXY_PORT` | SOCKS5 proxy port | `1080` |
| `SCAU_ENABLE_HTTP_PROXY` | Enable HTTP proxy | `true` |
| `SCAU_ENABLE_SOCKS5_PROXY` | Enable SOCKS5 | `false` |
| `SCAU_SESSION_FILE` | Session file path | `.session.json` |
| `SCAU_AUTO_RECONNECT` | Auto reconnect | `true` |
| `SCAU_DEBUG` | Debug mode | `false` |
| `SCAU_SKIP_SSL_VERIFY` | Skip SSL verify | `true` |
| `SCAU_HEADLESS_BROWSER` | Headless browser | `true` |
| `SCAU_BROWSER` | Browser type | `chrome` |

---

## Using the Proxy

### Quick Reference

By default, the proxy listens on `0.0.0.0:<port>`, which means **any device on the same LAN** can connect. Replace `<host>` with the machine's LAN IP (e.g., `192.168.1.x`) or `127.0.0.1` for local-only access.

| Client | HTTP | HTTPS |
|--------|------|-------|
| `curl` | `curl --proxy http://<host>:1081 http://...` | `curl -k --proxy http://<host>:1081 https://...` |
| `wget` | `wget -e use_proxy=yes -e http_proxy=<host>:1081 http://...` | `wget --no-check-certificate ...` |
| `git` | `git config --global http.proxy http://<host>:1081` | `git config --global https.proxy http://<host>:1081` |
| Python | `proxies={'http': 'http://<host>:1081'}` | `proxies={'https': 'http://<host>:1081'}` + `verify=False` |
| Browser | SwitchyOmega → `<host>:1081` | Same, import local CA |

### Restrict to Localhost Only

If you do **not** want other LAN devices to use the proxy:

```bash
scau-connect login --http-proxy-host 127.0.0.1
```

Or via environment variable:

```bash
export SCAU_HTTP_PROXY_HOST=127.0.0.1
```

### Trusting the Local CA

```bash
# Option A: Ignore cert errors (fastest)
curl -k --proxy http://<host>:1081 https://example.com

# Option B: Point curl to local CA
export CURL_CA_BUNDLE="$(pwd)/.proxy-ca/local-ca.crt.pem"
curl --proxy http://<host>:1081 https://example.com

# Option C: Import CA to system trust store
#   Windows: Double-click .crt → Install → Trusted Root CA
```

---

## Architecture

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
   → Get resource info (DNS, routes, IP ranges, etc.)
```

### HTTPS MITM Architecture

```
curl --proxy http://127.0.0.1:1081
            │
            ▼
  Local Proxy (127.0.0.1:1081)
  ┌─────────────────────────────────────┐
  │ 1. Return 200 Connection Established │
  │ 2. Terminate TLS with local CA cert  │
  │ 3. Decrypt to plaintext HTTP         │
  │ 4. Rewrite Host + Cookie            │
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

### TCP Tunnel Architecture

For internal IPs (e.g., `222.201.229.x`) that the web proxy cannot reach:

```
Client                TCP Tunnel Dialer           aTrust Node:441
  │                         │                            │
  │──── dial(222.201.229.x)─▶│                            │
  │                         │──── TLS connect ──────────▶│
  │                         │──── [0x05 init] ──────────▶│
  │                         │──── [0x05 dest+IP+port]──▶│
  │                         │◀─── [0x05][0x53 OK VIP] ───│
  │                         │                            │
  │◀─── L3 heartbeat ───────│  (keeps SID "online")      │
  │      (every 25s)         │                            │
  │                         │◀─── raw passthrough ───────│
  │◀─── raw bytes ──────────▶│                            │
```

- **L3 heartbeat**: Persistent TLS connection sending `0x15` heartbeat frames every 25s
- **TCP tunnel**: Separate connection for data, uses `0x05` fixed 10-byte header + raw passthrough
- **Session refresh**: Auto-refreshes `sid` when node rejects with code `10000004`

---

## Project Structure

```
scau-connect/
├── pyproject.toml           # uv project config
├── .env.example             # Environment variable template
├── LICENSE                  # MIT License
├── README.md                # English README
├── README_zh.md            # Chinese README
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
│   │   ├── auth/
│   │   │   ├── base.py      # AuthenticatorBase
│   │   │   └── cas.py       # Selenium CAS authenticator
│   │   └── tunnel/
│   │       ├── crypto.py    # Tunnel crypto (HMAC-SHA256, device ID)
│   │       ├── dialer.py    # Dialer abstract interface
│   │       ├── l3.py        # L3 WebSocket tunnel manager
│   │       ├── packet.py    # Tunnel packet framing (0x05 headers)
│   │       ├── resource_parser.py  # Parse clientResource for IP ranges
│   │       └── tcp_tunnel_dialer.py # TCP tunnel dialer via node:441
│   ├── proxy/
│   │   ├── base.py          # Proxy base class
│   │   ├── http.py          # HTTP CONNECT + local TLS MITM
│   │   ├── certificates.py  # Local CA + per-host leaf certs
│   │   ├── web_proxy_dialer.py # aTrust web proxy connection
│   │   ├── session_manager.py # Session keep-alive + auto-reconnect
│   │   └── socks5.py       # SOCKS5 proxy (experimental)
│   └── utils/
│       ├── http_client.py   # aTrust HTTP client
│       ├── crypto.py        # Crypto utilities
│       └── logger.py        # structlog wrapper
└── tests/
    ├── test_config.py       # Config unit tests
    ├── test_tunnel.py       # Tunnel tests
    └── test_tcp_tunnel_reader.py # TCP tunnel reader tests
```

---

## Troubleshooting

### Installation

**"Failed to start WebDriver" / Chrome not found**

```bash
# Windows: Install Chrome (WebDriver usually bundled)
# macOS:   brew install --cask google-chrome
# Linux:   sudo apt install google-chrome-stable
```

**`uv sync` fails**

Check uv version ≥ 0.4 (`uv --version`). Try recreating venv:

```bash
rm -rf .venv && uv sync
```

### Login

**Browser can't reach login page**

Check if you can access `https://vpn.scau.edu.cn/` directly. Wait if the VPN gateway is down.

**Password with special characters**

Use `.env` file — handles all special characters correctly.

**Debug browser operations**

```bash
uv run scau-connect login --no-headless-browser
```

### Proxy

**"SSL certificate problem" on HTTPS**

```bash
# Option A: Ignore cert errors
curl -k --proxy http://127.0.0.1:1081 https://example.com

# Option B: Trust local CA
export CURL_CA_BUNDLE="$(pwd)/.proxy-ca/local-ca.crt.pem"
curl --proxy http://127.0.0.1:1081 https://example.com
```

**502 on all requests**

Session expired. With credentials available, auto-reconnect should work. Otherwise:

```bash
rm .session.json && uv run scau-connect login
```

**502 after working fine**

This is aTrust idle timeout. Keep-alive is built in — check logs for "session_keepalive_ok".

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
