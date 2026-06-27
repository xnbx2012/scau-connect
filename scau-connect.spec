# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for scau-connect.
Run: pyinstaller scau-connect.spec
"""

from PyInstaller.utils.hooks import collect_submodules

# Collect all hidden imports
hiddenimports = [
    # Core dependencies
    'selenium',
    'selenium.webdriver.chrome.service',
    'selenium.webdriver.chrome.options',
    'selenium.webdriver.edge.service',
    'selenium.webdriver.edge.options',
    'httpx',
    'httpx._client',
    'httpx._config',
    'httpx._transports',
    'httpx._transports.asgi',
    'httpx._transports.http2',
    'httpx._transports.urllib3',
    'httpx._transports.websockets',
    'cryptography',
    'cryptography.x509',
    'cryptography.hazmat.primitives',
    'websockets',
    'websockets.sync',
    'websockets.asyncio',
    'structlog',
    'structlog.stdlib',
    'typer',
    'typer.cli',
    'rich',
    'rich.console',
    'rich.table',
    'pydantic',
    'pydantic.settings',
    'python_dotenv',
    # App modules
    'scau_connect',
    'scau_connect.cli',
    'scau_connect.config',
    'scau_connect.session',
    'scau_connect.main',
    'scau_connect.protocol',
    'scau_connect.protocol.atrust',
    'scau_connect.protocol.base',
    'scau_connect.protocol.auth',
    'scau_connect.protocol.auth.base',
    'scau_connect.protocol.auth.cas',
    'scau_connect.proxy',
    'scau_connect.proxy.base',
    'scau_connect.proxy.http',
    'scau_connect.proxy.certificates',
    'scau_connect.proxy.web_proxy_dialer',
    'scau_connect.proxy.session_manager',
    'scau_connect.proxy.socks5',
    'scau_connect.utils',
    'scau_connect.utils.crypto',
    'scau_connect.utils.http_client',
    'scau_connect.utils.logger',
]

# Add all submodules
hiddenimports += collect_submodules('selenium')
hiddenimports += collect_submodules('httpx')
hiddenimports += collect_submodules('cryptography')
hiddenimports += collect_submodules('websockets')

a = Analysis(
    ['src/scau_connect/__main__.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='scau-connect',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)