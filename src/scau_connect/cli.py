"""Typer command-line interface for scau-connect.

Provides login/status/proxy commands that orchestrate the existing aTrust
protocol, session persistence, and local HTTP/SOCKS5 proxy servers.
"""

from __future__ import annotations

import asyncio
import structlog
from contextlib import suppress
from pathlib import Path

import typer

from scau_connect.config import Config
from scau_connect.protocol.atrust import ATrustProtocol
from scau_connect.protocol.tunnel import (
    TCPTunnelDialer,
    build_default_ip_resource_db,
    parse_client_resource,
)
from scau_connect.proxy.http import HTTPProxy
from scau_connect.proxy.session_manager import SessionManager
from scau_connect.proxy.socks5 import Socks5Proxy
from scau_connect.proxy.web_proxy_dialer import WebProxyDialer
from scau_connect.session import Session

app = typer.Typer(
    name="scau-connect",
    help="SCAU aTrust CAS 认证转本地代理端口工具。",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def cli_callback(
    ctx: typer.Context,
    debug: bool = typer.Option(False, "--debug", "-d", help="开启调试日志。"),
) -> None:
    """scau-connect 顶层命令。"""
    ctx.obj = {"debug": debug}


def _build_config(
    *,
    server: str,
    port: int,
    username: str | None,
    password: str | None,
    http_proxy_host: str,
    http_proxy_port: int,
    socks5_proxy_host: str,
    socks5_proxy_port: int,
    enable_http_proxy: bool,
    enable_socks5_proxy: bool,
    session_file: str,
    auto_reconnect: bool,
    debug: bool,
    skip_ssl_verify: bool,
    headless_browser: bool,
    browser: str,
) -> Config:
    return Config(
        server=server,
        port=port,
        username=username,
        password=password,
        http_proxy_host=http_proxy_host,
        http_proxy_port=http_proxy_port,
        socks5_proxy_host=socks5_proxy_host,
        socks5_proxy_port=socks5_proxy_port,
        enable_http_proxy=enable_http_proxy,
        enable_socks5_proxy=enable_socks5_proxy,
        session_file=session_file,
        auto_reconnect=auto_reconnect,
        debug=debug,
        skip_ssl_verify=skip_ssl_verify,
        headless_browser=headless_browser,
        browser=browser,
    )


async def _run_login(config: Config, start_proxy: bool) -> int:
    protocol = ATrustProtocol(config)
    http_proxy: HTTPProxy | None = None
    socks_proxy: Socks5Proxy | None = None
    manager: SessionManager | None = None
    tcp_dialer: TCPTunnelDialer | None = None
    try:
        session = await protocol.authenticate()
        session.save(config.session_file)
        typer.echo(f"登录成功：{session.display_name or session.username or config.username or ''}")
        typer.echo(f"会话已保存到：{Path(config.session_file).resolve()}")

        if not start_proxy:
            return 0

        dialer = WebProxyDialer(session)
        tcp_dialer = _build_tcp_tunnel_dialer(session, protocol)
        http_proxy, socks_proxy = await _start_proxies(config, session, dialer, tcp_dialer)

        # Keep the session warm and auto-reconnect on expiry (the main reason
        # for the "502 after a while" problem: aTrust sessions expire).
        if config.auto_reconnect and config.username and config.password:
            manager = SessionManager(config, session, dialer)
            await manager.start()
            typer.echo("会话保活已启用（过期自动重新登录）")
        else:
            typer.echo("提示：未提供账号密码或已关闭 auto-reconnect，会话过期后将 502")

        if tcp_dialer is not None:
            typer.echo("TCP 隧道已就绪（可访问 222.201.229.x 等内部 IP）")
        typer.echo("代理已启动")
        if http_proxy:
            typer.echo(f"HTTP 代理：{config.http_proxy_host}:{config.http_proxy_port}")
        if socks_proxy:
            typer.echo(f"SOCKS5 代理：{config.socks5_proxy_host}:{config.socks5_proxy_port}")
        typer.echo("按 Ctrl+C 停止")
        await asyncio.Event().wait()
        return 0
    finally:
        if manager:
            with suppress(Exception):
                await manager.stop()
        if socks_proxy:
            with suppress(Exception):
                await socks_proxy.stop()
        if http_proxy:
            with suppress(Exception):
                await http_proxy.stop()
        if tcp_dialer:
            with suppress(Exception):
                await tcp_dialer.close()
        with suppress(Exception):
            await protocol.close()


def _build_tcp_tunnel_dialer(session: Session, protocol: ATrustProtocol | None = None) -> TCPTunnelDialer | None:
    """Build a TCP tunnel dialer from the session's resource data.

    Registers the protocol instance so the dialer can auto-refresh the session's
    ``sid`` cookie when the tunnel node rejects a dial with "invalid SID".
    """
    try:
        # Try to parse from clientResource if available
        raw = session.extra.get("resource_data")
        if raw and isinstance(raw, dict):
            db = parse_client_resource(raw)
            if db.resources:
                return TCPTunnelDialer(session, db, protocol=protocol)
    except Exception as exc:
        logger = structlog.get_logger()
        logger.debug("failed_to_parse_client_resource", error=str(exc))

    # Fall back to default SCAU IP ranges
    db = build_default_ip_resource_db()
    return TCPTunnelDialer(session, db, protocol=protocol)


async def _start_proxies(
    config: Config, session: Session, dialer: WebProxyDialer,
    tcp_tunnel_dialer: TCPTunnelDialer | None = None,
) -> tuple[HTTPProxy | None, Socks5Proxy | None]:
    http_proxy = (
        HTTPProxy(
            dialer,
            listen_host=config.http_proxy_host,
            listen_port=config.http_proxy_port,
            tcp_tunnel_dialer=tcp_tunnel_dialer,
        )
        if config.enable_http_proxy
        else None
    )
    socks_proxy = (
        Socks5Proxy(
            dialer,
            listen_host=config.socks5_proxy_host,
            listen_port=config.socks5_proxy_port,
            username=config.username,
            password=config.password,
        )
        if config.enable_socks5_proxy
        else None
    )

    if http_proxy:
        await http_proxy.start()
    if socks_proxy:
        await socks_proxy.start()
    return http_proxy, socks_proxy


@app.command()
def login(
    server: str = typer.Option("vpn.scau.edu.cn", help="VPN 服务器地址。"),
    port: int = typer.Option(443, help="VPN HTTPS 端口。"),
    username: str | None = typer.Option(None, "--username", envvar="SCAU_USERNAME", help="账号。"),
    password: str | None = typer.Option(None, "--password", envvar="SCAU_PASSWORD", help="密码。", hide_input=True),
    http_proxy_host: str = typer.Option("0.0.0.0", help="HTTP 代理监听地址，0.0.0.0 表示允许局域网访问。"),
    http_proxy_port: int = typer.Option(1081, help="HTTP 代理端口。"),
    socks5_proxy_host: str = typer.Option("0.0.0.0", help="SOCKS5 代理监听地址，0.0.0.0 表示允许局域网访问。"),
    socks5_proxy_port: int = typer.Option(1080, help="SOCKS5 代理端口（仅占位，未实现）。"),
    enable_http_proxy: bool = typer.Option(True, help="登录后启动 HTTP 代理。"),
    enable_socks5_proxy: bool = typer.Option(False, help="启用 SOCKS5 代理（实验性：aTrust 仅支持 HTTP 反向代理，SOCKS5 仅对 80 端口的部分 HTTP 请求可用）。"),
    session_file: str = typer.Option(".session.json", help="会话保存路径。"),
    auto_reconnect: bool = typer.Option(True, help="自动重连。"),
    debug: bool = typer.Option(False, "--debug", "-d", help="开启调试日志。"),
    skip_ssl_verify: bool = typer.Option(True, help="跳过 SSL 验证。"),
    headless_browser: bool = typer.Option(True, help="使用无头浏览器。"),
    browser: str = typer.Option("chrome", help="浏览器类型。"),
    start_proxy: bool = typer.Option(True, help="登录成功后保持进程并启动代理端口。"),
) -> None:
    config = _build_config(
        server=server,
        port=port,
        username=username,
        password=password,
        http_proxy_host=http_proxy_host,
        http_proxy_port=http_proxy_port,
        socks5_proxy_host=socks5_proxy_host,
        socks5_proxy_port=socks5_proxy_port,
        enable_http_proxy=enable_http_proxy,
        enable_socks5_proxy=enable_socks5_proxy,
        session_file=session_file,
        auto_reconnect=auto_reconnect,
        debug=debug,
        skip_ssl_verify=skip_ssl_verify,
        headless_browser=headless_browser,
        browser=browser,
    )

    if not config.username or not config.password:
        raise typer.BadParameter("必须通过 --username/--password 或 SCAU_USERNAME/SCAU_PASSWORD 提供账号密码")

    raise typer.Exit(code=asyncio.run(_run_login(config, start_proxy)))


@app.command()
def proxy(
    session_file: str = typer.Option(".session.json", help="会话文件路径。"),
    http_proxy_host: str = typer.Option("0.0.0.0", help="HTTP 代理监听地址，0.0.0.0 表示允许局域网访问。"),
    http_proxy_port: int = typer.Option(1081, help="HTTP 代理端口。"),
    socks5_proxy_host: str = typer.Option("0.0.0.0", help="SOCKS5 代理监听地址，0.0.0.0 表示允许局域网访问。"),
    socks5_proxy_port: int = typer.Option(1080, help="SOCKS5 代理端口（仅占位，未实现）。"),
    enable_http_proxy: bool = typer.Option(True, help="启动 HTTP 代理。"),
    enable_socks5_proxy: bool = typer.Option(False, help="启用 SOCKS5 代理（实验性）。"),
    debug: bool = typer.Option(False, "--debug", "-d", help="开启调试日志。"),
    username: str | None = typer.Option(None, "--username", envvar="SCAU_USERNAME", help="账号（用于会话过期时自动重新登录）。"),
    password: str | None = typer.Option(None, "--password", envvar="SCAU_PASSWORD", help="密码（用于会话过期时自动重新登录）。", hide_input=True),
    keepalive: bool = typer.Option(True, help="启用会话保活与过期自动重连。"),
) -> None:
    path = Path(session_file)
    if not path.exists():
        raise typer.BadParameter(f"找不到会话文件：{session_file}")

    session = Session.load(session_file)
    config = Config(
        server=session.base_url.replace("https://", "").rstrip("/"),
        username=username,
        password=password,
        http_proxy_host=http_proxy_host,
        http_proxy_port=http_proxy_port,
        socks5_proxy_host=socks5_proxy_host,
        socks5_proxy_port=socks5_proxy_port,
        enable_http_proxy=enable_http_proxy,
        enable_socks5_proxy=enable_socks5_proxy,
        session_file=session_file,
        auto_reconnect=keepalive,
        debug=debug,
    )

    async def _run() -> int:
        protocol = ATrustProtocol(config, session=session)
        http_proxy: HTTPProxy | None = None
        socks_proxy: Socks5Proxy | None = None
        manager: SessionManager | None = None
        tcp_dialer: TCPTunnelDialer | None = None
        try:
            dialer = WebProxyDialer(session)
            tcp_dialer = _build_tcp_tunnel_dialer(session, protocol)
            http_proxy, socks_proxy = await _start_proxies(config, session, dialer, tcp_dialer)

            if keepalive and config.username and config.password:
                manager = SessionManager(config, session, dialer)
                await manager.start()
                typer.echo("会话保活已启用（过期自动重新登录）")
            else:
                typer.echo("提示：未提供账号密码，会话过期后将 502。请加 --username/--password 启用自动重连。")

            if tcp_dialer is not None:
                typer.echo("TCP 隧道已就绪（可访问 222.201.229.x 等内部 IP）")
            typer.echo("代理已启动")
            if http_proxy:
                typer.echo(f"HTTP 代理：{config.http_proxy_host}:{config.http_proxy_port}")
            if socks_proxy:
                typer.echo(f"SOCKS5 代理：{config.socks5_proxy_host}:{config.socks5_proxy_port}")
            typer.echo("按 Ctrl+C 停止")
            await asyncio.Event().wait()
            return 0
        finally:
            if manager:
                with suppress(Exception):
                    await manager.stop()
            if socks_proxy:
                with suppress(Exception):
                    await socks_proxy.stop()
            if http_proxy:
                with suppress(Exception):
                    await http_proxy.stop()
            if tcp_dialer:
                with suppress(Exception):
                    await tcp_dialer.close()
            with suppress(Exception):
                await protocol.close()

    raise typer.Exit(code=asyncio.run(_run()))


@app.command()
def status(session_file: str = typer.Option(".session.json", help="会话文件路径。")) -> None:
    path = Path(session_file)
    if not path.exists():
        typer.echo(f"未找到会话文件：{session_file}")
        raise typer.Exit(code=1)
    session = Session.load(session_file)
    typer.echo(f"会话文件：{path.resolve()}")
    typer.echo(f"有效会话：{'是' if session.is_valid() else '否'}")
    typer.echo(f"在线状态：{'是' if session.is_online else '否'}")
    typer.echo(f"用户名：{session.username or '-'}")
    typer.echo(f"显示名：{session.display_name or '-'}")


def main() -> None:
    app()


def run() -> None:
    main()


if __name__ == "__main__":
    main()
