"""HTTP client for ATrust API communication.

Wraps :class:`httpx.AsyncClient` with aTrust-specific headers (CSRF token,
sdp-traceid, User-Agent) and a cookie jar that can be injected from
Selenium. SSL verification can be disabled for use behind corporate proxies.
"""

from __future__ import annotations

import secrets
from typing import Any, Self

import httpx

__all__ = ["ATrustHTTPClient", "ATrustHTTPError"]


# Default aTrust User-Agent matching the official client.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


class ATrustHTTPError(httpx.HTTPError):
    """Raised on HTTP-level errors from the aTrust server."""


class ATrustHTTPClient:
    """Async HTTP client with aTrust protocol headers and cookie injection.

    Parameters
    ----------
    base_url : str
        Base URL for the aTrust server, e.g. ``https://vpn.scau.edu.cn``.
    cookies : dict[str, str] | None
        Initial cookie jar (e.g. injected from Selenium).
    csrf_token : str | None
        Current ``x-csrf-token`` value.
    skip_ssl_verify : bool
        Disable TLS certificate verification (default ``True`` for development).
    user_agent : str
        User-Agent header value.
    timeout : float
        Default request timeout in seconds.

    Example
    -------
    >>> client = ATrustHTTPClient("https://vpn.scau.edu.cn")
    >>> await client.request("POST", "/api/auth/login", json={"username": "x"})
    >>> client.update_cookies_from_dict(selenium_cookies)
    """

    def __init__(
        self,
        base_url: str,
        *,
        cookies: dict[str, str] | None = None,
        csrf_token: str | None = None,
        skip_ssl_verify: bool = True,
        user_agent: str = DEFAULT_USER_AGENT,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._csrf_token = csrf_token
        self._cookies: dict[str, str] = dict(cookies) if cookies else {}
        self._user_agent = user_agent
        self._skip_ssl_verify = skip_ssl_verify
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    # -------------------------------------------------------------------------
    # Internal httpx client management
    # -------------------------------------------------------------------------

    def _build_headers(self, extra: dict[str, str] | None = None) -> httpx.Headers:
        """Build the default request headers including aTrust-specific fields."""
        headers: dict[str, str] = {
            "User-Agent": self._user_agent,
        }
        if self._csrf_token:
            headers["x-csrf-token"] = self._csrf_token
        headers["x-sdp-traceid"] = self._next_traceid()
        if extra:
            headers.update(extra)
        return httpx.Headers(headers)

    @staticmethod
    def _next_traceid() -> str:
        """Generate an 8-character hex trace ID."""
        return secrets.token_hex(4).upper()

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                cookies=self._cookies,
                verify=self._skip_ssl_verify,
                timeout=httpx.Timeout(self._timeout),
                follow_redirects=False,
                headers={
                    "User-Agent": self._user_agent,
                },
            )
        return self._client

    # -------------------------------------------------------------------------
    # Public request API
    # -------------------------------------------------------------------------

    async def request(
        self,
        method: str,
        path: str = "/",
        *,
        follow_redirects: bool = False,
        **kwargs: Any,
    ) -> httpx.Response:
        """Send an HTTP request with aTrust headers.

        Parameters
        ----------
        method : str
            HTTP method (``GET``, ``POST``, etc.).
        path : str
            URL path appended to :attr:`base_url`.
        follow_redirects : bool
            Whether httpx should follow HTTP redirects (default ``False`` to
            allow callers to handle redirects explicitly).
        **kwargs
            Additional arguments forwarded to :meth:`httpx.AsyncClient.request`.

        Returns
        -------
        httpx.Response

        Raises
        ------
        ATrustHTTPError
            On any HTTP error.
        """
        client = self._ensure_client()

        headers = dict(kwargs.pop("headers", {}))
        headers["x-sdp-traceid"] = self._next_traceid()
        if self._csrf_token:
            headers["x-csrf-token"] = self._csrf_token

        # Inject persistent cookies
        cookies = httpx.Cookies()
        for name, value in self._cookies.items():
            cookies.set(name, value)

        try:
            response = await client.request(
                method=method.upper(),
                url=path,
                headers=headers,
                cookies=cookies,
                follow_redirects=follow_redirects,
                **kwargs,
            )
            # Sync inbound cookies back into our jar
            for name, value in response.cookies.items():
                self._cookies[name] = value
            return response
        except httpx.HTTPError as exc:
            raise ATrustHTTPError(f"aTrust request failed: {exc}") from exc

    async def get(self, path: str = "/", **kwargs: Any) -> httpx.Response:
        """Convenience GET."""
        return await self.request("GET", path, **kwargs)

    async def post(self, path: str = "/", **kwargs: Any) -> httpx.Response:
        """Convenience POST."""
        return await self.request("POST", path, **kwargs)

    # -------------------------------------------------------------------------
    # Cookie management
    # -------------------------------------------------------------------------

    def update_cookies_from_dict(self, cookies: dict[str, str]) -> None:
        """Merge a dict of cookies into the client jar.

        Parameters
        ----------
        cookies : dict[str, str]
            Cookies as returned by Selenium's ``driver.get_cookies()``.
        """
        self._cookies.update(cookies)

    def update_cookies_from_list(self, cookies: list[dict[str, Any]]) -> None:
        """Merge a list of Selenium-style cookie dicts into the client jar.

        Parameters
        ----------
        cookies : list[dict[str, Any]]
            Each dict must contain at least ``name`` and ``value`` keys.
            ``domain`` and ``path`` are ignored (Selenium already scoped them).
        """
        for c in cookies:
            if "name" in c and "value" in c:
                self._cookies[c["name"]] = str(c["value"])

    def get_cookie(self, name: str) -> str | None:
        """Return the value of a cookie by name, or ``None`` if not found."""
        return self._cookies.get(name)

    @property
    def cookies(self) -> dict[str, str]:
        """Live view of the current cookie jar."""
        return self._cookies.copy()

    @property
    def csrf_token(self) -> str | None:
        """Current CSRF token, or ``None``."""
        return self._csrf_token

    @csrf_token.setter
    def csrf_token(self, value: str) -> None:
        self._csrf_token = value

    # -------------------------------------------------------------------------
    # Context-manager lifecycle
    # -------------------------------------------------------------------------

    async def __aenter__(self) -> Self:
        self._ensure_client()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying httpx client and release connections."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
