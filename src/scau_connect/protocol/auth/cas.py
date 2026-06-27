"""CAS authentication via Selenium browser automation.

SCAU's lyuapServer handles CAS login in-browser. We use Selenium to:
1. Navigate to the aTrust CAS login URL.
2. Fill in credentials (Selenium lets the browser handle RSA password encryption).
3. Submit the form and capture the resulting CAS ticket + cookies via CDP.
4. Hand off the cookies to ATrustHTTPClient for the rest of the aTrust handshake.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.edge.options import Options as EdgeOptions
from selenium.webdriver.edge.service import Service as EdgeService

from scau_connect.protocol.auth.base import AuthenticationError, AuthenticatorBase
from scau_connect.session import Session

if TYPE_CHECKING:
    from scau_connect.config import Config


__all__ = ["CASAuthenticator", "AuthenticationError"]


# How long Selenium waits for page elements to appear (seconds).
SELENIUM_TIMEOUT = 45


class CASAuthenticator(AuthenticatorBase):
    """CAS login via Selenium headless browser.

    The SCAU lyuapServer login page uses in-browser RSA encryption for the
    password field. By running the page in Selenium we let the browser JS
    handle the encryption transparently, avoiding the need to reverse-engineer
    the RSA public key.

    After form submission the CAS server auto-submits the ticket through a
    redirect chain, landing on the SCAU main site. We use Chrome DevTools
    Protocol (CDP) to read HttpOnly cookies (CASTGC, sid) that Selenium's
    standard API cannot access.
    """

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self._driver: webdriver.Remote | None = None

    # ------------------------------------------------------------------
    # Driver lifecycle
    # ------------------------------------------------------------------

    def _make_driver(self) -> webdriver.Remote:
        """Create and return a configured browser WebDriver.

        Prefer Edge in this environment because the driver is available locally.
        Fall back to Chrome if Edge cannot be started.
        """
        last_error: Exception | None = None

        # Prefer Edge.
        try:
            edge_opts = EdgeOptions()
            if self.config.headless_browser:
                edge_opts.add_argument("--headless=new")
            edge_opts.add_argument("--no-sandbox")
            edge_opts.add_argument("--disable-dev-shm-usage")
            edge_opts.add_argument("--disable-gpu")
            edge_opts.add_argument("--window-size=1280,800")
            edge_opts.add_experimental_option("excludeSwitches", ["enable-automation"])
            edge_opts.add_experimental_option("useAutomationExtension", False)
            edge_service = EdgeService()
            driver = webdriver.Edge(service=edge_service, options=edge_opts)
            driver.set_page_load_timeout(SELENIUM_TIMEOUT)
            return driver
        except Exception as exc:
            last_error = exc

        # Fallback to Chrome.
        try:
            chrome_opts = ChromeOptions()
            if self.config.headless_browser:
                chrome_opts.add_argument("--headless=new")
            chrome_opts.add_argument("--no-sandbox")
            chrome_opts.add_argument("--disable-dev-shm-usage")
            chrome_opts.add_argument("--disable-gpu")
            chrome_opts.add_argument("--window-size=1280,800")
            chrome_opts.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_opts.add_experimental_option("useAutomationExtension", False)
            chrome_service = ChromeService()
            driver = webdriver.Chrome(service=chrome_service, options=chrome_opts)
            driver.set_page_load_timeout(SELENIUM_TIMEOUT)
            return driver
        except Exception as exc:
            if last_error:
                raise AuthenticationError(
                    f"Failed to start Edge or Chrome WebDriver: edge={last_error}; chrome={exc}"
                ) from exc
            raise AuthenticationError(f"Failed to start WebDriver: {exc}") from exc

    def _ensure_driver(self) -> webdriver.Remote:
        if self._driver is None:
            self._driver = self._make_driver()
        return self._driver

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    async def login(self) -> Session:
        """Open CAS login page, submit credentials, return Session with cookies + ticket."""
        username = self.config.username
        password = self.config.password

        if not username or not password:
            raise AuthenticationError(
                "config.username and config.password must be set before calling login()."
            )

        cookies, ticket = await asyncio.get_event_loop().run_in_executor(
            None, self._sync_login, username, password
        )

        # Convert cookie list to {name: value} dict.
        cookie_dict = {c["name"]: c["value"] for c in cookies if "name" in c}
        session = Session(
            base_url=f"https://{self.config.server}",
            username=username,
            cookies=cookie_dict,
        )
        session.extra["cas_ticket"] = ticket
        return session

    def _sync_login(self, username: str, password: str) -> tuple[list[dict], str]:
        driver = self._ensure_driver()
        base_url = f"https://{self.config.server}"
        login_url = f"{base_url}/passport/v1/public/casLogin"

        try:
            # Step 1: Navigate to VPN domain FIRST to establish CDP session there.
            driver.get(base_url)
            time.sleep(1)

            # Step 2: Enable CDP on VPN domain (must be done before navigating away).
            driver.execute_cdp_cmd("Network.enable", {})
            time.sleep(1)

            # Step 3: Navigate to CAS login page via VPN domain.
            driver.get(login_url)
            time.sleep(2)

            # Step 4: Fill login form and submit.
            self._wait_and_fill_login(driver, username, password)

            # Step 5: Wait for CAS login to complete.
            # The browser will redirect to www.scau.edu.cn or similar.
            self._wait_for_cas_login(driver)

            # Step 6: Navigate to portal shortcut page to trigger session establishment.
            # This page runs the JS that calls authConfig?mod=1, authCheck, ticketExchange.
            driver.get(f"{base_url}/portal/shortcut.html")
            # Wait for the portal JS chain (authConfig?mod=1 → authCheck → ticketExchange)
            # to complete and set online=1. In headless mode this can take >8s, so we must
            # wait for the cookie to actually appear rather than sleep a fixed time.
            self._wait_for_portal_session(driver)

            # Step 7: Collect cookies while still on VPN domain.
            cookies = self._get_all_cookies(driver)

            # Also get Selenium cookies.
            selenium_cookies = driver.get_cookies()

            # Merge: prefer CDP cookies for HttpOnly ones.
            merged = {c["name"]: c for c in cookies}
            for c in selenium_cookies:
                if c["name"] not in merged:
                    merged[c["name"]] = {"name": c["name"], "value": c["value"]}

            cookies = list(merged.values())
            return cookies, ""

        except Exception as exc:
            raise AuthenticationError(f"Selenium CAS login failed: {exc}") from exc

    def _get_all_cookies(self, driver: webdriver.Remote) -> list[dict]:
        """Get all browser cookies via CDP, including HttpOnly cookies.

        CDP's Network.getAllCookies returns cookies that Selenium's standard
        API cannot read (CASTGC, sid, etc.).

        Note: CDP may return cookies with domain suffixes like "CASTGC_-_vpn.scau.edu.cn".
        We strip the suffix to get the canonical name.
        """
        try:
            # Collect VPN-domain cookies first, then fall back to all cookies.
            try:
                result = driver.execute_cdp_cmd("Network.getCookies", {
                    "domains": ["vpn.scau.edu.cn", ".vpn.scau.edu.cn"]
                })
                raw_cookies = result.get("cookies", [])
            except Exception:
                raw_cookies = []

            if not raw_cookies:
                try:
                    result = driver.execute_cdp_cmd("Network.getAllCookies", {})
                    raw_cookies = result.get("cookies", [])
                except Exception:
                    raw_cookies = []

            merged: dict[str, dict] = {}

            for c in raw_cookies:
                name = c.get("name", "")
                value = c.get("value", "")
                if not name:
                    continue

                # CDP returns cookies with domain suffix in the name field,
                # e.g., "CASTGC_-_vpn.scau.edu.cn" -> canonical name is "CASTGC"
                canonical = name
                for suffix in ["_-_vpn.scau.edu.cn", ".vpn.scau.edu.cn"]:
                    if name.endswith(suffix):
                        canonical = name[:-len(suffix)]
                        break

                # For each canonical name, keep the cookie with the non-empty value
                if canonical in merged:
                    # If current has value but existing doesn't, replace
                    if value and not merged[canonical].get("value"):
                        merged[canonical] = {
                            "name": canonical,
                            "value": value,
                            "domain": c.get("domain", ""),
                            "path": c.get("path", "/"),
                            "secure": c.get("secure", True),
                            "expires": c.get("expires", -1),
                            "sameSite": "None",
                            "_original_name": name,
                        }
                else:
                    merged[canonical] = {
                        "name": canonical,
                        "value": value,
                        "domain": c.get("domain", ""),
                        "path": c.get("path", "/"),
                        "secure": c.get("secure", True),
                        "expires": c.get("expires", -1),
                        "sameSite": "None",
                        "_original_name": name,
                    }

            return list(merged.values())
        except Exception:
            # Fallback to Selenium cookies if CDP fails.
            return driver.get_cookies()

    @staticmethod
    def _on_vpn_domain(driver: webdriver.Remote) -> bool:
        """Check if the current URL is on the VPN domain."""
        return "vpn.scau.edu.cn" in driver.current_url

    def _wait_and_fill_login(
        self, driver: webdriver.Remote, username: str, password: str
    ) -> None:
        """Fill the CAS login form and submit it."""
        # Wait for page to load
        time.sleep(3)

        # Use JavaScript to find and fill form elements, then submit
        driver.execute_script("""
            // Find the form
            var form = document.querySelector('form');
            if (!form) {
                console.log('No form found');
                return;
            }

            // Find username field and set value
            var usernameField = form.querySelector('input#userName, input[name="username"], input[type="text"]');
            if (usernameField) {
                // Use native value setter to trigger Vue/React reactivity
                Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(usernameField, arguments[0]);
                usernameField.dispatchEvent(new Event('input', { bubbles: true }));
                usernameField.dispatchEvent(new Event('change', { bubbles: true }));
            }

            // Find password field and set value
            var passwordField = form.querySelector('input#password, input[name="password"], input[type="password"]');
            if (passwordField) {
                Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(passwordField, arguments[1]);
                passwordField.dispatchEvent(new Event('input', { bubbles: true }));
                passwordField.dispatchEvent(new Event('change', { bubbles: true }));
            }

            // Find submit button
            var submitBtn = form.querySelector('button[type="button"]');
            if (submitBtn) {
                submitBtn.click();
                return;
            }

            // Try to trigger submit event
            var evt = new Event('submit', { bubbles: true, cancelable: true });
            form.dispatchEvent(evt);
        """, username, password)

        # Wait for the form to process
        time.sleep(2)

    def _wait_for_cas_login(self, driver: webdriver.Remote) -> None:
        """Wait for CAS login to complete by checking for CASTGC cookie.

        The CAS login redirects through multiple pages. We wait until the CASTGC
        cookie appears, indicating successful CAS authentication.
        """
        deadline = time.time() + 60
        while time.time() < deadline:
            time.sleep(1)
            try:
                castgc = driver.get_cookie("CASTGC")
                if castgc and castgc.get("value"):
                    return
            except Exception:
                pass
        # Timeout - CAS might have completed anyway

    def _wait_for_portal_session(self, driver: webdriver.Remote) -> None:
        """Wait for the portal JS to finish its post-CAS handshake.

        After the CAS callback sets the initial sid cookie, the portal page JS
        runs authConfig?mod=1 → authCheck (sets a NEW sid) → ticketExchange.
        Only after ticketExchange does the online cookie become "1".
        """
        deadline = time.time() + SELENIUM_TIMEOUT + 30
        while time.time() < deadline:
            time.sleep(1)
            try:
                online = driver.get_cookie("online")
                if online and online.get("value") == "1":
                    time.sleep(2)
                    return
            except Exception:
                pass
        # Timeout - session might have completed anyway
        time.sleep(5)

    # ------------------------------------------------------------------
    # Logout
    # ------------------------------------------------------------------

    async def logout(self, session: Session | None = None) -> None:
        if self._driver:
            await asyncio.get_event_loop().run_in_executor(None, self._driver.quit)
            self._driver = None
