"""Dominus Node OpenAI-compatible function calling handler (Python).

Provides a factory function that creates a handler for dispatching
OpenAI function calls to the Dominus Node REST API. Works with any
function-calling LLM system: OpenAI GPT, Anthropic Claude tool_use,
Google Gemini, or custom implementations.

Example::

    from handler import create_dominusnode_function_handler

    handler = create_dominusnode_function_handler(
        api_key="dn_live_...",
        base_url="https://api.dominusnode.com",
    )

    # Dispatch a function call from an LLM response
    result = await handler("dominusnode_check_balance", {})
    print(result)  # JSON string with balance info

Requires: httpx (``pip install httpx``)
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import socket
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict, Optional, Set
from urllib.parse import quote, urlparse

import httpx

# ---------------------------------------------------------------------------
# SSRF Prevention -- URL validation
# ---------------------------------------------------------------------------

BLOCKED_HOSTNAMES: Set[str] = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "[::1]",
    "[::ffff:127.0.0.1]",
    "0.0.0.0",
    "[::]",
}


def _normalize_ipv4(hostname: str) -> Optional[str]:
    """Normalize non-standard IPv4 representations to dotted-decimal.

    Handles hex (0x7f000001), octal (0177.0.0.1), and decimal integer
    (2130706433) forms to prevent SSRF bypasses.
    """
    # Single decimal integer (e.g., 2130706433 = 127.0.0.1)
    if re.match(r"^\d+$", hostname):
        n = int(hostname)
        if 0 <= n <= 0xFFFFFFFF:
            return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"

    # Hex notation (e.g., 0x7f000001)
    if re.match(r"^0x[0-9a-fA-F]+$", hostname, re.IGNORECASE):
        n = int(hostname, 16)
        if 0 <= n <= 0xFFFFFFFF:
            return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"

    # Octal or mixed-radix octets (e.g., 0177.0.0.1)
    parts = hostname.split(".")
    if len(parts) == 4:
        octets = []
        for part in parts:
            try:
                if re.match(r"^0x[0-9a-fA-F]+$", part, re.IGNORECASE):
                    val = int(part, 16)
                elif re.match(r"^0\d+$", part):
                    val = int(part, 8)
                elif re.match(r"^\d+$", part):
                    val = int(part, 10)
                else:
                    return None
                if val < 0 or val > 255:
                    return None
                octets.append(val)
            except ValueError:
                return None
        return ".".join(str(o) for o in octets)

    return None


def _is_private_ip(hostname: str) -> bool:
    """Check if a hostname resolves to a private/reserved IP range."""
    ip = hostname.strip("[]")

    # Strip IPv6 zone ID
    zone_idx = ip.find("%")
    if zone_idx != -1:
        ip = ip[:zone_idx]

    normalized = _normalize_ipv4(ip)
    check_ip = normalized if normalized else ip

    # IPv4 private ranges
    ipv4_match = re.match(
        r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", check_ip
    )
    if ipv4_match:
        a, b = int(ipv4_match.group(1)), int(ipv4_match.group(2))
        if a == 0:
            return True  # 0.0.0.0/8
        if a == 10:
            return True  # 10.0.0.0/8
        if a == 127:
            return True  # 127.0.0.0/8
        if a == 169 and b == 254:
            return True  # 169.254.0.0/16
        if a == 172 and 16 <= b <= 31:
            return True  # 172.16.0.0/12
        if a == 192 and b == 168:
            return True  # 192.168.0.0/16
        if a == 100 and 64 <= b <= 127:
            return True  # 100.64.0.0/10 CGNAT
        if a >= 224:
            return True  # multicast + reserved
        return False

    # IPv6 private ranges
    ip_lower = ip.lower()
    if ip_lower == "::1":
        return True
    if ip_lower == "::":
        return True
    if ip_lower.startswith("fc") or ip_lower.startswith("fd"):
        return True  # fc00::/7 ULA
    if ip_lower.startswith("fe80"):
        return True  # fe80::/10 link-local
    if ip_lower.startswith("::ffff:"):
        embedded = ip_lower[7:]
        if "." in embedded:
            return _is_private_ip(embedded)
        hex_parts = embedded.split(":")
        if len(hex_parts) == 2:
            try:
                hi = int(hex_parts[0], 16)
                lo = int(hex_parts[1], 16)
                reconstructed = (
                    f"{(hi >> 8) & 0xFF}.{hi & 0xFF}.{(lo >> 8) & 0xFF}.{lo & 0xFF}"
                )
                return _is_private_ip(reconstructed)
            except ValueError:
                pass
        return _is_private_ip(embedded)

    # IPv4-compatible IPv6 (::x.x.x.x or hex form ::7f00:1)
    if ip_lower.startswith("::") and not ip_lower.startswith("::ffff:"):
        try:
            addr = ipaddress.IPv6Address(ip_lower)
            packed = addr.packed
            if all(b == 0 for b in packed[:12]):
                embedded = ipaddress.IPv4Address(packed[12:16])
                if embedded.is_private or embedded.is_loopback or embedded.is_reserved:
                    return True
        except (ValueError, ipaddress.AddressValueError):
            pass

    # Teredo tunneling (2001:0000::/32)
    if ip_lower.startswith("2001:0000:") or ip_lower.startswith("2001:0:"):
        return True

    # 6to4 tunneling (2002::/16)
    if ip_lower.startswith("2002:"):
        return True

    # IPv6 multicast (ff00::/8)
    if ip_lower.startswith("ff"):
        return True

    return False


def validate_url(url: str) -> str:
    """Validate a URL for SSRF safety.

    Args:
        url: The URL to validate.

    Returns:
        The validated URL string.

    Raises:
        ValueError: If the URL is invalid or targets a private/blocked address.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        raise ValueError(f"Invalid URL: {url}")

    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"Only http: and https: protocols are supported, got {parsed.scheme}:"
        )

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValueError("URL must contain a hostname")

    if hostname in BLOCKED_HOSTNAMES:
        raise ValueError("Requests to localhost/loopback addresses are blocked")

    if _is_private_ip(hostname):
        raise ValueError("Requests to private/internal IP addresses are blocked")

    if hostname.endswith(".localhost"):
        raise ValueError("Requests to localhost/loopback addresses are blocked")

    if (
        hostname.endswith(".local")
        or hostname.endswith(".internal")
        or hostname.endswith(".arpa")
    ):
        raise ValueError("Requests to internal network hostnames are blocked")

    # Block embedded credentials in URL
    if parsed.username or parsed.password:
        raise ValueError("URLs with embedded credentials are not allowed")

    # DNS rebinding protection: resolve hostname and check all IPs
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        # It is a hostname, not a raw IP -- try resolving
        try:
            infos = socket.getaddrinfo(
                hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
            )
            for _family, _type, _proto, _canonname, sockaddr in infos:
                addr_str = sockaddr[0]
                if "%" in addr_str:
                    addr_str = addr_str.split("%")[0]
                if _is_private_ip(addr_str):
                    raise ValueError(
                        f"Hostname {hostname!r} resolves to private IP {addr_str}"
                    )
        except socket.gaierror:
            raise ValueError(f"Could not resolve hostname: {hostname!r}")

    return url


# ---------------------------------------------------------------------------
# Sanctioned countries (OFAC)
# ---------------------------------------------------------------------------

SANCTIONED_COUNTRIES: Set[str] = {"CU", "IR", "KP", "RU", "SY"}

# ---------------------------------------------------------------------------
# Max response size
# ---------------------------------------------------------------------------

MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB

# ---------------------------------------------------------------------------
# Credential sanitization
# ---------------------------------------------------------------------------

_CREDENTIAL_RE = re.compile(r"dn_(live|test)_[a-zA-Z0-9]+")


def _sanitize_error(message: str) -> str:
    """Remove Dominus Node API key patterns from error messages."""
    return _CREDENTIAL_RE.sub("***", message)


# ---------------------------------------------------------------------------
# Prototype pollution prevention
# ---------------------------------------------------------------------------

_DANGEROUS_KEYS = frozenset({"__proto__", "constructor", "prototype"})


def _strip_dangerous_keys(obj: Any, depth: int = 0) -> None:
    """Remove prototype pollution keys from parsed JSON."""
    if depth > 50 or obj is None or not isinstance(obj, (dict, list)):
        return
    if isinstance(obj, list):
        for item in obj:
            _strip_dangerous_keys(item, depth + 1)
        return
    keys_to_remove = [k for k in obj if k in _DANGEROUS_KEYS]
    for k in keys_to_remove:
        del obj[k]
    for v in obj.values():
        if isinstance(v, (dict, list)):
            _strip_dangerous_keys(v, depth + 1)


# ---------------------------------------------------------------------------
# Allowed HTTP methods for proxied fetch
# ---------------------------------------------------------------------------

_ALLOWED_FETCH_METHODS: Set[str] = {"GET", "HEAD", "OPTIONS"}

# ---------------------------------------------------------------------------
# Handler type
# ---------------------------------------------------------------------------

FunctionHandler = Callable[[str, Dict[str, Any]], Awaitable[str]]

# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------


def create_dominusnode_function_handler(
    api_key: str,
    base_url: str = "https://api.dominusnode.com",
    timeout: float = 30.0,
    agent_secret: Optional[str] = None,
) -> FunctionHandler:
    # Fall back to environment variable if not explicitly provided
    if not agent_secret:
        agent_secret = os.environ.get("DOMINUSNODE_AGENT_SECRET")
    """Create a Dominus Node function handler for OpenAI-compatible function calling.

    Authenticates using the provided API key, then returns an async handler
    function that dispatches function calls to the appropriate Dominus Node REST
    API endpoint.

    Args:
        api_key: Dominus Node API key (starts with ``dn_live_`` or ``dn_test_``).
        base_url: Base URL of the Dominus Node REST API.
        timeout: HTTP request timeout in seconds.

    Returns:
        An async handler function: ``(name, args) -> str``

    Example::

        handler = create_dominusnode_function_handler(api_key="dn_live_abc123")
        result = await handler("dominusnode_check_balance", {})
        data = json.loads(result)
        print(f"Balance: ${data['balanceUsd']}")
    """
    if not api_key or not isinstance(api_key, str):
        raise ValueError("api_key is required and must be a non-empty string")

    auth_token: Optional[str] = None

    async def authenticate() -> str:
        """Authenticate with the Dominus Node API using the API key."""
        nonlocal auth_token

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
        ) as client:
            auth_headers: Dict[str, str] = {
                    "User-Agent": "dominusnode-openai-functions/1.0.0",
                    "Content-Type": "application/json",
                }
            if agent_secret:
                auth_headers["X-DominusNode-Agent"] = "mcp"
                auth_headers["X-DominusNode-Agent-Secret"] = agent_secret

            resp = await client.post(
                f"{base_url}/api/auth/verify-key",
                json={"apiKey": api_key},
                headers=auth_headers,
            )

            if resp.status_code != 200:
                body = _sanitize_error(resp.text[:500])
                raise RuntimeError(
                    f"Authentication failed ({resp.status_code}): {body}"
                )

            data = resp.json()
            token = data.get("token")
            if not token:
                raise RuntimeError("Authentication response missing token")
            auth_token = token
            return token

    async def ensure_auth() -> None:
        nonlocal auth_token
        if auth_token is None:
            await authenticate()

    async def api_request(
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Make an authenticated API request."""
        if auth_token is None:
            raise RuntimeError("Not authenticated")

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
        ) as client:
            req_headers: Dict[str, str] = {
                    "User-Agent": "dominusnode-openai-functions/1.0.0",
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {auth_token}",
                }
            if agent_secret:
                req_headers["X-DominusNode-Agent"] = "mcp"
                req_headers["X-DominusNode-Agent-Secret"] = agent_secret

            kwargs: Dict[str, Any] = {
                "headers": req_headers,
            }

            if body is not None:
                kwargs["json"] = body

            resp = await client.request(method, f"{base_url}{path}", **kwargs)

            if len(resp.content) > MAX_RESPONSE_BYTES:
                raise RuntimeError("Response body too large")

            if resp.status_code >= 400:
                try:
                    err_data = resp.json()
                    msg = err_data.get("error", resp.text)
                except Exception:
                    msg = resp.text
                msg = str(msg)[:500]
                raise RuntimeError(f"API error {resp.status_code}: {_sanitize_error(msg)}")

            if resp.text:
                data = resp.json()
                _strip_dangerous_keys(data)
                return data
            return {}

    # -------------------------------------------------------------------
    # Period to date range helper
    # -------------------------------------------------------------------

    def _period_to_date_range(period: str) -> Dict[str, str]:
        now = datetime.now(timezone.utc)
        until = now.isoformat()

        if period == "day":
            since = (now - timedelta(days=1)).isoformat()
        elif period == "week":
            since = (now - timedelta(weeks=1)).isoformat()
        else:  # month
            since = (now - timedelta(days=30)).isoformat()

        return {"since": since, "until": until}

    # -------------------------------------------------------------------
    # Individual function handlers
    # -------------------------------------------------------------------

    async def handle_proxied_fetch(args: Dict[str, Any]) -> str:
        url = args.get("url")
        if not url or not isinstance(url, str):
            return json.dumps({"error": "url is required and must be a string"})

        # SSRF validation
        try:
            validate_url(url)
        except ValueError as e:
            return json.dumps({"error": str(e)})

        # Country validation
        country = args.get("country")
        if country:
            upper = country.upper()
            if upper in SANCTIONED_COUNTRIES:
                return json.dumps(
                    {"error": f"Country '{upper}' is blocked (OFAC sanctioned country)"}
                )

        method = (args.get("method") or "GET").upper()

        # Restrict to read-only HTTP methods
        if method not in _ALLOWED_FETCH_METHODS:
            return json.dumps({
                "error": f"HTTP method '{method}' is not allowed. Only GET, HEAD, OPTIONS are permitted."
            })

        proxy_type = args.get("proxy_type") or "dc"
        headers = args.get("headers") or {}

        # Strip security-sensitive headers
        blocked_header_names = {
            "host", "connection", "content-length", "transfer-encoding",
            "proxy-authorization", "authorization", "user-agent",
        }
        safe_headers: Dict[str, str] = {}
        for key, value in headers.items():
            if key.lower() not in blocked_header_names:
                # CRLF injection prevention
                if "\r" in key or "\n" in key or "\0" in key:
                    continue
                if "\r" in str(value) or "\n" in str(value) or "\0" in str(value):
                    continue
                safe_headers[key] = str(value)

        try:
            proxy_host = os.environ.get("DOMINUSNODE_PROXY_HOST", "proxy.dominusnode.com")
            proxy_port = os.environ.get("DOMINUSNODE_PROXY_PORT", "8080")
            api_key_val = api_key  # from outer scope

            # Build proxy username for routing
            parts: list[str] = []
            if proxy_type and proxy_type != "auto":
                parts.append(proxy_type)
            if country:
                parts.append(f"country-{country.upper()}")
            username = "-".join(parts) if parts else "auto"

            proxy_url = f"http://{username}:{api_key_val}@{proxy_host}:{proxy_port}"

            async with httpx.AsyncClient(
                proxy=proxy_url,
                timeout=30.0,
                follow_redirects=False,
                max_redirects=0,
            ) as proxy_client:
                resp = await proxy_client.request(
                    method=method,
                    url=url,
                    headers=safe_headers,
                )
                body = resp.text[:4000]  # Truncate for AI consumption
                resp_headers = dict(resp.headers)
                # Scrub sensitive headers
                for h in ("set-cookie", "www-authenticate", "proxy-authenticate"):
                    resp_headers.pop(h, None)
                return json.dumps({
                    "status": resp.status_code,
                    "headers": resp_headers,
                    "body": body,
                })
        except Exception as e:
            return json.dumps({
                "error": f"Proxy fetch failed: {_sanitize_error(str(e))}",
                "hint": "Ensure the Dominus Node proxy gateway is running and accessible.",
            })

    async def handle_check_balance(_args: Dict[str, Any]) -> str:
        result = await api_request("GET", "/api/wallet")
        return json.dumps(result)

    async def handle_check_usage(args: Dict[str, Any]) -> str:
        period = args.get("period", "month")
        date_range = _period_to_date_range(period)
        result = await api_request(
            "GET",
            f"/api/usage?since={quote(date_range['since'], safe='')}"
            f"&until={quote(date_range['until'], safe='')}",
        )
        return json.dumps(result)

    async def handle_get_proxy_config(_args: Dict[str, Any]) -> str:
        result = await api_request("GET", "/api/proxy/config")
        return json.dumps(result)

    async def handle_list_sessions(_args: Dict[str, Any]) -> str:
        result = await api_request("GET", "/api/sessions/active")
        return json.dumps(result)

    _DOMAIN_RE = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?"
        r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$"
    )

    async def handle_create_agentic_wallet(args: Dict[str, Any]) -> str:
        label = args.get("label")
        spending_limit_cents = args.get("spending_limit_cents")

        if not label or not isinstance(label, str):
            return json.dumps({"error": "label is required and must be a string"})
        if len(label) > 100:
            return json.dumps({"error": "label must be 100 characters or fewer"})
        if any(0 <= ord(c) <= 0x1F or ord(c) == 0x7F for c in label):
            return json.dumps({"error": "label contains invalid control characters"})

        if (
            not isinstance(spending_limit_cents, int)
            or spending_limit_cents <= 0
            or spending_limit_cents > 2_147_483_647
        ):
            return json.dumps({
                "error": "spending_limit_cents must be a positive integer <= 2,147,483,647"
            })

        body: Dict[str, Any] = {
            "label": label,
            "spendingLimitCents": spending_limit_cents,
        }

        # Optional daily_limit_cents
        if "daily_limit_cents" in args:
            daily_limit = args["daily_limit_cents"]
            if (
                not isinstance(daily_limit, int)
                or daily_limit < 1
                or daily_limit > 1_000_000
            ):
                return json.dumps({
                    "error": "daily_limit_cents must be an integer between 1 and 1,000,000"
                })
            body["dailyLimitCents"] = daily_limit

        # Optional allowed_domains
        if "allowed_domains" in args:
            domains = args["allowed_domains"]
            if not isinstance(domains, list):
                return json.dumps({"error": "allowed_domains must be an array of strings"})
            if len(domains) > 100:
                return json.dumps({"error": "allowed_domains must have 100 or fewer entries"})
            for d in domains:
                if not isinstance(d, str):
                    return json.dumps({"error": "Each allowed_domains entry must be a string"})
                if len(d) > 253:
                    return json.dumps(
                        {"error": "Each allowed_domains entry must be 253 characters or fewer"}
                    )
                if not _DOMAIN_RE.match(d):
                    return json.dumps({"error": f"Invalid domain format: {d}"})
            body["allowedDomains"] = domains

        result = await api_request("POST", "/api/agent-wallet", body)
        return json.dumps(result)

    async def handle_fund_agentic_wallet(args: Dict[str, Any]) -> str:
        wallet_id = args.get("wallet_id")
        amount_cents = args.get("amount_cents")

        if not wallet_id or not isinstance(wallet_id, str):
            return json.dumps({"error": "wallet_id is required and must be a string"})

        if (
            not isinstance(amount_cents, int)
            or amount_cents <= 0
            or amount_cents > 2_147_483_647
        ):
            return json.dumps({
                "error": "amount_cents must be a positive integer <= 2,147,483,647"
            })

        result = await api_request(
            "POST",
            f"/api/agent-wallet/{quote(wallet_id, safe='')}/fund",
            {"amountCents": amount_cents},
        )
        return json.dumps(result)

    async def handle_agentic_wallet_balance(args: Dict[str, Any]) -> str:
        wallet_id = args.get("wallet_id")

        if not wallet_id or not isinstance(wallet_id, str):
            return json.dumps({"error": "wallet_id is required and must be a string"})

        result = await api_request(
            "GET",
            f"/api/agent-wallet/{quote(wallet_id, safe='')}",
        )
        return json.dumps(result)

    async def handle_list_agentic_wallets(_args: Dict[str, Any]) -> str:
        result = await api_request("GET", "/api/agent-wallet")
        return json.dumps(result)

    async def handle_agentic_transactions(args: Dict[str, Any]) -> str:
        wallet_id = args.get("wallet_id")
        if not wallet_id or not isinstance(wallet_id, str):
            return json.dumps({"error": "wallet_id is required and must be a string"})

        limit = args.get("limit")
        qs = ""
        if limit is not None:
            if not isinstance(limit, int) or limit < 1 or limit > 100:
                return json.dumps(
                    {"error": "limit must be an integer between 1 and 100"}
                )
            qs = f"?limit={limit}"

        result = await api_request(
            "GET",
            f"/api/agent-wallet/{quote(wallet_id, safe='')}/transactions{qs}",
        )
        return json.dumps(result)

    async def handle_freeze_agentic_wallet(args: Dict[str, Any]) -> str:
        wallet_id = args.get("wallet_id")
        if not wallet_id or not isinstance(wallet_id, str):
            return json.dumps({"error": "wallet_id is required and must be a string"})

        result = await api_request(
            "POST",
            f"/api/agent-wallet/{quote(wallet_id, safe='')}/freeze",
        )
        return json.dumps(result)

    async def handle_unfreeze_agentic_wallet(args: Dict[str, Any]) -> str:
        wallet_id = args.get("wallet_id")
        if not wallet_id or not isinstance(wallet_id, str):
            return json.dumps({"error": "wallet_id is required and must be a string"})

        result = await api_request(
            "POST",
            f"/api/agent-wallet/{quote(wallet_id, safe='')}/unfreeze",
        )
        return json.dumps(result)

    async def handle_delete_agentic_wallet(args: Dict[str, Any]) -> str:
        wallet_id = args.get("wallet_id")
        if not wallet_id or not isinstance(wallet_id, str):
            return json.dumps({"error": "wallet_id is required and must be a string"})

        result = await api_request(
            "DELETE",
            f"/api/agent-wallet/{quote(wallet_id, safe='')}",
        )
        return json.dumps(result)

    _UUID_RE = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )

    async def handle_update_wallet_policy(args: Dict[str, Any]) -> str:
        wallet_id = args.get("wallet_id")
        if not wallet_id or not isinstance(wallet_id, str):
            return json.dumps({"error": "wallet_id is required and must be a string"})
        if not _UUID_RE.match(wallet_id):
            return json.dumps({"error": "wallet_id must be a valid UUID"})

        body: Dict[str, Any] = {}

        # daily_limit_cents: integer or None (to remove)
        if "daily_limit_cents" in args:
            daily_limit = args["daily_limit_cents"]
            if daily_limit is None:
                body["dailyLimitCents"] = None
            else:
                if (
                    not isinstance(daily_limit, int)
                    or daily_limit < 1
                    or daily_limit > 1_000_000
                ):
                    return json.dumps({
                        "error": "daily_limit_cents must be an integer between 1 and 1,000,000 (or null to remove)"
                    })
                body["dailyLimitCents"] = daily_limit

        # allowed_domains: list or None (to remove)
        if "allowed_domains" in args:
            domains = args["allowed_domains"]
            if domains is None:
                body["allowedDomains"] = None
            else:
                if not isinstance(domains, list):
                    return json.dumps(
                        {"error": "allowed_domains must be an array of strings or null"}
                    )
                if len(domains) > 100:
                    return json.dumps(
                        {"error": "allowed_domains must have 100 or fewer entries"}
                    )
                for d in domains:
                    if not isinstance(d, str):
                        return json.dumps(
                            {"error": "Each allowed_domains entry must be a string"}
                        )
                    if len(d) > 253:
                        return json.dumps(
                            {"error": "Each allowed_domains entry must be 253 characters or fewer"}
                        )
                    if not _DOMAIN_RE.match(d):
                        return json.dumps({"error": f"Invalid domain format: {d}"})
                body["allowedDomains"] = domains

        if not body:
            return json.dumps(
                {"error": "At least one of daily_limit_cents or allowed_domains must be provided"}
            )

        result = await api_request(
            "PATCH",
            f"/api/agent-wallet/{quote(wallet_id, safe='')}/policy",
            body,
        )
        return json.dumps(result)

    async def handle_create_team(args: Dict[str, Any]) -> str:
        name = args.get("name")
        if not name or not isinstance(name, str):
            return json.dumps({"error": "name is required and must be a string"})
        if len(name) > 100:
            return json.dumps({"error": "name must be 100 characters or fewer"})
        # Block control characters
        if any(0 <= ord(c) <= 0x1F or ord(c) == 0x7F for c in name):
            return json.dumps(
                {"error": "name contains invalid control characters"}
            )

        body: Dict[str, Any] = {"name": name}
        max_members = args.get("max_members")
        if max_members is not None:
            if not isinstance(max_members, int) or max_members < 1 or max_members > 100:
                return json.dumps(
                    {"error": "max_members must be an integer between 1 and 100"}
                )
            body["maxMembers"] = max_members

        result = await api_request("POST", "/api/teams", body)
        return json.dumps(result)

    async def handle_list_teams(_args: Dict[str, Any]) -> str:
        result = await api_request("GET", "/api/teams")
        return json.dumps(result)

    async def handle_team_details(args: Dict[str, Any]) -> str:
        team_id = args.get("team_id")
        if not team_id or not isinstance(team_id, str):
            return json.dumps({"error": "team_id is required and must be a string"})

        result = await api_request(
            "GET", f"/api/teams/{quote(team_id, safe='')}"
        )
        return json.dumps(result)

    async def handle_team_fund(args: Dict[str, Any]) -> str:
        team_id = args.get("team_id")
        amount_cents = args.get("amount_cents")

        if not team_id or not isinstance(team_id, str):
            return json.dumps({"error": "team_id is required and must be a string"})

        if (
            not isinstance(amount_cents, int)
            or amount_cents < 100
            or amount_cents > 1_000_000
        ):
            return json.dumps({
                "error": "amount_cents must be an integer between 100 ($1) and 1,000,000 ($10,000)"
            })

        result = await api_request(
            "POST",
            f"/api/teams/{quote(team_id, safe='')}/wallet/fund",
            {"amountCents": amount_cents},
        )
        return json.dumps(result)

    async def handle_team_create_key(args: Dict[str, Any]) -> str:
        team_id = args.get("team_id")
        label = args.get("label")

        if not team_id or not isinstance(team_id, str):
            return json.dumps({"error": "team_id is required and must be a string"})
        if not label or not isinstance(label, str):
            return json.dumps({"error": "label is required and must be a string"})
        if len(label) > 100:
            return json.dumps({"error": "label must be 100 characters or fewer"})
        # Block control characters
        if any(0 <= ord(c) <= 0x1F or ord(c) == 0x7F for c in label):
            return json.dumps(
                {"error": "label contains invalid control characters"}
            )

        result = await api_request(
            "POST",
            f"/api/teams/{quote(team_id, safe='')}/keys",
            {"label": label},
        )
        return json.dumps(result)

    async def handle_team_usage(args: Dict[str, Any]) -> str:
        team_id = args.get("team_id")
        if not team_id or not isinstance(team_id, str):
            return json.dumps({"error": "team_id is required and must be a string"})

        limit = args.get("limit")
        qs = ""
        if limit is not None:
            if not isinstance(limit, int) or limit < 1 or limit > 100:
                return json.dumps(
                    {"error": "limit must be an integer between 1 and 100"}
                )
            qs = f"?limit={limit}"

        result = await api_request(
            "GET",
            f"/api/teams/{quote(team_id, safe='')}/wallet/transactions{qs}",
        )
        return json.dumps(result)

    async def handle_update_team(args: Dict[str, Any]) -> str:
        team_id = args.get("team_id")
        if not team_id or not isinstance(team_id, str):
            return json.dumps({"error": "team_id is required and must be a string"})
        if not _UUID_RE.match(team_id):
            return json.dumps({"error": "team_id must be a valid UUID"})

        body: Dict[str, Any] = {}

        name = args.get("name")
        if name is not None:
            if not isinstance(name, str) or len(name) == 0:
                return json.dumps({"error": "name must be a non-empty string"})
            if len(name) > 100:
                return json.dumps({"error": "name must be 100 characters or fewer"})
            if any(0 <= ord(c) <= 0x1F or ord(c) == 0x7F for c in name):
                return json.dumps(
                    {"error": "name contains invalid control characters"}
                )
            body["name"] = name

        max_members = args.get("max_members")
        if max_members is not None:
            if not isinstance(max_members, int) or max_members < 1 or max_members > 100:
                return json.dumps(
                    {"error": "max_members must be an integer between 1 and 100"}
                )
            body["maxMembers"] = max_members

        if not body:
            return json.dumps(
                {"error": "At least one of name or max_members must be provided"}
            )

        result = await api_request(
            "PATCH",
            f"/api/teams/{quote(team_id, safe='')}",
            body,
        )
        return json.dumps(result)

    async def handle_topup_paypal(args: Dict[str, Any]) -> str:
        amount_cents = args.get("amount_cents")

        if isinstance(amount_cents, bool):
            return json.dumps({
                "error": "amount_cents must be an integer between 500 ($5) and 100,000 ($1,000)",
            })
        if not isinstance(amount_cents, int) or amount_cents < 500 or amount_cents > 100_000:
            return json.dumps({
                "error": "amount_cents must be an integer between 500 ($5) and 100,000 ($1,000)",
            })

        result = await api_request("POST", "/api/wallet/topup/paypal", {"amountCents": amount_cents})
        return json.dumps(result)

    async def handle_topup_stripe(args: Dict[str, Any]) -> str:
        amount_cents = args.get("amount_cents")

        if isinstance(amount_cents, bool):
            return json.dumps({
                "error": "amount_cents must be an integer between 500 ($5) and 100,000 ($1,000)",
            })
        if not isinstance(amount_cents, int) or amount_cents < 500 or amount_cents > 100_000:
            return json.dumps({
                "error": "amount_cents must be an integer between 500 ($5) and 100,000 ($1,000)",
            })

        result = await api_request("POST", "/api/wallet/topup/stripe", {"amountCents": amount_cents})
        return json.dumps(result)

    async def handle_topup_crypto(args: Dict[str, Any]) -> str:
        amount_usd = args.get("amount_usd")
        currency = args.get("currency")

        if isinstance(amount_usd, bool):
            return json.dumps({
                "error": "amount_usd must be a number between 5 and 1,000",
            })
        if not isinstance(amount_usd, (int, float)) or not math.isfinite(amount_usd) or amount_usd < 5 or amount_usd > 1000:
            return json.dumps({
                "error": "amount_usd must be a number between 5 and 1,000",
            })

        valid_currencies = {"BTC", "ETH", "LTC", "XMR", "ZEC", "USDC", "SOL", "USDT", "DAI", "BNB", "LINK"}
        if not currency or not isinstance(currency, str) or currency.upper() not in valid_currencies:
            return json.dumps({
                "error": "currency must be one of: BTC, ETH, LTC, XMR, ZEC, USDC, SOL, USDT, DAI, BNB, LINK",
            })

        result = await api_request("POST", "/api/wallet/topup/crypto", {
            "amountUsd": amount_usd,
            "currency": currency.lower(),
        })
        return json.dumps(result)

    async def handle_x402_info(_args: Dict[str, Any]) -> str:
        result = await api_request("GET", "/api/x402/info")
        return json.dumps(result)

    async def handle_update_team_member_role(args: Dict[str, Any]) -> str:
        team_id = args.get("team_id")
        user_id = args.get("user_id")
        role = args.get("role")

        if not team_id or not isinstance(team_id, str):
            return json.dumps({"error": "team_id is required and must be a string"})
        if not _UUID_RE.match(team_id):
            return json.dumps({"error": "team_id must be a valid UUID"})
        if not user_id or not isinstance(user_id, str):
            return json.dumps({"error": "user_id is required and must be a string"})
        if not _UUID_RE.match(user_id):
            return json.dumps({"error": "user_id must be a valid UUID"})
        if not role or not isinstance(role, str):
            return json.dumps({"error": "role is required and must be a string"})
        if role not in ("member", "admin"):
            return json.dumps({"error": "role must be 'member' or 'admin'"})

        result = await api_request(
            "PATCH",
            f"/api/teams/{quote(team_id, safe='')}/members/{quote(user_id, safe='')}",
            {"role": role},
        )
        return json.dumps(result)

    # -------------------------------------------------------------------
    # Dispatch table
    # -------------------------------------------------------------------

    handlers: Dict[str, Callable[[Dict[str, Any]], Awaitable[str]]] = {
        "dominusnode_proxied_fetch": handle_proxied_fetch,
        "dominusnode_check_balance": handle_check_balance,
        "dominusnode_check_usage": handle_check_usage,
        "dominusnode_get_proxy_config": handle_get_proxy_config,
        "dominusnode_list_sessions": handle_list_sessions,
        "dominusnode_create_agentic_wallet": handle_create_agentic_wallet,
        "dominusnode_fund_agentic_wallet": handle_fund_agentic_wallet,
        "dominusnode_agentic_wallet_balance": handle_agentic_wallet_balance,
        "dominusnode_list_agentic_wallets": handle_list_agentic_wallets,
        "dominusnode_agentic_transactions": handle_agentic_transactions,
        "dominusnode_freeze_agentic_wallet": handle_freeze_agentic_wallet,
        "dominusnode_unfreeze_agentic_wallet": handle_unfreeze_agentic_wallet,
        "dominusnode_delete_agentic_wallet": handle_delete_agentic_wallet,
        "dominusnode_update_wallet_policy": handle_update_wallet_policy,
        "dominusnode_create_team": handle_create_team,
        "dominusnode_list_teams": handle_list_teams,
        "dominusnode_team_details": handle_team_details,
        "dominusnode_team_fund": handle_team_fund,
        "dominusnode_team_create_key": handle_team_create_key,
        "dominusnode_team_usage": handle_team_usage,
        "dominusnode_update_team": handle_update_team,
        "dominusnode_update_team_member_role": handle_update_team_member_role,
        "dominusnode_topup_paypal": handle_topup_paypal,
        "dominusnode_topup_stripe": handle_topup_stripe,
        "dominusnode_topup_crypto": handle_topup_crypto,
        "dominusnode_x402_info": handle_x402_info,
    }

    # -------------------------------------------------------------------
    # Main handler
    # -------------------------------------------------------------------

    async def handler(name: str, args: Dict[str, Any]) -> str:
        """Dispatch an OpenAI function call to the appropriate Dominus Node API endpoint.

        Args:
            name: The function name (e.g., ``dominusnode_check_balance``).
            args: The function arguments as a dict.

        Returns:
            A JSON string with the result or error.
        """
        await ensure_auth()

        fn = handlers.get(name)
        if fn is None:
            return json.dumps({
                "error": f"Unknown function: {name}",
                "available": list(handlers.keys()),
            })

        try:
            return await fn(args)
        except Exception as e:
            if "401" in str(e):
                nonlocal auth_token
                auth_token = None
                await ensure_auth()
                return await fn(args)
            return json.dumps({"error": _sanitize_error(str(e))})

    return handler
