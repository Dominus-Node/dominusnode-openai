"""Tests for the Dominus Node OpenAI-compatible function calling handler (Python).

Run with: python -m pytest test_handler.py -v
"""

from __future__ import annotations

import json
import re
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from handler import (
    _is_private_ip,
    _normalize_ipv4,
    _sanitize_error,
    _strip_dangerous_keys,
    SANCTIONED_COUNTRIES,
    validate_url,
    create_dominusnode_function_handler,
)


# =========================================================================
# SSRF Protection — _is_private_ip
# =========================================================================


class TestIsPrivateIp:
    """Tests for private IP detection."""

    def test_loopback_127_0_0_1(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_loopback_127_255_255_255(self):
        assert _is_private_ip("127.255.255.255") is True

    def test_private_10_network(self):
        assert _is_private_ip("10.0.0.0") is True

    def test_private_10_upper(self):
        assert _is_private_ip("10.255.255.255") is True

    def test_private_172_16(self):
        assert _is_private_ip("172.16.0.1") is True

    def test_private_172_31(self):
        assert _is_private_ip("172.31.255.255") is True

    def test_not_private_172_15(self):
        assert _is_private_ip("172.15.0.1") is False

    def test_not_private_172_32(self):
        assert _is_private_ip("172.32.0.1") is False

    def test_private_192_168(self):
        assert _is_private_ip("192.168.0.1") is True

    def test_link_local(self):
        assert _is_private_ip("169.254.169.254") is True

    def test_zero_network(self):
        assert _is_private_ip("0.0.0.0") is True

    def test_cgnat_lower(self):
        assert _is_private_ip("100.64.0.1") is True

    def test_cgnat_upper(self):
        assert _is_private_ip("100.127.255.255") is True

    def test_below_cgnat(self):
        assert _is_private_ip("100.63.255.255") is False

    def test_multicast(self):
        assert _is_private_ip("224.0.0.1") is True

    def test_broadcast(self):
        assert _is_private_ip("255.255.255.255") is True

    def test_public_8_8_8_8(self):
        assert _is_private_ip("8.8.8.8") is False

    def test_public_1_1_1_1(self):
        assert _is_private_ip("1.1.1.1") is False

    # IPv6
    def test_ipv6_loopback(self):
        assert _is_private_ip("::1") is True

    def test_ipv6_unspecified(self):
        assert _is_private_ip("::") is True

    def test_ipv6_ula_fc(self):
        assert _is_private_ip("fc00::1") is True

    def test_ipv6_ula_fd(self):
        assert _is_private_ip("fd12::1") is True

    def test_ipv6_link_local(self):
        assert _is_private_ip("fe80::1") is True

    def test_ipv4_mapped_loopback(self):
        assert _is_private_ip("::ffff:127.0.0.1") is True

    def test_ipv4_mapped_private(self):
        assert _is_private_ip("::ffff:10.0.0.1") is True

    def test_ipv4_mapped_hex(self):
        assert _is_private_ip("::ffff:7f00:0001") is True

    def test_zone_id_stripping(self):
        assert _is_private_ip("fe80::1%eth0") is True

    def test_bracketed_ipv6(self):
        assert _is_private_ip("[::1]") is True


# =========================================================================
# SSRF Protection — _normalize_ipv4
# =========================================================================


class TestNormalizeIpv4:
    """Tests for IPv4 normalization."""

    def test_decimal_integer(self):
        assert _normalize_ipv4("2130706433") == "127.0.0.1"

    def test_hex_notation(self):
        assert _normalize_ipv4("0x7f000001") == "127.0.0.1"

    def test_octal_octets(self):
        assert _normalize_ipv4("0177.0.0.1") == "127.0.0.1"

    def test_mixed_radix(self):
        assert _normalize_ipv4("0xC0.0xA8.0x01.0x01") == "192.168.1.1"

    def test_hostname_returns_none(self):
        assert _normalize_ipv4("example.com") is None

    def test_zero(self):
        assert _normalize_ipv4("0") == "0.0.0.0"

    def test_max_uint32(self):
        assert _normalize_ipv4("4294967295") == "255.255.255.255"


# =========================================================================
# SSRF Protection — validate_url
# =========================================================================


class TestValidateUrl:
    """Tests for URL validation."""

    def test_accepts_https(self):
        result = validate_url("https://httpbin.org/ip")
        assert result == "https://httpbin.org/ip"

    def test_accepts_http(self):
        result = validate_url("http://example.com/path")
        assert result == "http://example.com/path"

    def test_rejects_file_protocol(self):
        with pytest.raises(ValueError, match="protocols"):
            validate_url("file:///etc/passwd")

    def test_rejects_ftp_protocol(self):
        with pytest.raises(ValueError, match="protocols"):
            validate_url("ftp://ftp.example.com")

    def test_rejects_localhost(self):
        with pytest.raises(ValueError, match="localhost"):
            validate_url("http://localhost/secret")

    def test_rejects_private_ip(self):
        with pytest.raises(ValueError, match="private"):
            validate_url("http://192.168.1.1/admin")

    def test_rejects_localhost_tld(self):
        with pytest.raises(ValueError, match="localhost"):
            validate_url("http://evil.localhost/")

    def test_rejects_local_hostname(self):
        with pytest.raises(ValueError, match="internal"):
            validate_url("http://printer.local/")

    def test_rejects_internal_hostname(self):
        with pytest.raises(ValueError, match="internal"):
            validate_url("http://db.internal/")

    def test_rejects_arpa_hostname(self):
        with pytest.raises(ValueError, match="internal"):
            validate_url("http://1.168.192.in-addr.arpa/")

    def test_rejects_embedded_credentials(self):
        with pytest.raises(ValueError, match="credentials"):
            validate_url("http://user:pass@example.com/")

    def test_rejects_cloud_metadata(self):
        with pytest.raises(ValueError, match="private"):
            validate_url("http://169.254.169.254/latest/meta-data/")


# =========================================================================
# Credential Sanitization
# =========================================================================


class TestSanitizeError:
    """Tests for credential sanitization."""

    def test_redacts_live_tokens(self):
        result = _sanitize_error("failed with dn_live_abc123key")
        assert "dn_live_abc123key" not in result
        assert "***" in result

    def test_redacts_test_tokens(self):
        result = _sanitize_error("error at dn_test_xyz789")
        assert "dn_test_xyz789" not in result

    def test_redacts_multiple(self):
        result = _sanitize_error("keys: dn_live_a and dn_test_b")
        assert "dn_live_a" not in result
        assert "dn_test_b" not in result

    def test_no_credentials_unchanged(self):
        assert _sanitize_error("no secrets here") == "no secrets here"

    def test_empty_string(self):
        assert _sanitize_error("") == ""


# =========================================================================
# Prototype Pollution Prevention
# =========================================================================


class TestStripDangerousKeys:
    """Tests for prototype pollution prevention."""

    def test_removes_constructor(self):
        obj = {"constructor": "evil", "a": 1}
        _strip_dangerous_keys(obj)
        assert "constructor" not in obj
        assert obj["a"] == 1

    def test_removes_prototype(self):
        obj = {"prototype": "evil", "b": 2}
        _strip_dangerous_keys(obj)
        assert "prototype" not in obj

    def test_removes___proto__(self):
        obj = {"__proto__": {"evil": True}, "c": 3}
        _strip_dangerous_keys(obj)
        assert "__proto__" not in obj

    def test_nested_recursive(self):
        obj = {"nested": {"constructor": "bad", "ok": True}}
        _strip_dangerous_keys(obj)
        assert "constructor" not in obj["nested"]
        assert obj["nested"]["ok"] is True

    def test_handles_arrays(self):
        arr = [{"constructor": "bad"}, {"safe": True}]
        _strip_dangerous_keys(arr)
        assert "constructor" not in arr[0]
        assert arr[1]["safe"] is True

    def test_handles_none(self):
        _strip_dangerous_keys(None)  # should not raise

    def test_handles_primitives(self):
        _strip_dangerous_keys(42)  # should not raise
        _strip_dangerous_keys("string")  # should not raise


# =========================================================================
# Handler Factory
# =========================================================================


class TestCreateHandler:
    """Tests for the handler factory."""

    def test_rejects_empty_api_key(self):
        with pytest.raises(ValueError, match="api_key"):
            create_dominusnode_function_handler(api_key="")

    def test_rejects_none_api_key(self):
        with pytest.raises(ValueError, match="api_key"):
            create_dominusnode_function_handler(api_key=None)  # type: ignore

    def test_returns_callable(self):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        assert callable(handler)


# =========================================================================
# Handler Dispatch — async tests
# =========================================================================


class TestHandlerDispatch:
    """Tests for handler function dispatching."""

    @pytest.fixture
    def mock_httpx(self):
        """Mock httpx.AsyncClient for all API calls."""
        with patch("handler.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()

            # Auth response
            auth_resp = MagicMock()
            auth_resp.status_code = 200
            auth_resp.text = '{"token": "jwt-mock-token"}'
            auth_resp.json.return_value = {"token": "jwt-mock-token"}

            # Default API response
            api_resp = MagicMock()
            api_resp.status_code = 200
            api_resp.text = '{"success": true}'
            api_resp.content = b'{"success": true}'
            api_resp.json.return_value = {"success": True}

            mock_client.post.return_value = auth_resp
            mock_client.request.return_value = api_resp

            # Context manager support
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            yield mock_client

    @pytest.mark.asyncio
    async def test_unknown_function(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(await handler("unknown_function", {}))
        assert "Unknown function" in result["error"]
        assert "available" in result

    @pytest.mark.asyncio
    async def test_dispatch_check_balance(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(await handler("dominusnode_check_balance", {}))
        assert "success" in result

    @pytest.mark.asyncio
    async def test_dispatch_list_teams(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(await handler("dominusnode_list_teams", {}))
        assert "success" in result

    @pytest.mark.asyncio
    async def test_handler_has_26_functions(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(await handler("nonexistent", {}))
        assert len(result["available"]) == 26

    @pytest.mark.asyncio
    async def test_dispatch_update_wallet_policy(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_update_wallet_policy",
                {
                    "wallet_id": "550e8400-e29b-41d4-a716-446655440000",
                    "daily_limit_cents": 5000,
                },
            )
        )
        assert "success" in result


# =========================================================================
# Input Validation — per-handler
# =========================================================================


class TestHandlerValidation:
    """Tests for individual handler input validation."""

    @pytest.fixture
    def mock_httpx(self):
        with patch("handler.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()

            auth_resp = MagicMock()
            auth_resp.status_code = 200
            auth_resp.text = '{"token": "jwt-mock-token"}'
            auth_resp.json.return_value = {"token": "jwt-mock-token"}

            api_resp = MagicMock()
            api_resp.status_code = 200
            api_resp.text = '{"success": true}'
            api_resp.content = b'{"success": true}'
            api_resp.json.return_value = {"success": True}

            mock_client.post.return_value = auth_resp
            mock_client.request.return_value = api_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client
            yield mock_client

    @pytest.mark.asyncio
    async def test_proxied_fetch_missing_url(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler("dominusnode_proxied_fetch", {})
        )
        assert "url" in result["error"]

    @pytest.mark.asyncio
    async def test_proxied_fetch_rejects_localhost(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler("dominusnode_proxied_fetch", {"url": "http://localhost/"})
        )
        assert "localhost" in result["error"]

    @pytest.mark.asyncio
    async def test_proxied_fetch_rejects_ofac_country(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_proxied_fetch",
                {"url": "https://example.com", "country": "CU"},
            )
        )
        assert "OFAC" in result["error"]

    @pytest.mark.asyncio
    async def test_proxied_fetch_rejects_post(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_proxied_fetch",
                {"url": "https://example.com", "method": "POST"},
            )
        )
        assert "not allowed" in result["error"]

    @pytest.mark.asyncio
    async def test_create_wallet_missing_label(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_create_agentic_wallet",
                {"spending_limit_cents": 100},
            )
        )
        assert "label" in result["error"]

    @pytest.mark.asyncio
    async def test_create_wallet_long_label(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_create_agentic_wallet",
                {"label": "a" * 101, "spending_limit_cents": 100},
            )
        )
        assert "100" in result["error"]

    @pytest.mark.asyncio
    async def test_create_wallet_control_chars(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_create_agentic_wallet",
                {"label": "test\x00label", "spending_limit_cents": 100},
            )
        )
        assert "control characters" in result["error"]

    @pytest.mark.asyncio
    async def test_fund_wallet_missing_id(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_fund_agentic_wallet",
                {"amount_cents": 100},
            )
        )
        assert "wallet_id" in result["error"]

    @pytest.mark.asyncio
    async def test_fund_wallet_invalid_amount(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_fund_agentic_wallet",
                {"wallet_id": "abc", "amount_cents": -5},
            )
        )
        assert "amount_cents" in result["error"]

    @pytest.mark.asyncio
    async def test_create_team_missing_name(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler("dominusnode_create_team", {})
        )
        assert "name" in result["error"]

    @pytest.mark.asyncio
    async def test_create_team_control_chars(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler("dominusnode_create_team", {"name": "team\x07name"})
        )
        assert "control characters" in result["error"]

    @pytest.mark.asyncio
    async def test_create_team_invalid_max_members(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_create_team",
                {"name": "test", "max_members": 101},
            )
        )
        assert "max_members" in result["error"]

    @pytest.mark.asyncio
    async def test_team_details_missing_id(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler("dominusnode_team_details", {})
        )
        assert "team_id" in result["error"]

    @pytest.mark.asyncio
    async def test_team_fund_missing_id(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler("dominusnode_team_fund", {"amount_cents": 100})
        )
        assert "team_id" in result["error"]

    @pytest.mark.asyncio
    async def test_team_fund_low_amount(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_team_fund",
                {"team_id": "abc", "amount_cents": 50},
            )
        )
        assert "amount_cents" in result["error"]

    @pytest.mark.asyncio
    async def test_team_create_key_missing_label(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_team_create_key",
                {"team_id": "abc"},
            )
        )
        assert "label" in result["error"]

    @pytest.mark.asyncio
    async def test_team_create_key_control_chars(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_team_create_key",
                {"team_id": "abc", "label": "key\x01name"},
            )
        )
        assert "control characters" in result["error"]

    @pytest.mark.asyncio
    async def test_team_usage_missing_id(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler("dominusnode_team_usage", {})
        )
        assert "team_id" in result["error"]

    @pytest.mark.asyncio
    async def test_team_usage_invalid_limit(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_team_usage",
                {"team_id": "abc", "limit": 0},
            )
        )
        assert "limit" in result["error"]

    # create_agentic_wallet with daily_limit_cents
    @pytest.mark.asyncio
    async def test_create_wallet_with_daily_limit(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_create_agentic_wallet",
                {"label": "test-bot", "spending_limit_cents": 500, "daily_limit_cents": 10000},
            )
        )
        assert "success" in result

    @pytest.mark.asyncio
    async def test_create_wallet_invalid_daily_limit(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_create_agentic_wallet",
                {"label": "test-bot", "spending_limit_cents": 500, "daily_limit_cents": 0},
            )
        )
        assert "daily_limit_cents" in result["error"]

    @pytest.mark.asyncio
    async def test_create_wallet_daily_limit_too_high(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_create_agentic_wallet",
                {"label": "test-bot", "spending_limit_cents": 500, "daily_limit_cents": 1000001},
            )
        )
        assert "daily_limit_cents" in result["error"]

    # create_agentic_wallet with allowed_domains
    @pytest.mark.asyncio
    async def test_create_wallet_with_allowed_domains(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_create_agentic_wallet",
                {
                    "label": "test-bot",
                    "spending_limit_cents": 500,
                    "allowed_domains": ["example.com", "api.github.com"],
                },
            )
        )
        assert "success" in result

    @pytest.mark.asyncio
    async def test_create_wallet_invalid_domain_format(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_create_agentic_wallet",
                {
                    "label": "test-bot",
                    "spending_limit_cents": 500,
                    "allowed_domains": ["-invalid.com"],
                },
            )
        )
        assert "Invalid domain format" in result["error"]

    @pytest.mark.asyncio
    async def test_create_wallet_too_many_domains(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        domains = [f"d{i}.com" for i in range(101)]
        result = json.loads(
            await handler(
                "dominusnode_create_agentic_wallet",
                {
                    "label": "test-bot",
                    "spending_limit_cents": 500,
                    "allowed_domains": domains,
                },
            )
        )
        assert "100" in result["error"]

    # update_wallet_policy
    @pytest.mark.asyncio
    async def test_update_wallet_policy_missing_wallet_id(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_update_wallet_policy",
                {"daily_limit_cents": 5000},
            )
        )
        assert "wallet_id" in result["error"]

    @pytest.mark.asyncio
    async def test_update_wallet_policy_invalid_uuid(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_update_wallet_policy",
                {"wallet_id": "not-a-uuid", "daily_limit_cents": 5000},
            )
        )
        assert "UUID" in result["error"]

    @pytest.mark.asyncio
    async def test_update_wallet_policy_invalid_daily_limit(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_update_wallet_policy",
                {
                    "wallet_id": "550e8400-e29b-41d4-a716-446655440000",
                    "daily_limit_cents": -1,
                },
            )
        )
        assert "daily_limit_cents" in result["error"]

    @pytest.mark.asyncio
    async def test_update_wallet_policy_invalid_domain(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_update_wallet_policy",
                {
                    "wallet_id": "550e8400-e29b-41d4-a716-446655440000",
                    "allowed_domains": ["..bad"],
                },
            )
        )
        assert "Invalid domain format" in result["error"]

    @pytest.mark.asyncio
    async def test_update_wallet_policy_empty_body(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_update_wallet_policy",
                {"wallet_id": "550e8400-e29b-41d4-a716-446655440000"},
            )
        )
        assert "At least one" in result["error"]

    @pytest.mark.asyncio
    async def test_update_wallet_policy_null_daily_limit(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_update_wallet_policy",
                {
                    "wallet_id": "550e8400-e29b-41d4-a716-446655440000",
                    "daily_limit_cents": None,
                },
            )
        )
        assert "success" in result

    @pytest.mark.asyncio
    async def test_update_wallet_policy_null_allowed_domains(self, mock_httpx):
        handler = create_dominusnode_function_handler(api_key="dn_test_abc123")
        result = json.loads(
            await handler(
                "dominusnode_update_wallet_policy",
                {
                    "wallet_id": "550e8400-e29b-41d4-a716-446655440000",
                    "allowed_domains": None,
                },
            )
        )
        assert "success" in result
