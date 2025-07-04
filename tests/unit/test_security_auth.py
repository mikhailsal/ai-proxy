import pytest
from unittest.mock import patch
from fastapi import HTTPException
from fastapi.security import APIKeyHeader

from ai_proxy.security.auth import get_api_key, API_KEY_HEADER


class TestSecurityAuth:
    """Test cases for the security auth module."""

    def test_api_key_header_configuration(self):
        """Test that API_KEY_HEADER is properly configured."""
        assert isinstance(API_KEY_HEADER, APIKeyHeader)
        assert API_KEY_HEADER.model.name == "Authorization"
        # auto_error is a parameter of APIKeyHeader constructor, not model attribute
        assert API_KEY_HEADER.auto_error is True

    @pytest.mark.asyncio
    async def test_get_api_key_valid_bearer_token(self):
        """Test get_api_key with valid Bearer token."""
        with patch("ai_proxy.security.auth.settings") as mock_settings:
            mock_settings.api_keys = ["valid_key", "another_key"]

            result = await get_api_key("Bearer valid_key")
            assert result == "valid_key"

    @pytest.mark.asyncio
    async def test_get_api_key_valid_bearer_token_multiple_keys(self):
        """Test get_api_key with valid Bearer token from multiple valid keys."""
        with patch("ai_proxy.security.auth.settings") as mock_settings:
            mock_settings.api_keys = ["key1", "key2", "key3"]

            result = await get_api_key("Bearer key2")
            assert result == "key2"

    @pytest.mark.asyncio
    async def test_get_api_key_invalid_format_no_space(self):
        """Test get_api_key with invalid format (no space)."""
        with patch("ai_proxy.security.auth.settings") as mock_settings:
            mock_settings.api_keys = ["valid_key"]

            with pytest.raises(HTTPException) as exc_info:
                await get_api_key("InvalidFormat")

            assert exc_info.value.status_code == 401
            assert "Invalid Authorization header format" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_get_api_key_invalid_scheme(self):
        """Test get_api_key with invalid scheme (not Bearer)."""
        with patch("ai_proxy.security.auth.settings") as mock_settings:
            mock_settings.api_keys = ["valid_key"]

            with pytest.raises(HTTPException) as exc_info:
                await get_api_key("Basic valid_key")

            assert exc_info.value.status_code == 401
            assert "Invalid Authorization scheme" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_get_api_key_case_insensitive_bearer(self):
        """Test get_api_key with case-insensitive Bearer scheme."""
        with patch("ai_proxy.security.auth.settings") as mock_settings:
            mock_settings.api_keys = ["valid_key"]

            # Test different cases
            result1 = await get_api_key("bearer valid_key")
            assert result1 == "valid_key"

            result2 = await get_api_key("BEARER valid_key")
            assert result2 == "valid_key"

            result3 = await get_api_key("BeArEr valid_key")
            assert result3 == "valid_key"

    @pytest.mark.asyncio
    async def test_get_api_key_invalid_key(self):
        """Test get_api_key with invalid API key."""
        with patch("ai_proxy.security.auth.settings") as mock_settings:
            mock_settings.api_keys = ["valid_key1", "valid_key2"]

            with pytest.raises(HTTPException) as exc_info:
                await get_api_key("Bearer invalid_key")

            assert exc_info.value.status_code == 401
            assert "Invalid or missing API Key" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_get_api_key_empty_key_list(self):
        """Test get_api_key with empty API key list."""
        with patch("ai_proxy.security.auth.settings") as mock_settings:
            mock_settings.api_keys = []

            with pytest.raises(HTTPException) as exc_info:
                await get_api_key("Bearer any_key")

            assert exc_info.value.status_code == 401
            assert "Invalid or missing API Key" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_get_api_key_with_empty_string_keys(self):
        """Test get_api_key with empty string keys in the list."""
        with patch("ai_proxy.security.auth.settings") as mock_settings:
            mock_settings.api_keys = ["", "valid_key", ""]

            result = await get_api_key("Bearer valid_key")
            assert result == "valid_key"

    @pytest.mark.asyncio
    async def test_get_api_key_with_only_empty_string_keys(self):
        """Test get_api_key with only empty string keys."""
        with patch("ai_proxy.security.auth.settings") as mock_settings:
            mock_settings.api_keys = ["", "", ""]

            with pytest.raises(HTTPException) as exc_info:
                await get_api_key("Bearer any_key")

            assert exc_info.value.status_code == 401
            assert "Invalid or missing API Key" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_get_api_key_timing_attack_protection(self):
        """Test that get_api_key uses secrets.compare_digest for timing attack protection."""
        with patch("ai_proxy.security.auth.settings") as mock_settings:
            mock_settings.api_keys = ["secret_key"]

            # Mock secrets.compare_digest to ensure it's called
            with patch("ai_proxy.security.auth.secrets.compare_digest") as mock_compare:
                mock_compare.return_value = True

                result = await get_api_key("Bearer secret_key")
                assert result == "secret_key"

                # Verify compare_digest was called
                mock_compare.assert_called_with("secret_key", "secret_key")

    @pytest.mark.asyncio
    async def test_get_api_key_multiple_spaces_in_header(self):
        """Test get_api_key with multiple spaces in header."""
        with patch("ai_proxy.security.auth.settings") as mock_settings:
            mock_settings.api_keys = ["key_with_spaces"]

            result = await get_api_key("Bearer key_with_spaces")
            assert result == "key_with_spaces"

    @pytest.mark.asyncio
    async def test_get_api_key_bearer_with_extra_spaces(self):
        """Test get_api_key with Bearer and extra spaces."""
        with patch("ai_proxy.security.auth.settings") as mock_settings:
            # The partition method will include the extra space in the key
            mock_settings.api_keys = [" valid_key"]  # Include space in the valid key

            result = await get_api_key("Bearer  valid_key")
            assert result == " valid_key"  # Extra space becomes part of the key
