import pytest
from unittest.mock import patch, mock_open

from ai_proxy.api.v1.health import health_check


class TestHealthEndpoint:
    """Test suite for health check endpoint."""

    @patch("ai_proxy.api.v1.health.logger")
    @pytest.mark.asyncio
    async def test_health_check_with_timestamp_file(self, mock_logger):
        """Test health check with deployment timestamp file."""
        mock_timestamp = "2024-01-01T12:00:00Z"

        with patch("builtins.open", mock_open(read_data=mock_timestamp)):
            response = await health_check()

        assert response == {
            "status": "ok",
            "version": "test-final-deployment",
            "script_tested": True,
            "deployment_timestamp": mock_timestamp,
        }

    @patch("ai_proxy.api.v1.health.logger")
    @pytest.mark.asyncio
    async def test_health_check_file_not_found(self, mock_logger):
        """Test health check when deployment timestamp file is not found."""
        with patch("builtins.open", side_effect=FileNotFoundError()):
            response = await health_check()

        assert response == {
            "status": "ok",
            "version": "test-final-deployment",
            "script_tested": True,
            "deployment_timestamp": "unknown",
        }
        mock_logger.warning.assert_called_once()

    @patch("ai_proxy.api.v1.health.logger")
    @pytest.mark.asyncio
    async def test_health_check_file_read_error(self, mock_logger):
        """Test health check when file read fails."""
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            response = await health_check()

        assert response == {
            "status": "ok",
            "version": "test-final-deployment",
            "script_tested": True,
            "deployment_timestamp": "unknown",
        }
        mock_logger.error.assert_called_once()
