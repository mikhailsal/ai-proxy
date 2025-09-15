import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI

from ai_proxy.main import app


class TestMainApp:
    """Test suite for main FastAPI application."""

    def test_app_creation(self):
        """Test FastAPI app is created correctly."""
        assert isinstance(app, FastAPI)
        assert app.title == "AI Proxy Service"

    def test_cors_middleware_configured(self):
        """Test CORS middleware is properly configured."""
        # Check that CORS middleware is in the middleware stack
        from fastapi.middleware.cors import CORSMiddleware

        middleware_found = False
        for middleware in app.user_middleware:
            if hasattr(middleware, "cls") and issubclass(
                middleware.cls, CORSMiddleware
            ):
                middleware_found = True
                break
        assert middleware_found, "CORS middleware not found in middleware stack"


class TestLifespan:
    """Test suite for lifespan event handler."""

    @pytest.mark.asyncio
    async def test_lifespan_startup(self):
        """Test lifespan startup logs correctly."""
        from unittest.mock import patch
        from ai_proxy.main import lifespan

        with patch("ai_proxy.main.logger") as mock_logger:
            async with lifespan(app):
                pass

            mock_logger.info.assert_called_once_with("Application startup")


class TestIntegrationWithTestClient:
    """Integration tests using FastAPI TestClient."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    def test_health_endpoint_integration(self, client):
        """Test health endpoint integration."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data

    def test_cors_options_integration(self, client):
        """Test CORS options endpoint integration."""
        response = client.options("/v1/chat/completions")
        assert response.status_code == 200
        assert response.headers["Access-Control-Allow-Origin"] == "*"

    def test_models_endpoint_integration(self, client):
        """Test models endpoint integration."""
        response = client.get("/v1/models")
        assert response.status_code == 200
        data = response.json()
        assert "object" in data
        assert data["object"] == "list"
        assert "data" in data
        assert isinstance(data["data"], list)


