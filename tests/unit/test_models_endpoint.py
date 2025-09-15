import pytest
from unittest.mock import patch

from ai_proxy.api.v1.models_endpoint import list_models


class TestModelsEndpoint:
    """Test suite for models listing endpoint."""

    @patch("ai_proxy.api.v1.models_endpoint.settings")
    @pytest.mark.asyncio
    async def test_list_models_success(self, mock_settings):
        """Test successful models listing."""
        # Setup mock model mappings
        mock_settings.model_mappings = {
            "gpt-4": "openrouter:openai/gpt-4",
            "claude-3-opus": "openrouter:anthropic/claude-3-opus",
            "gemini-pro": "gemini:gemini-2.0-flash-001",
            "mistral-small": "openrouter:mistralai/mistral-small-3.2-24b-instruct:free",
            "*": "openrouter:mistralai/mistral-small-3.2-24b-instruct:free",  # Should be skipped
        }

        # Mock the _parse_provider_model method
        def mock_parse(model_string):
            if ":" in model_string:
                provider, model = model_string.split(":", 1)
                return provider.strip(), model.strip()
            else:
                return "openrouter", model_string.strip()

        mock_settings._parse_provider_model.side_effect = mock_parse

        # Execute
        response = await list_models()

        # Verify
        assert "object" in response
        assert response["object"] == "list"
        assert "data" in response
        assert isinstance(response["data"], list)

        # Should have 4 models (excluding wildcard "*")
        models = response["data"]
        assert len(models) == 4

        # Check model structure
        for model in models:
            assert "id" in model
            assert "object" in model
            assert model["object"] == "model"
            assert "created" in model
            assert "owned_by" in model
            assert "permission" in model
            assert "root" in model
            assert "parent" in model

        # Check specific models are present
        model_ids = [model["id"] for model in models]
        assert "gpt-4" in model_ids
        assert "claude-3-opus" in model_ids
        assert "gemini-pro" in model_ids
        assert "mistral-small" in model_ids
        assert "*" not in model_ids  # Wildcard should be excluded

        # Check providers are correctly set
        model_by_id = {model["id"]: model for model in models}
        assert model_by_id["gpt-4"]["owned_by"] == "openrouter"
        assert model_by_id["claude-3-opus"]["owned_by"] == "openrouter"
        assert model_by_id["gemini-pro"]["owned_by"] == "gemini"
        assert model_by_id["mistral-small"]["owned_by"] == "openrouter"

    @patch("ai_proxy.api.v1.models_endpoint.settings")
    @pytest.mark.asyncio
    async def test_list_models_empty_mappings(self, mock_settings):
        """Test models listing with empty mappings."""
        # Setup empty model mappings
        mock_settings.model_mappings = {}

        # Execute
        response = await list_models()

        # Verify
        assert "object" in response
        assert response["object"] == "list"
        assert "data" in response
        assert isinstance(response["data"], list)
        assert len(response["data"]) == 0

    @patch("ai_proxy.api.v1.models_endpoint.settings")
    @pytest.mark.asyncio
    async def test_list_models_only_wildcards(self, mock_settings):
        """Test models listing with only wildcard patterns."""
        # Setup model mappings with only wildcards
        mock_settings.model_mappings = {
            "*": "openrouter:mistralai/mistral-small-3.2-24b-instruct:free",
            "gpt-*": "openrouter:openai/gpt-4",
            "claude-*": "openrouter:anthropic/claude-3-opus",
        }

        # Execute
        response = await list_models()

        # Verify
        assert "object" in response
        assert response["object"] == "list"
        assert "data" in response
        assert isinstance(response["data"], list)
        assert len(response["data"]) == 0  # All wildcards should be excluded

    @patch("ai_proxy.api.v1.models_endpoint.settings")
    @pytest.mark.asyncio
    async def test_list_models_mixed_patterns(self, mock_settings):
        """Test models listing with mixed patterns and wildcards."""
        # Setup mixed model mappings
        mock_settings.model_mappings = {
            "gpt-4": "openrouter:openai/gpt-4",
            "gpt-*": "openrouter:openai/gpt-4",  # Should be skipped
            "claude-3-opus": "openrouter:anthropic/claude-3-opus",
            "*": "openrouter:mistralai/mistral-small-3.2-24b-instruct:free",  # Should be skipped
        }

        # Mock the _parse_provider_model method
        def mock_parse(model_string):
            if ":" in model_string:
                provider, model = model_string.split(":", 1)
                return provider.strip(), model.strip()
            else:
                return "openrouter", model_string.strip()

        mock_settings._parse_provider_model.side_effect = mock_parse

        # Execute
        response = await list_models()

        # Verify
        assert "object" in response
        assert response["object"] == "list"
        assert "data" in response
        models = response["data"]
        assert len(models) == 2  # Only non-wildcard models

        model_ids = [model["id"] for model in models]
        assert "gpt-4" in model_ids
        assert "claude-3-opus" in model_ids
        assert "gpt-*" not in model_ids
        assert "*" not in model_ids
