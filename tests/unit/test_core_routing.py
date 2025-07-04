import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
from fastapi import HTTPException

from ai_proxy.core.routing import Router, router
from ai_proxy.adapters.openrouter import OpenRouterAdapter
from ai_proxy.adapters.gemini import GeminiAdapter


class TestRouter:
    """Test cases for the Router class."""

    def test_router_initialization(self):
        """Test Router initialization with adapters."""
        with patch("ai_proxy.core.routing.settings") as mock_settings:
            mock_settings.openrouter_api_key = "test_or_key"
            mock_settings.gemini_api_key = "test_gemini_key"
            
            test_router = Router()
            
            assert "openrouter" in test_router.adapters
            assert "gemini" in test_router.adapters
            assert isinstance(test_router.adapters["openrouter"], OpenRouterAdapter)
            assert isinstance(test_router.adapters["gemini"], GeminiAdapter)

    def test_router_initialization_with_missing_keys(self):
        """Test Router initialization with missing API keys."""
        with patch("ai_proxy.core.routing.settings") as mock_settings:
            mock_settings.openrouter_api_key = None
            mock_settings.gemini_api_key = None
            
            test_router = Router()
            
            # Should still create adapters with empty keys
            assert "openrouter" in test_router.adapters
            assert "gemini" in test_router.adapters

    def test_get_adapter_valid_provider(self):
        """Test _get_adapter with valid provider."""
        with patch("ai_proxy.core.routing.settings") as mock_settings:
            mock_settings.openrouter_api_key = "test_key"
            mock_settings.gemini_api_key = "test_key"
            
            test_router = Router()
            
            openrouter_adapter = test_router._get_adapter("openrouter")
            gemini_adapter = test_router._get_adapter("gemini")
            
            assert isinstance(openrouter_adapter, OpenRouterAdapter)
            assert isinstance(gemini_adapter, GeminiAdapter)

    def test_get_adapter_invalid_provider(self):
        """Test _get_adapter with invalid provider."""
        with patch("ai_proxy.core.routing.settings"):
            test_router = Router()
            
            with pytest.raises(HTTPException) as exc_info:
                test_router._get_adapter("invalid_provider")
            
            assert exc_info.value.status_code == 400
            assert "Unsupported provider: invalid_provider" in str(exc_info.value.detail)

    def test_validate_provider_key_openrouter_valid(self):
        """Test _validate_provider_key with valid OpenRouter key."""
        with patch("ai_proxy.core.routing.settings") as mock_settings:
            mock_settings.openrouter_api_key = "valid_key"
            
            test_router = Router()
            # Should not raise exception
            test_router._validate_provider_key("openrouter")

    def test_validate_provider_key_openrouter_missing(self):
        """Test _validate_provider_key with missing OpenRouter key."""
        with patch("ai_proxy.core.routing.settings") as mock_settings:
            mock_settings.openrouter_api_key = None
            
            test_router = Router()
            
            with pytest.raises(HTTPException) as exc_info:
                test_router._validate_provider_key("openrouter")
            
            assert exc_info.value.status_code == 500
            assert "OPENROUTER_API_KEY is not configured" in str(exc_info.value.detail)

    def test_validate_provider_key_gemini_valid(self):
        """Test _validate_provider_key with valid Gemini key."""
        with patch("ai_proxy.core.routing.settings") as mock_settings:
            mock_settings.gemini_api_key = "valid_key"
            
            test_router = Router()
            # Should not raise exception
            test_router._validate_provider_key("gemini")

    def test_validate_provider_key_gemini_missing(self):
        """Test _validate_provider_key with missing Gemini key."""
        with patch("ai_proxy.core.routing.settings") as mock_settings:
            mock_settings.gemini_api_key = None
            
            test_router = Router()
            
            with pytest.raises(HTTPException) as exc_info:
                test_router._validate_provider_key("gemini")
            
            assert exc_info.value.status_code == 500
            assert "GEMINI_API_KEY is not configured" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_route_chat_completions_non_streaming(self):
        """Test route_chat_completions for non-streaming request."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        
        with patch("ai_proxy.core.routing.settings") as mock_settings:
            mock_settings.openrouter_api_key = "test_key"
            mock_settings.gemini_api_key = "test_key"
            mock_settings.get_mapped_model.return_value = ("openrouter", "gpt-4")
            
            with patch("ai_proxy.core.routing.logger") as mock_logger:
                mock_logger.bind.return_value = mock_logger
                
                with patch("ai_proxy.core.routing.get_endpoint_logger") as mock_endpoint_logger:
                    mock_endpoint_logger.return_value = MagicMock()
                    
                    with patch("ai_proxy.core.routing.get_model_logger") as mock_model_logger:
                        mock_model_logger.return_value = MagicMock()
                        
                        test_router = Router()
                        
                        # Mock the adapter
                        mock_adapter = AsyncMock()
                        mock_adapter.chat_completions.return_value = mock_response
                        mock_adapter.get_name.return_value = "MockAdapter"
                        test_router.adapters["openrouter"] = mock_adapter
                        
                        request_data = {
                            "model": "gpt-4",
                            "messages": [{"role": "user", "content": "Hello"}],
                            "stream": False
                        }
                        
                        result = await test_router.route_chat_completions(request_data, "test_api_key")
                        
                        assert result == mock_response
                        mock_adapter.chat_completions.assert_called_once()
                        assert request_data["model"] == "gpt-4"  # Updated with mapped model

    @pytest.mark.asyncio
    async def test_route_chat_completions_streaming(self):
        """Test route_chat_completions for streaming request."""
        async def mock_stream():
            yield "data: chunk1"
            yield "data: chunk2"
        
        with patch("ai_proxy.core.routing.settings") as mock_settings:
            mock_settings.openrouter_api_key = "test_key"
            mock_settings.gemini_api_key = "test_key"
            mock_settings.get_mapped_model.return_value = ("openrouter", "gpt-4")
            
            with patch("ai_proxy.core.routing.logger") as mock_logger:
                mock_logger.bind.return_value = mock_logger
                
                with patch("ai_proxy.core.routing.get_endpoint_logger") as mock_endpoint_logger:
                    mock_endpoint_logger.return_value = MagicMock()
                    
                    with patch("ai_proxy.core.routing.get_model_logger") as mock_model_logger:
                        mock_model_logger.return_value = MagicMock()
                        
                        test_router = Router()
                        
                        # Mock the adapter
                        mock_adapter = AsyncMock()
                        mock_adapter.chat_completions.return_value = mock_stream()
                        mock_adapter.get_name.return_value = "MockAdapter"
                        test_router.adapters["openrouter"] = mock_adapter
                        
                        request_data = {
                            "model": "gpt-4",
                            "messages": [{"role": "user", "content": "Hello"}],
                            "stream": True
                        }
                        
                        result = await test_router.route_chat_completions(request_data, "test_api_key")
                        
                        # Should return the async generator
                        assert hasattr(result, '__aiter__')
                        mock_adapter.chat_completions.assert_called_once()

    @pytest.mark.asyncio
    async def test_route_chat_completions_with_error(self):
        """Test route_chat_completions when adapter raises exception."""
        with patch("ai_proxy.core.routing.settings") as mock_settings:
            mock_settings.openrouter_api_key = "test_key"
            mock_settings.gemini_api_key = "test_key"
            mock_settings.get_mapped_model.return_value = ("openrouter", "gpt-4")
            
            with patch("ai_proxy.core.routing.logger") as mock_logger:
                mock_logger.bind.return_value = mock_logger
                
                with patch("ai_proxy.core.routing.get_endpoint_logger") as mock_endpoint_logger:
                    mock_endpoint_logger.return_value = MagicMock()
                    
                    with patch("ai_proxy.core.routing.get_model_logger") as mock_model_logger:
                        mock_model_logger.return_value = MagicMock()
                        
                        test_router = Router()
                        
                        # Mock the adapter to raise an exception
                        mock_adapter = AsyncMock()
                        mock_adapter.chat_completions.side_effect = Exception("Test error")
                        mock_adapter.get_name.return_value = "MockAdapter"
                        test_router.adapters["openrouter"] = mock_adapter
                        
                        request_data = {
                            "model": "gpt-4",
                            "messages": [{"role": "user", "content": "Hello"}],
                            "stream": False
                        }
                        
                        with pytest.raises(Exception, match="Test error"):
                            await test_router.route_chat_completions(request_data, "test_api_key")

    @pytest.mark.asyncio
    async def test_route_chat_completions_model_mapping(self):
        """Test route_chat_completions with model mapping."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        
        with patch("ai_proxy.core.routing.settings") as mock_settings:
            mock_settings.openrouter_api_key = "test_key"
            mock_settings.gemini_api_key = "test_key"
            mock_settings.get_mapped_model.return_value = ("gemini", "gemini-1.5-pro")
            
            with patch("ai_proxy.core.routing.logger") as mock_logger:
                mock_logger.bind.return_value = mock_logger
                
                with patch("ai_proxy.core.routing.get_endpoint_logger") as mock_endpoint_logger:
                    mock_endpoint_logger.return_value = MagicMock()
                    
                    with patch("ai_proxy.core.routing.get_model_logger") as mock_model_logger:
                        mock_model_logger.return_value = MagicMock()
                        
                        test_router = Router()
                        
                        # Mock the adapter
                        mock_adapter = AsyncMock()
                        mock_adapter.chat_completions.return_value = mock_response
                        mock_adapter.get_name.return_value = "GeminiAdapter"
                        test_router.adapters["gemini"] = mock_adapter
                        
                        request_data = {
                            "model": "gpt-4",  # Original model
                            "messages": [{"role": "user", "content": "Hello"}],
                            "stream": False
                        }
                        
                        result = await test_router.route_chat_completions(request_data, "test_api_key")
                        
                        assert result == mock_response
                        assert request_data["model"] == "gemini-1.5-pro"  # Should be updated with mapped model

    @pytest.mark.asyncio
    async def test_route_chat_completions_logging(self):
        """Test that route_chat_completions logs correctly."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        
        with patch("ai_proxy.core.routing.settings") as mock_settings:
            mock_settings.openrouter_api_key = "test_key"
            mock_settings.gemini_api_key = "test_key"
            mock_settings.get_mapped_model.return_value = ("openrouter", "gpt-4")
            
            with patch("ai_proxy.core.routing.logger") as mock_logger:
                mock_bound_logger = MagicMock()
                mock_logger.bind.return_value = mock_bound_logger
                
                with patch("ai_proxy.core.routing.get_endpoint_logger") as mock_endpoint_logger:
                    mock_routing_logger = MagicMock()
                    mock_endpoint_logger.return_value = mock_routing_logger
                    
                    with patch("ai_proxy.core.routing.get_model_logger") as mock_model_logger:
                        mock_model_log = MagicMock()
                        mock_model_logger.return_value = mock_model_log
                        
                        test_router = Router()
                        
                        # Mock the adapter
                        mock_adapter = AsyncMock()
                        mock_adapter.chat_completions.return_value = mock_response
                        mock_adapter.get_name.return_value = "MockAdapter"
                        test_router.adapters["openrouter"] = mock_adapter
                        
                        request_data = {
                            "model": "gpt-4",
                            "messages": [{"role": "user", "content": "Hello"}],
                            "stream": False
                        }
                        
                        await test_router.route_chat_completions(request_data, "test_api_key")
                        
                        # Verify logging calls
                        mock_bound_logger.info.assert_called()
                        mock_routing_logger.info.assert_called()
                        mock_model_log.info.assert_called()

    def test_global_router_instance(self):
        """Test that the global router instance is created."""
        assert isinstance(router, Router)
        assert hasattr(router, 'adapters')
        assert "openrouter" in router.adapters
        assert "gemini" in router.adapters 