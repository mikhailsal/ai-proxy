from typing import Dict, Any
import httpx
from fastapi import HTTPException

from ai_proxy.core.config import settings
from ai_proxy.adapters.openrouter import OpenRouterAdapter
from ai_proxy.adapters.gemini import GeminiAdapter
from ai_proxy.logging.config import logger, get_endpoint_logger, get_model_logger

class Router:
    def __init__(self):
        # Initialize adapters - keys can be missing, check at request time
        self.adapters = {
            "openrouter": OpenRouterAdapter(settings.openrouter_api_key or ""),
            "gemini": GeminiAdapter(settings.gemini_api_key or "")
        }

    def _get_adapter(self, provider: str):
        """Get adapter for the specified provider."""
        if provider not in self.adapters:
            raise HTTPException(
                status_code=400, 
                detail=f"Unsupported provider: {provider}"
            )
        return self.adapters[provider]

    def _validate_provider_key(self, provider: str):
        """Validate that the provider API key is configured."""
        if provider == "openrouter" and not settings.openrouter_api_key:
            raise HTTPException(
                status_code=500, 
                detail="OPENROUTER_API_KEY is not configured"
            )
        elif provider == "gemini" and not settings.gemini_api_key:
            raise HTTPException(
                status_code=500, 
                detail="GEMINI_API_KEY is not configured"
            )

    async def route_chat_completions(self, request_data: Dict[str, Any], api_key: str) -> httpx.Response:
        """
        Routes a chat completion request to the appropriate provider.
        """
        original_model = request_data.get("model")
        provider, mapped_model = settings.get_mapped_model(original_model)
        
        # Validate provider API key
        self._validate_provider_key(provider)
        
        # Get the appropriate adapter
        adapter = self._get_adapter(provider)
        
        # Update request with mapped model
        request_data["model"] = mapped_model

        log = logger.bind(
            api_key_hash=hash(api_key),
            original_model=original_model,
            mapped_model=mapped_model,
            provider=provider,
            adapter=adapter.get_name()
        )

        log.info("Routing chat completion request")
        
        # Also log to routing-specific log
        routing_logger = get_endpoint_logger("routing")
        routing_logger.info(
            "Model mapping and routing",
            original_model=original_model,
            mapped_model=mapped_model,
            provider=provider,
            adapter_name=adapter.get_name(),
            api_key_hash=str(hash(api_key))
        )
        
        # Log to model-specific logs
        if original_model:
            original_model_logger = get_model_logger(original_model)
            original_model_logger.info(
                "Model request routing",
                original_model=original_model,
                mapped_model=mapped_model,
                provider=provider,
                adapter=adapter.get_name(),
                api_key_hash=str(hash(api_key))
            )
        
        if mapped_model and mapped_model != original_model:
            mapped_model_logger = get_model_logger(mapped_model)
            mapped_model_logger.info(
                "Mapped model request",
                original_model=original_model,
                mapped_model=mapped_model,
                provider=provider,
                adapter=adapter.get_name(),
                api_key_hash=str(hash(api_key))
            )

        try:
            response = await adapter.chat_completions(request_data)
            log.info("Successfully routed request", status_code=response.status_code)
            
            # Log successful response to model logs
            if original_model:
                original_model_logger = get_model_logger(original_model)
                original_model_logger.info(
                    "Model response received",
                    original_model=original_model,
                    mapped_model=mapped_model,
                    provider=provider,
                    status_code=response.status_code,
                    api_key_hash=str(hash(api_key))
                )
            
            return response
        except Exception as e:
            log.error("Error in routing request", error=str(e), exc_info=e)
            
            # Log error to model logs
            if original_model:
                original_model_logger = get_model_logger(original_model)
                original_model_logger.error(
                    "Model request failed",
                    original_model=original_model,
                    mapped_model=mapped_model,
                    provider=provider,
                    error=str(e),
                    api_key_hash=str(hash(api_key))
                )
            
            raise

router = Router()
