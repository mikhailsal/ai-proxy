from typing import Dict, Any
import httpx
from fastapi import HTTPException

from ai_proxy.core.config import settings
from ai_proxy.adapters.openrouter import OpenRouterAdapter
from ai_proxy.logging.config import logger, get_endpoint_logger, get_model_logger

class Router:
    def __init__(self):
        # The adapter is initialized here, but the key can be missing.
        # The check will be performed at request time.
        self.adapter = OpenRouterAdapter(settings.openrouter_api_key or "")

    async def route_chat_completions(self, request_data: Dict[str, Any], api_key: str) -> httpx.Response:
        """
        Routes a chat completion request.
        """
        if not settings.openrouter_api_key:
            logger.error("OPENROUTER_API_KEY is not set.")
            raise HTTPException(status_code=500, detail="Backend provider API key is not configured.")

        original_model = request_data.get("model")
        mapped_model = settings.get_mapped_model(original_model)
        
        request_data["model"] = mapped_model

        log = logger.bind(
            api_key_hash=hash(api_key),
            original_model=original_model,
            mapped_model=mapped_model,
            adapter=self.adapter.get_name()
        )

        log.info("Routing chat completion request")
        
        # Also log to routing-specific log
        routing_logger = get_endpoint_logger("routing")
        routing_logger.info(
            "Model mapping and routing",
            original_model=original_model,
            mapped_model=mapped_model,
            adapter_name=self.adapter.get_name(),
            api_key_hash=str(hash(api_key))
        )
        
        # Log to model-specific logs
        if original_model:
            original_model_logger = get_model_logger(original_model)
            original_model_logger.info(
                "Model request routing",
                original_model=original_model,
                mapped_model=mapped_model,
                adapter=self.adapter.get_name(),
                api_key_hash=str(hash(api_key))
            )
        
        if mapped_model and mapped_model != original_model:
            mapped_model_logger = get_model_logger(mapped_model)
            mapped_model_logger.info(
                "Mapped model request",
                original_model=original_model,
                mapped_model=mapped_model,
                adapter=self.adapter.get_name(),
                api_key_hash=str(hash(api_key))
            )

        try:
            response = await self.adapter.chat_completions(request_data)
            log.info("Successfully routed request", status_code=response.status_code)
            
            # Log successful response to model logs
            if original_model:
                original_model_logger = get_model_logger(original_model)
                original_model_logger.info(
                    "Model response received",
                    original_model=original_model,
                    mapped_model=mapped_model,
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
                    error=str(e),
                    api_key_hash=str(hash(api_key))
                )
            
            raise

router = Router()
