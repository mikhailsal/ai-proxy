from typing import Dict, Any
import httpx
from fastapi import HTTPException

from ai_proxy.core.config import settings
from ai_proxy.adapters.openrouter import OpenRouterAdapter
from ai_proxy.logging.config import logger

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

        return await self.adapter.chat_completions(request_data)

router = Router()
