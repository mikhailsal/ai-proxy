from typing import Dict, Any
import httpx

from ai_proxy.adapters.base import BaseAdapter

OPENROUTER_API_BASE = "https://openrouter.ai/api/v1"

class OpenRouterAdapter(BaseAdapter):
    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.client.base_url = OPENROUTER_API_BASE
        self.client.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

    async def chat_completions(self, request_data: Dict[str, Any]) -> httpx.Response:
        """
        Forward the chat completion request to OpenRouter.
        """
        # OpenRouter uses the same format as OpenAI, so no translation is needed.
        # We just forward the request body.
        
        # Per OpenRouter docs, add optional headers for ranking
        headers = {
            "HTTP-Referer": "http://localhost:8123", # Replace with your actual site URL
            "X-Title": "AI Proxy" 
        }

        response = await self.client.post(
            "/chat/completions",
            json=request_data,
            headers=headers,
            timeout=300.0 # Set a reasonable timeout
        )
        # We don't raise for status here, as we want to proxy the status code back to the client
        return response
