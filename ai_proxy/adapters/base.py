from abc import ABC, abstractmethod
from typing import Dict, Any
import httpx

class BaseAdapter(ABC):
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.client = httpx.AsyncClient()

    @abstractmethod
    async def chat_completions(self, request_data: Dict[str, Any]) -> httpx.Response:
        """
        Proxy a chat completion request to the provider.
        """
        pass

    def get_name(self) -> str:
        """
        Return the name of the adapter.
        """
        return self.__class__.__name__
