from abc import ABC, abstractmethod
from typing import Dict, Any, Union, AsyncGenerator
import httpx

class BaseAdapter(ABC):
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.client = httpx.AsyncClient()

    @abstractmethod
    async def chat_completions(self, request_data: Dict[str, Any]) -> Union[httpx.Response, AsyncGenerator[str, None]]:
        """
        Proxy a chat completion request to the provider.
        Returns either an httpx.Response for non-streaming or AsyncGenerator for streaming.
        """
        pass

    def get_name(self) -> str:
        """
        Return the name of the adapter.
        """
        return self.__class__.__name__
