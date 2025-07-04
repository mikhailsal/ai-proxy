from typing import Dict, Any, Union, AsyncGenerator
import httpx
import json

from ai_proxy.adapters.base import BaseAdapter

OPENROUTER_API_BASE = "https://openrouter.ai/api/v1"


class OpenRouterAdapter(BaseAdapter):
    def __init__(self, api_key: str):
        super().__init__(api_key)
        self.client.base_url = OPENROUTER_API_BASE
        self.client.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _generate_system_fingerprint(self, model: str) -> str:
        """Generate a system fingerprint for OpenRouter responses."""
        return f"fp_openrouter_{hash(model) % 100000000:08x}"

    async def chat_completions(
        self, request_data: Dict[str, Any]
    ) -> Union[httpx.Response, AsyncGenerator[str, None]]:
        """
        Forward the chat completion request to OpenRouter.
        """
        # OpenRouter uses the same format as OpenAI, so no translation is needed.
        # We just forward the request body.

        # Per OpenRouter docs, add optional headers for ranking
        headers = {
            "HTTP-Referer": "http://localhost:8123",  # Replace with your actual site URL
            "X-Title": "AI Proxy",
        }

        # Check if streaming is requested
        stream = request_data.get("stream", False)

        if stream:
            # Return async generator for streaming
            return self._stream_chat_completions(request_data, headers)
        else:
            # Return regular response for non-streaming
            response = await self.client.post(
                "/chat/completions",
                json=request_data,
                headers=headers,
                timeout=300.0,  # Set a reasonable timeout
            )

            # Add system_fingerprint to non-streaming response
            if response.status_code == 200:
                try:
                    response_data = response.json()
                    model = response_data.get(
                        "model", request_data.get("model", "unknown")
                    )
                    response_data["system_fingerprint"] = (
                        self._generate_system_fingerprint(model)
                    )

                    # Create new response with modified content
                    return httpx.Response(
                        status_code=response.status_code,
                        content=json.dumps(response_data).encode(),
                        headers={"content-type": "application/json"},
                    )
                except (json.JSONDecodeError, KeyError):
                    # If we can't parse the response, return as-is
                    pass

            # We don't raise for status here, as we want to proxy the status code back to the client
            return response

    async def _stream_chat_completions(
        self, request_data: Dict[str, Any], headers: Dict[str, str]
    ) -> AsyncGenerator[str, None]:
        """
        Handle streaming chat completions from OpenRouter.
        """
        model = request_data.get("model", "unknown")
        system_fingerprint = self._generate_system_fingerprint(model)

        try:
            async with self.client.stream(
                "POST",
                "/chat/completions",
                json=request_data,
                headers=headers,
                timeout=300.0,
            ) as response:
                # Check for HTTP errors before streaming
                if response.status_code >= 400:
                    error_content = await response.aread()
                    try:
                        error_data = json.loads(error_content.decode())
                        error_message = error_data.get("error", {}).get(
                            "message", f"HTTP {response.status_code}"
                        )
                    except (json.JSONDecodeError, AttributeError):
                        error_message = (
                            f"HTTP {response.status_code}: {error_content.decode()}"
                        )

                    # Yield error in SSE format
                    error_chunk = f'data: {{"error": {{"message": "{error_message}", "code": {response.status_code}}}}}\n\ndata: [DONE]\n\n'
                    yield error_chunk
                    return

                async for chunk in response.aiter_text():
                    if chunk.strip():
                        # Parse and modify each chunk to add system_fingerprint
                        modified_chunk = self._add_system_fingerprint_to_chunk(
                            chunk, system_fingerprint
                        )
                        yield modified_chunk
        except httpx.TimeoutException:
            error_chunk = 'data: {"error": {"message": "Request timeout", "code": 408}}\n\ndata: [DONE]\n\n'
            yield error_chunk
        except httpx.RequestError as e:
            error_chunk = f'data: {{"error": {{"message": "Connection error: {str(e)}", "code": 502}}}}\n\ndata: [DONE]\n\n'
            yield error_chunk
        except Exception as e:
            error_chunk = f'data: {{"error": {{"message": "Streaming error: {str(e)}", "code": 500}}}}\n\ndata: [DONE]\n\n'
            yield error_chunk

    def _add_system_fingerprint_to_chunk(
        self, chunk: str, system_fingerprint: str
    ) -> str:
        """Add system_fingerprint to streaming chunk if it's a valid JSON data chunk."""
        try:
            lines = chunk.split("\n")
            modified_lines = []

            for line in lines:
                if line.startswith("data: ") and not line.endswith("[DONE]"):
                    json_data = line[6:]  # Remove 'data: ' prefix
                    try:
                        chunk_data = json.loads(json_data)
                        # Add system_fingerprint if this is a completion chunk
                        if (
                            "object" in chunk_data
                            and chunk_data["object"] == "chat.completion.chunk"
                        ):
                            chunk_data["system_fingerprint"] = system_fingerprint
                        modified_lines.append(f"data: {json.dumps(chunk_data)}")
                    except json.JSONDecodeError:
                        # If we can't parse, keep original
                        modified_lines.append(line)
                else:
                    modified_lines.append(line)

            return "\n".join(modified_lines)
        except Exception:
            # If anything goes wrong, return original chunk
            return chunk
