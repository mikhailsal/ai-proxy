from typing import Dict, Any, Union, AsyncGenerator
import httpx
import json
import time
from google import genai
from google.genai import types

from ai_proxy.adapters.base import BaseAdapter


class GeminiAdapter(BaseAdapter):
    def __init__(self, api_key: str):
        super().__init__(api_key)
        # Initialize Gemini client
        self.gemini_client = genai.Client(api_key=self.api_key)

    async def chat_completions(self, request_data: Dict[str, Any]) -> Union[httpx.Response, AsyncGenerator[str, None]]:
        """
        Convert OpenAI format to Gemini format and forward the request.
        """
        try:
            # Convert OpenAI format to Gemini format
            gemini_request = self._convert_openai_to_gemini(request_data)
            
            # Check if streaming is requested
            stream = request_data.get("stream", False)
            
            if stream:
                # Return async generator for streaming
                return self._stream_chat_completions(gemini_request)
            else:
                # Handle non-streaming response
                return await self._handle_non_streaming_response(gemini_request)
                
        except Exception as e:
            # Return error response in OpenAI format
            error_response = {
                "error": {
                    "message": str(e),
                    "type": "gemini_api_error",
                    "code": "api_error"
                }
            }
            return httpx.Response(
                status_code=500,
                content=json.dumps(error_response),
                headers={"content-type": "application/json"}
            )

    async def _stream_chat_completions(self, gemini_request: Dict[str, Any]) -> AsyncGenerator[str, None]:
        """
        Handle streaming Gemini response and convert to OpenAI streaming format.
        """
        model = gemini_request["model"]
        chat_id = f"chatcmpl-gemini-{int(time.time())}"
        created_time = int(time.time())
        
        try:
            # Generate streaming content using Gemini
            stream_response = await self.gemini_client.aio.models.generate_content_stream(
                model=gemini_request["model"],
                contents=gemini_request["contents"],
                config=types.GenerateContentConfig(**gemini_request.get("config", {}))
            )
            
            async for chunk in stream_response:
                if chunk.text:
                    # Convert to OpenAI streaming format
                    chunk_data = {
                        "id": chat_id,
                        "object": "chat.completion.chunk",
                        "created": created_time,
                        "model": model,
                        "choices": [
                            {
                                "index": 0,
                                "delta": {
                                    "content": chunk.text
                                },
                                "finish_reason": None
                            }
                        ]
                    }
                    yield f"data: {json.dumps(chunk_data)}\n\n"
            
            # Send final chunk with finish_reason
            final_chunk = {
                "id": chat_id,
                "object": "chat.completion.chunk",
                "created": created_time,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "delta": {},
                        "finish_reason": "stop"
                    }
                ]
            }
            yield f"data: {json.dumps(final_chunk)}\n\n"
            yield "data: [DONE]\n\n"
            
        except Exception as e:
            # Send error in streaming format
            error_chunk = {
                "id": chat_id,
                "object": "chat.completion.chunk",
                "created": created_time,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "delta": {},
                        "finish_reason": "error"
                    }
                ],
                "error": {
                    "message": str(e),
                    "type": "gemini_api_error",
                    "code": "api_error"
                }
            }
            yield f"data: {json.dumps(error_chunk)}\n\n"
            yield "data: [DONE]\n\n"

    def _convert_openai_to_gemini(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert OpenAI chat completion format to Gemini format.
        """
        messages = request_data.get("messages", [])
        model = request_data.get("model", "gemini-2.0-flash-001")
        
        # Convert messages to Gemini contents format
        contents = []
        for message in messages:
            role = message.get("role")
            content = message.get("content", "")
            
            # Map OpenAI roles to Gemini roles
            if role == "system":
                # System messages are handled separately in Gemini
                continue
            elif role == "user":
                contents.append(types.Content(
                    role="user",
                    parts=[types.Part.from_text(text=content)]
                ))
            elif role == "assistant":
                contents.append(types.Content(
                    role="model",  # Gemini uses "model" instead of "assistant"
                    parts=[types.Part.from_text(text=content)]
                ))
        
        # Extract system message if present
        system_instruction = None
        for message in messages:
            if message.get("role") == "system":
                system_instruction = message.get("content", "")
                break
        
        gemini_request = {
            "model": model,
            "contents": contents,
            "config": {}
        }
        
        if system_instruction:
            gemini_request["config"]["system_instruction"] = system_instruction
            
        # Handle other OpenAI parameters
        if "temperature" in request_data:
            gemini_request["config"]["temperature"] = request_data["temperature"]
        if "max_tokens" in request_data:
            gemini_request["config"]["max_output_tokens"] = request_data["max_tokens"]
        if "top_p" in request_data:
            gemini_request["config"]["top_p"] = request_data["top_p"]
            
        return gemini_request

    async def _handle_non_streaming_response(self, gemini_request: Dict[str, Any]) -> httpx.Response:
        """
        Handle non-streaming Gemini response and convert to OpenAI format.
        """
        # Generate content using Gemini
        response = await self.gemini_client.aio.models.generate_content(
            model=gemini_request["model"],
            contents=gemini_request["contents"],
            config=types.GenerateContentConfig(**gemini_request.get("config", {}))
        )
        
        # Convert Gemini response to OpenAI format
        openai_response = self._convert_gemini_to_openai(response, gemini_request["model"])
        
        return httpx.Response(
            status_code=200,
            content=json.dumps(openai_response),
            headers={"content-type": "application/json"}
        )

    def _convert_gemini_to_openai(self, gemini_response, model: str) -> Dict[str, Any]:
        """
        Convert Gemini response to OpenAI chat completion format.
        """
        return {
            "id": f"chatcmpl-gemini-{hash(str(gemini_response))}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": gemini_response.text
                    },
                    "finish_reason": "stop"
                }
            ],
            "usage": {
                "prompt_tokens": 0,  # Gemini doesn't provide token counts in the same way
                "completion_tokens": 0,
                "total_tokens": 0
            }
        } 