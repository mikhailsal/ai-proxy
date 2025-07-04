import pytest
from unittest.mock import Mock, patch, AsyncMock
import json
import httpx
import time
from typing import AsyncGenerator

from ai_proxy.adapters.gemini import GeminiAdapter
from google.genai import types


class TestGeminiAdapter:
    """Test suite for GeminiAdapter."""
    
    @pytest.fixture
    def gemini_adapter(self):
        """Create GeminiAdapter instance for testing."""
        with patch('ai_proxy.adapters.gemini.genai.Client') as mock_client:
            adapter = GeminiAdapter("test-api-key")
            adapter.gemini_client = mock_client.return_value
            return adapter
    
    @pytest.fixture
    def openai_request(self):
        """Sample OpenAI format request."""
        return {
            "model": "gemini-pro",
            "messages": [
                {"role": "user", "content": "Hello"}
            ],
            "stream": False
        }
    
    @pytest.fixture
    def streaming_request(self):
        """Sample streaming request."""
        return {
            "model": "gemini-pro",
            "messages": [
                {"role": "user", "content": "Hello"}
            ],
            "stream": True
        }
    
    def test_init(self):
        """Test GeminiAdapter initialization."""
        with patch('ai_proxy.adapters.gemini.genai.Client') as mock_client:
            adapter = GeminiAdapter("test-api-key")
            assert adapter.api_key == "test-api-key"
            mock_client.assert_called_once_with(api_key="test-api-key")
    
    @pytest.mark.asyncio
    async def test_chat_completions_non_streaming_success(self, gemini_adapter, openai_request):
        """Test successful non-streaming chat completion."""
        # Mock the response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = json.dumps({"choices": [{"message": {"content": "Hello!"}}]})
        mock_response.headers = {"content-type": "application/json"}
        
        with patch.object(gemini_adapter, '_handle_non_streaming_response', return_value=mock_response):
            result = await gemini_adapter.chat_completions(openai_request)
            assert result.status_code == 200
    
    @pytest.mark.asyncio
    async def test_chat_completions_streaming_success(self, gemini_adapter, streaming_request):
        """Test successful streaming chat completion."""
        async def mock_stream():
            yield "data: {\"text\": \"Hello\"}\n\n"
            yield "data: [DONE]\n\n"
        
        with patch.object(gemini_adapter, '_stream_chat_completions', return_value=mock_stream()):
            result = await gemini_adapter.chat_completions(streaming_request)
            assert hasattr(result, '__aiter__')  # Should be an async generator
    
    @pytest.mark.asyncio
    async def test_chat_completions_exception_handling(self, gemini_adapter, openai_request):
        """Test exception handling in chat_completions."""
        with patch.object(gemini_adapter, '_convert_openai_to_gemini', side_effect=Exception("Test error")):
            result = await gemini_adapter.chat_completions(openai_request)
            assert result.status_code == 500
            response_data = json.loads(result.content)
            assert "error" in response_data
            assert response_data["error"]["message"] == "Test error"
    
    def test_convert_openai_to_gemini_basic(self, gemini_adapter):
        """Test basic OpenAI to Gemini conversion."""
        openai_request = {
            "model": "gemini-pro",
            "messages": [
                {"role": "user", "content": "Hello"}
            ]
        }
        
        result = gemini_adapter._convert_openai_to_gemini(openai_request)
        
        assert result["model"] == "gemini-pro"
        assert "contents" in result
        assert len(result["contents"]) == 1
        
        # Check that the content is a types.Content object
        content = result["contents"][0]
        assert isinstance(content, types.Content)
        assert content.role == "user"
        assert len(content.parts) == 1
        assert content.parts[0].text == "Hello"
    
    def test_convert_openai_to_gemini_with_system_message(self, gemini_adapter):
        """Test conversion with system message."""
        openai_request = {
            "model": "gemini-pro",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant"},
                {"role": "user", "content": "Hello"}
            ]
        }
        
        result = gemini_adapter._convert_openai_to_gemini(openai_request)
        
        # System message should be in config
        assert "config" in result
        assert "system_instruction" in result["config"]
        assert result["config"]["system_instruction"] == "You are a helpful assistant"
    
    def test_convert_openai_to_gemini_with_temperature(self, gemini_adapter):
        """Test conversion with temperature parameter."""
        openai_request = {
            "model": "gemini-pro",
            "messages": [{"role": "user", "content": "Hello"}],
            "temperature": 0.7
        }
        
        result = gemini_adapter._convert_openai_to_gemini(openai_request)
        
        assert "config" in result
        assert result["config"]["temperature"] == 0.7
    
    def test_convert_openai_to_gemini_with_max_tokens(self, gemini_adapter):
        """Test conversion with max_tokens parameter."""
        openai_request = {
            "model": "gemini-pro",
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 100
        }
        
        result = gemini_adapter._convert_openai_to_gemini(openai_request)
        
        assert "config" in result
        assert result["config"]["max_output_tokens"] == 100
    
    def test_convert_openai_to_gemini_with_stop_sequences(self, gemini_adapter):
        """Test conversion with stop sequences."""
        openai_request = {
            "model": "gemini-pro",
            "messages": [{"role": "user", "content": "Hello"}],
            "stop": ["STOP", "END"]
        }
        
        result = gemini_adapter._convert_openai_to_gemini(openai_request)
        
        assert "config" in result
        assert result["config"]["stop_sequences"] == ["STOP", "END"]
    
    def test_convert_openai_to_gemini_conversation_history(self, gemini_adapter):
        """Test conversion with conversation history."""
        openai_request = {
            "model": "gemini-pro",
            "messages": [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi there!"},
                {"role": "user", "content": "How are you?"}
            ]
        }
        
        result = gemini_adapter._convert_openai_to_gemini(openai_request)
        
        assert len(result["contents"]) == 3
        assert result["contents"][0].role == "user"
        assert result["contents"][1].role == "model"
        assert result["contents"][2].role == "user"
    
    def test_convert_gemini_to_openai_basic(self, gemini_adapter):
        """Test basic Gemini to OpenAI conversion."""
        gemini_response = Mock()
        gemini_response.text = "Hello there!"
        gemini_response.candidates = [Mock()]
        gemini_response.candidates[0].content.parts = [Mock()]
        gemini_response.candidates[0].content.parts[0].text = "Hello there!"
        
        result = gemini_adapter._convert_gemini_to_openai(gemini_response, "gemini-pro")
        
        assert result["model"] == "gemini-pro"
        assert result["object"] == "chat.completion"
        assert result["choices"][0]["message"]["content"] == "Hello there!"
        assert result["choices"][0]["message"]["role"] == "assistant"
        assert result["usage"]["prompt_tokens"] == 0
        assert result["usage"]["completion_tokens"] == 0
        assert result["usage"]["total_tokens"] == 0
    
    def test_convert_gemini_to_openai_with_usage(self, gemini_adapter):
        """Test conversion with usage statistics."""
        gemini_response = Mock()
        gemini_response.text = "Hello there!"
        gemini_response.candidates = [Mock()]
        gemini_response.candidates[0].content.parts = [Mock()]
        gemini_response.candidates[0].content.parts[0].text = "Hello there!"
        
        # Mock usage metadata
        gemini_response.usage_metadata = Mock()
        gemini_response.usage_metadata.prompt_token_count = 10
        gemini_response.usage_metadata.candidates_token_count = 5
        gemini_response.usage_metadata.total_token_count = 15
        
        result = gemini_adapter._convert_gemini_to_openai(gemini_response, "gemini-pro")
        
        assert result["usage"]["prompt_tokens"] == 0
        assert result["usage"]["completion_tokens"] == 0
        assert result["usage"]["total_tokens"] == 0
    
    @pytest.mark.asyncio
    async def test_handle_non_streaming_response_success(self, gemini_adapter):
        """Test successful non-streaming response handling."""
        gemini_request = {
            "model": "gemini-pro",
            "contents": [types.Content(role="user", parts=[types.Part.from_text(text="Hello")])]
        }
        
        # Mock Gemini response
        mock_gemini_response = Mock()
        mock_gemini_response.text = "Hello there!"
        mock_gemini_response.candidates = [Mock()]
        mock_gemini_response.candidates[0].content.parts = [Mock()]
        mock_gemini_response.candidates[0].content.parts[0].text = "Hello there!"
        
        # Create async mock
        async_mock = AsyncMock(return_value=mock_gemini_response)
        
        with patch.object(gemini_adapter.gemini_client.aio.models, 'generate_content', async_mock):
            result = await gemini_adapter._handle_non_streaming_response(gemini_request, {})
            
            assert isinstance(result, httpx.Response)
            assert result.status_code == 200
            
            response_data = json.loads(result.content)
            assert response_data["choices"][0]["message"]["content"] == "Hello there!"
    
    @pytest.mark.asyncio
    async def test_handle_non_streaming_response_with_gemini_as_is(self, gemini_adapter):
        """Test non-streaming response with GEMINI_AS_IS enabled."""
        gemini_request = {
            "model": "gemini-pro",
            "contents": [types.Content(role="user", parts=[types.Part.from_text(text="Hello")])]
        }
        
        # Mock Gemini response
        mock_gemini_response = Mock()
        mock_gemini_response.text = "Hello there!"
        
        # Create async mock
        async_mock = AsyncMock(return_value=mock_gemini_response)

        with patch('ai_proxy.adapters.gemini.settings.gemini_as_is', True):
            with patch.object(gemini_adapter.gemini_client.aio.models, 'generate_content', async_mock):
                result = await gemini_adapter._handle_non_streaming_response(gemini_request, {})
                
                assert isinstance(result, httpx.Response)
                assert result.status_code == 200
                response_data = json.loads(result.content)
                assert response_data["text"] == "Hello there!"
                assert response_data["model"] == "gemini-pro"
    
    @pytest.mark.asyncio
    async def test_handle_non_streaming_response_exception(self, gemini_adapter):
        """Test exception handling in non-streaming response."""
        gemini_request = {
            "model": "gemini-pro",
            "contents": [types.Content(role="user", parts=[types.Part.from_text(text="Hello")])]
        }
        
        # Create async mock that raises exception
        async_mock = AsyncMock(side_effect=Exception("API error"))

        with patch.object(gemini_adapter.gemini_client.aio.models, 'generate_content', async_mock):
            with pytest.raises(Exception, match="API error"):
                await gemini_adapter._handle_non_streaming_response(gemini_request, {})
    
    @pytest.mark.asyncio
    async def test_stream_chat_completions_openai_format(self, gemini_adapter):
        """Test streaming with OpenAI format output."""
        gemini_request = {
            "model": "gemini-pro",
            "contents": [types.Content(role="user", parts=[types.Part.from_text(text="Hello")])]
        }
        
        # Mock streaming response
        async def mock_stream():
            chunk1 = Mock()
            chunk1.text = "Hello"
            chunk2 = Mock()
            chunk2.text = " there!"
            for chunk in [chunk1, chunk2]:
                yield chunk
        
        with patch('ai_proxy.adapters.gemini.settings.gemini_as_is', False):
            with patch.object(gemini_adapter.gemini_client.aio.models, 'generate_content_stream', 
                            AsyncMock(return_value=mock_stream())):
                result = gemini_adapter._stream_chat_completions(gemini_request, {})
                
                chunks = []
                async for chunk in result:
                    chunks.append(chunk)
                
                # Should have chunks with content plus final chunk
                assert len(chunks) >= 2
                assert "Hello" in chunks[0] or "Hello" in chunks[1]
                assert "data: [DONE]" in chunks[-1]
    
    @pytest.mark.asyncio
    async def test_stream_chat_completions_gemini_as_is(self, gemini_adapter):
        """Test streaming with Gemini raw format output."""
        gemini_request = {
            "model": "gemini-pro",
            "contents": [types.Content(role="user", parts=[types.Part.from_text(text="Hello")])]
        }
        
        # Mock streaming response
        async def mock_stream():
            chunk = Mock()
            chunk.text = "Hello there!"
            yield chunk
        
        with patch('ai_proxy.adapters.gemini.settings.gemini_as_is', True):
            with patch.object(gemini_adapter.gemini_client.aio.models, 'generate_content_stream', 
                            AsyncMock(return_value=mock_stream())):
                result = gemini_adapter._stream_chat_completions(gemini_request, {})
                
                chunks = []
                async for chunk in result:
                    chunks.append(chunk)
                
                assert len(chunks) == 2  # content chunk + DONE
                assert "Hello there!" in chunks[0]
                assert "data: [DONE]" in chunks[1]
    
    @pytest.mark.asyncio
    async def test_stream_chat_completions_empty_chunks(self, gemini_adapter):
        """Test streaming with empty chunks."""
        gemini_request = {
            "model": "gemini-pro",
            "contents": [types.Content(role="user", parts=[types.Part.from_text(text="Hello")])]
        }
        
        # Mock streaming response with empty chunks
        async def mock_stream():
            chunk1 = Mock()
            chunk1.text = None  # Empty chunk
            chunk2 = Mock()
            chunk2.text = "Hello"
            for chunk in [chunk1, chunk2]:
                yield chunk
        
        with patch('ai_proxy.adapters.gemini.settings.gemini_as_is', False):
            with patch.object(gemini_adapter.gemini_client.aio.models, 'generate_content_stream', 
                            AsyncMock(return_value=mock_stream())):
                result = gemini_adapter._stream_chat_completions(gemini_request, {})
                
                chunks = []
                async for chunk in result:
                    chunks.append(chunk)
                
                # Should handle empty chunks gracefully
                assert len(chunks) >= 2
                assert "data: [DONE]" in chunks[-1]
    
    @pytest.mark.asyncio
    async def test_stream_chat_completions_exception_openai_format(self, gemini_adapter):
        """Test streaming exception handling with OpenAI format."""
        gemini_request = {
            "model": "gemini-pro",
            "contents": [types.Content(role="user", parts=[types.Part.from_text(text="Hello")])]
        }
        
        with patch('ai_proxy.adapters.gemini.settings.gemini_as_is', False):
            with patch.object(gemini_adapter.gemini_client.aio.models, 'generate_content_stream', 
                            AsyncMock(side_effect=Exception("Stream error"))):
                result = gemini_adapter._stream_chat_completions(gemini_request, {})
                
                chunks = []
                async for chunk in result:
                    chunks.append(chunk)
                
                # Should have error chunk
                assert len(chunks) >= 1
                assert any("error" in chunk for chunk in chunks)
    
    @pytest.mark.asyncio
    async def test_stream_chat_completions_exception_gemini_as_is(self, gemini_adapter):
        """Test streaming exception handling with Gemini raw format."""
        gemini_request = {
            "model": "gemini-pro",
            "contents": [types.Content(role="user", parts=[types.Part.from_text(text="Hello")])]
        }
        
        with patch('ai_proxy.adapters.gemini.settings.gemini_as_is', True):
            with patch.object(gemini_adapter.gemini_client.aio.models, 'generate_content_stream', 
                            AsyncMock(side_effect=Exception("Stream error"))):
                result = gemini_adapter._stream_chat_completions(gemini_request, {})
                
                chunks = []
                async for chunk in result:
                    chunks.append(chunk)
                
                # Should have error chunk in Gemini format
                assert len(chunks) == 2  # error chunk + DONE
                assert "Stream error" in chunks[0]
                assert "data: [DONE]" in chunks[-1] 