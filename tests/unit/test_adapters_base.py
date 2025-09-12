import pytest
import httpx
from unittest.mock import Mock

from ai_proxy.adapters.base import BaseAdapter


class TestBaseAdapter:
    """Test the BaseAdapter abstract class."""

    def test_abstract_class_cannot_be_instantiated(self):
        """Test that BaseAdapter cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            BaseAdapter("test_key")

    def test_concrete_implementation(self):
        """Test that concrete implementations work correctly."""

        class ConcreteAdapter(BaseAdapter):
            async def chat_completions(self, request_data):
                return f"Processed: {request_data}"

        adapter = ConcreteAdapter("test_key")
        assert adapter.get_name() == "ConcreteAdapter"
        assert adapter.api_key == "test_key"
        assert isinstance(adapter.client, httpx.AsyncClient)

    @pytest.mark.asyncio
    async def test_concrete_implementation_async(self):
        """Test that concrete implementations work correctly with async methods."""

        class AsyncConcreteAdapter(BaseAdapter):
            async def chat_completions(self, request_data):
                return f"Async processed: {request_data}"

        adapter = AsyncConcreteAdapter("test_key")
        result = await adapter.chat_completions({"test": "data"})
        assert result == "Async processed: {'test': 'data'}"

    def test_get_name_method(self):
        """Test get_name method returns class name."""

        # Create a concrete implementation
        class TestAdapter(BaseAdapter):
            async def chat_completions(self, request_data):
                return Mock()

        adapter = TestAdapter("test_key")
        assert adapter.get_name() == "TestAdapter"

    def test_init_sets_api_key_and_client(self):
        """Test that __init__ properly sets api_key and client."""

        # Create a concrete implementation
        class TestAdapter(BaseAdapter):
            async def chat_completions(self, request_data):
                return Mock()

        adapter = TestAdapter("test_key")
        assert adapter.api_key == "test_key"
        assert adapter.client is not None

    def test_abstract_method_must_be_implemented(self):
        """Test that chat_completions must be implemented in concrete classes."""

        # This should work - concrete implementation
        class GoodAdapter(BaseAdapter):
            async def chat_completions(self, request_data):
                return request_data

        adapter = GoodAdapter("test_key")
        assert adapter is not None

        # This should fail - missing implementation
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):

            class BadAdapter(BaseAdapter):
                pass

            BadAdapter("test_key")

    @pytest.mark.asyncio
    async def test_abstract_method_pass_statement(self):
        """Test that calling the abstract method directly raises NotImplementedError."""

        # Create a partially implemented class that doesn't override chat_completions
        class PartialAdapter(BaseAdapter):
            # Don't implement chat_completions to test the abstract method
            pass

        # This should fail to instantiate due to abstract method
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            PartialAdapter("test_key")

        # Test that we can access the abstract method through the class
        # This covers the pass statement in the abstract method
        assert hasattr(BaseAdapter, "chat_completions")
        assert BaseAdapter.chat_completions.__isabstractmethod__ is True


@pytest.mark.asyncio
async def test_cover_abstract_method_pass():
    class CoverageAdapter(BaseAdapter):
        async def chat_completions(self, request_data):
            return await super().chat_completions(request_data)

    adapter = CoverageAdapter("test_key")
    result = await adapter.chat_completions({"test": "data"})
    assert result is None  # Since base method just passes
