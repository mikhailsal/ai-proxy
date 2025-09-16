import pytest
import os
import tempfile
from unittest.mock import patch
import yaml

from ai_proxy.core.config import Settings, settings


class TestSettings:
    """Test cases for the Settings class."""

    def test_init_with_env_vars(self):
        """Test Settings initialization with environment variables."""
        with patch.dict(
            os.environ,
            {
                "API_KEYS": "key1,key2,key3",
                "OPENROUTER_API_KEY": "or_test_key",
                "GEMINI_API_KEY": "gemini_test_key",
                "GEMINI_AS_IS": "TRUE",
            },
        ):
            settings = Settings()
            assert settings.api_keys == ["key1", "key2", "key3"]
            assert settings.openrouter_api_key == "or_test_key"
            assert settings.gemini_api_key == "gemini_test_key"
            assert settings.gemini_as_is is True

    def test_init_with_default_values(self):
        """Test Settings initialization with default values."""
        with patch.dict(os.environ, {}, clear=True):
            with patch(
                "ai_proxy.core.config.load_dotenv"
            ):  # Mock load_dotenv to prevent .env loading
                settings = Settings()
                assert settings.api_keys == [""]
                assert settings.openrouter_api_key is None
                assert settings.gemini_api_key is None
                assert settings.gemini_as_is is False

    def test_get_mapped_model_direct_match(self):
        """Test direct model mapping match."""
        settings = Settings()
        settings.model_mappings = {
            "gpt-4": "openrouter:openai/gpt-4",
            "claude-3-opus": "anthropic:claude-3-opus",
        }

        provider, model = settings.get_mapped_model("gpt-4")
        assert provider == "openrouter"
        assert model == "openai/gpt-4"

        provider, model = settings.get_mapped_model("claude-3-opus")
        assert provider == "anthropic"
        assert model == "claude-3-opus"

    def test_get_mapped_model_wildcard_match(self):
        """Test wildcard model mapping match."""
        settings = Settings()
        settings.model_mappings = {
            "gpt-4*": "openrouter:openai/gpt-4",
            "claude-3-*": "anthropic:claude-3-sonnet",
        }

        provider, model = settings.get_mapped_model("gpt-4-turbo")
        assert provider == "openrouter"
        assert model == "openai/gpt-4"

        provider, model = settings.get_mapped_model("claude-3-haiku")
        assert provider == "anthropic"
        assert model == "claude-3-sonnet"

    def test_get_mapped_model_no_match(self):
        """Test model mapping when no match found."""
        settings = Settings()
        settings.model_mappings = {"gpt-4": "openrouter:openai/gpt-4"}

        provider, model = settings.get_mapped_model("unknown-model")
        assert provider == "openrouter"
        assert model == "unknown-model"

    def test_parse_provider_model_with_colon(self):
        """Test parsing provider:model format."""
        settings = Settings()

        provider, model = settings._parse_provider_model(
            "openrouter:mistralai/mistral-small"
        )
        assert provider == "openrouter"
        assert model == "mistralai/mistral-small"

        provider, model = settings._parse_provider_model("gemini:gemini-2.0-flash-001")
        assert provider == "gemini"
        assert model == "gemini-2.0-flash-001"

    def test_parse_provider_model_without_colon(self):
        """Test parsing model format without provider (defaults to openrouter)."""
        settings = Settings()

        provider, model = settings._parse_provider_model("mistralai/mistral-small")
        assert provider == "openrouter"
        assert model == "mistralai/mistral-small"

    def test_load_config_with_valid_file(self):
        """Test loading configuration from a valid YAML file."""
        config_data = {
            "model_mappings": {
                "gpt-4": "openrouter:openai/gpt-4",
                "claude-*": "anthropic:claude-3-sonnet",
            }
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name

        try:
            with patch.dict(os.environ, {"CONFIG_PATH": config_path}):
                settings = Settings()
                assert settings.model_mappings == config_data["model_mappings"]
        finally:
            os.unlink(config_path)

    def test_load_config_with_nonexistent_file(self):
        """Test loading configuration when file doesn't exist."""
        with patch.dict(os.environ, {"CONFIG_PATH": "/nonexistent/path/config.yml"}):
            settings = Settings()
            assert settings.model_mappings == {}

    def test_reload_config(self):
        """Test reloading configuration."""
        config_data = {"model_mappings": {"test-model": "openrouter:test/model"}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name

        try:
            with patch.dict(os.environ, {"CONFIG_PATH": config_path}):
                settings = Settings()
                assert settings.model_mappings == config_data["model_mappings"]

                # Modify the config file
                new_config = {
                    "model_mappings": {"new-model": "gemini:new-gemini-model"}
                }

                with open(config_path, "w") as f:
                    yaml.dump(new_config, f)

                # Reload and check
                settings.reload()
                assert settings.model_mappings == new_config["model_mappings"]
        finally:
            os.unlink(config_path)

    def test_load_config_with_empty_file(self):
        """Test loading configuration from an empty YAML file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write("")  # Empty file
            config_path = f.name

        try:
            with patch.dict(os.environ, {"CONFIG_PATH": config_path}):
                settings = Settings()
                assert settings.model_mappings == {}
        finally:
            os.unlink(config_path)

    def test_load_config_with_no_model_mappings(self):
        """Test loading configuration without model_mappings key."""
        config_data = {"other_setting": "value"}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(config_data, f)
            config_path = f.name

        try:
            with patch.dict(os.environ, {"CONFIG_PATH": config_path}):
                settings = Settings()
                assert settings.model_mappings == {}
        finally:
            os.unlink(config_path)

    def test_gemini_as_is_false_values(self):
        """Test GEMINI_AS_IS with various false values."""
        false_values = ["false", "False", "FALSE", "0", "no", ""]

        for value in false_values:
            with patch.dict(os.environ, {"GEMINI_AS_IS": value}):
                settings = Settings()
                assert settings.gemini_as_is is False

    def test_parse_provider_model_with_whitespace(self):
        """Test parsing provider:model format with whitespace."""
        settings = Settings()

        provider, model = settings._parse_provider_model("  openrouter  :  model  ")
        assert provider == "openrouter"
        assert model == "model"

        provider, model = settings._parse_provider_model("  just_model  ")
        assert provider == "openrouter"
        assert model == "just_model"

    def test_get_mapped_model_priority(self):
        """Test that direct matches take priority over wildcard matches."""
        settings = Settings()
        settings.model_mappings = {
            "gpt-4": "openrouter:specific/gpt-4",
            "gpt-*": "openrouter:general/gpt",
        }

        # Direct match should take priority
        provider, model = settings.get_mapped_model("gpt-4")
        assert provider == "openrouter"
        assert model == "specific/gpt-4"

        # Wildcard should work for non-direct matches
        provider, model = settings.get_mapped_model("gpt-3.5")
        assert provider == "openrouter"
        assert model == "general/gpt"

    def test_global_settings_instance(self):
        """Test that the global settings instance exists and works."""
        assert isinstance(settings, Settings)
        assert hasattr(settings, "api_keys")
        assert hasattr(settings, "get_mapped_model")
        assert hasattr(settings, "model_mappings")

    def test_clean_env_value_with_quotes(self):
        """Test _clean_env_value with quoted strings."""
        settings = Settings()

        # Test double quotes
        assert settings._clean_env_value('"quoted_value"') == "quoted_value"
        # Test single quotes
        assert settings._clean_env_value("'single_quoted'") == "single_quoted"
        # Test unquoted value
        assert settings._clean_env_value("unquoted_value") == "unquoted_value"
        # Test None value
        assert settings._clean_env_value(None) is None
        # Test empty string
        assert settings._clean_env_value("") == ""
        # Test whitespace around quotes
        assert settings._clean_env_value(' " spaced " ') == ' " spaced " '

    def test_is_valid_model(self):
        """Test is_valid_model method."""
        settings = Settings()

        # Valid models
        assert settings.is_valid_model("gpt-4") is True
        assert settings.is_valid_model("claude-3-opus") is True
        assert settings.is_valid_model("gemini-pro") is True
        assert settings.is_valid_model("some-valid-model") is True

        # Invalid models with bad patterns
        assert settings.is_valid_model("nonexistent-model") is False
        assert settings.is_valid_model("invalid-test") is False
        assert settings.is_valid_model("test-bad-model") is False
        assert settings.is_valid_model("NONEXISTENT") is False
        assert settings.is_valid_model("INVALID") is False
        assert settings.is_valid_model("TEST-BAD") is False

    def test_main_block_execution(self):
        """Test the main block execution for coverage."""
        import tempfile
        import os

        # Read the main block code from config.py
        config_file_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "ai_proxy", "core", "config.py"
        )
        with open(config_file_path, "r") as f:
            config_content = f.read()

        # Extract the main block (everything after 'if __name__ == "__main__":')
        main_block_start = config_content.find('if __name__ == "__main__":')
        if main_block_start == -1:
            pytest.fail("Could not find main block in config.py")

        main_block_code = config_content[main_block_start:]

        # Create a temporary directory for the test
        with tempfile.TemporaryDirectory() as temp_dir:
            # Change to temp directory to avoid creating files in project root
            original_cwd = os.getcwd()
            try:
                os.chdir(temp_dir)

                # Execute the main block code directly
                # Set up the namespace with necessary imports
                namespace = {
                    "os": os,
                    "yaml": yaml,
                    "Settings": Settings,
                }

                exec(main_block_code, namespace)

            finally:
                os.chdir(original_cwd)


if __name__ == "__main__":
    pytest.main([__file__])
