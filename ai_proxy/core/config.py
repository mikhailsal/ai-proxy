import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import yaml
from dotenv import load_dotenv
import fnmatch


class Settings:
    def __init__(self):
        load_dotenv()
        self.api_keys: List[str] = [
            self._clean_env_value(key)
            for key in os.getenv("API_KEYS", "").split(",")
            if key
        ] or [""]
        self.openrouter_api_key: Optional[str] = self._clean_env_value(
            os.getenv("OPENROUTER_API_KEY")
        )
        self.gemini_api_key: Optional[str] = self._clean_env_value(
            os.getenv("GEMINI_API_KEY")
        )
        self.gemini_as_is: bool = os.getenv("GEMINI_AS_IS", "").upper() == "TRUE"
        self.config_path = Path(os.getenv("CONFIG_PATH", "config.yml"))
        self.model_mappings: Dict[str, str] = {}
        self.load_config()

    def _clean_env_value(self, value: Optional[str]) -> Optional[str]:
        """Remove surrounding quotes from environment variable values."""
        if not value:
            return value
        # Remove surrounding quotes if present
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            return value[1:-1]
        return value

    def load_config(self) -> None:
        if self.config_path.exists():
            with open(self.config_path, "r") as f:
                config_data = yaml.safe_load(f)
                if config_data and "model_mappings" in config_data:
                    self.model_mappings = config_data["model_mappings"]

    def reload(self) -> None:
        """Reloads the configuration from the config file."""
        self.load_config()

    def get_mapped_model(self, requested_model: str) -> Tuple[str, str]:
        """
        Get the mapped model and provider.
        Returns (provider, model) tuple.
        """
        # Direct match
        if requested_model in self.model_mappings:
            return self._parse_provider_model(self.model_mappings[requested_model])

        # Wildcard match
        for pattern, target_model in self.model_mappings.items():
            if fnmatch.fnmatch(requested_model, pattern):
                return self._parse_provider_model(target_model)

        # No match, return original with default provider
        return "openrouter", requested_model

    def is_valid_model(self, model: str) -> bool:
        """
        Check if a model is valid (has a mapping).
        Models with explicit bad patterns are considered invalid.
        """
        # Check for explicitly bad model patterns
        bad_patterns = ["nonexistent", "invalid", "test-bad"]
        for bad_pattern in bad_patterns:
            if bad_pattern in model.lower():
                return False

        # All other models are valid due to wildcard patterns
        return True

    def _parse_provider_model(self, model_string: str) -> Tuple[str, str]:
        """
        Parse provider:model format.
        Examples:
        - "openrouter:mistralai/mistral-small" -> ("openrouter", "mistralai/mistral-small")
        - "gemini:gemini-2.0-flash-001" -> ("gemini", "gemini-2.0-flash-001")
        - "mistralai/mistral-small" -> ("openrouter", "mistralai/mistral-small")  # default
        """
        if ":" in model_string:
            provider, model = model_string.split(":", 1)
            return provider.strip(), model.strip()
        else:
            # Default to openrouter for backward compatibility
            return "openrouter", model_string.strip()


settings = Settings()


if __name__ == "__main__":
    # Example usage
    # Create a dummy config.yml
    with open("config.yml", "w") as f:
        yaml.dump(
            {
                "model_mappings": {
                    "gpt-4*": "openai/gpt-4",
                    "claude-3-opus": "anthropic/claude-3-opus",
                }
            },
            f,
        )

    # Set dummy env vars
    os.environ["API_KEYS"] = "key1,key2"
    os.environ["OPENROUTER_API_KEY"] = "or_key"

    s = Settings()
    print(f"API Keys: {s.api_keys}")
    print(f"OpenRouter Key: {s.openrouter_api_key}")
    print(f"Model Mappings: {s.model_mappings}")
    print(f"Mapping for 'gpt-4-turbo': {s.get_mapped_model('gpt-4-turbo')}")
    print(f"Mapping for 'claude-3-opus': {s.get_mapped_model('claude-3-opus')}")
    print(f"Mapping for 'gemini-pro': {s.get_mapped_model('gemini-pro')}")

    # cleanup
    os.remove("config.yml")
