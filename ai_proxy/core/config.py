import os
from pathlib import Path
from typing import Dict, List, Optional
import yaml
from dotenv import load_dotenv
import fnmatch


class Settings:
    def __init__(self):
        load_dotenv()
        self.api_keys: List[str] = os.getenv("API_KEYS", "").split(",")
        self.openrouter_api_key: Optional[str] = os.getenv(
            "OPENROUTER_API_KEY"
        )
        self.config_path = Path(os.getenv("CONFIG_PATH", "config.yml"))
        self.model_mappings: Dict[str, str] = {}
        self.load_config()

    def load_config(self):
        if self.config_path.exists():
            with open(self.config_path, "r") as f:
                config_data = yaml.safe_load(f)
                if config_data and "model_mappings" in config_data:
                    self.model_mappings = config_data["model_mappings"]

    def reload(self):
        """Reloads the configuration from the config file."""
        self.load_config()

    def get_mapped_model(self, requested_model: str) -> str:
        # Direct match
        if requested_model in self.model_mappings:
            return self.model_mappings[requested_model]

        # Wildcard match
        for pattern, target_model in self.model_mappings.items():
            if fnmatch.fnmatch(requested_model, pattern):
                return target_model

        # No match, return original
        return requested_model


settings = Settings()


if __name__ == "__main__":
    # Example usage
    # Create a dummy config.yml
    with open("config.yml", "w") as f:
        yaml.dump({
            "model_mappings": {
                "gpt-4*": "openai/gpt-4",
                "claude-3-opus": "anthropic/claude-3-opus"
            }
        }, f)

    # Set dummy env vars
    os.environ["API_KEYS"] = "key1,key2"
    os.environ["OPENROUTER_API_KEY"] = "or_key"

    s = Settings()
    print(f"API Keys: {s.api_keys}")
    print(f"OpenRouter Key: {s.openrouter_api_key}")
    print(f"Model Mappings: {s.model_mappings}")
    print(f"Mapping for 'gpt-4-turbo': {s.get_mapped_model('gpt-4-turbo')}")
    print(f"Mapping for 'claude-3-opus': "
          f"{s.get_mapped_model('claude-3-opus')}")
    print(f"Mapping for 'gemini-pro': {s.get_mapped_model('gemini-pro')}")

    # cleanup
    os.remove("config.yml")
