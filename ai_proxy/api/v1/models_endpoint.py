"""
Models listing endpoint.
"""

from fastapi import APIRouter
from ai_proxy.core.config import settings

router = APIRouter(tags=["API"])


@router.get("/v1/models")
async def list_models():
    """List available models (OpenAI-compatible endpoint)."""
    models = []

    # Get all configured models from settings
    for model_name, mapping in settings.model_mappings.items():
        # Skip wildcard patterns
        if "*" in model_name:
            continue

        # Parse provider and model info
        provider, mapped_model = settings._parse_provider_model(mapping)

        # Create model object in OpenAI format
        model_obj = {
            "id": model_name,
            "object": "model",
            "created": 1677610602,  # Static timestamp for consistency
            "owned_by": provider,
            "permission": [],
            "root": model_name,
            "parent": None,
        }
        models.append(model_obj)

    return {"object": "list", "data": models}
