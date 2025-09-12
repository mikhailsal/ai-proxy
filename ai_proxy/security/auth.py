from fastapi import HTTPException, Security, Request
from fastapi.security import APIKeyHeader
from starlette import status
import secrets

from ai_proxy.core.config import settings

API_KEY_HEADER = APIKeyHeader(name="Authorization", auto_error=False)


def get_api_key_dependency():
    """Factory function to create the API key dependency."""

    async def get_api_key(
        request: Request, api_key_header: str = Security(API_KEY_HEADER)
    ):
        """
        Dependency to validate the API key.
        The key is expected to be passed as 'Bearer <key>'.
        """
        if not api_key_header:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Authorization header",
            )

        if " " not in api_key_header:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Authorization header format. Expected 'Bearer <key>'",
            )

        scheme, _, key = api_key_header.partition(" ")
        if scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Authorization scheme. Expected 'Bearer'",
            )

        if not any(
            secrets.compare_digest(key, valid_key)
            for valid_key in settings.api_keys
            if valid_key
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API Key",
            )
        return key

    return get_api_key


# Create the dependency instance
get_api_key = get_api_key_dependency()
