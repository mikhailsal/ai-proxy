"""
Health check endpoint.
"""

from fastapi import APIRouter
from ai_proxy.logging.config import logger

# Path to the deployment timestamp file
DEPLOYMENT_TIMESTAMP_FILE = "/workspace/deployment-timestamp.txt"

router = APIRouter(tags=["Admin"])


@router.get("/health")
async def health_check():
    """Health check endpoint."""

    deployment_timestamp = "unknown"
    try:
        with open(DEPLOYMENT_TIMESTAMP_FILE, "r") as f:
            deployment_timestamp = f.read().strip()
    except FileNotFoundError:
        logger.warning(
            f"Deployment timestamp file not found at {DEPLOYMENT_TIMESTAMP_FILE}"
        )
    except Exception as e:
        logger.error(f"Error reading deployment timestamp: {e}")

    return {
        "status": "ok",
        "version": "test-final-deployment",
        "script_tested": True,
        "deployment_timestamp": deployment_timestamp,
    }
