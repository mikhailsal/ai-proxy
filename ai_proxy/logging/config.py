import logging
import sys
import json
from pathlib import Path
from typing import Dict, Any
import structlog
from datetime import datetime


class PrettyJSONRenderer:
    """Custom JSON renderer that formats JSON in a readable way."""

    def __call__(self, logger, method_name, event_dict):
        return json.dumps(event_dict, indent=2, ensure_ascii=False, default=str)


class EndpointFileHandler:
    """Custom handler that creates separate log files for different endpoints."""

    def __init__(self, base_log_dir: str = "logs"):
        self.base_log_dir = Path(base_log_dir)
        self.base_log_dir.mkdir(exist_ok=True)
        self.handlers: Dict[str, logging.FileHandler] = {}

    def get_handler(self, endpoint: str) -> logging.FileHandler:
        """Get or create a file handler for a specific endpoint."""
        # Clean endpoint name for filename
        clean_endpoint = endpoint.replace("/", "_").replace(":", "").strip("_")
        if not clean_endpoint:
            clean_endpoint = "general"

        if clean_endpoint not in self.handlers:
            log_file = self.base_log_dir / f"{clean_endpoint}.log"
            handler = logging.FileHandler(log_file, encoding="utf-8")
            handler.setLevel(logging.INFO)

            # Set formatter for readable output
            formatter = logging.Formatter(
                fmt="%(asctime)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            handler.setFormatter(formatter)
            self.handlers[clean_endpoint] = handler

        return self.handlers[clean_endpoint]


class ModelFileHandler:
    """Custom handler that creates separate log files for different models."""

    def __init__(self, base_log_dir: str = "logs/models"):
        self.base_log_dir = Path(base_log_dir)
        self.base_log_dir.mkdir(parents=True, exist_ok=True)
        self.handlers: Dict[str, logging.FileHandler] = {}

    def get_handler(self, model_name: str) -> logging.FileHandler:
        """Get or create a file handler for a specific model."""
        # Clean model name for filename
        clean_model = (
            model_name.replace("/", "_").replace(":", "_").replace("*", "star")
        )
        if not clean_model:
            clean_model = "unknown_model"

        if clean_model not in self.handlers:
            log_file = self.base_log_dir / f"{clean_model}.log"
            handler = logging.FileHandler(log_file, encoding="utf-8")
            handler.setLevel(logging.INFO)

            # Set formatter for readable output
            formatter = logging.Formatter(
                fmt="%(asctime)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            handler.setFormatter(formatter)
            self.handlers[clean_model] = handler

        return self.handlers[clean_model]


# Global handler instances
endpoint_handler = EndpointFileHandler()
model_handler = ModelFileHandler()


def setup_logging(log_level: str = "INFO", enable_file_logging: bool = True):
    """
    Configure structured logging with file output support.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        enable_file_logging: Whether to enable file logging
    """
    # Ensure logs directory exists
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)

    # Configure basic logging
    log_level_obj = getattr(logging, log_level.upper(), logging.INFO)

    # Console handler with pretty JSON
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level_obj)
    
    # Reduce verbosity for higher log levels (WARNING, ERROR)
    if log_level_obj >= logging.WARNING:
        # Disable some noisy loggers for tests
        logging.getLogger("httpx").setLevel(logging.ERROR)
        logging.getLogger("httpcore").setLevel(logging.ERROR)
        logging.getLogger("uvicorn").setLevel(logging.ERROR)
        logging.getLogger("uvicorn.access").setLevel(logging.ERROR)

    # Main application log file handler
    if enable_file_logging:
        main_log_file = logs_dir / "app.log"
        file_handler = logging.FileHandler(main_log_file, encoding="utf-8")
        file_handler.setLevel(log_level_obj)

        # Configure root logger
        logging.basicConfig(
            level=log_level_obj,
            handlers=[console_handler, file_handler],
            format="%(message)s",
        )
    else:
        logging.basicConfig(
            level=log_level_obj, handlers=[console_handler], format="%(message)s"
        )

    # Configure structlog
    processors = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    # Use different renderer based on log level
    if log_level_obj >= logging.WARNING:
        # For tests/high log levels, use simpler output
        processors.append(structlog.dev.ConsoleRenderer())
    else:
        # Use pretty JSON renderer for better readability in development
        processors.append(PrettyJSONRenderer())

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_endpoint_logger(endpoint: str):
    """
    Get a logger that writes to an endpoint-specific file.

    Args:
        endpoint: The endpoint name (e.g., "/v1/chat/completions")

    Returns:
        A logger instance that writes to the endpoint-specific log file
    """
    logger_name = f"endpoint.{endpoint.replace('/', '.').strip('.')}"
    endpoint_logger = logging.getLogger(logger_name)

    if not endpoint_logger.handlers:
        handler = endpoint_handler.get_handler(endpoint)
        endpoint_logger.addHandler(handler)
        endpoint_logger.setLevel(logging.INFO)
        endpoint_logger.propagate = False  # Don't propagate to root logger

    return structlog.wrap_logger(endpoint_logger)


def get_model_logger(model_name: str):
    """
    Get a logger that writes to a model-specific file.

    Args:
        model_name: The model name (e.g., "gpt-4", "claude-3-opus")

    Returns:
        A logger instance that writes to the model-specific log file
    """
    logger_name = f"model.{model_name.replace('/', '.').replace(':', '.')}"
    model_logger = logging.getLogger(logger_name)

    if not model_logger.handlers:
        handler = model_handler.get_handler(model_name)
        model_logger.addHandler(handler)
        model_logger.setLevel(logging.INFO)
        model_logger.propagate = False  # Don't propagate to root logger

    return structlog.wrap_logger(model_logger)


# Main application logger
logger = structlog.get_logger()


def log_request_response(
    endpoint: str,
    request_data: Dict[str, Any],
    response_data: Dict[str, Any],
    status_code: int,
    latency_ms: float,
    api_key_hash: str = None,
):
    """
    Log request and response data to endpoint-specific log file.

    Args:
        endpoint: The API endpoint
        request_data: Request payload
        response_data: Response payload
        status_code: HTTP status code
        latency_ms: Request latency in milliseconds
        api_key_hash: Hashed API key for tracking
    """
    endpoint_logger = get_endpoint_logger(endpoint)

    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "endpoint": endpoint,
        "status_code": status_code,
        "latency_ms": round(latency_ms, 2),
        "request": request_data,
        "response": response_data,
    }

    if api_key_hash:
        log_entry["api_key_hash"] = api_key_hash

    endpoint_logger.info("API Request/Response", **log_entry)


def log_model_usage(
    original_model: str,
    mapped_model: str,
    request_data: Dict[str, Any],
    response_data: Dict[str, Any],
    status_code: int,
    latency_ms: float,
    api_key_hash: str = None,
):
    """
    Log model usage data to model-specific log files.

    Args:
        original_model: The original model requested by client
        mapped_model: The actual model used after mapping
        request_data: Request payload
        response_data: Response payload
        status_code: HTTP status code
        latency_ms: Request latency in milliseconds
        api_key_hash: Hashed API key for tracking
    """
    # Log to original model file
    if original_model:
        original_logger = get_model_logger(original_model)
        original_logger.info(
            "Model usage (original)",
            timestamp=datetime.utcnow().isoformat(),
            original_model=original_model,
            mapped_model=mapped_model,
            status_code=status_code,
            latency_ms=round(latency_ms, 2),
            request=request_data,
            response=response_data,
            api_key_hash=api_key_hash,
        )

    # Log to mapped model file (if different)
    if mapped_model and mapped_model != original_model:
        mapped_logger = get_model_logger(mapped_model)
        mapped_logger.info(
            "Model usage (mapped)",
            timestamp=datetime.utcnow().isoformat(),
            original_model=original_model,
            mapped_model=mapped_model,
            status_code=status_code,
            latency_ms=round(latency_ms, 2),
            request=request_data,
            response=response_data,
            api_key_hash=api_key_hash,
        )
