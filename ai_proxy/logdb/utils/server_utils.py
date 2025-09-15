import os
import socket
import uuid
from typing import Optional


def derive_server_id(base_db_dir: Optional[str] = None) -> str:
    """Derive a stable server id and persist it once per host.

    Resolution order (Stage C):
    1) LOGDB_SERVER_ID env var (explicit override)
    2) .server_id file under base_db_dir (if provided)
    3) Create and persist a new UUID4 into .server_id (if base_db_dir provided)
    4) Fallback: deterministic UUID5 from hostname+env
    """
    # Explicit override is highest priority
    explicit = os.getenv("LOGDB_SERVER_ID")
    if explicit:
        return explicit.strip()

    server_file_path = None
    if base_db_dir:
        try:
            server_file_path = os.path.join(os.path.abspath(base_db_dir), ".server_id")
            # Read if exists
            if os.path.isfile(server_file_path):
                with open(server_file_path, "r", encoding="utf-8") as f:
                    sid = f.read().strip()
                    if sid:
                        return sid
        except Exception:
            # Non-fatal: fall through to generation
            server_file_path = None

    # Generate a new id
    if server_file_path:
        try:
            os.makedirs(os.path.dirname(server_file_path), exist_ok=True)
            new_id = str(uuid.uuid4())
            with open(server_file_path, "w", encoding="utf-8") as f:
                f.write(new_id)
            return new_id
        except Exception:
            pass

    # Last resort: deterministic based on hostname and env
    env = os.getenv("LOGDB_ENV") or os.getenv("ENV") or "dev"
    hostname = socket.gethostname()
    server_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"ai-proxy|{hostname}|{env}")
    return str(server_uuid)