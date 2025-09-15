import hashlib
import os
import socket
import uuid
import datetime as dt
from typing import Optional


def _derive_server_id(base_db_dir: Optional[str] = None) -> str:
    explicit = os.getenv("LOGDB_SERVER_ID")
    if explicit:
        return explicit.strip()

    server_file_path = None
    if base_db_dir:
        try:
            server_file_path = os.path.join(os.path.abspath(base_db_dir), ".server_id")
            if os.path.isfile(server_file_path):
                with open(server_file_path, "r", encoding="utf-8") as f:
                    sid = f.read().strip()
                    if sid:
                        return sid
        except Exception:
            server_file_path = None

    if server_file_path:
        try:
            os.makedirs(os.path.dirname(server_file_path), exist_ok=True)
            new_id = str(uuid.uuid4())
            with open(server_file_path, "w", encoding="utf-8") as f:
                f.write(new_id)
            return new_id
        except Exception:
            pass

    env = os.getenv("LOGDB_ENV") or os.getenv("ENV") or "dev"
    hostname = socket.gethostname()
    server_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"ai-proxy|{hostname}|{env}")
    return str(server_uuid)


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _file_prefix_sha256(path: str, upto_bytes: int) -> str:
    h = hashlib.sha256()
    read_left = max(0, int(upto_bytes))
    with open(path, "rb") as f:
        while read_left > 0:
            chunk = f.read(min(65536, read_left))
            if not chunk:
                break
            h.update(chunk)
            read_left -= len(chunk)
    return h.hexdigest()


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)).strip())
    except Exception:
        return default

