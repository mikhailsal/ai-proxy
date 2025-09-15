import hashlib
import os


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def file_prefix_sha256(path: str, upto_bytes: int) -> str:
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


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)).strip())
    except Exception:
        return default