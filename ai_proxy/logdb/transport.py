import hashlib
import os
from typing import Tuple


def _sha256_of_file(path: str) -> Tuple[str, int]:
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            if not chunk:
                break
            h.update(chunk)
            total += len(chunk)
    return h.hexdigest(), total


def copy_with_resume(src_path: str, dst_path: str) -> Tuple[int, str]:
    """Copy a file with resume capability using a .part temp file.

    - If a previous partial copy exists (dst_path + ".part"), resume appending from
      its current size.
    - On success, atomically replace/rename to final destination path.
    - If destination already exists and matches source checksum, do nothing.

    Returns (final_size_bytes, sha256_hex) for the destination file.
    """
    src_abs = os.path.abspath(src_path)
    dst_abs = os.path.abspath(dst_path)
    tmp_abs = dst_abs + ".part"

    if not os.path.isfile(src_abs):
        raise FileNotFoundError(src_abs)

    os.makedirs(os.path.dirname(dst_abs) or ".", exist_ok=True)

    src_sha, src_size = _sha256_of_file(src_abs)

    # If final destination already exists, verify checksum and return
    if os.path.isfile(dst_abs):
        dst_sha, dst_size = _sha256_of_file(dst_abs)
        if dst_size == src_size and dst_sha == src_sha:
            return dst_size, dst_sha
        # Destination exists but differs; refuse to overwrite silently
        raise ValueError(f"Destination exists with different content: {dst_abs}")

    # Determine resume point from temp file
    start_pos = 0
    if os.path.isfile(tmp_abs):
        try:
            start_pos = os.path.getsize(tmp_abs)
            # Sanity: don't resume past source size
            if start_pos > src_size:
                start_pos = 0
        except OSError:
            start_pos = 0

    # Stream copy from start_pos
    with open(src_abs, "rb") as src, open(tmp_abs, "ab" if start_pos else "wb") as dst:
        if start_pos:
            src.seek(start_pos)
        for chunk in iter(lambda: src.read(65536), b""):
            if not chunk:
                break
            dst.write(chunk)

    # Verify checksum of temp file matches source, then finalize
    tmp_sha, tmp_size = _sha256_of_file(tmp_abs)
    if tmp_size != src_size or tmp_sha != src_sha:
        # Leave .part for future resume, but signal mismatch
        raise ValueError("Checksum mismatch after copy_with_resume")

    os.replace(tmp_abs, dst_abs)
    return tmp_size, tmp_sha


__all__ = [
    "copy_with_resume",
]


