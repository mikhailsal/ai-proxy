import datetime as dt
import json
import os
import tarfile
import hashlib
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .partitioning import compute_partition_path


@dataclass(frozen=True)
class BundleFile:
    path: str
    sha256: str
    bytes: int


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


def _collect_db_files(base_db_dir: str, since: dt.date, to: dt.date) -> List[str]:
    files: List[str] = []
    cur = since
    while cur <= to:
        p = compute_partition_path(base_db_dir, cur)
        if os.path.isfile(p):
            files.append(p)
        cur = cur + dt.timedelta(days=1)
    return files


def _collect_raw_logs(source_logs_dir: str, since: Optional[dt.date], to: Optional[dt.date]) -> List[str]:
    # Conservative: include all .log files when include_raw requested; stage plan allows flag-driven choice
    out: List[str] = []
    for root, _dirs, names in os.walk(source_logs_dir):
        for n in names:
            if n.endswith(".log") or ".log." in n:
                out.append(os.path.join(root, n))
    return sorted(out)


def create_bundle(
    base_db_dir: str,
    since: dt.date,
    to: dt.date,
    out_path: str,
    include_raw: bool = False,
    raw_logs_dir: Optional[str] = None,
    server_id: Optional[str] = None,
    schema_version: str = "v1",
) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)

    db_files = _collect_db_files(base_db_dir, since, to)
    if include_raw and raw_logs_dir:
        raw_files = _collect_raw_logs(raw_logs_dir, since, to)
    else:
        raw_files = []

    files_meta: List[BundleFile] = []

    # Build tar.gz
    with tarfile.open(out_path, mode="w:gz") as tar:
        # Add DB files under db/
        for abs_path in db_files:
            sha, size = _sha256_of_file(abs_path)
            rel_in_tar = os.path.join("db", os.path.relpath(abs_path, start=os.path.abspath(base_db_dir)))
            tar.add(abs_path, arcname=rel_in_tar)
            files_meta.append(BundleFile(path=rel_in_tar, sha256=sha, bytes=size))

        # Optionally add raw log files under raw/
        for abs_path in raw_files:
            sha, size = _sha256_of_file(abs_path)
            # Preserve directory structure relative to provided source dir
            base = os.path.abspath(raw_logs_dir or ".")
            rel = os.path.relpath(abs_path, start=base)
            rel_in_tar = os.path.join("raw", rel)
            tar.add(abs_path, arcname=rel_in_tar)
            files_meta.append(BundleFile(path=rel_in_tar, sha256=sha, bytes=size))

        # Prepare metadata.json in-memory
        meta = {
            "bundle_id": hashlib.sha256((str(dt.datetime.utcnow().timestamp()) + out_path).encode("utf-8")).hexdigest()[:32],
            "created_at": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "server_id": server_id or "",
            "schema_version": schema_version,
            "files": [
                {"path": f.path, "sha256": f.sha256, "bytes": f.bytes} for f in files_meta
            ],
            "include_raw": bool(include_raw),
        }

        # Write metadata.json into the tar as a file
        meta_bytes = json.dumps(meta, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
        info = tarfile.TarInfo(name="metadata.json")
        info.size = len(meta_bytes)
        info.mtime = int(dt.datetime.utcnow().timestamp())
        tar.addfile(info, fileobj=_BytesIO(meta_bytes))

    return out_path


def verify_bundle(bundle_path: str) -> bool:
    # Verify checksums of all files listed in metadata.json
    with tarfile.open(bundle_path, mode="r:gz") as tar:
        meta_member = tar.getmember("metadata.json")
        with tar.extractfile(meta_member) as f:
            assert f is not None
            meta = json.loads(f.read().decode("utf-8"))

        files = meta.get("files", [])
        for item in files:
            path = item.get("path")
            expected = item.get("sha256")
            if not path or not expected:
                return False
            try:
                member = tar.getmember(path)
            except KeyError:
                return False
            with tar.extractfile(member) as f:
                assert f is not None
                h = hashlib.sha256()
                for chunk in iter(lambda: f.read(65536), b""):
                    if not chunk:
                        break
                    h.update(chunk)
                if h.hexdigest() != expected:
                    return False
    return True


class _BytesIO:
    def __init__(self, b: bytes):
        self._b = b
        self._pos = 0

    def read(self, n: Optional[int] = None) -> bytes:  # pragma: no cover (simple helper)
        if n is None or n < 0:
            n = len(self._b) - self._pos
        start = self._pos
        end = min(len(self._b), self._pos + n)
        self._pos = end
        return self._b[start:end]


