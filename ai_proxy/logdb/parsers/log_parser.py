import datetime as dt
import hashlib
import json
from typing import Dict, Iterator, Optional, Tuple


def _safe_iso_to_datetime(ts: str) -> Optional[dt.datetime]:
    if not ts:
        return None
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return dt.datetime.fromisoformat(ts)
    except Exception:
        return None


def _iter_json_blocks(f) -> Iterator[Tuple[int, str]]:
    buffer = None
    depth = 0
    while True:
        line = f.readline()
        if not line:
            if buffer is not None:
                buffer = None
                depth = 0
            break

        if buffer is None:
            brace_idx = line.find("{")
            if brace_idx == -1:
                continue
            buffer = [line[brace_idx:]]
            depth = buffer[-1].count("{") - buffer[-1].count("}")
            if depth == 0:
                json_text = "".join(buffer)
                buffer = None
                yield f.tell(), json_text
            continue

        buffer.append(line)
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            json_text = "".join(buffer)
            buffer = None
            yield f.tell(), json_text


def _parse_log_entry(json_text: str) -> Optional[Dict]:
    try:
        entry = json.loads(json_text)
    except Exception:
        return None

    if not isinstance(entry, dict):
        return None
    if "endpoint" not in entry or "request" not in entry or "response" not in entry:
        return None

    return entry


def _normalize_entry(entry: Dict) -> Optional[Dict]:
    ts_iso = entry.get("timestamp")
    if ts_iso is None:
        return None
    ts_iso = str(ts_iso)
    dt_obj = _safe_iso_to_datetime(ts_iso)
    if dt_obj is None:
        return None
    if dt_obj.tzinfo is None:
        dt_obj = dt_obj.replace(tzinfo=dt.timezone.utc)
    epoch_sec = int(dt_obj.timestamp())

    endpoint = str(entry.get("endpoint", ""))
    if not endpoint:
        return None

    request_obj = entry.get("request")
    response_obj = entry.get("response")
    if request_obj is None or response_obj is None:
        return None

    try:
        request_json = json.dumps(request_obj, ensure_ascii=False, sort_keys=True)
        response_json = json.dumps(response_obj, ensure_ascii=False, sort_keys=True)
    except Exception:
        return None

    model_original = None
    if isinstance(request_obj, dict):
        model_original = request_obj.get("model")
    model_mapped = None
    if isinstance(response_obj, dict):
        model_mapped = response_obj.get("model")

    status_code_val = entry.get("status_code")
    try:
        status_code = int(status_code_val) if status_code_val is not None else None
    except Exception:
        status_code = None

    latency_val = entry.get("latency_ms")
    try:
        latency_ms = float(latency_val) if latency_val is not None else None
    except Exception:
        latency_ms = None
    api_key_hash = entry.get("api_key_hash")

    return {
        "ts_iso": ts_iso,
        "epoch_sec": epoch_sec,
        "endpoint": endpoint,
        "model_original": model_original,
        "model_mapped": model_mapped,
        "status_code": status_code,
        "latency_ms": latency_ms,
        "api_key_hash": api_key_hash,
        "request_json": request_json,
        "response_json": response_json,
        "date": dt_obj.astimezone(dt.timezone.utc).date(),
    }


def _compute_request_id(server_id: str, norm: Dict) -> str:
    req_sha = hashlib.sha256(norm["request_json"].encode("utf-8")).hexdigest()
    resp_sha = hashlib.sha256(norm["response_json"].encode("utf-8")).hexdigest()
    key = f"{server_id}|{norm['ts_iso']}|{norm['endpoint']}|{req_sha}|{resp_sha}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()

