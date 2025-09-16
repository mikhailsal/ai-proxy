# Sample log entries for ingest testing
SAMPLE_ENTRY_1 = (
    "2025-09-10 12:00:00 - INFO - {\n"
    '  "timestamp": "2025-09-10T12:00:00Z",\n'
    '  "endpoint": "/v1/chat/completions",\n'
    '  "status_code": 200,\n'
    '  "latency_ms": 123.45,\n'
    '  "request": {\n'
    '    "model": "gpt-4",\n'
    '    "messages": [{"role": "user", "content": "Hi"}]\n'
    "  },\n"
    '  "response": {\n'
    '    "id": "chatcmpl-1",\n'
    '    "model": "openrouter/openai/gpt-4",\n'
    '    "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello"}}]\n'
    "  }\n"
    "}\n"
)


SAMPLE_ENTRY_2 = (
    "2025-09-10 12:05:00 - INFO - {\n"
    '  "timestamp": "2025-09-10T12:05:00Z",\n'
    '  "endpoint": "/v1/chat/completions",\n'
    '  "status_code": 200,\n'
    '  "latency_ms": 98.7,\n'
    '  "request": {\n'
    '    "model": "gemini-pro",\n'
    '    "messages": [{"role": "user", "content": "Count 1-3"}]\n'
    "  },\n"
    '  "response": {\n'
    '    "id": "chatcmpl-2",\n'
    '    "model": "gemini:gemini-2.0-flash-001",\n'
    '    "choices": [{"index": 0, "message": {"role": "assistant", "content": "1,2,3"}}]\n'
    "  }\n"
    "}\n"
)
