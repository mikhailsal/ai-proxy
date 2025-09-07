# Functional Tests

This directory contains functional tests that make real API calls to external services to verify end-to-end functionality of the AI Proxy service.

## ⚠️ Important Warning

**These tests consume real API quotas and may incur costs!**

- Tests make actual HTTP requests to external LLM providers (Gemini, OpenRouter)
- Each test consumes tokens from your API quotas
- Tests are **disabled by default** for safety

## Running Functional Tests

### Prerequisites

1. **API Keys**: Ensure your `.env` file contains valid API keys:
   ```env
   API_KEYS=your-proxy-api-key
   GEMINI_API_KEY=your-gemini-api-key
   OPENROUTER_API_KEY=your-openrouter-api-key
   ```

2. **Service Running**: The AI proxy service must be running and accessible at `http://localhost:8123` (or set `FUNCTIONAL_TEST_BASE_URL` environment variable)

### Running Tests

```bash
# Run all functional tests
make test-functional

# Run specific functional test
make test-specific TEST=tests/functional/test_real_api_calls.py::TestRealAPIFunctionality::test_gemini_chat_completion

# Run functional tests with custom base URL
FUNCTIONAL_TEST_BASE_URL=http://localhost:9000 make test-functional
```

### Test Categories

#### TestRealAPIFunctionality
- `test_health_endpoint`: Verifies service health endpoint
- `test_gemini_chat_completion`: Tests Gemini API integration
- `test_openrouter_chat_completion`: Tests OpenRouter API integration  
- `test_streaming_chat_completion`: Tests streaming responses
- `test_invalid_api_key`: Tests authentication failure
- `test_missing_api_key`: Tests missing authentication

#### TestEdgeCases
- `test_invalid_model`: Tests handling of invalid model names
- `test_malformed_request`: Tests handling of malformed requests
- `test_options_request`: Tests CORS preflight requests

## Test Behavior

- **Automatic Skipping**: Tests are automatically skipped unless `ENABLE_FUNCTIONAL_TESTS=true`
- **Docker Only**: Tests must run in Docker containers (enforced by project rules)
- **Environment Checks**: Tests verify required API keys and service availability
- **Graceful Failures**: Tests handle missing API keys by skipping relevant tests

## Environment Variables

- `ENABLE_FUNCTIONAL_TESTS`: Set to `true` to enable functional tests
- `FUNCTIONAL_TEST_BASE_URL`: Base URL for the proxy service (default: `http://localhost:8123`)
- `API_KEYS`: Comma-separated list of proxy API keys
- `GEMINI_API_KEY`: Google Gemini API key
- `OPENROUTER_API_KEY`: OpenRouter API key

## Cost Considerations

- Each test typically uses 10-50 tokens per request
- Streaming tests may use more tokens
- Consider running tests sparingly to avoid unnecessary costs
- Monitor your API usage dashboards after running tests

## Troubleshooting

### Tests Skip with "API_KEYS not set"
- Ensure your `.env` file contains valid `API_KEYS`
- Check that the `.env` file is in the project root directory

### Tests Skip with "Service not available"
- Start the AI proxy service: `make dev` or `docker-compose up`
- Verify the service is accessible at the expected URL
- Check that the health endpoint returns 200: `curl http://localhost:8123/health`

### Tests Fail with Authentication Errors
- Verify your provider API keys are valid and have sufficient quota
- Check that API keys are correctly formatted in `.env`
- Ensure the proxy service can access the provider APIs

### Tests Timeout
- Increase timeout values in test fixtures if needed
- Check network connectivity to external services
- Verify provider services are operational 