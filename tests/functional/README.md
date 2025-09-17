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

# Run specific provider tests
make test-functional-gemini      # Only Gemini tests
make test-functional-openrouter  # Only OpenRouter tests
make test-functional-general     # Only general tests (no API costs)

# Run specific functional test
make test-specific TEST=tests/functional/test_gemini.py::TestGeminiFunctionality::test_gemini_chat_completion

# Run functional tests with custom base URL
FUNCTIONAL_TEST_BASE_URL=http://localhost:9000 make test-functional
```

### Test Categories

#### TestGeminiFunctionality (test_gemini.py)
- `test_health_endpoint`: Verifies service health endpoint
- `test_gemini_chat_completion`: Tests Gemini API integration
- `test_gemini_streaming_chat_completion`: Tests Gemini streaming responses

#### TestGeminiEdgeCases (test_gemini.py)
- `test_gemini_model_mapping_consistency`: Tests Gemini model aliases

#### TestGeminiPerformanceAndReliability (test_gemini.py)
- `test_gemini_concurrent_requests`: Tests concurrent Gemini requests
- `test_gemini_request_timeout_handling`: Tests timeout handling
- `test_gemini_empty_message_content`: Tests empty message handling
- `test_gemini_very_long_message`: Tests long message handling
- `test_gemini_special_characters_in_message`: Tests special characters

#### TestOpenRouterFunctionality (test_openrouter.py)
- `test_health_endpoint`: Verifies service health endpoint
- `test_openrouter_chat_completion`: Tests OpenRouter API integration
- `test_openrouter_streaming_chat_completion`: Tests OpenRouter streaming responses

#### TestOpenRouterEdgeCases (test_openrouter.py)
- `test_openrouter_model_variations`: Tests different OpenRouter models

#### TestOpenRouterPerformanceAndReliability (test_openrouter.py)
- `test_openrouter_concurrent_requests`: Tests concurrent OpenRouter requests
- `test_openrouter_request_timeout_handling`: Tests timeout handling
- `test_openrouter_empty_message_content`: Tests empty message handling
- `test_openrouter_very_long_message`: Tests long message handling
- `test_openrouter_special_characters_in_message`: Tests special characters

#### TestGeneralAuthentication (test_general.py)
- `test_invalid_api_key`: Tests authentication failure (401)
- `test_missing_api_key`: Tests missing authentication (401)
- `test_options_request`: Tests CORS preflight requests

#### TestGeneralEdgeCases (test_general.py)
- `test_invalid_model`: Tests handling of invalid model names
- `test_malformed_request`: Tests handling of malformed requests
- `test_health_endpoint`: Verifies service health endpoint

#### TestGeneralEndpoints (test_general.py)
- `test_health_endpoint_unauthenticated`: Tests health endpoint without auth
- `test_unknown_endpoint`: Tests 404 for unknown endpoints
- `test_root_endpoint`: Tests root endpoint response

## Test Behavior

- **Automatic Skipping**: Tests are automatically skipped unless `ENABLE_FUNCTIONAL_TESTS=true`
- **Docker Only**: Tests must run in Docker containers (enforced by project rules)
- **Provider-Specific**: Tests are organized by provider to allow selective testing
- **Environment Checks**: Tests verify required API keys and service availability
- **Graceful Failures**: Tests handle missing API keys by skipping relevant tests
- **Cost Management**: General tests don't incur external API costs

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
