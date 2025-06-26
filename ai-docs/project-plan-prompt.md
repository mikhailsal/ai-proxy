Act as a senior software architect and Python expert.

Goal  
Design a robust, production-ready proxy service that:  
• Implements the OpenAI REST API spec (chat/completions, embeddings, etc.) so it is a drop-in replacement for official endpoints.  
• Transparently forwards each incoming request to one or more configurable LLM provider back-ends (e.g., OpenAI, Anthropic, Azure OpenAI, local models) and returns the selected response.  
• Logs every request, response, timing, and metadata in a research-ready format for later analysis.  
• Adheres to modern Python best practices (type hints, linting, async IO, dependency injection, modular design, testing, CI/CD, security).
• Step by step development starting with the simplest possible implementation and gradually adding complexity.

Deliverables  
Please produce a detailed project plan that contains:

1. High-level architecture  
   • Main components and how they interact (HTTP layer, routing/orchestration, provider adapters, logging layer, persistence, config, auth, observability).  
   • Recommended protocols, libraries, and patterns (e.g., FastAPI, pydantic, httpx/asyncio, structured logging, OpenTelemetry).  

2. API surface  
   • Endpoint list matching the OpenAI spec, including required/optional fields and example payloads.  
   • Any additional internal/admin endpoints (health, metrics).  

3. Provider abstraction layer  
   • Strategy for pluggable adapters. 
   • Configuration of provider credentials via env vars/secrets.  

4. Logging & data storage  
   • Schema for storing requests/responses, including token counts and latency.  
   • Recommendations for database/warehouse choices and GDPR/PII handling.  

5. Security & compliance  
   • Authentication/authorization options (API keys).   

6. Observability & reliability  
   • Metrics, tracing, structured logs.  
   • Graceful error handling, retries, timeouts, circuit breakers.  

7. Testing strategy  
   • Unit, integration, contract, and load tests; mocking external APIs.  

8. Deployment & operations  
   • Containerization (Docker)
   • Rollback/versioning strategy, config management, secret handling.  

9. Project structure & coding standards  
   • Recommended folder layout, naming conventions, pre-commit hooks, lint/format tools.  
   • Use of type annotations, mypy, Ruff/Flake8, Black, isort.  

10. Timeline & milestones  
    • Phased implementation roadmap with estimated effort per phase.

Present the plan in clear sections with bullet points, code snippets where useful, and concise explanations.

Also create checkpoint [ ] for each phase to be able to track the progress. The first stage should be the simplest possible implementation.

Write your plan in ai-docs/project-plan.md file.