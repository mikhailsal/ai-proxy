FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install poetry
RUN pip install poetry

# Configure poetry to not create virtual environment (we're in a container)
ENV POETRY_VENV_IN_PROJECT=false
ENV POETRY_VIRTUALENVS_CREATE=false

# Copy project files
COPY poetry.lock pyproject.toml ./

# Install dependencies
RUN poetry install --no-root --only main

# Copy application source code
COPY ./ai_proxy ./ai_proxy
COPY ./config.yml ./config.yml

# Expose port and run application
EXPOSE 8123
CMD ["uvicorn", "ai_proxy.main:app", "--host", "0.0.0.0", "--port", "8123"] 