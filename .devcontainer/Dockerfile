# Use the Python 3.9 slim image as base
FROM python:3.9-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VENV_IN_PROJECT=1 \
    POETRY_CACHE_DIR=/opt/poetry_cache \
    PATH="/app/.venv/bin:$PATH"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    libpcap-dev \
    curl \
    git \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install poetry

# Create non-root user
RUN useradd --create-home --shell /bin/bash app

# Set work directory
WORKDIR /app

# Install development tools
RUN pip install --no-cache-dir \
    black \
    isort \
    mypy \
    pylint \
    flake8

# Switch to non-root user
USER app

# Expose port
EXPOSE 8000

# Default command
CMD ["uvicorn", "src.network_security_suite.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
