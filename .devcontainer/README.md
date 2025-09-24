# Development Container for Network Security Suite

This directory contains configuration for using Visual Studio Code's [Development Containers](https://code.visualstudio.com/docs/remote/containers) feature with this project.

## Prerequisites

To use this development container, you need:

1. [Docker](https://www.docker.com/products/docker-desktop) installed and running
2. [Visual Studio Code](https://code.visualstudio.com/) installed
3. [Remote - Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension installed in VS Code

## Getting Started

1. Clone the repository to your local machine
2. Open the repository folder in VS Code
3. When prompted, click "Reopen in Container" or run the "Remote-Containers: Reopen in Container" command from the Command Palette (F1)
4. VS Code will build the development container and connect to it, which may take a few minutes the first time

## Features

This development container includes:

- Python 3.9 environment with Poetry for dependency management
- PostgreSQL, Redis, Prometheus, and Grafana services
- Pre-configured linting and formatting tools (pylint, mypy, flake8, black, isort)
- Testing setup with pytest
- Recommended VS Code extensions for Python development
- Git and GitHub CLI tools

## Port Forwarding

The following ports are automatically forwarded:

- 8000: FastAPI application
- 5433: PostgreSQL
- 6379: Redis
- 9090: Prometheus
- 3000: Grafana

## Customization

If you need to customize the development container, you can modify:

- `.devcontainer/devcontainer.json`: VS Code settings and extensions
- `docker-compose.yml`: Service configuration
- `Dockerfile`: Base image and dependencies