#!/bin/bash
# Serve the documentation locally

echo "Starting MkDocs documentation server..."
echo "Documentation will be available at: http://127.0.0.1:8000"
echo "Press Ctrl+C to stop the server"
echo ""

uv run mkdocs serve
