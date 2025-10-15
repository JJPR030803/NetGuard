#!/bin/bash
# Build MkDocs documentation for deployment

cd "$(dirname "$0")"

echo "Building MkDocs documentation..."

# Clean previous build
rm -rf site/

# Build documentation
uv run mkdocs build

echo ""
echo "✓ Documentation built successfully!"
echo "Output directory: ./site/"
echo ""
echo "To serve locally: uv run mkdocs serve"
echo "To deploy to GitHub Pages: uv run mkdocs gh-deploy"
