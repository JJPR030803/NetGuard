#!/bin/bash
# Build the documentation

echo "Building MkDocs documentation..."
uv run mkdocs build --clean

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Documentation built successfully!"
    echo "  Output directory: site/"
    echo ""
    echo "To deploy to GitHub Pages, run:"
    echo "  uv run mkdocs gh-deploy"
else
    echo ""
    echo "✗ Documentation build failed"
    exit 1
fi
