#!/bin/bash

# Script to convert Mermaid diagrams to PNG images
# Requires Node.js and the @mermaid-js/mermaid-cli package

# Check if mmdc (Mermaid CLI) is installed
if ! command -v mmdc &> /dev/null; then
    echo "Mermaid CLI not found. Installing..."
    npm install -g @mermaid-js/mermaid-cli
fi

# Convert the architecture diagram
echo "Converting architecture diagram..."
mmdc -i docs/latex/figures/architecture_diagram_simple.md -o docs/latex/figures/architecture_diagram.png -w 1200 -H 800 -b transparent

echo "Conversion complete. PNG file created at docs/latex/figures/architecture_diagram.png"