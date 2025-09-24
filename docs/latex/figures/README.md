# Architecture Diagrams

This directory contains architecture diagrams for the Network Security Suite.

## Mermaid Diagrams

The following Mermaid diagram files are provided:

- `architecture_diagram_mermaid.md` - Comprehensive architecture diagram
- `architecture_diagram_simple.md` - Simplified architecture diagram

## PNG Files

The LaTeX documents reference the following PNG files:

- `architecture_diagram.png` - High-level architecture diagram
- `ml_architecture.png` - Machine learning subsystem architecture
- `dashboard_screenshot.png` - Dashboard screenshot
- `roadmap_timeline.png` - Development roadmap timeline

## Generating PNG Files from Mermaid Diagrams

To generate the PNG files from the Mermaid diagrams:

1. Ensure you have Node.js installed
2. Run the conversion script from the project root:
   ```bash
   ./convert_mermaid.sh
   ```

Alternatively, you can use online Mermaid tools:

1. Copy the content of the Mermaid file
2. Paste it into an online Mermaid editor like [Mermaid Live Editor](https://mermaid.live/)
3. Export as PNG and save to this directory

## Important Note

The LaTeX compilation will fail if these PNG files are empty or missing. Make sure to generate or provide these files before compiling the LaTeX documents.