# Network Security Suite Documentation

This directory contains comprehensive documentation for the Network Security Suite in multiple formats and languages.

## Directory Structure

### IEEE Format (English)

- `latex/` - Main LaTeX documentation directory (IEEE format, English)
  - `main.tex` - Main LaTeX document that includes all sections
  - `sections/` - Individual section files
    - `introduction.tex` - Introduction to the Network Security Suite
    - `architecture.tex` - System architecture overview
    - `components.tex` - Detailed component descriptions
    - `installation.tex` - Installation and setup instructions
    - `configuration.tex` - Configuration options and examples
    - `usage.tex` - Usage instructions and examples
    - `api.tex` - API reference documentation
    - `ml_models.tex` - Machine learning models documentation
    - `development.tex` - Development guidelines and processes
    - `security.tex` - Security considerations and best practices
    - `performance.tex` - Performance optimizations and tuning
    - `future_work.tex` - Future development roadmap
    - `conclusion.tex` - Conclusion and summary
  - `figures/` - Figures and diagrams (currently placeholder files)
    - `architecture_diagram.png` - System architecture diagram
    - `ml_architecture.png` - Machine learning subsystem architecture
    - `dashboard_screenshot.png` - Dashboard screenshot
    - `roadmap_timeline.png` - Development roadmap timeline
  - `references/` - Bibliography and references
    - `references.bib` - BibTeX references file in IEEE format

### APA Format (Spanish)

- `latex_apa_es/` - Spanish LaTeX documentation directory (APA format)
  - `main.tex` - Main LaTeX document that includes all sections (in Spanish)
  - `sections/` - Individual section files (in Spanish)
    - `introduccion.tex` - Introduction to the Network Security Suite
    - `arquitectura.tex` - System architecture overview
    - `componentes.tex` - Detailed component descriptions
    - `instalacion.tex` - Installation and setup instructions
    - `configuracion.tex` - Configuration options and examples
    - `uso.tex` - Usage instructions and examples
    - `api.tex` - API reference documentation
    - `modelos_ml.tex` - Machine learning models documentation
    - `desarrollo.tex` - Development guidelines and processes
    - `seguridad.tex` - Security considerations and best practices
    - `rendimiento.tex` - Performance optimizations and tuning
    - `trabajo_futuro.tex` - Future development roadmap
    - `conclusion.tex` - Conclusion and summary
  - `figures/` - Figures and diagrams (shared with English documentation)
  - `references/` - Bibliography and references
    - `referencias.bib` - BibTeX references file in APA format (in Spanish)

## Building the Documentation

To build the documentation, you need LaTeX installed on your system. You can use the provided script to compile all LaTeX files and clean up temporary files:

```bash
# Run the compilation script from the project root to build all documentation
./compile_latex.sh
```

This will compile all LaTeX files in both the `docs/latex` (IEEE English) and `docs/latex_apa_es` (APA Spanish) directories, generate PDF files, and clean up temporary files.

### Script Options

The `compile_latex.sh` script supports the following options:

```bash
Usage: ./compile_latex.sh [options]
Options:
  -h, --help     Show this help message
  -v, --verbose  Enable verbose output
  -k, --keep     Keep temporary files (default: remove them)
  -d, --dir DIR  Specify LaTeX directory (default: all directories)
  -a, --all      Process all LaTeX directories (default behavior)
```

### Building Specific Documentation

If you want to build only a specific documentation format/language, you can use the `-d` option:

```bash
# Build only the IEEE English documentation
./compile_latex.sh -d docs/latex

# Build only the APA Spanish documentation
./compile_latex.sh -d docs/latex_apa_es
```

### Manual Compilation

If you prefer to compile the documentation manually, you can use the following commands:

#### IEEE English Documentation

```bash
# Navigate to the IEEE English latex directory
cd docs/latex

# Build the PDF using pdflatex and bibtex
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

This will generate a PDF file named `main.pdf` in the `docs/latex` directory.

#### APA Spanish Documentation

```bash
# Navigate to the APA Spanish latex directory
cd docs/latex_apa_es

# Build the PDF using pdflatex and bibtex
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

This will generate a PDF file named `main.pdf` in the `docs/latex_apa_es` directory.

## Customizing the Documentation

### Adding Content

#### English IEEE Documentation
To add or modify content for the English IEEE documentation, edit the appropriate section file in the `latex/sections/` directory.

#### Spanish APA Documentation
To add or modify content for the Spanish APA documentation, edit the appropriate section file in the `latex_apa_es/sections/` directory. Make sure to write the content in Spanish.

### Adding Figures

The figures are shared between both documentation formats. Replace the placeholder files in the `latex/figures/` directory with actual images. The following image formats are supported:
- PNG (recommended for screenshots and diagrams)
- PDF (recommended for vector graphics)
- JPEG (use only for photographs)

#### Using Mermaid Diagrams

The project includes Mermaid diagrams for architecture visualization. These are located in:
- `latex/figures/architecture_diagram_mermaid.md` - Comprehensive architecture diagram
- `latex/figures/architecture_diagram_simple.md` - Simplified architecture diagram

To convert these Mermaid diagrams to PNG images for use in LaTeX:

1. Ensure you have Node.js installed
2. Run the conversion script:
   ```bash
   ./convert_mermaid.sh
   ```
3. This will generate `latex/figures/architecture_diagram.png` which is referenced in the LaTeX files

Alternatively, you can use online Mermaid tools to convert the diagrams:
1. Copy the content of the Mermaid file
2. Paste it into an online Mermaid editor like [Mermaid Live Editor](https://mermaid.live/)
3. Export as PNG and save to the appropriate location

### Adding References

#### English IEEE Documentation
Add new references to the `latex/references/references.bib` file following the BibTeX format with IEEE style.

#### Spanish APA Documentation
Add new references to the `latex_apa_es/references/referencias.bib` file following the BibTeX format with APA style. Make sure to translate the reference titles and other fields to Spanish.

## Notes

- The English documentation is structured according to IEEE conference paper format.
- The Spanish documentation is structured according to APA format.
- The placeholder image files need to be replaced with actual images before building the documentation.
- The documentation is designed to be comprehensive and cover all aspects of the Network Security Suite.
- Both documentation formats share the same figures to maintain consistency.

## Future Improvements

- Add actual diagrams and screenshots
- Add more detailed examples
- Add a glossary of terms in both languages
- Add an index for both documentation formats
- Complete all Spanish section files
- Add more language options as needed
