#!/bin/bash

# Script to compile LaTeX files and clean up temporary files
# Author: Network Security Team
# Date: May 28, 2023

# Set the base directories for LaTeX files
LATEX_DIRS=("docs/latex" "docs/latex_apa_es")
LATEX_DIR="docs/latex"  # Default directory for backward compatibility

# Function to display script usage
function show_usage {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -v, --verbose  Enable verbose output"
    echo "  -k, --keep     Keep temporary files (default: remove them)"
    echo "  -d, --dir DIR  Specify LaTeX directory (default: all directories in ${LATEX_DIRS[*]})"
    echo "  -a, --all      Process all LaTeX directories (default behavior)"
}

# Parse command line arguments
VERBOSE=0
KEEP_TEMP=0
PROCESS_ALL=1  # Default to processing all directories

# Initialize lists for tracking successful and failed compilations
SUCCESSFUL_PDFS=""
FAILED_COMPILATIONS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -k|--keep)
            KEEP_TEMP=1
            shift
            ;;
        -d|--dir)
            LATEX_DIR="$2"
            PROCESS_ALL=0  # Process only the specified directory
            shift 2
            ;;
        -a|--all)
            PROCESS_ALL=1  # Process all directories
            shift
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Function to process a single LaTeX directory
function process_latex_directory {
    local DIR="$1"

    # Check if the LaTeX directory exists
    if [ ! -d "$DIR" ]; then
        echo "Error: LaTeX directory '$DIR' does not exist."
        return 1
    fi

    echo "Processing LaTeX directory: $DIR"

    # Find all .tex files in the LaTeX directory
    local TEX_FILES=$(find "$DIR" -name "*.tex" -type f -not -path "*/\.*" | sort)

    # Check if any .tex files were found
    if [ -z "$TEX_FILES" ]; then
        echo "No .tex files found in '$DIR'."
        return 1
    fi

    # Count the number of .tex files
    local NUM_FILES=$(echo "$TEX_FILES" | wc -l)
    echo "Found $NUM_FILES .tex files to process in $DIR."

    # Process each .tex file
    for TEX_FILE in $TEX_FILES; do
        # Get the directory and filename without extension
        local FILE_DIR=$(dirname "$TEX_FILE")
        local FILENAME=$(basename "$TEX_FILE" .tex)

        # Skip files that are included in other files (typically section files)
        # Only process files that have \documentclass
        if ! grep -q "\\documentclass" "$TEX_FILE"; then
            [ $VERBOSE -eq 1 ] && echo "Skipping $TEX_FILE (not a main document)"
            continue
        fi

        echo "Compiling $TEX_FILE..."

        # Change to the directory containing the .tex file
        cd "$FILE_DIR"

        # Create log directory if it doesn't exist
        local LOG_DIR="$FILE_DIR/logs"
        mkdir -p "$LOG_DIR"

        # Run pdflatex (1st pass)
        [ $VERBOSE -eq 1 ] && echo "Running pdflatex (1st pass)..."
        pdflatex -interaction=nonstopmode "$FILENAME.tex" > "$LOG_DIR/$FILENAME.compile.log" 2>&1
        local PDFLATEX_STATUS=$?

        # Run bibtex if there are citations
        if grep -q "\\bibliography" "$FILENAME.tex" || grep -q "\\cite" "$FILENAME.tex"; then
            [ $VERBOSE -eq 1 ] && echo "Running bibtex..."
            bibtex "$FILENAME" >> "$LOG_DIR/$FILENAME.compile.log" 2>&1
            local BIBTEX_STATUS=$?
            if [ $BIBTEX_STATUS -ne 0 ] && [ $VERBOSE -eq 1 ]; then
                echo "Warning: BibTeX returned non-zero exit code. Check $LOG_DIR/$FILENAME.compile.log for details."
            fi
        fi

        # Run pdflatex (2nd pass)
        [ $VERBOSE -eq 1 ] && echo "Running pdflatex (2nd pass)..."
        pdflatex -interaction=nonstopmode "$FILENAME.tex" >> "$LOG_DIR/$FILENAME.compile.log" 2>&1

        # Run pdflatex (3rd pass)
        [ $VERBOSE -eq 1 ] && echo "Running pdflatex (3rd pass)..."
        pdflatex -interaction=nonstopmode "$FILENAME.tex" >> "$LOG_DIR/$FILENAME.compile.log" 2>&1
        local FINAL_STATUS=$?

        # Check if PDF was generated
        if [ -f "$FILENAME.pdf" ]; then
            echo "Successfully generated $FILENAME.pdf"
            # Add to successful compilations list
            SUCCESSFUL_PDFS="$SUCCESSFUL_PDFS $FILE_DIR/$FILENAME.pdf"
        else
            echo "Error: Failed to generate $FILENAME.pdf"
            if [ $VERBOSE -eq 1 ]; then
                echo "Check the log file for details: $LOG_DIR/$FILENAME.compile.log"
                # Show the last few lines of the log file to help diagnose the issue
                echo "Last 10 lines of the log file:"
                tail -n 10 "$LOG_DIR/$FILENAME.compile.log"
            fi
            # Add to failed compilations list
            FAILED_COMPILATIONS="$FAILED_COMPILATIONS $TEX_FILE"
        fi

        # Clean up temporary files if not keeping them
        if [ $KEEP_TEMP -eq 0 ]; then
            [ $VERBOSE -eq 1 ] && echo "Cleaning up temporary files..."
            # List of extensions to remove
            local TEMP_EXTS=("aux" "log" "out" "toc" "lof" "lot" "bbl" "blg" "synctex.gz" "nav" "snm" "vrb" "fls" "fdb_latexmk" "run.xml" "bcf" "idx" "ilg" "ind" "dvi" "ps")

            for EXT in "${TEMP_EXTS[@]}"; do
                if [ -f "$FILENAME.$EXT" ]; then
                    rm "$FILENAME.$EXT"
                    [ $VERBOSE -eq 1 ] && echo "Removed $FILENAME.$EXT"
                fi
            done
        fi

        # Return to the original directory
        cd - > /dev/null
    done

    return 0
}

# Process LaTeX directories
if [ $PROCESS_ALL -eq 1 ]; then
    # Process all LaTeX directories
    for DIR in "${LATEX_DIRS[@]}"; do
        process_latex_directory "$DIR"
    done
else
    # Process only the specified directory
    process_latex_directory "$LATEX_DIR"
fi

# Print summary of compilation results
echo "LaTeX compilation summary:"
echo "------------------------"

# Count successful compilations
SUCCESSFUL_COUNT=$(echo "$SUCCESSFUL_PDFS" | wc -w)
if [ $SUCCESSFUL_COUNT -gt 0 ]; then
    echo "Successfully generated $SUCCESSFUL_COUNT PDF files:"
    for PDF in $SUCCESSFUL_PDFS; do
        echo "  - $PDF"
    done
else
    echo "No PDF files were successfully generated."
fi

# Count failed compilations
FAILED_COUNT=$(echo "$FAILED_COMPILATIONS" | wc -w)
if [ $FAILED_COUNT -gt 0 ]; then
    echo "Failed to generate $FAILED_COUNT PDF files:"
    for TEX in $FAILED_COMPILATIONS; do
        echo "  - $TEX"
    done
    echo "Check the log files in the logs directory for details."
    exit 1
else
    echo "All LaTeX files were compiled successfully."
fi

echo "LaTeX compilation complete. All temporary files have been cleaned up."
