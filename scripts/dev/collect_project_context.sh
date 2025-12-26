#!/bin/bash

# Script to collect project files for AI context
# Usage: ./collect_project_context.sh [directory] [output_file]

# Default values
SEARCH_DIR="${1:-.}"
OUTPUT_FILE="${2:-project_context.txt}"

# File extensions to search for
EXTENSIONS=("*.py" "*.sh" "*.yml" "*.yaml")

# Clear or create the output file
> "$OUTPUT_FILE"

echo "Collecting project context from: $SEARCH_DIR"
echo "Output file: $OUTPUT_FILE"
echo ""

# Add header to output file
cat << EOF > "$OUTPUT_FILE"
================================================================================
PROJECT CONTEXT DUMP
Generated on: $(date)
Source directory: $(realpath "$SEARCH_DIR")
================================================================================

EOF

# Counter for files processed
file_count=0

# Function to process each file
process_file() {
    local file="$1"
    local relative_path="${file#$SEARCH_DIR/}"

    # Add file separator and header
    cat << EOF >> "$OUTPUT_FILE"

################################################################################
# FILE: $relative_path
# Full path: $(realpath "$file")
# Size: $(wc -c < "$file") bytes
# Lines: $(wc -l < "$file")
################################################################################

EOF

    # Add file contents
    cat "$file" >> "$OUTPUT_FILE"

    # Add footer separator
    cat << EOF >> "$OUTPUT_FILE"

################################################################################
# END OF FILE: $relative_path
################################################################################

EOF

    ((file_count++))
    echo "  ✓ Added: $relative_path"
}

# Search for each file extension
for ext in "${EXTENSIONS[@]}"; do
    echo "Searching for $ext files..."
    while IFS= read -r -d '' file; do
        process_file "$file"
    done < <(find "$SEARCH_DIR" -type f -name "$ext" -print0 2>/dev/null | sort -z)
done

# Add summary footer
cat << EOF >> "$OUTPUT_FILE"

================================================================================
SUMMARY
================================================================================
Total files processed: $file_count
Generated on: $(date)
================================================================================
EOF

echo ""
echo "Done! Processed $file_count files."
echo "Output saved to: $(realpath "$OUTPUT_FILE")"
