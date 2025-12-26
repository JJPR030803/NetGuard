#!/bin/bash
# Script para reorganizar estructura de tests - FASE 1
# Este script mueve tests existentes a la nueva estructura

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TESTS_DIR="$PROJECT_ROOT/tests"
echo "My script is in: $SCRIPT_DIR"
echo "My project root is in: $PROJECT_ROOT"
echo "My tests are in: $TESTS_DIR"

echo "=========================================="
echo "NetGuard - Test Reorganization Script"
echo "=========================================="
echo ""
echo "Project Root: $PROJECT_ROOT"
echo "Tests Dir: $TESTS_DIR"
echo ""

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Función para logging
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar que estamos en el directorio correcto
if [ ! -d "$TESTS_DIR" ]; then
    log_error "Tests directory not found: $TESTS_DIR"
    exit 1
fi

log_info "Backing up current tests structure..."
if [ -d "$TESTS_DIR.backup" ]; then
    log_warn "Backup already exists. Removing old backup..."
    rm -rf "$TESTS_DIR.backup"
fi
cp -r "$TESTS_DIR" "$TESTS_DIR.backup"
log_info "✓ Backup created: $TESTS_DIR.backup"
echo ""

# Crear nueva estructura de directorios
log_info "Creating new test structure..."

# Directorios principales
mkdir -p "$TESTS_DIR/unit/capture"
mkdir -p "$TESTS_DIR/unit/preprocessing/analyzers/fixtures"
mkdir -p "$TESTS_DIR/unit/core"
mkdir -p "$TESTS_DIR/unit/workflows"
mkdir -p "$TESTS_DIR/unit/models"
mkdir -p "$TESTS_DIR/integration"
mkdir -p "$TESTS_DIR/e2e"
mkdir -p "$TESTS_DIR/performance"
mkdir -p "$TESTS_DIR/fixtures/sample_data"

log_info "✓ Directory structure created"
echo ""

# Crear __init__.py en todos los directorios
log_info "Creating __init__.py files..."
find "$TESTS_DIR" -type d -exec touch {}/__init__.py \;
log_info "✓ __init__.py files created"
echo ""

# Mover tests existentes
log_info "Moving existing tests to new structure..."

# Unit tests (anteriormente en tests/unit/)
if [ -d "$TESTS_DIR/unit.backup" ]; then
    log_warn "Found old unit/ directory, will be processed manually"
fi

# ML tests -> preprocessing tests
if [ -d "$TESTS_DIR/ml" ]; then
    log_info "Moving ML tests to preprocessing/..."

    # Mover tests de analyzers
    if [ -d "$TESTS_DIR/ml/analyzers" ]; then
        for file in "$TESTS_DIR/ml/analyzers"/test_*.py; do
            if [ -f "$file" ]; then
                filename=$(basename "$file")
                mv "$file" "$TESTS_DIR/unit/preprocessing/analyzers/"
                log_info "  Moved: $filename"
            fi
        done
    fi

    # Mover otros tests de ml/
    for file in "$TESTS_DIR/ml"/test_*.py; do
        if [ -f "$file" ]; then
            filename=$(basename "$file")
            case "$filename" in
                test_parquet_analysis.py)
                    mv "$file" "$TESTS_DIR/unit/workflows/"
                    log_info "  Moved: $filename → workflows/"
                    ;;
                test_workflows.py)
                    mv "$file" "$TESTS_DIR/unit/workflows/"
                    log_info "  Moved: $filename → workflows/"
                    ;;
                test_utils.py)
                    mv "$file" "$TESTS_DIR/unit/preprocessing/"
                    log_info "  Moved: $filename → preprocessing/"
                    ;;
                test_errors.py)
                    mv "$file" "$TESTS_DIR/unit/core/"
                    log_info "  Moved: $filename → core/"
                    ;;
                test_preprocessing_config.py)
                    mv "$file" "$TESTS_DIR/unit/workflows/"
                    log_info "  Moved: $filename → workflows/"
                    ;;
                *)
                    log_warn "  Unknown test file: $filename (keeping in ml/)"
                    ;;
            esac
        fi
    done
fi

# Unit tests originales
if [ -d "$TESTS_DIR.backup/unit" ]; then
    log_info "Processing original unit tests..."
    for file in "$TESTS_DIR.backup/unit"/test_*.py; do
        if [ -f "$file" ]; then
            filename=$(basename "$file")
            case "$filename" in
                test_packet_capture.py)
                    cp "$file" "$TESTS_DIR/unit/capture/"
                    log_info "  Moved: $filename → capture/"
                    ;;
                test_packet_methods.py)
                    cp "$file" "$TESTS_DIR/unit/capture/"
                    log_info "  Moved: $filename → capture/"
                    ;;
                test_sniffer_exceptions.py)
                    cp "$file" "$TESTS_DIR/unit/core/"
                    log_info "  Moved: $filename → core/"
                    ;;
                *)
                    log_warn "  Unknown test: $filename"
                    ;;
            esac
        fi
    done
fi

# Integration tests
if [ -d "$TESTS_DIR.backup/integration" ]; then
    log_info "Moving integration tests..."
    if [ "$(ls -A $TESTS_DIR.backup/integration)" ]; then
        cp -r "$TESTS_DIR.backup/integration"/* "$TESTS_DIR/integration/" 2>/dev/null || true
        log_info "  ✓ Integration tests moved"
    else
        log_warn "  Integration directory is empty"
    fi
fi

# E2E tests
if [ -d "$TESTS_DIR.backup/e2e" ]; then
    log_info "Moving e2e tests..."
    if [ "$(ls -A $TESTS_DIR.backup/e2e)" ]; then
        cp -r "$TESTS_DIR.backup/e2e"/* "$TESTS_DIR/e2e/" 2>/dev/null || true
        log_info "  ✓ E2E tests moved"
    else
        log_warn "  E2E directory is empty"
    fi
fi

# Test en raíz
if [ -f "$TESTS_DIR.backup/test_sniffer_config_docs.py" ]; then
    log_info "Moving root test file..."
    cp "$TESTS_DIR.backup/test_sniffer_config_docs.py" "$TESTS_DIR/unit/core/"
    log_info "  ✓ test_sniffer_config_docs.py → core/"
fi

echo ""
log_info "✓ Tests moved to new structure"
echo ""

# Limpiar directorios viejos vacíos
log_info "Cleaning up old structure..."
rm -rf "$TESTS_DIR/ml" 2>/dev/null || true
log_info "✓ Cleanup complete"
echo ""

# Resumen
echo "=========================================="
echo "Summary"
echo "=========================================="
echo ""
log_info "New test structure created at: $TESTS_DIR"
log_info "Backup of old structure at: $TESTS_DIR.backup"
echo ""
log_info "Next steps:"
echo "  1. Review moved tests in new locations"
echo "  2. Install test dependencies: make install-dev"
echo "  3. Run tests: make test-unit"
echo "  4. If everything works, remove backup: rm -rf $TESTS_DIR.backup"
echo ""
log_warn "Note: Some tests may need import path updates"
echo ""
echo "=========================================="