#!/bin/bash

# Get the directory where the script is located
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

# Define exact paths for your system
VENV_PATH="/home/batman/.cache/pypoetry/virtualenvs/network-security-suite-Sgl7fm98-py3.12"
PYTHON_EXECUTABLE="$VENV_PATH/bin/python"

# Define logs directory
LOGS_DIR="$PROJECT_ROOT/logs"

# Check if logs directory exists, if not create it with proper permissions
if [ ! -d "$LOGS_DIR" ]; then
    echo "Creating logs directory at $LOGS_DIR"
    sudo mkdir -p "$LOGS_DIR" || {
        echo "Failed to create logs directory" >&2
        exit 1
    }
    sudo chmod 777 "$LOGS_DIR" || {
        echo "Failed to set permissions on logs directory" >&2
        exit 1
    }
else
    echo "Logs directory already exists at $LOGS_DIR"
fi

# Verify the virtual environment exists
if [ ! -f "$PYTHON_EXECUTABLE" ]; then
    echo "Python executable not found at $PYTHON_EXECUTABLE"
    echo "Please run 'poetry install' first."
    exit 1
fi

# Run the Python script with sudo while preserving the environment
sudo \
    PYTHONPATH="$PROJECT_ROOT" \
    "$PYTHON_EXECUTABLE" -B \
    "$PROJECT_ROOT/src/network_security_suite/main.py"

# Fix permissions for any newly created log files
sudo chmod -R 777 "$LOGS_DIR"