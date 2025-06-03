#!/bin/bash

# Get the directory where the script is located
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

# Define exact paths for your system
VENV_PATH="/home/batman/.cache/pypoetry/virtualenvs/network-security-suite-Sgl7fm98-py3.12"
PYTHON_EXECUTABLE="$VENV_PATH/bin/python"

# Verify the virtual environment exists
if [ ! -f "$PYTHON_EXECUTABLE" ]; then
    echo "Python executable not found at $PYTHON_EXECUTABLE"
    echo "Please run 'poetry install' first."
    exit 1
fi

# Run the Python script with sudo while preserving the environment
sudo \
    PYTHONPATH="$PROJECT_ROOT" \
    "$PYTHON_EXECUTABLE" \
    "$PROJECT_ROOT/src/network_security_suite/sniffer/testing.py"