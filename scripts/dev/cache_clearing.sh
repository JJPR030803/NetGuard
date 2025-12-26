find . -name "*.pyc" -delete
find . -type d -name "__pycache__" -exec rm -r {} +
