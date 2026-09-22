#!/bin/bash
# Run script for the AI Database Assistant (macOS / Linux)

echo "=== Starting AI Database Assistant ==="
echo ""

# This script lives in ./scripts but operates on the project root (parent dir),
# so cd there regardless of where it is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "Error: Virtual environment not found."
    echo "Create one with: python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi

# Activate virtual environment
source .venv/bin/activate

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "Error: .env file not found"
    echo "Copy .env.example to .env and fill in your values"
    exit 1
fi

# Check if api-admin.p12 exists
if [ ! -f "certs/api-admin.p12" ]; then
    echo "Warning: certs/api-admin.p12 not found"
    echo "Certificate issuance from EJBCA will fail"
    echo "See certs/README.md for instructions"
fi

# Run Streamlit app
echo "Starting Streamlit app..."
echo "Access the app at: http://localhost:8501"
echo ""
python -m streamlit run streamlit_app.py
