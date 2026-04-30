#!/bin/bash
# MalChela Server Launcher
# Activates venv and starts the Flask server

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/venv"

# Create venv if it doesn't exist
if [ ! -d "$VENV" ]; then
    echo "[MalChela] Creating virtual environment..."
    python3 -m venv "$VENV"
    echo "[MalChela] Installing dependencies..."
    "$VENV/bin/pip" install flask flask-cors pyyaml --quiet
    echo "[MalChela] Dependencies installed."
fi

echo "[MalChela] Starting server..."
exec "$VENV/bin/python3" "$SCRIPT_DIR/malchela_server.py" "$@"
