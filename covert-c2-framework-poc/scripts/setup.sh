#!/bin/bash
set -e

echo "[Setup] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq gcc libcurl4-openssl-dev libssl-dev bind9-utils 2>/dev/null || {
    echo "[Setup] Some system packages not available (non-Debian system?) - continuing..."
}

echo "[Setup] Creating Python virtual environment..."
python3 -m venv .venv || python -m venv .venv
source .venv/bin/activate

echo "[Setup] Installing Python dependencies..."
pip install -r requirements.txt

echo "[Setup] Compiling C agent..."
cd src/modules/agent_handler
make clean 2>/dev/null || true
make
cd ../../..

echo ""
echo "[Setup] Complete!"
echo "  - Activate environment: source .venv/bin/activate"
echo "  - Run C2 server:        python src/core/c2_server.py --secret-key YOUR_KEY_32_BYTES"
echo "  - Run Python agent:     python src/core/c2_agent.py --server-url http://localhost:8080 --secret-key YOUR_KEY_32_BYTES"
echo "  - Run C agent binary:   ./src/modules/agent_handler/agent"
echo "  - Run tests:            python -m pytest tests/ -v"
