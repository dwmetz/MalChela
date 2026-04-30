#!/bin/bash
# update_malchela.sh — Copy latest PWA/server files and restart

echo "🦀 MalChela Update Script"
echo "─────────────────────────────────────"

echo "📋 Copying malchela_pwa.html..."
cp /Users/dmetz/Desktop/malchela_pwa.html /Users/dmetz/tools/MalChela/server/malchela_pwa.html
echo "   ✓ malchela_pwa.html copied"

echo "📋 Copying server_config.yaml..."
cp /Users/dmetz/Desktop/server_config.yaml /Users/dmetz/tools/MalChela/server/server_config.yaml
echo "   ✓server_config.yaml copied"

echo "📋 Copying malchela_server.py..."
cp /Users/dmetz/Desktop/malchela_server.py /Users/dmetz/tools/MalChela/server/malchela_server.py
echo "   ✓ malchela_server.py copied"

echo "─────────────────────────────────────"
echo "🚀 Starting server..."
echo ""

cd /Users/dmetz/tools/MalChela/server
source .venv/bin/activate 2>/dev/null || true
python3 malchela_server.py
