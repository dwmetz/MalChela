% echo "─────────────────────────────────────"
echo "🚀 Starting server..."
echo ""

cd /Users/dmetz/tools/MalChela/server
source .venv/bin/activate 2>/dev/null || true
python3 malchela_server.py
