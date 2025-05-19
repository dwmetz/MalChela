#!/bin/bash
echo "[INFO] Starting Volatility at $(date)"
echo "Running: \"/Users/dmetz/.local/bin/vol3\" "-f" "/Users/dmetz/Desktop/Dumps/RAMDump-NORADCO-WS02-20230906-104014-WinVer10.0.16299.64.dmp" "windows.psscan""
/Users/dmetz/.local/bin/vol3 "-f" "/Users/dmetz/Desktop/Dumps/RAMDump-NORADCO-WS02-20230906-104014-WinVer10.0.16299.64.dmp" "windows.psscan"
echo
read -p "Press Enter to close..."
