#!/bin/bash
# MalChela Server Setup
# Interactive script to configure server_config.yaml

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="$SCRIPT_DIR/server_config.yaml"

# Colors
CY='\033[0;36m'  # cyan
OR='\033[0;33m'  # orange
GR='\033[0;32m'  # green
RD='\033[0;31m'  # red
DM='\033[2m'     # dim
NC='\033[0m'     # reset

echo ""
echo -e "${OR}  ╔══════════════════════════════════════╗${NC}"
echo -e "${OR}  ║   MalChela Server Setup  v4.0        ║${NC}"
echo -e "${OR}  ║   Baker Street Forensics             ║${NC}"
echo -e "${OR}  ╚══════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: MalChela root ────────────────────────────────────────────────────
echo -e "${CY}Step 1: MalChela root directory${NC}"
echo -e "${DM}  This is the folder containing Cargo.toml and target/release/${NC}"
echo ""

# Try to auto-detect
DETECTED_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
if [ -f "$DETECTED_ROOT/Cargo.toml" ]; then
    echo -e "  Auto-detected: ${GR}$DETECTED_ROOT${NC}"
    read -p "  Use this? [Y/n]: " CONFIRM
    if [[ "$CONFIRM" =~ ^[Nn] ]]; then
        read -p "  Enter MalChela root path: " MALCHELA_ROOT
    else
        MALCHELA_ROOT="$DETECTED_ROOT"
    fi
else
    read -p "  Enter MalChela root path: " MALCHELA_ROOT
fi

# Validate
if [ ! -d "$MALCHELA_ROOT" ]; then
    echo -e "  ${RD}Directory not found: $MALCHELA_ROOT${NC}"
    exit 1
fi
echo -e "  ${GR}✓ $MALCHELA_ROOT${NC}"
echo ""

# ── Step 2: Browser root ─────────────────────────────────────────────────────
echo -e "${CY}Step 2: Browser root (file browse jail)${NC}"
echo -e "${DM}  The file browser will only show files within this directory.${NC}"
echo -e "${DM}  Typically your home directory.${NC}"
echo ""

DETECTED_HOME="$HOME"
echo -e "  Detected home: ${GR}$DETECTED_HOME${NC}"
read -p "  Use this? [Y/n]: " CONFIRM
if [[ "$CONFIRM" =~ ^[Nn] ]]; then
    read -p "  Enter browser root path: " BROWSER_ROOT
else
    BROWSER_ROOT="$DETECTED_HOME"
fi
echo -e "  ${GR}✓ $BROWSER_ROOT${NC}"
echo ""

# ── Step 3: Port ─────────────────────────────────────────────────────────────
echo -e "${CY}Step 3: Server port${NC}"
echo -e "${DM}  Default is 8675. Change if running multiple instances.${NC}"
echo ""
read -p "  Port [8675]: " PORT
PORT="${PORT:-8675}"
echo -e "  ${GR}✓ Port $PORT${NC}"
echo ""

# ── Step 4: Extra tool paths ──────────────────────────────────────────────────
echo -e "${CY}Step 4: Additional tool paths${NC}"
echo -e "${DM}  Directories to search for external tools (tshark, vol3, yr, capa, etc.)${NC}"
echo -e "${DM}  These are added to PATH when locating binaries.${NC}"
echo -e "${DM}  Common paths: /usr/local/bin  /usr/bin  ~/.local/bin${NC}"
echo ""

TOOL_PATHS=()

# Auto-detect common tool locations
for p in "/usr/local/bin" "$HOME/.local/bin" "/opt/homebrew/bin"; do
    if [ -d "$p" ]; then
        TOOL_PATHS+=("$p")
    fi
done

if [ ${#TOOL_PATHS[@]} -gt 0 ]; then
    echo -e "  Auto-detected:"
    for p in "${TOOL_PATHS[@]}"; do
        echo -e "    ${GR}$p${NC}"
    done
    read -p "  Use these? [Y/n]: " CONFIRM
    if [[ "$CONFIRM" =~ ^[Nn] ]]; then
        TOOL_PATHS=()
    fi
fi

echo -e "  Add more paths? (press Enter to skip each)"
while true; do
    read -p "  Additional path (or Enter to finish): " EXTRA_PATH
    [ -z "$EXTRA_PATH" ] && break
    if [ -d "$EXTRA_PATH" ]; then
        TOOL_PATHS+=("$EXTRA_PATH")
        echo -e "  ${GR}✓ Added $EXTRA_PATH${NC}"
    else
        echo -e "  ${RD}Directory not found, skipping${NC}"
    fi
done
echo ""

# ── Write config ──────────────────────────────────────────────────────────────
echo -e "${CY}Writing server_config.yaml...${NC}"

# Build tool_paths yaml block
TOOL_PATHS_YAML=""
for p in "${TOOL_PATHS[@]}"; do
    TOOL_PATHS_YAML="$TOOL_PATHS_YAML  - $p\n"
done
[ -z "$TOOL_PATHS_YAML" ] && TOOL_PATHS_YAML="  []\n"

# Backup existing config
if [ -f "$CONFIG" ]; then
    cp "$CONFIG" "${CONFIG}.bak"
    echo -e "  ${DM}Backed up existing config to server_config.yaml.bak${NC}"
fi

cat > "$CONFIG" << EOF
malchela_root: $MALCHELA_ROOT
browser_root:  $BROWSER_ROOT
port: $PORT
tool_paths:
$(printf "$TOOL_PATHS_YAML")
EOF

echo -e "  ${GR}✓ Written to $CONFIG${NC}"
echo ""

chmod +x "$SCRIPT_DIR/start_server.sh"

# ── Summary ───────────────────────────────────────────────────────────────────
echo -e "${OR}  Configuration complete:${NC}"
echo -e "  MalChela root : ${CY}$MALCHELA_ROOT${NC}"
echo -e "  Browser root  : ${CY}$BROWSER_ROOT${NC}"
echo -e "  Port          : ${CY}$PORT${NC}"
echo -e "  Tool paths    : ${CY}${TOOL_PATHS[*]:-none}${NC}"
echo ""

# ── Offer to start ────────────────────────────────────────────────────────────
read -p "  Start the server now? [Y/n]: " START
if [[ ! "$START" =~ ^[Nn] ]]; then
    echo ""
    "$SCRIPT_DIR/start_server.sh"
fi
