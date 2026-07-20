#!/usr/bin/env bash
#
# mac_stack.sh — MalChela Mac Stack runner
#
# Runs the four Mac Analysis tools — plist_analyzer, codesign_check,
# macho_info, mstrings — against a macOS .app bundle or a raw Mach-O binary.
#
# plist_analyzer and codesign_check accept a .app bundle path directly.
# macho_info and mstrings expect the raw Mach-O binary, so when given a
# bundle, this script resolves the main executable via Info.plist's
# CFBundleExecutable (falling back to the sole file in Contents/MacOS/ if
# extraction fails) before invoking them.
#
# Usage:
#   ./mac_stack.sh                              interactive prompts
#   ./mac_stack.sh /path/to/Thing.app            skip the path prompt
#   ./mac_stack.sh /path/to/Thing.app mycase     skip path + case prompts
#
# Set MALCHELA_DIR to point at a MalChela checkout other than the one this
# script lives in (defaults to this script's own directory).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MALCHELA_DIR="${MALCHELA_DIR:-$SCRIPT_DIR}"
RELEASE_DIR="$MALCHELA_DIR/target/release"

TOOLS=(plist_analyzer codesign_check macho_info mstrings)
RAW_MACHO_TOOLS=(macho_info mstrings)

needs_raw_macho() {
  local tool="$1"
  for t in "${RAW_MACHO_TOOLS[@]}"; do
    [[ "$t" == "$tool" ]] && return 0
  done
  return 1
}

# ── binary check ─────────────────────────────────────────────────────────
missing=()
for tool in "${TOOLS[@]}"; do
  [[ -x "$RELEASE_DIR/$tool" ]] || missing+=("$tool")
done
if [[ ${#missing[@]} -gt 0 ]]; then
  echo "Missing binaries: ${missing[*]}"
  echo "Build them first: cd \"$MALCHELA_DIR\" && ./release.sh"
  exit 1
fi

# ── input ────────────────────────────────────────────────────────────────
TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
  read -rp "Path to .app bundle or Mach-O binary: " TARGET
fi

# Expand a leading ~ and drop a trailing slash
TARGET="${TARGET/#\~/$HOME}"
TARGET="${TARGET%/}"

if [[ ! -e "$TARGET" ]]; then
  echo "Path not found: $TARGET"
  exit 1
fi

CASE_NAME="${2:-}"
if [[ -z "$CASE_NAME" ]]; then
  read -rp "Case name to save reports under (blank to skip): " CASE_NAME
fi

CASE_ARGS=()
if [[ -n "$CASE_NAME" ]]; then
  CASE_ARGS=(--case "$CASE_NAME" -o -t)
fi

# ── bundle resolution (macho_info / mstrings only) ──────────────────────
is_app_bundle() {
  [[ "$1" == *.app && -d "$1" && -d "$1/Contents" ]]
}

resolve_bundle_executable() {
  local bundle="$1"
  local info_plist="$bundle/Contents/Info.plist"
  local macos_dir="$bundle/Contents/MacOS"
  local exec_name=""

  if [[ -f "$info_plist" ]]; then
    exec_name="$(plutil -extract CFBundleExecutable raw -o - "$info_plist" 2>/dev/null)"
  fi

  if [[ -n "$exec_name" && -f "$macos_dir/$exec_name" ]]; then
    printf '%s' "$macos_dir/$exec_name"
    return 0
  fi

  if [[ -d "$macos_dir" ]]; then
    local candidates=("$macos_dir"/*)
    if [[ ${#candidates[@]} -eq 1 && -f "${candidates[0]}" ]]; then
      printf '%s' "${candidates[0]}"
      return 0
    fi
  fi

  return 1
}

RAW_BINARY_TARGET="$TARGET"
if is_app_bundle "$TARGET"; then
  if RAW_BINARY_TARGET="$(resolve_bundle_executable "$TARGET")"; then
    echo "Bundle detected. Main executable resolved to: $RAW_BINARY_TARGET"
  else
    echo "Could not resolve a single main executable inside $TARGET/Contents/MacOS/"
    echo "Pass the binary path directly instead of the bundle."
    exit 1
  fi
fi

# ── run the stack ────────────────────────────────────────────────────────
# cd into MALCHELA_DIR so each tool's own cwd-relative "saved_output/..."
# path lands in the same workspace that MALCHELA_DIR points at, rather than
# wherever this script happened to be invoked from.
cd "$MALCHELA_DIR" || { echo "Could not cd into MALCHELA_DIR: $MALCHELA_DIR"; exit 1; }

run_tool() {
  local tool="$1"
  local path="$2"
  echo ""
  echo "════════════════════════════════════════════════════════════"
  echo "  $tool"
  echo "════════════════════════════════════════════════════════════"
  "$RELEASE_DIR/$tool" "$path" "${CASE_ARGS[@]}"
}

for tool in "${TOOLS[@]}"; do
  if needs_raw_macho "$tool"; then
    run_tool "$tool" "$RAW_BINARY_TARGET"
  else
    run_tool "$tool" "$TARGET"
  fi
done

echo ""
echo "Mac Stack complete."
if [[ -n "$CASE_NAME" ]]; then
  echo "Reports saved under: $MALCHELA_DIR/saved_output/cases/$CASE_NAME/"
fi
