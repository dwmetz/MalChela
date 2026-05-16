#!/usr/bin/env bash
#
# audit_yara_rules.sh - shell mirror of yara-backend's src/audit.rs
#
# Walks a directory of .yar / .yara files and refuses any rule that
# imports a module yara-x does not implement. Intended for use as a
# CI pre-build hook so unsupported rules are caught before cargo
# tries to compile them.
#
# Matches the Rust audit's parsing semantics:
#   * `/* ... */` block comments are stripped before scanning so a
#     commented-out import is not flagged.
#   * `//` line comments are stripped before scanning.
#   * Whitespace between the `import` keyword and the module string
#     can include newlines / carriage returns (yara-x is whitespace
#     insensitive between tokens, so this audit must be too).
#
# Limitation: this script does not decode `\xHH` style escapes inside
# import strings. Rules like `import "ma\x67ic"` will slip through
# the shell audit but are caught by the Rust audit at compile time,
# so the result is still correct. The Rust audit (src/audit.rs) is
# authoritative for tricky cases; this script is the fast first pass.
#
# Exit codes:
#   0 - clean (every rule uses only supported imports)
#   1 - one or more rules use a forbidden import
#   2 - usage error (directory does not exist or argument missing)
#
# Usage:
#   tools/audit_yara_rules.sh [<rules_dir>]
#
# If <rules_dir> is omitted it defaults to ./yara_rules

set -eu

# Modules yara-x does not implement. Keep this list in sync with
# FORBIDDEN_IMPORTS in src/audit.rs.
FORBIDDEN_MODULES=(
    "magic"
)

RULES_DIR="${1:-yara_rules}"

if [ ! -d "$RULES_DIR" ]; then
    echo "audit_yara_rules: directory not found: $RULES_DIR" >&2
    exit 2
fi

# Strip /* ... */ block comments AND // line comments, then collapse all
# whitespace runs (including newlines) to a single space so the grep
# pattern matches multi-line `import\n"magic"` the same way yara-x does.
# Implemented in awk so the script stays portable across macOS / Linux
# without GNU sed extensions.
normalise_source() {
    awk '
        BEGIN { in_block = 0 }
        {
            line = $0
            out = ""
            i = 1
            n = length(line)
            while (i <= n) {
                if (in_block) {
                    rest = substr(line, i)
                    p = index(rest, "*/")
                    if (p > 0) {
                        i = i + p + 1
                        in_block = 0
                    } else {
                        i = n + 1
                    }
                } else {
                    rest = substr(line, i)
                    p = index(rest, "/*")
                    lp = index(rest, "//")
                    if (lp > 0 && (p == 0 || lp < p)) {
                        out = out substr(line, i, lp - 1)
                        i = n + 1
                    } else if (p > 0) {
                        out = out substr(line, i, p - 1)
                        i = i + p + 1
                        in_block = 1
                    } else {
                        out = out substr(line, i)
                        i = n + 1
                    }
                }
            }
            print out
        }
    ' "$1" | tr '\n\r\t' '   ' | tr -s ' '
}

hits=0
while IFS= read -r -d '' f; do
    cleaned=$(normalise_source "$f")
    # Match `import` at a word boundary that is NOT inside a string literal
    # (preceded by `"` or `'`). The Rust audit handles string literal scoping
    # precisely; this is the shell first pass.
    for forbidden in "${FORBIDDEN_MODULES[@]}"; do
        if printf '%s\n' "$cleaned" \
            | grep -qE "(^|[^A-Za-z0-9_\"'])import +[\"']${forbidden}[\"']"; then
            echo "audit_yara_rules: $f imports unsupported module \`$forbidden\`" >&2
            hits=$((hits + 1))
        fi
    done
done < <(find "$RULES_DIR" -type f \( -iname '*.yar' -o -iname '*.yara' \) -print0)

if [ "$hits" -gt 0 ]; then
    echo "audit_yara_rules: $hits rule file(s) use unsupported imports" >&2
    exit 1
fi

echo "audit_yara_rules: ok (every rule file under $RULES_DIR uses supported imports only)"
exit 0
