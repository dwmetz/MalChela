
echo "Defaulting to parallel build."
echo "To run in throttled mode, run release.sh"

BUILD_CMD="cargo build --release -p"
for tool in malchela fileminer mstrings hashit hashcheck mzcount mzhash xmzhash combine_yara strings_to_yara malhash nsrlquery extract_samples about fileanalyzer MITRE_lookup MalChelaGUI; do
  echo "Building release for $tool..."
  $BUILD_CMD "$tool"
done
