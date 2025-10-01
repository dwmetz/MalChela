
echo "Choose build mode:"
echo "1) Default parallel build (fast, uses all CPU cores)"
echo "2) Throttled build (-j 1, for low-powered systems like Raspberry Pi)"
read -p "Enter 1 or 2 [1]: " build_mode

if [[ "$build_mode" == "2" ]]; then
  BUILD_CMD="cargo build -j 1 --release -p"
else
  BUILD_CMD="cargo build --release -p"
fi

for tool in malchela fileminer mstrings hashit hashcheck mzcount mzhash xmzhash combine_yara strings_to_yara malhash nsrlquery extract_samples about fileanalyzer MITRE_lookup MalChelaGUI; do
  echo "Building release for $tool..."
  $BUILD_CMD "$tool"
done
