for tool in malchela fileminer mstrings hashit hashcheck mzcount mzhash xmzhash combine_yara strings_to_yara malhash nsrlquery extract_samples about fileanalyzer MITRE_lookup MalChelaGUI; do
  echo "Building release for $tool..."
  cargo build --release -p "$tool"
done

#  For Raspberry Pi and lower powered devices:
#  
#  for tool in malchela fileminer mstrings hashit hashcheck mzcount mzhash xmzhash combine_yara strings_to_yara malhash nsrlquery extract_samples about fileanal$
#  echo "Building release for $tool..."
#  cargo build -j 1 --release -p "$tool"
#  done
