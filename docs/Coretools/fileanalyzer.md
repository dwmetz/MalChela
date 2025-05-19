FileAnalyzer performs deep static analysis on a single file. It extracts hashes, entropy, file type metadata, YARA rule matches, NSRL validation, and — for PE files — rich header details including import/export tables, compile timestamp, and section flags. Ideal for triaging unknown executables or confirming known file traits.

<figure>
  <img src="/images/fileanalyzer.png" alt="File Analyzer">
  <figcaption><strong>Figure 1:</strong> File Analyzer</figcaption>
</figure>

- YARA rules for `fileanalyzer` are stored in the `yara_rules` folder in the workspace. You can modify or add rules here.
