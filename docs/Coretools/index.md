<figure>
  <img src="/images/malchela_screenshot.png" alt="MalChela GUI">
  <figcaption><strong>Figure 1:</strong> MalChela GUI</figcaption>
</figure>

<figure>
  <img src="/images/malchela_cli_screenshot.png" alt="MalChela CLI">
  <figcaption><strong>Figure 2:</strong> MalChela CLI</figcaption>
</figure>

<h2 style="text-align: center;">MalChela Core Tools</h2>
<p style="text-align: center;">
  These built-in programs provide fast, flexible functionality for forensics and malware triage.
</p>

<table style="margin-left: 10%; width: 100%;">
  <thead>
    <tr>
      <th>Program</th>
      <th>Function</th>
    </tr>
  </thead>
  <tbody>
    <tr><td>Combine YARA</td><td>Point it at a directory of YARA files and it will output one combined rule</td></tr>
    <tr><td>Extract Samples</td><td>Point it at a directory of password protected malware files to extract all</td></tr>
    <tr><td>File Analyzer</td><td>Get the hash, entropy, packing, PE info, YARA and VT match status for a file</td></tr>
    <tr><td>Hash It</td><td>Point it to a file and get the MD5, SHA1 and SHA256 hash</td></tr>
    <tr><td>Mismatch Miner</td><td>Hunts for exes disguised as other formats</td></tr>
    <tr><td>mStrings</td><td>Analyzes files with Sigma rules (YAML), extracts strings, matches ReGex</td></tr>
    <tr><td>MZMD5</td><td>Recurse a directory, for files with MZ header, create hash list</td></tr>
    <tr><td>MZcount</td><td>Recurse a directory, uses YARA to count MZ, Zip, PDF, other</td></tr>
    <tr><td>NSRL Query</td><td>Query a MD5 or SHA1 hash against NSRL</td></tr>
    <tr><td>Strings to YARA</td><td>Prompts for metadata and strings (text file) to create a YARA rule</td></tr>
    <tr><td>Malware Hash Lookup</td><td>Query a hash value against VirusTotal & Malware Bazaar*</td></tr>
    <tr><td>XMZMD5</td><td>Recurse a directory, for files without MZ, Zip or PDF header, create hash list</td></tr>
  </tbody>
</table>

<p style="text-align: center;">
  <strong>*The Malware Hash Lookup requires an API key for VirusTotal and Malware Bazaar.</strong> If unidentified, MalChela will prompt you to create them the first time you run the malware lookup function.
</p>