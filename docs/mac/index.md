
<p style="text-align: center;">
  While many MalChela tools are file-type agnostic — Hash It, Threat Intel Query, File Miner, and others work the same regardless of what platform a sample targets — the tools on this page have been specifically implemented for the analysis of macOS malware: Mach-O binaries, <code>.app</code> bundles, code signing, property lists, and Apple's DMG/PKG installer formats.
</p>

<h2 style="text-align: center;">Mac Analysis Tools</h2>
<p style="text-align: center;">
  Dedicated tools for static analysis of macOS binaries, bundles, and property lists.
</p>

<table style="margin-left: 8%; width: 100%;">
  <thead>
    <tr>
      <th>Program</th>
      <th>Function</th>
    </tr>
  </thead>
  <tbody>
    <tr><td>Analyze</td><td>One-click auto-triage for a file, folder, or .app bundle — dispatches every relevant tool, including the Mac Analysis stack, and produces a combined rollup report</td></tr>
    <tr><td>Code Sign Check</td><td>Inspects macOS code signing: Developer-signed vs. ad-hoc vs. unsigned, Team ID, Bundle ID, entitlements, and get-task-allow flag</td></tr>
    <tr><td>dpp Extract</td><td>Unwraps a .dmg or .pkg (UDIF &rarr; HFS+/APFS &rarr; XAR &rarr; PBZX/CPIO) to reach the real payload files inside</td></tr>
    <tr><td>Mach-O Info</td><td>Parses Mach-O binaries: architecture, linked libraries, section entropy, symbol status, RPATH entries, and deprecated crypto library detection</td></tr>
    <tr><td>mStrings</td><td>Extracts strings, IOCs, and MITRE ATT&CK matches from Mach-O binaries and .app bundles</td></tr>
    <tr><td>Plist Analyzer</td><td>Parses .plist files and .app bundle Info.plist for malware indicators: hidden background agent, ATS disabled, custom URL schemes, env injection</td></tr>
  </tbody>
</table>

<p style="text-align: center;">
  Code Sign Check, Mach-O Info, mStrings, and Plist Analyzer auto-resolve a .app bundle's main executable — point them at the bundle directly. Run those four together against a bundle or binary with <code>./mac_stack.sh</code>.
</p>
