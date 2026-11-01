#!/usr/bin/env node
/**
 * mcp-malchela — MCP Server for the MalChela Toolkit
 * Exposes all MalChela tools to Claude Desktop as native MCP tools.
 *
 * Setup:
 *   npm install @modelcontextprotocol/sdk
 *   node index.js
 *
 * Claude Desktop config:
 * {
 *   "mcpServers": {
 *     "malchela": {
 *       "command": "node",
 *       "args": ["/Users/dmetz/mcp-malchela/index.js"],
 *       "env": {
 *         "MALCHELA_DIR": "/Users/dmetz/GitHub/MalChela"
 *       }
 *     }
 *   }
 * }
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { execFileSync } from 'child_process';
import {
  existsSync, readdirSync, statSync, mkdirSync, writeFileSync, readFileSync,
  realpathSync, openSync, closeSync, unlinkSync, rmSync, renameSync,
} from 'fs';
import { dirname, basename, extname } from 'path';
import { load as yamlLoad, dump as yamlDump } from 'js-yaml';

// Session-level case state — null until the user selects a case
let currentCase = null;

const MALCHELA_DIR = process.env.MALCHELA_DIR || (() => {
  throw new Error(
    'MALCHELA_DIR environment variable is not set.\n' +
    'Set it to the root of your local MalChela installation.\n' +
    'Example: export MALCHELA_DIR=/home/user/MalChela'
  );
})();
const RELEASE_DIR  = `${MALCHELA_DIR}/target/release`;

// Release version, read from [workspace.package] in the workspace Cargo.toml
// (the single place it's set) so the MCP server reports the same version as
// the Rust tools and the web UI.
const MALCHELA_VERSION = (() => {
  try {
    const toml = readFileSync(`${MALCHELA_DIR}/Cargo.toml`, 'utf8');
    const section = toml.split('[workspace.package]')[1] || '';
    const m = section.match(/^\s*version\s*=\s*"([^"]+)"/m);
    return m ? m[1] : 'unknown';
  } catch {
    return 'unknown';
  }
})();
const TIMEOUT_MS   = 60000;

// Tools whose underlying binary needs a raw Mach-O binary, not a bundle directory.
// If a .app bundle path is passed to one of these, we resolve it to the actual
// executable inside Contents/MacOS/ before shelling out.
const REQUIRES_RAW_MACHO = new Set(['macho_info', 'mstrings']);

// ── Tool definitions — sourced directly from tools.yaml ──────────────────────
const TOOLS = [

  // Case Management
  {
    name: 'set_case',
    category: 'Case Management',
    input_type: 'meta',
    description:
      'Set the active investigation case for this session. All subsequent tool output ' +
      'will be automatically saved to the case directory on disk. Call this once at the ' +
      'start of a session, before running any analysis tools.',
    inputSchema: {
      type: 'object',
      properties: {
        case_name: {
          type: 'string',
          description: 'Case name to activate or create (e.g. "ransomware-jan-2025", "incident-42")',
        },
      },
      required: ['case_name'],
    },
  },

  // File Analysis
  {
    name: 'fileanalyzer',
    category: 'File Analysis',
    input_type: 'file',
    description:
      'Static file analysis: MD5/SHA1/SHA256 hashes, entropy, packing detection, ' +
      'PE metadata (imports, sections, timestamps), YARA rule matches, and ' +
      'VirusTotal status. Best first step for any unknown file.',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: { type: 'string', description: 'Absolute path to the file' },
        output:   { type: 'string', description: 'Optional: save report to this path' },
      },
      required: ['filepath'],
    },
  },

  {
    name: 'mstrings',
    category: 'Strings Analysis',
    input_type: 'file',
    description:
      'String extraction with IOC detection and MITRE ATT&CK mapping. Applies ' +
      'Sigma-style YAML detection rules, flags suspicious patterns (registry keys, ' +
      'encoded payloads, suspicious DLL+API combos), maps findings to ATT&CK ' +
      'techniques. Run after fileanalyzer when entropy or PE indicators warrant ' +
      'deeper investigation. Supports macOS Mach-O binaries and .app bundles — if ' +
      'given a bundle path, the main executable is auto-resolved from Info.plist.',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: {
          type: 'string',
          description: 'Absolute path to the file, or to a .app bundle (main executable is auto-resolved)',
        },
        output: { type: 'string', description: 'Optional: save report to this path' },
      },
      required: ['filepath'],
    },
  },

  {
    name: 'fileminer',
    category: 'File Analysis',
    input_type: 'folder',
    description:
      'Scans a folder for file type mismatches and metadata. Classifies all files, ' +
      'flags executables disguised as other types (common dropper/attachment trick), ' +
      'and suggests appropriate MalChela tools for each file found. Use as entry ' +
      'point when analyzing an unknown directory or sample set.',
    inputSchema: {
      type: 'object',
      properties: {
        folderpath: { type: 'string', description: 'Absolute path to the folder to scan' },
      },
      required: ['folderpath'],
    },
  },

  {
    name: 'analyze',
    category: 'File Analysis',
    input_type: 'analyze',
    description:
      'One-shot auto-triage: runs fileminer against a file, folder, .app bundle, .dmg, or .pkg, ' +
      'then automatically dispatches every tool fileminer suggests for every file found (no need ' +
      'to call fileminer yourself and manually decide which follow-up tools to run). A .dmg/.pkg ' +
      'target is auto-unwrapped via dpp_extract first (UDIF -> HFS+/APFS -> XAR -> PBZX/CPIO). ' +
      'Every executable is also run through unpack (static: UPX incl. tampered, PyInstaller, ' +
      '.NET/Costura, NSIS/Inno, fat Mach-O, overlays) and recovered payloads are analyzed as ' +
      'files of their own, so the rollup covers the real payload, not just the packer stub. ' +
      'Writes a combined rollup report alongside the individual per-tool reports. Best entry ' +
      'point for a single sample or small bundle (limit 25 files) — over that (common for a ' +
      'dpp-extracted PKG payload, which often bundles the full legitimate app it trojanized ' +
      'alongside the injected malicious file(s)), returns a file listing (mismatches first) ' +
      'instead of auto-running everything; call individual tools yourself on files of interest, ' +
      'or fileminer + MZHash/MZCount/XMZHash directly for corpus-scale scans. Requires an active ' +
      'case (set_case first).',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Absolute path to a file, folder, or .app bundle' },
      },
      required: ['path'],
    },
  },

  // Threat Intel
  {
    name: 'tiquery',
    category: 'Threat Intel',
    input_type: 'hash',
    description:
      'Multi-source threat intel lookup for a file hash, an IP address, or a URL. ' +
      'Hashes: MalwareBazaar, VirusTotal, AlienVault OTX, MetaDefender, Hybrid Analysis, ' +
      'FileScan, Malshare, Triage, Objective-See. IPs (IPv4/IPv6, defanged accepted): ' +
      'VirusTotal (detections, AS owner, country), OTX (pulses), and GreyNoise (known ' +
      'internet scanner vs. known benign service such as a cloud or CDN address). ' +
      'URLs: VirusTotal, urlscan.io, Google Safe Browsing. Private and reserved IPs, and URLs ' +
      'with internal hosts, are refused. Keyed sources are queried only with an API key in ' +
      'api/*.txt. Keyless urlscan.io is opt-in (the user enables it in MalChela; it receives ' +
      'the full URL) — do not pass it in sources unless the user asks for it.',
    inputSchema: {
      type: 'object',
      properties: {
        hash:    { type: 'string', description: 'MD5/SHA1/SHA256 hash, IP address, or http(s) URL to query' },
        sources: {
          type: 'string',
          description: 'Comma-separated source IDs (hashes: mb,vt,otx,md,ha,fs,ms,tr,os; IPs: vt,otx,gn; URLs: vt,urlscan,gsb). Default: every source for the input type that has a key, plus keyless sources the user has opted in to',
        },
      },
      required: ['hash'],
    },
  },

  {
    name: 'nsrlquery',
    category: 'Threat Intel',
    input_type: 'hash',
    description:
      'Checks a hash against the NIST NSRL database. A positive hit indicates a ' +
      'known-good file — useful for quickly excluding legitimate system files. ' +
      'Accepts MD5 or SHA1.',
    inputSchema: {
      type: 'object',
      properties: {
        hash: { type: 'string', description: 'MD5 or SHA1 hash to query against NSRL' },
      },
      required: ['hash'],
    },
  },

  // Hashing Tools
  {
    name: 'hashit',
    category: 'Hashing Tools',
    input_type: 'file',
    description:
      'Generates MD5, SHA1, and SHA256 hashes for a single file. Lightweight ' +
      'when you need hashes without full fileanalyzer output.',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: { type: 'string', description: 'Absolute path to the file' },
      },
      required: ['filepath'],
    },
  },

  {
    name: 'hashcheck',
    category: 'Hashing Tools',
    input_type: 'file',
    description:
      'Checks a hash against a local lookup file of known hashes. Useful for ' +
      'checking against custom threat intel lists or previously built hash sets.',
    inputSchema: {
      type: 'object',
      properties: {
        filepath:    { type: 'string', description: 'Absolute path to the file to check' },
        lookup_file: { type: 'string', description: 'Optional: path to hash lookup file' },
      },
      required: ['filepath'],
    },
  },

  {
    name: 'mzhash',
    category: 'Hashing Tools',
    input_type: 'folder',
    description:
      'Recursively scans a folder and generates hash sets for all files with MZ ' +
      'headers (Windows PE executables and DLLs). Creates one hash file per ' +
      'algorithm plus a TSV lookup table mapping hashes to paths.',
    inputSchema: {
      type: 'object',
      properties: {
        folderpath:  { type: 'string', description: 'Absolute path to the folder to scan' },
        algorithms:  {
          type: 'array',
          items: { type: 'string', enum: ['MD5', 'SHA1', 'SHA256'] },
          description: 'Algorithms to generate (default: all three)',
        },
      },
      required: ['folderpath'],
    },
  },

  {
    name: 'xmzhash',
    category: 'Hashing Tools',
    input_type: 'folder',
    description:
      'Like mzhash but inverted — hashes files that do NOT have MZ, ZIP, or PDF ' +
      'headers. Surfaces Linux, Mac, or unusual samples in a mixed corpus.',
    inputSchema: {
      type: 'object',
      properties: {
        folderpath: { type: 'string', description: 'Absolute path to the folder to scan' },
      },
      required: ['folderpath'],
    },
  },

  {
    name: 'mzcount',
    category: 'Hashing Tools',
    input_type: 'folder',
    description:
      'Counts and summarizes file types within a directory. Quick triage to ' +
      'understand the composition of a sample set before deeper analysis.',
    inputSchema: {
      type: 'object',
      properties: {
        folderpath: { type: 'string', description: 'Absolute path to the folder' },
      },
      required: ['folderpath'],
    },
  },

  // YARA Tools
  {
    name: 'strings_to_yara',
    category: 'YARA Tools',
    input_type: 'file',
    description:
      'Converts a text file of extracted strings (one per line) into a properly ' +
      'formatted YARA rule draft. Handles escaping and formatting automatically. ' +
      'Typically used after mstrings extraction.',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: { type: 'string', description: 'Path to text file of strings (one per line)' },
      },
      required: ['filepath'],
    },
  },

  {
    name: 'yara_scan',
    category: 'YARA Tools',
    input_type: 'yara_scan',
    description:
      'Scans a file or folder with YARA rules on MalChela\'s embedded YARA-X engine ' +
      '(no yr install needed). Rules can be a single .yar/.yara file or a folder of rules. ' +
      'Returns one NDJSON line per file that matched, with each rule\'s namespace, tags, ' +
      'metadata, and matching strings with offsets. Flags follow VirusTotal\'s `yr scan`. ' +
      'Saved to the active case as a Markdown report when one is set.',
    inputSchema: {
      type: 'object',
      properties: {
        rules_path: { type: 'string', description: 'A .yar/.yara file or a folder of rules (optionally NAMESPACE:path)' },
        target_path: { type: 'string', description: 'File or folder to scan' },
        recursive: { type: 'boolean', description: 'Scan subfolders of target_path (default false)' },
        negate: { type: 'boolean', description: 'List the rules that did NOT match instead' },
        tag: { type: 'string', description: 'Only report rules with this tag' },
        defines: {
          type: 'array', items: { type: 'string' },
          description: 'External variables as VAR=VALUE, VALUE in JSON form: 10, true, "text"',
        },
        timeout: { type: 'integer', description: 'Per-file timeout in seconds' },
      },
      required: ['rules_path', 'target_path'],
    },
  },

  {
    name: 'combine_yara',
    category: 'YARA Tools',
    input_type: 'folder',
    description:
      'Merges multiple YARA rule files from a folder into a single consolidated ' +
      'ruleset. Useful for managing and deploying rule collections.',
    inputSchema: {
      type: 'object',
      properties: {
        folderpath: { type: 'string', description: 'Folder containing YARA rule files' },
      },
      required: ['folderpath'],
    },
  },

  // Mac Analysis
  {
    name: 'plist_analyzer',
    category: 'Mac Analysis',
    input_type: 'file',
    description:
      'Parses macOS .plist files and .app bundle Info.plist for malware indicators. ' +
      'Detects: LSUIElement/NSUIElement (hidden background agent), NSAllowsArbitraryLoads ' +
      '(ATS disabled — unencrypted HTTP allowed), CFBundleURLTypes (custom URL scheme ' +
      'registration), CFBundleSignature="????" (no creator code), LSEnvironment (env var ' +
      'injection), missing or extra binaries in Contents/MacOS/. ' +
      'Use on any .plist file or point at a .app bundle directory.',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: { type: 'string', description: 'Absolute path to a .plist file or .app bundle' },
      },
      required: ['filepath'],
    },
  },

  {
    name: 'macho_info',
    category: 'Mac Analysis',
    input_type: 'file',
    description:
      'Parses Mach-O binaries (thin and fat/universal): CPU architecture, file type, ' +
      'PIE/ASLR status, __PAGEZERO integrity, linked libraries, RPATH entries, section ' +
      'entropy, and symbol table status. Flags: stripped symbols, high-entropy sections ' +
      '(packed/encrypted content), zero-sized __PAGEZERO (privilege escalation), RPATH ' +
      'entries (dylib hijacking), deprecated/EOL crypto libraries (libcrypto.0.9.8, etc.), ' +
      'and the CoreFoundation+SystemConfiguration+Security dylib triad common in C2 implants. ' +
      'Accepts a bare Mach-O binary or a .app bundle — bundle paths are auto-resolved to the ' +
      'main executable via Info.plist (CFBundleExecutable).',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: {
          type: 'string',
          description: 'Absolute path to a Mach-O binary, or a .app bundle (main executable is auto-resolved)',
        },
      },
      required: ['filepath'],
    },
  },

  {
    name: 'codesign_check',
    category: 'Mac Analysis',
    input_type: 'file',
    description:
      'Inspects macOS code signing by parsing the code signature superblob directly from ' +
      'the Mach-O binary. Reports: signature status (Developer-signed, Ad-hoc, or Unsigned), ' +
      'Bundle ID and Team ID from the CodeDirectory, entitlements presence, get-task-allow ' +
      'flag (debug/dev build), and _CodeSignature/ directory verification. ' +
      'Accepts a .app bundle path or a bare Mach-O binary. Handles fat/universal binaries.',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: { type: 'string', description: 'Absolute path to a .app bundle or Mach-O binary' },
      },
      required: ['filepath'],
    },
  },

  // Utilities
  {
    name: 'extract_samples',
    category: 'Utilities',
    input_type: 'folder',
    description:
      'Extracts contents from password-protected archives commonly used to package ' +
      'malware samples (e.g. zip files with passwords "infected", "malware", "virus").',
    inputSchema: {
      type: 'object',
      properties: {
        folderpath: { type: 'string', description: 'Folder containing protected archives' },
        password:   {
          type: 'string',
          description: 'Archive password (common: "infected", "malware", "virus")',
        },
      },
      required: ['folderpath'],
    },
  },

  {
    name: 'dpp_extract',
    category: 'Utilities',
    input_type: 'dpp_extract',
    description:
      'Unwraps a .dmg or .pkg container (UDIF -> HFS+/APFS -> XAR -> PBZX/CPIO) to reach the ' +
      'real payload files inside — fileanalyzer/mstrings/macho_info can\'t see through either ' +
      'container format directly. Also pulls each PKG component\'s Scripts (preinstall/' +
      'postinstall) archive alongside Payload, since some installers ship an empty Payload and ' +
      'put their actual behavior there instead. A trojanized installer commonly bundles the ' +
      'full legitimate app it trojanized alongside the injected malicious file(s), so the ' +
      'extracted directory can be large — follow up with fileminer on the result rather than ' +
      'fileanalyzer/mstrings directly on the whole tree. analyze() calls this automatically ' +
      'when pointed at a .dmg/.pkg; call it directly only if you need the extracted files ' +
      'without Analyze\'s auto-dispatch.',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: { type: 'string', description: 'Absolute path to a .dmg or .pkg file' },
      },
      required: ['filepath'],
    },
  },

  {
    name: 'unpack',
    category: 'File Analysis',
    input_type: 'unpack',
    description:
      'Static packer detection and unpacking for PE, ELF, and Mach-O — never executes the sample. ' +
      'Identifies packers/protectors/installers with the evidence behind each call, then recovers ' +
      'what can be recovered statically: UPX (including Mirai-style tampered headers, repaired ' +
      'before upx -d), fat Mach-O slices, PyInstaller entry scripts (rebuilt as .pyc), .NET ' +
      'manifest resources and Costura.Fody assemblies, NSIS (7-Zip) and Inno Setup (innoextract) ' +
      'payloads, and appended/embedded executables. Recurses into recovered payloads (default ' +
      'depth 3). Protectors such as Themida/VMProtect are identified but need emulation or a ' +
      'sandbox. analyze() runs this automatically on every executable and analyzes the recovered ' +
      'payloads; call it directly to inspect the layer tree or unpack a single file.',
    inputSchema: {
      type: 'object',
      properties: {
        filepath:  { type: 'string', description: 'Absolute path to the file to unpack' },
        max_depth: { type: 'integer', description: 'Maximum unpacking depth (default 3)' },
      },
      required: ['filepath'],
    },
  },

  // Reporting
  {
    name: 'report_template',
    category: 'Reporting',
    input_type: 'meta',
    description:
      "Get Lenny Zeltser's Malware Analysis Report template (Markdown, CC BY 4.0, bundled for " +
      'offline use) plus a guide to which MalChela output fills each section. Call this after the ' +
      'analysis, when the user asks for a malware report, then write the report and save it with ' +
      'save_report. Headings marked (Optional) are conditional: include them only when the findings ' +
      'warrant it, and drop the "(Optional)" marker.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'save_report',
    category: 'Reporting',
    input_type: 'meta',
    description:
      'Save a finished malware analysis report (Markdown) to the active case, under ' +
      'saved_output/cases/<case>/report/, and register it in the case manifest. Requires an active ' +
      'case. Will not overwrite an existing report unless overwrite is true.',
    inputSchema: {
      type: 'object',
      properties: {
        filename: {
          type: 'string',
          description: 'Report file name, e.g. "Mirai_sh7f3a_Malware_Analysis_Report" (".md" is added if missing)',
        },
        content: { type: 'string', description: 'The full report in Markdown' },
        target: { type: 'string', description: 'Path or SHA-256 of the primary sample the report covers (recorded in the case manifest)' },
        overwrite: { type: 'boolean', description: 'Replace an existing report with the same name (default false)' },
      },
      required: ['filename', 'content'],
    },
  },
];

// ── Malware analysis report (Lenny Zeltser's template) ───────────────────────
const REPORT_TEMPLATE_DIR = `${MALCHELA_DIR}/assets/report_templates`;

// Where MalChela's own output lands in the template. Kept short: the template's
// bracketed guidance does the rest.
const REPORT_FILL_GUIDE = [
  'How MalChela output maps to the template:',
  '- Sample Snapshot / Malware Family Identification: tiquery (family names and tags, detection ratios per source) — cite the source for each family call; confidence follows the evidence, not the vendor count.',
  '- Component Inventory: unpack (recovered payloads and the layer tree: fat slices, UPX layers, PyInstaller entry scripts, carved executables) and fileminer (types and extension mismatches). One row per artifact; hashes go in Indicators of Compromise.',
  '- Runtime Requirements: fileanalyzer (PE imports, compile time), macho_info (architecture, linked libraries, RPATH), plist_analyzer (Info.plist requirements).',
  '- Sources: tiquery links (MalwareBazaar, VirusTotal, and so on) and where the sample came from (ask the user if unknown).',
  '- Capabilities: mstrings rule hits and the Analyze MITRE ATT&CK matrix (mitre_matrix_<ts>.json / navigator_layer_<ts>.json in the case analyze folder). The template uses MBC behaviors; cite the ATT&CK technique IDs MalChela found in the Notes column. Treat a rule hit as evidence to corroborate, not a capability on its own — check the matched strings, and discount hits from a bundler bootloader or runtime (PyInstaller, NSIS) rather than the sample\'s own code.',
  '- Indicators of Compromise: mstrings "Potential Network IOCs" (already defanged), hashes from fileanalyzer/hashit for every component, host artifacts from plist_analyzer and strings. Public DNS resolvers mstrings lists separately are not C2. List only indicators the sample actually uses.',
  '- Analysis Details > Automated Analysis: name MalChela and its version, the tools Analyze ran, and the analysis depth (static only).',
  '- Analysis Details > Static Properties Analysis: fileanalyzer (entropy, packing, imphash, signing), macho_info (section entropy, stripped symbols), codesign_check (ad-hoc vs. developer signing, Team ID, entitlements), unpack (packer verdict and whether properties describe the packed or unpacked form).',
  '- Analysis Details > Behavioral / Memory Analysis: MalChela is static only — say these were not performed unless the user supplies results.',
  '- Appendix: Analysis Environment: MalChela version (from this server), the host OS, and that samples were never executed.',
  '- Save the finished report with save_report (it goes in the case report/ folder).',
].join('\n');

function reportTemplateText() {
  const md = readFileSync(`${REPORT_TEMPLATE_DIR}/zeltser_malware_analysis_report.md`, 'utf8');
  let meta = {};
  try { meta = JSON.parse(readFileSync(`${REPORT_TEMPLATE_DIR}/zeltser_malware_analysis_report.json`, 'utf8')); } catch { /* optional */ }
  const src = meta.source || {};
  const conv = meta.optional_section_convention || {};
  return [
    `Malware Analysis Report Template v${src.sourceVersion || '?'} (${src.sourceDate || '?'}) — ${meta.attribution || 'Lenny Zeltser, CC BY 4.0'}`,
    `Canonical, continuously updated source: ${src.fallbackArticleUrl || 'https://zeltser.com/malware-analysis-report'}`,
    '',
    'Optional sections: ' + (conv.principle ||
      'Headings ending in "(Optional)" are conditional markers: include the section only when warranted, and remove the marker from the heading, the Contents entry, and every link to it.'),
    '',
    REPORT_FILL_GUIDE,
    '',
    `MalChela version: ${MALCHELA_VERSION}`,
    '',
    '──────── TEMPLATE ────────',
    md,
  ].join('\n');
}

function saveReport(args) {
  let name = basename(String(args.filename || '').trim()).replace(/[^A-Za-z0-9._ -]+/g, '_').replace(/\s+/g, '_');
  if (!name || name.startsWith('.')) throw new Error('A report file name is required.');
  if (!name.toLowerCase().endsWith('.md')) name += '.md';
  const content = String(args.content || '');
  if (!content.trim()) throw new Error('The report content is empty.');
  const dir = `${MALCHELA_DIR}/saved_output/cases/${currentCase}/report`;
  mkdirSync(dir, { recursive: true });
  const path = `${dir}/${name}`;
  if (existsSync(path) && !args.overwrite) {
    throw new Error(`${path} already exists. Pass overwrite: true to replace it, or use a different file name.`);
  }
  writeFileSync(path, content.endsWith('\n') ? content : content + '\n');
  registerCaseOutput('report', currentCase, String(args.target || ''), path);
  return path;
}

// ── Mac bundle resolution helpers ────────────────────────────────────────────
function isAppBundle(p) {
  try {
    return p.endsWith('.app') && statSync(p).isDirectory() && existsSync(`${p}/Contents`);
  } catch {
    return false;
  }
}

// Resolve a .app bundle path down to its main Mach-O executable, for tools
// (macho_info, mstrings) that need a raw binary rather than a bundle directory.
// Tries Info.plist's CFBundleExecutable first (via macOS's built-in `plutil`),
// then falls back to the sole file in Contents/MacOS/ if there's exactly one.
function resolveBundleExecutable(bundlePath) {
  const infoPlist = `${bundlePath}/Contents/Info.plist`;
  const macosDir  = `${bundlePath}/Contents/MacOS`;

  if (existsSync(infoPlist)) {
    try {
      const bundleExec = execFileSync(
        'plutil', ['-extract', 'CFBundleExecutable', 'raw', '-o', '-', infoPlist],
        { encoding: 'utf8', timeout: 5000 }
      ).trim();
      if (bundleExec) {
        const candidate = `${macosDir}/${bundleExec}`;
        if (existsSync(candidate) && statSync(candidate).isFile()) {
          return candidate;
        }
      }
    } catch {
      // plutil failed (malformed/binary plist edge case, or key missing) — fall through
    }
  }

  if (existsSync(macosDir)) {
    const files = readdirSync(macosDir).filter(f => {
      try { return statSync(`${macosDir}/${f}`).isFile(); } catch { return false; }
    });
    if (files.length === 1) return `${macosDir}/${files[0]}`;
    if (files.length > 1) {
      throw new Error(
        `Bundle resolution ambiguous: multiple executables in ${macosDir} ` +
        `(${files.join(', ')}) and CFBundleExecutable could not be read from Info.plist. ` +
        `Pass the specific binary path instead of the bundle.`
      );
    }
  }

  throw new Error(`Could not resolve main executable for bundle: ${bundlePath}`);
}

// ── Command builder ───────────────────────────────────────────────────────────
// Returns { bin, args } for execFileSync — never a shell string. No argument
// here (paths, case names, hashes) goes through a shell, so nothing a caller
// controls can break out of quoting to inject a second command.
function buildCommand(toolName, args) {
  const binary = `${RELEASE_DIR}/${toolName}`;

  if (!existsSync(binary)) {
    throw new Error(
      `Binary not found: ${binary}\n` +
      `Build MalChela first: cd ${MALCHELA_DIR} && ./release.sh`
    );
  }

  const tool = TOOLS.find(t => t.name === toolName);

  switch (tool.input_type) {
    case 'file': {
      let targetPath = args.filepath;

      // macho_info and mstrings need the raw Mach-O binary, not the bundle
      // directory. plist_analyzer and codesign_check accept .app bundle paths
      // directly and handle resolution internally, so they're left untouched.
      if (REQUIRES_RAW_MACHO.has(toolName) && isAppBundle(targetPath)) {
        targetPath = resolveBundleExecutable(targetPath);
      }

      if (currentCase) {
        return { bin: binary, args: [targetPath, '--case', currentCase, '-o', '-m'] };  // Markdown: mitre_matrix.for_case() only parses pipe tables
      }
      const cmdArgs = [targetPath];
      if (args.output) cmdArgs.push('-o', args.output);
      return { bin: binary, args: cmdArgs };
    }
    case 'folder': {
      if (toolName === 'mzhash' && args.algorithms?.length) {
        const flags = args.algorithms.flatMap(a => ['-a', a]);
        return { bin: binary, args: [args.folderpath, '--', ...flags] };
      }
      return { bin: binary, args: [args.folderpath] };
    }
    case 'dpp_extract': {
      const cmdArgs = [args.filepath];
      if (currentCase) cmdArgs.push('--case', currentCase);
      return { bin: binary, args: cmdArgs };
    }
    case 'unpack': {
      const cmdArgs = [args.filepath];
      if (Number.isInteger(args.max_depth)) cmdArgs.push('--max-depth', String(args.max_depth));
      if (currentCase) cmdArgs.push('--case', currentCase, '-o', '-m');
      return { bin: binary, args: cmdArgs };
    }
    case 'yara_scan': {
      const cmdArgs = ['--output-format', 'ndjson', '--print-strings=60', '--print-meta', '--print-tags', '--print-namespace'];
      if (args.recursive) cmdArgs.push('--recursive');
      if (args.negate) cmdArgs.push('--negate');
      if (args.tag) cmdArgs.push('--tag', String(args.tag));
      for (const d of Array.isArray(args.defines) ? args.defines : []) cmdArgs.push('--define', String(d));
      if (Number.isInteger(args.timeout) && args.timeout > 0) cmdArgs.push('--timeout', String(args.timeout));
      if (currentCase) cmdArgs.push('--case', currentCase, '--save=md');
      cmdArgs.push('--', args.rules_path, args.target_path);
      return { bin: binary, args: cmdArgs };
    }
    case 'hash': {
      const caseArgs = currentCase ? ['--case', currentCase, '-o', '-m'] : [];
      if (toolName === 'tiquery') {
        const srcArgs = args.sources ? ['--sources', args.sources] : [];
        return { bin: binary, args: [args.hash, ...srcArgs, '--json', ...caseArgs] };
      }
      return { bin: binary, args: [args.hash, ...caseArgs] };
    }
    default:
      throw new Error(`Unknown input_type for tool: ${toolName}`);
  }
}

// Mirrors _sanitize_case_name() in server/malchela_server.py — only word
// chars, hyphens, and dots survive, and a literal ".." anywhere rejects the
// name outright. Applied once, at set_case (the single point of entry for
// currentCase), so every downstream path built from it — registerCaseOutput,
// runAnalyze's rollupDir, buildCommand's --case arg, readToolMarkdown's
// toolDir — is safe from traversal without each of them re-checking.
const CASE_NAME_RE = /[^\w\-.]/g;

function sanitizeCaseName(name) {
  if (!name) return null;
  const clean = String(name).trim().replace(CASE_NAME_RE, '_');
  if (!clean || clean.includes('..')) return null;
  return clean.slice(0, 128);
}

// ── Case manifest registration ───────────────────────────────────────────────
// Mirrors common_config::register_case_output() (Rust) / _register_cli_case_output()
// (Python web server) so a file written directly by this MCP process — the
// analyze rollup, which no single Rust binary produces — still shows up in
// case.yaml. The Rust-side tools this dispatches (macho_info, mstrings,
// codesign_check, plist_analyzer, fileanalyzer, tiquery) already register
// their own per-tool reports internally; this only covers the rollup file.

// Blocking sleep with no subprocess spawn — avoids depending on a `sleep`
// binary being present/behaving consistently across macOS/Linux, and skips
// the process-spawn overhead on what can be a hot retry loop.
function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function acquireCaseLock(caseDir) {
  const lockPath = `${caseDir}/case.yaml.lock`;
  let attempts = 0;
  for (;;) {
    try {
      const fd = openSync(lockPath, 'wx');
      closeSync(fd);
      return lockPath;
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      try {
        const age = Date.now() - statSync(lockPath).mtimeMs;
        if (age > 10000) { unlinkSync(lockPath); continue; }
      } catch { /* lock vanished between stat and check — retry */ }
      attempts += 1;
      if (attempts > 50) throw new Error('Timed out waiting for case.yaml lock');
      sleepSync(100);
    }
  }
}

function registerCaseOutput(tool, caseName, target, outputPath) {
  try {
    const caseDir = `${MALCHELA_DIR}/saved_output/cases/${caseName}`;
    mkdirSync(caseDir, { recursive: true });
    const filename = outputPath.split('/').pop();
    const relPath = `${tool}/${filename}`;
    const timestamp = new Date().toISOString();

    const lockPath = acquireCaseLock(caseDir);
    try {
      const yamlPath = `${caseDir}/case.yaml`;
      let manifest;
      if (existsSync(yamlPath)) {
        try {
          manifest = yamlLoad(readFileSync(yamlPath, 'utf8')) || {};
        } catch {
          // Never replace a manifest we can't parse (that used to wipe every
          // registered file) — skip this registration instead.
          return;
        }
      }
      if (!manifest) {
        manifest = {
          created: timestamp, description: '', files: [], modified: timestamp,
          name: caseName, notes: '', status: 'open', tags: [],
        };
      }
      manifest.files = manifest.files || [];
      if (!manifest.files.some(f => f.path === relPath)) {
        manifest.files.push({ filename, path: relPath, target, timestamp, tool });
        manifest.modified = timestamp;
        writeFileSync(yamlPath, yamlDump(manifest));
      }
    } finally {
      unlinkSync(lockPath);
    }
  } catch {
    // Manifest tracking is a convenience, not something that should fail the run.
  }
}

// ── Analyze (auto-triage) ────────────────────────────────────────────────────
// Ports server/malchela_server.py's /analyze route: fileminer scan, then
// dispatch every suggested tool per file, then a mechanical rollup — kept in
// sync by hand since the MCP shells out to binaries directly rather than
// going through the Flask server.

const ANALYZE_MAX_FILES = 25; // matches _ANALYZE_MAX_FILES in malchela_server.py
const ANALYZE_TIMEOUT_MS = 90000;
const FILEMINER_TIMEOUT_MS = 120000;
const DPP_EXTRACT_TIMEOUT_MS = 180000;
const UNPACK_TIMEOUT_MS = 300000;
const ANALYZE_MAX_BUFFER = 50 * 1024 * 1024; // fileminer's JSON dump easily exceeds execFileSync's 1MB default

function pathsMatch(candidate, resolvedTarget) {
  if (!candidate) return false;
  try {
    return realpathSync(candidate) === resolvedTarget;
  } catch {
    return candidate === resolvedTarget;
  }
}

// Same on-disk toggle the PWA's Configuration screen writes
// (server/malchela_server.py's is_offline_mode()) — a plain file, not a
// server-process flag, so both the Flask app and this separate Node process
// read the identical source of truth with no IPC needed.
const OFFLINE_MODE_FILE = `${MALCHELA_DIR}/api/offline_mode.txt`;
function isOfflineMode() {
  try {
    return readFileSync(OFFLINE_MODE_FILE, 'utf8').trim() === '1';
  } catch {
    return false;
  }
}

const EMBEDDED_BINARY_MARKERS = ['/Contents/Frameworks/', '/Contents/PlugIns/', '/Contents/XPCServices/'];

// Best-effort "is this the top-level executable, not something embedded
// inside a bundle" check — scopes Analyze's --check-revocation to the main
// binary instead of firing an OCSP query for every framework/plugin/XPC
// helper a bundle carries (Audacity.app alone embeds 90+ signed dylibs).
function isTopLevelBinary(filepath, singleFileMode, resolvedTarget) {
  if (singleFileMode) {
    return resolvedTarget != null && pathsMatch(filepath, resolvedTarget);
  }
  if (EMBEDDED_BINARY_MARKERS.some(marker => filepath.includes(marker))) {
    return false;
  }
  // Nested bundle (e.g. a wrapper .app bundling a second real .app inside
  // Resources/, or Sparkle's Autoupdate.app) — only the outermost bundle's
  // own executable counts as top-level.
  if ((filepath.match(/\.app\//g) || []).length > 1) {
    return false;
  }
  return true;
}

// Read back the .md report a tool just wrote (Analyze always requests -o -m,
// case or not) so the rollup can embed genuinely formatted content instead of
// raw CLI stdout. Picks the most-recently-modified report_*.md in the tool's
// output dir; safe because dispatch is fully sequential — nothing else writes
// there between this tool's run and this read.
//
// In a case, the report is then renamed from report_<ts>.md to
// <file>_<ts>.md (as the server's _rename_case_report() does), and its
// case.yaml entry follows. Without this, two runs of the same tool within one
// second (three files' tiquery lookups, say) wrote the same report_<ts>.md,
// each overwriting the last in the case folder.
function readToolMarkdown(tool, caseName, displayName = '') {
  const toolDir = caseName
    ? `${MALCHELA_DIR}/saved_output/cases/${caseName}/${tool}`
    : `${MALCHELA_DIR}/saved_output/${tool}`;
  if (!existsSync(toolDir)) return '';
  const mdFiles = readdirSync(toolDir)
    .filter(f => f.startsWith('report_') && f.endsWith('.md'))
    .map(f => `${toolDir}/${f}`)
    .sort((a, b) => statSync(a).mtimeMs - statSync(b).mtimeMs);
  if (!mdFiles.length) return '';
  const latest = mdFiles[mdFiles.length - 1];
  const md = readFileSync(latest, 'utf8');
  if (caseName && displayName) renameCaseReport(tool, caseName, displayName, latest);
  return md;
}

function renameCaseReport(tool, caseName, displayName, reportPath) {
  try {
    const name = basename(reportPath);
    const ts = (/report_(\d{8}_\d{6})/.exec(name) || [])[1];
    if (!ts) return;
    const stem = basename(displayName).replace(/\.[^.]*$/, '').replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 80) || 'file';
    const newPath = `${dirname(reportPath)}/${stem}_${ts}${extname(name)}`;
    if (newPath === reportPath || existsSync(newPath)) return;
    const caseDir = `${MALCHELA_DIR}/saved_output/cases/${caseName}`;
    const lockPath = acquireCaseLock(caseDir);
    try {
      renameSync(reportPath, newPath);
      const yamlPath = `${caseDir}/case.yaml`;
      if (!existsSync(yamlPath)) return;
      let manifest;
      try { manifest = yamlLoad(readFileSync(yamlPath, 'utf8')) || {}; } catch { return; }
      const oldRel = `${tool}/${name}`;
      const newRel = `${tool}/${basename(newPath)}`;
      let changed = false;
      for (const f of manifest.files || []) {
        if (f.path === oldRel) { f.path = newRel; f.filename = basename(newPath); changed = true; }
      }
      if (changed) writeFileSync(yamlPath, yamlDump(manifest));
    } finally {
      unlinkSync(lockPath);
    }
  } catch {
    // A failed rename only costs the friendlier file name.
  }
}

// Shift a tool's own ATX headings down 2 levels so its "# ... Report" nests
// under the rollup's "## <filename>" section instead of colliding with it.
function demoteMarkdownHeadings(md, shift = 2) {
  return md.replace(/^(#{1,6})( .*)$/gm, (_, hashes, rest) => '#'.repeat(Math.min(hashes.length + shift, 6)) + rest);
}

// Best-effort malicious flag for the triage banner — not a full multi-source
// verdict, just enough signal without parsing every tool's ad-hoc text
// output. Two signals, checked in order:
//   1. FileAnalyzer's own VirusTotal line (PE / generic-unknown files only —
//      FileAnalyzer isn't suggested for Mach-O).
//   2. tiquery's VT row detection ratio (suggested for PE, Mach-O, and
//      generic-unknown — the one source common across file types, so this is
//      what actually catches Mach-O malware).
const TIQUERY_VT_ROW = /^\s*VT\s+FOUND\s+.*?(\d+)\/(\d+)/m;

function flagVerdict(toolRuns) {
  for (const run of toolRuns) {
    if (!run.success) continue;
    const output = run.output || '';
    if (output.includes('VirusTotal: Malicious')) {
      return { flagged: true, reason: 'VirusTotal: Malicious' };
    }
    const m = TIQUERY_VT_ROW.exec(output);
    if (m && parseInt(m[1], 10) > 0) {
      return { flagged: true, reason: `VirusTotal: ${m[1]}/${m[2]} (via tiquery)` };
    }
  }
  return { flagged: false, reason: '' };
}

// Parse mstrings' markdown "Detections" table (Count | Rule | Matched Strings
// | Tactic | Technique | ID) into { rawTotal, tactics }. Scoped to a single
// mstrings run's markdown, so the digit-first/6-column heuristic isn't at
// risk of matching some other tool's table. A rule mapped to multiple
// tactics (comma-separated) credits its count to each — that's how ATT&CK
// tagging works — so tactics can sum to more than rawTotal; rawTotal is the
// true per-file match count.
const MD_MITRE_ROW = /^\|\s*(\d+)\s*\|([^|]*)\|[^|]*\|\s*([^|]+?)\s*\|[^|]*\|[^|]*\|\s*$/gm;
// mStrings' summary row for a table of encoded strings re-counts the same
// strings its base64-blob rule already matched — a finding, not more strings.
const MSTRINGS_SUMMARY_ROWS = ["Encoded string table"];

// Tactic counts are per matched RULE, not per matched string: one rule that
// fires on 1,164 encoded chunks (AMOS) is one finding. rawTotal keeps the
// string count for context. Mirrors the server's _extract_mitre_tactics().
function extractMitreTactics(markdown) {
  let rawTotal = 0;
  let ruleHits = 0;
  const tactics = {};
  let m;
  MD_MITRE_ROW.lastIndex = 0;
  while ((m = MD_MITRE_ROW.exec(markdown)) !== null) {
    if (!MSTRINGS_SUMMARY_ROWS.some(p => m[2].trim().startsWith(p))) rawTotal += parseInt(m[1], 10);
    ruleHits += 1;
    for (const tactic of m[3].split(',')) {
      const t = tactic.trim();
      if (t) tactics[t] = (tactics[t] || 0) + 1;
    }
  }
  return { rawTotal, ruleHits, tactics };
}

// Pull non-empty Family/Tags values from tiquery's markdown Results table
// (Source | Status | Family / Tags | Detections | Link), for sources that
// returned a FOUND hit. \s*FOUND\s* between pipes only matches a cell that's
// exactly "FOUND" — "NOT FOUND" has "NOT " in the way, so it's naturally
// excluded. Order-preserving, exact-text dedup only — sources use their own
// naming conventions, so no attempt is made to merge near-duplicate family
// names across sources.
const TIQUERY_TAG_ROW = /^\|\s*[^\s|]+\s*\|\s*FOUND\s*\|\s*([^|]+?)\s*\|[^|]*\|[^|]*\|\s*$/gm;

function extractTiqueryTags(markdown) {
  const tags = [];
  const seen = new Set();
  let m;
  TIQUERY_TAG_ROW.lastIndex = 0;
  while ((m = TIQUERY_TAG_ROW.exec(markdown)) !== null) {
    const tag = m[1].trim();
    if (tag && !seen.has(tag)) {
      seen.add(tag);
      tags.push(tag);
    }
  }
  return tags;
}

// Pull '[!]'-style flag/indicator lines from a tool's markdown report.
// macho_info and plist_analyzer emit an identical '- **[!]** ...' bullet
// list under their own 'Flags / Indicators' heading; codesign_check's own
// saved report instead emits a plain '## Flags' heading followed by plain
// '- ...' bullets (its "No suspicious indicators" clean case emits nothing
// under that heading at all), so it needs its own block-scoped pattern —
// scoped to codesign_check specifically so this can't match some other
// tool's bullet list.
const MD_FLAG_BULLET = /^-\s*\*\*\[!\]\*\*\s*(.+)$/gm;
const CODESIGN_FLAGS_BLOCK = /^## Flags\n\n((?:-.*\n?)+)/m;
const MD_PLAIN_BULLET = /^- (.+)$/gm;

// True if codesign_check's Revocation (OCSP) summary-table row reports
// REVOKED. Deliberately independent of extractFlags/CODESIGN_FLAGS_BLOCK
// above — matches the literal table row so this stays correct even if the
// Flags section's wording ever changes.
function extractRevokedCert(markdown) {
  return markdown.includes('| Revocation (OCSP) | REVOKED |');
}

function extractFlags(tool, markdown) {
  if (tool === 'codesign_check') {
    const block = CODESIGN_FLAGS_BLOCK.exec(markdown);
    if (!block) return [];
    MD_PLAIN_BULLET.lastIndex = 0;
    const flags = [];
    let bm;
    while ((bm = MD_PLAIN_BULLET.exec(block[1])) !== null) flags.push(bm[1].trim());
    return flags;
  }
  const pattern = MD_FLAG_BULLET;
  pattern.lastIndex = 0;
  const flags = [];
  let m;
  while ((m = pattern.exec(markdown)) !== null) {
    flags.push(m[1].trim());
  }
  return flags;
}

// Pull filesystem/network IOC bullets out of mstrings' own markdown sections
// ('## Potential Filesystem IOCs' / '## Potential Network IOCs', each a
// plain '- `ioc`' bullet list — the only place mstrings emits that exact
// bullet pattern, so no cross-section ambiguity).
const MSTRINGS_FS_IOC_BLOCK = /## Potential Filesystem IOCs\n\n((?:- `.+`\n)+)/;
const MSTRINGS_NET_IOC_BLOCK = /## Potential Network IOCs\n\n((?:- `.+`\n)+)/;
const MD_BACKTICK_BULLET = /- `(.+)`/g;

// Defang a network IOC before it's ever displayed — standard analyst
// practice (hxxp(s):// keeps the scheme unresolvable, [.] stops chat/email
// clients and copy-paste from treating it as a live link/domain). Applied
// only where net_iocs get formatted for display; filesystem IOCs and
// filenames elsewhere in the rollup are never touched.
// Idempotent: mstrings now defangs its own "Potential Network IOCs"
// section, so this rollup re-extracts already-defanged text out of that
// markdown — bail out early rather than double-defang "[.]" into "[[.]]".
function defang(ioc) {
  if (ioc.includes('[.]') || ioc.toLowerCase().includes('hxxp')) return ioc;
  return ioc
    .replace(/http:\/\//g, 'hxxp://')
    .replace(/https:\/\//g, 'hxxps://')
    .replace(/ftp:\/\//g, 'fxxp://')
    .replace(/\./g, '[.]');
}

function extractMstringsIocs(markdown) {
  const bullets = (blockPattern) => {
    const m = blockPattern.exec(markdown);
    if (!m) return [];
    MD_BACKTICK_BULLET.lastIndex = 0;
    const out = [];
    let bm;
    while ((bm = MD_BACKTICK_BULLET.exec(m[1])) !== null) out.push(bm[1]);
    return out;
  };
  return { fs: bullets(MSTRINGS_FS_IOC_BLOCK), net: bullets(MSTRINGS_NET_IOC_BLOCK) };
}

// Highest base64 re-encoding depth mstrings had to peel through to reach any
// detection in this file (0 if none). mstrings only annotates a row this way
// at >1 layer — a single decode is routine and not itself a tell — so any
// nonzero result here is already meaningful: the malware deliberately
// re-encoded its payload multiple times, not just used base64 for convenience.
// mStrings' "IP Address Lists" section: runs of IPs stored together (often an
// anti-analysis blocklist), kept out of its Network IOCs. Mirrors the server's
// _extract_ip_lists().
const MSTRINGS_IP_LIST_BLOCK = /## IP Address Lists[^\n]*\n\n(?:[^\n]*\n\n)?((?:- \*\*.+\n)+)/;
const MSTRINGS_IP_LIST_ROW = /^- \*\*(\d+) addresses\*\* at (0x[0-9A-Fa-f]+)\S(0x[0-9A-Fa-f]+): (.+)$/gm;

function extractIpLists(markdown) {
  const m = MSTRINGS_IP_LIST_BLOCK.exec(markdown);
  if (!m) return [];
  const out = [];
  MSTRINGS_IP_LIST_ROW.lastIndex = 0;
  let r;
  while ((r = MSTRINGS_IP_LIST_ROW.exec(m[1])) !== null) {
    out.push({ count: parseInt(r[1], 10), range: `${r[2]}–${r[3]}`, ips: [...r[4].matchAll(/`([^`]+)`/g)].map(x => x[1]) });
  }
  return out;
}

const MD_OBFUSCATION_LAYERS = /found after (\d+) layers of base64 decoding/g;

function extractMaxObfuscationLayers(markdown) {
  MD_OBFUSCATION_LAYERS.lastIndex = 0;
  let max = 0;
  let m;
  while ((m = MD_OBFUSCATION_LAYERS.exec(markdown)) !== null) {
    const n = parseInt(m[1], 10);
    if (n > max) max = n;
  }
  return max;
}

// Files are grouped by SHA256 for display: duplicate content saved under
// different names (common with carved/exported network artifacts) gets one
// write-up instead of the same tool output repeated verbatim per filename.
// This only changes what's shown here — every path was still dispatched and
// still has its own saved report and case.yaml entry.
// unpack's markdown report carries a one-line "**Packer verdict:** ..." marker.
const UNPACK_VERDICT = /^\*\*Packer verdict:\*\*\s*(.+?)\s*$/m;

// ── Analyze summary, in the order of Lenny Zeltser's report template ─────────
// Mirrors the server's _build_analyze_rollup(): Sample Snapshot, Component
// Inventory, Capabilities, Indicators of Compromise, Analysis Details (every
// tool's output, per file — same shape as before, so the server's case matrix
// still parses MCP-saved summaries), and Analysis Environment. Sections that
// need an analyst's judgment are left for the written report.
const TIQUERY_FOUND_ROW = /^\|\s*([^\s|]+)\s*\|\s*FOUND\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|[^|]*\|\s*$/gm;
const UNPACK_FORMAT = /^\*\*Format:\*\*\s*(.+?)\s*$/m;
const IPV4_RE = /^\d{1,3}(?:\[?\.\]?\d{1,3}){3}$/;
const SUMMARY_ROW_CAP = 25;
// mStrings' Detections table: Count | Rule | Matched Strings | Tactic | Technique | ID
const MSTRINGS_ROW = /^\|\s*(\d+)\s*\|\s*([^|]*?)\s*\|[^|]*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|\s*(T\d{4}(?:\.\d{3})?)\s*\|\s*$/gm;
// Unpack's MITRE ATT&CK table: ID | Technique | Tactic
const UNPACK_MITRE_ROW = /^\|\s*(T\d{4}(?:\.\d{3})?)\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|\s*$/gm;

let attackRef = null;
// ATT&CK v20 reference (technique names and tactics, tactic order) from the
// bundled assets, loaded once. Null if the assets can't be read — the table
// then falls back to the names the tools printed.
function attackReference() {
  if (attackRef !== null) return attackRef || null;
  try {
    const techs = JSON.parse(readFileSync(`${MALCHELA_DIR}/assets/mitre_techniques.json`, 'utf8'));
    const tactics = JSON.parse(readFileSync(`${MALCHELA_DIR}/assets/mitre_tactics.json`, 'utf8'));
    const byId = new Map(techs.map(t => [t.id, t]));
    const fullName = (id) => {
      const t = byId.get(id);
      if (!t) return '';
      const parent = id.includes('.') ? byId.get(id.split('.')[0]) : null;
      return parent ? `${parent.name}: ${t.name}` : t.name;
    };
    const resolve = (id) => {
      let t = byId.get(id), hops = 0;
      while (t && t.deprecated && t.revoked_by && hops++ < 10) { id = t.revoked_by; t = byId.get(id); }
      return t ? id : null;
    };
    const tacticsOf = (id) => (byId.get(id)?.tactic || '').split(',').map(s => s.trim()).filter(Boolean);
    const shortByName = new Map(tactics.map(t => [t.name.toLowerCase(), t.shortname]));
    attackRef = { fullName, resolve, tacticsOf, tactics, shortByName };
  } catch {
    attackRef = false;
  }
  return attackRef || null;
}

let flagMapCache = null;
function flagMap() {
  if (flagMapCache) return flagMapCache;
  flagMapCache = [];
  try {
    for (const e of yamlLoad(readFileSync(`${MALCHELA_DIR}/assets/flag_attack_map.yaml`, 'utf8')) || []) {
      try { flagMapCache.push({ tool: e.tool, re: new RegExp(e.match, 'i'), technique: e.technique, confidence: e.confidence || 'low' }); } catch { /* bad regex: skip */ }
    }
  } catch { /* no map: no flag techniques */ }
  return flagMapCache;
}

// Technique hits in one tool's report: { id, name, tactics[], tool, source, confidence }.
function techniqueHits(tool, markdown) {
  const ref = attackReference();
  const hits = [];
  const add = (id, name, tacticNames, source, confidence) => {
    const rid = ref ? ref.resolve(id) : id;
    if (!rid) return;
    let tactics = [];
    if (ref) {
      const valid = ref.tacticsOf(rid);
      tactics = tacticNames.map(n => ref.shortByName.get(n.toLowerCase())).filter(s => s && valid.includes(s));
      if (!tactics.length) tactics = valid;
    } else {
      tactics = tacticNames;
    }
    hits.push({ id: rid, name: (ref && ref.fullName(rid)) || name || rid, tactics, tool, source, confidence });
  };
  let m;
  if (tool === 'mstrings') {
    MSTRINGS_ROW.lastIndex = 0;
    while ((m = MSTRINGS_ROW.exec(markdown)) !== null) {
      add(m[5], m[4], m[3].split(',').map(s => s.trim()).filter(Boolean), m[2], 'high');
    }
  } else if (tool === 'unpack') {
    UNPACK_MITRE_ROW.lastIndex = 0;
    while ((m = UNPACK_MITRE_ROW.exec(markdown)) !== null) add(m[1], m[2], [], m[2], 'high');
  } else {
    const entries = flagMap().filter(e => e.tool === tool);
    const seen = new Set();
    for (const line of markdown.split('\n')) {
      let text = line.replace(/^\s*[-*]\s*(\*\*\[!\]\*\*\s*)?/, '').trim();
      if (!text) continue;
      for (const e of entries) {
        if (!e.re.test(text)) continue;
        if (text.startsWith('|')) text = text.replace(/^\||\|$/g, '').split('|').map(c => c.trim()).filter(Boolean).join(': ');
        if (seen.has(e.technique + text)) continue;
        seen.add(e.technique + text);
        add(e.technique, '', [], text, e.confidence);
      }
    }
  }
  return hits;
}

function platformFor(filetype, fmt) {
  const ft = (filetype || '').toLowerCase();
  const f = fmt || '';
  const am = /\(([^)]*)\)\s*$/.exec(f);
  const arch = am ? am[1] : '';
  let base;
  if (ft.includes('portable-executable') || f.startsWith('PE')) base = 'Windows';
  else if (ft.includes('mach') || f.startsWith('Mach-O')) base = 'macOS';
  else if (ft.includes('x-executable') || f.startsWith('ELF')) base = 'Linux / Unix (ELF)';
  else if (ft.startsWith('text/')) base = 'Script / text';
  else return '';
  return arch ? `${base} (${arch})` : base;
}

function mdCell(text) {
  return String(text ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

// The offline toggle file, or MALCHELA_OFFLINE=1 in the environment (which
// the Rust tools also honor).
function lookupsOffline() {
  return isOfflineMode() || process.env.MALCHELA_OFFLINE === '1';
}

// ── IP reputation (capped) — mirrors the server's _lookup_ip_reputation() ────
// At most MALCHELA_IP_LOOKUPS (default 5) standalone IP IOCs per run are
// looked up through tiquery (VT, OTX, GreyNoise): a free VT key allows 4
// lookups a minute. IP address lists and public DNS resolvers never are.
const IP_LOOKUP_DEFAULT_CAP = 5;
const IP_LOOKUP_TIMEOUT_MS = 90000;

function ipLookupCap() {
  const n = parseInt(process.env.MALCHELA_IP_LOOKUPS ?? IP_LOOKUP_DEFAULT_CAP, 10);
  return Number.isFinite(n) && n >= 0 ? n : IP_LOOKUP_DEFAULT_CAP;
}

function isPublicIp(ip) {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (v4) {
    const [a, b] = [parseInt(v4[1], 10), parseInt(v4[2], 10)];
    if ([v4[1], v4[2], v4[3], v4[4]].some(x => parseInt(x, 10) > 255)) return false;
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)
      || ip.startsWith('192.0.2.') || ip.startsWith('198.51.100.') || ip.startsWith('203.0.113.') || (a === 198 && (b === 18 || b === 19)));
  }
  if (/^[0-9a-f:]+$/i.test(ip) && ip.includes(':')) {
    const l = ip.toLowerCase();
    return !(l === '::1' || l === '::' || /^f[cd]/.test(l) || /^fe[89ab]/.test(l) || l.startsWith('ff') || l.startsWith('2001:db8'));
  }
  return false;
}

function summarizeIpResults(results) {
  const parts = [];
  let flagged = false;
  for (const r of results || []) {
    const src = r.source || '?', st = r.status, fam = r.family || '', det = r.detections || '';
    if (st === 'found') {
      if (src === 'VT') {
        const m = /^(\d+)\/(\d+)/.exec(det);
        if (m && parseInt(m[1], 10) > 0) flagged = true;
        parts.push(`VT ${det}` + (fam ? ` · ${fam}` : ''));
      } else if (src === 'GN') {
        if (det === 'malicious') flagged = true;
        parts.push(`GreyNoise: ${fam}` + (det ? ` (${det})` : ''));
      } else if (src === 'OTX') {
        parts.push(`OTX ${det}` + (fam ? ` · ${fam}` : ''));
      } else {
        parts.push(`${src} ${det || 'found'}`);
      }
    } else if (st === 'not_found') {
      parts.push({ GN: 'GreyNoise: not seen scanning, not a known service', OTX: 'OTX: no pulses' }[src] || `${src}: not found`);
    } else if (st && typeof st === 'object' && st.error) {
      parts.push(`${src}: ${st.error}`);
    }
  }
  return { summary: parts.join('; '), flagged };
}

function lookupIpReputation(perFileResults) {
  const out = { ips: new Map(), skipped: 0, cap: ipLookupCap(), offline: lookupsOffline() };
  const candidates = [];
  for (const f of perFileResults) {
    for (const run of f.tool_runs || []) {
      if (run.tool !== 'mstrings' || !run.success || !run.markdown) continue;
      for (const ioc of extractMstringsIocs(run.markdown).net) {
        const ip = ioc.trim().replace(/\[\.\]/g, '.').replace(/\[:\]/g, ':');
        if (isPublicIp(ip) && !candidates.includes(ip)) candidates.push(ip);
      }
    }
  }
  if (out.offline || out.cap === 0 || !candidates.length) {
    out.skipped = candidates.length;
    return out;
  }
  const binary = `${RELEASE_DIR}/tiquery`;
  candidates.forEach((ip, i) => {
    if (i >= out.cap) { out.skipped = candidates.length - out.cap; return; }
    const args = [ip, '--json'];
    if (currentCase) args.push('--case', currentCase, '-o', '-m');
    let results = [];
    try {
      const raw = execFileSync(binary, args, { cwd: MALCHELA_DIR, encoding: 'utf8', timeout: IP_LOOKUP_TIMEOUT_MS, maxBuffer: ANALYZE_MAX_BUFFER });
      results = JSON.parse(raw || '[]');
    } catch (err) {
      const line = String(err.stderr || err.message || '').trim().split('\n').pop();
      out.ips.set(ip, { summary: `lookup failed: ${line.slice(0, 80)}`, flagged: false });
      return;
    }
    if (currentCase) readToolMarkdown('tiquery', currentCase, `ip_${ip.replace(/[.:]/g, '-')}`);
    const s = summarizeIpResults(results);
    out.ips.set(ip, results.length ? s : { summary: 'no IP reputation source configured (add a VT, OTX, or GreyNoise key)', flagged: false });
  });
  return out;
}

function ipRepNote(rep) {
  if (!rep) return 'Not run';
  const looked = rep.ips.size, skipped = rep.skipped;
  if (rep.offline) return 'Off (offline mode)' + (skipped ? ` — ${skipped} standalone IP(s) not looked up` : '');
  if (rep.cap === 0) return 'Off (MALCHELA_IP_LOOKUPS=0)';
  if (!looked && !skipped) return 'No standalone public IPs to look up';
  let s = `${looked} standalone IP(s) looked up via tiquery (VT, OTX, GreyNoise)`;
  if (skipped) s += `; ${skipped} more not looked up (cap ${rep.cap}, set MALCHELA_IP_LOOKUPS to change)`;
  return s + '; IP address lists and public DNS resolvers are never looked up';
}

function buildAnalyzeRollup(target, perFileResults, extractionNote, ipReputation = null) {
  const groups = new Map();
  const order = [];
  for (const f of perFileResults) {
    const key = f.sha256 || f.filepath;
    if (!groups.has(key)) { groups.set(key, []); order.push(key); }
    groups.get(key).push(f);
  }
  // Anchor ids keyed by the SHA256/filepath dedup key (not by filename), as
  // explicit <a id=...> tags so no heading-slug algorithm has to match.
  const anchorByKey = new Map(order.map((key, idx) => [key, `file-${idx}`]));
  const link = (name, anchor) => `[\`${name}\`](#${anchor})`;

  const flagged = [];
  const dupGroups = [];
  let mitreTotal = 0;
  let mitreStrings = 0;
  const tiRows = []; const tiSeen = new Set();
  const flagFindings = [];
  const fsIocs = []; const fsIocsSeen = new Set();
  const netIocs = []; const netIocsSeen = new Set();
  const ipLists = []; // { count, range, ips, anchor, fname }
  const obfuscationFindings = [];
  const revokedCerts = [];
  const packerFindings = [];
  const fmtByKey = new Map();
  const toolsRun = {};
  const techs = new Map(); // id -> { id, name, tactics:Set, hits:[], files:[] , high:bool }

  for (const key of order) {
    const members = groups.get(key);
    const anchor = anchorByKey.get(key);
    const fname = members[0].filename;
    if (flagVerdict(members[0].tool_runs).flagged) flagged.push({ filename: fname, anchor });
    if (members.length > 1) dupGroups.push(members);
    for (const run of members[0].tool_runs) {
      toolsRun[run.tool] = (toolsRun[run.tool] || 0) + 1;
      const md = run.success ? (run.markdown || '') : '';
      if (run.tool === 'unpack' && run.success) {
        const m = UNPACK_VERDICT.exec(md);
        packerFindings.push({ filename: fname, verdict: m ? m[1].trim() : run.output, anchor });
        const fm = UNPACK_FORMAT.exec(md);
        if (fm) fmtByKey.set(key, fm[1].trim());
      }
      if (run.tool === 'codesign_check' && md && extractRevokedCert(md)) revokedCerts.push({ filename: fname, anchor });
      if (run.tool === 'mstrings' && md) {
        const { rawTotal, ruleHits } = extractMitreTactics(md);
        mitreTotal += ruleHits;
        mitreStrings += rawTotal;
        const { fs, net } = extractMstringsIocs(md);
        for (const l of extractIpLists(md)) ipLists.push({ ...l, anchor, fname });
        for (const ioc of fs) if (!fsIocsSeen.has(ioc)) { fsIocsSeen.add(ioc); fsIocs.push({ ioc, anchor, fname }); }
        for (const ioc of net) if (!netIocsSeen.has(ioc)) { netIocsSeen.add(ioc); netIocs.push({ ioc, anchor, fname }); }
        const maxLayers = extractMaxObfuscationLayers(md);
        if (maxLayers > 1) obfuscationFindings.push({ filename: fname, maxLayers });
      }
      if (run.tool === 'tiquery' && md) {
        TIQUERY_FOUND_ROW.lastIndex = 0;
        let m;
        while ((m = TIQUERY_FOUND_ROW.exec(md)) !== null) {
          const [src, fam, det] = [m[1], m[2], m[3]];
          if (fam && !tiSeen.has(src + '\u0000' + fam)) { tiSeen.add(src + '\u0000' + fam); tiRows.push({ src, fam, det }); }
        }
      }
      if (md && ['macho_info', 'plist_analyzer', 'codesign_check'].includes(run.tool)) {
        for (const text of extractFlags(run.tool, md)) flagFindings.push({ filename: fname, tool: run.tool, text, anchor });
      }
      if (md) {
        for (const h of techniqueHits(run.tool, md)) {
          if (!techs.has(h.id)) techs.set(h.id, { id: h.id, name: h.name, tactics: new Set(), evidence: [], files: [], high: false });
          const t = techs.get(h.id);
          h.tactics.forEach(x => t.tactics.add(x));
          const ev = `${h.tool}: ${h.source || ''}`.trim();
          if (!t.evidence.includes(ev)) t.evidence.push(ev);
          if (!t.files.some(f => f.anchor === anchor)) t.files.push({ name: fname, anchor });
          if (h.confidence === 'high') t.high = true;
        }
      }
    }
  }

  const topKeys = order.filter(k => !groups.get(k)[0].unpacked_from);
  const single = topKeys.length === 1;
  const offline = lookupsOffline();

  // ── Header ──
  const lines = [
    `# MalChela Summary — ${target}`,
    '',
    `Generated: ${new Date().toISOString()}  `,
    `Files analyzed: ${perFileResults.length}  `,
  ];
  if (extractionNote) lines.push(`_${extractionNote}_`);
  lines.push(
    '',
    "_An evidence rollup in the order of Lenny Zeltser's Malware Analysis Report template. " +
    "Sections that need an analyst's judgment (Executive Summary, family confidence, What We " +
    "Don't Know, Infection Vector) are left for the written report. Links jump to that file's " +
    'section below; network indicators are defanged (hxxp, `[.]`)._',
    '',
  );

  // ── Sample Snapshot ──
  lines.push('## Sample Snapshot', '', '|  |  |', '|---|---|');
  let ti;
  if (tiRows.length) {
    ti = tiRows.slice(0, 8).map(r => `${mdCell(r.fam)} — ${r.src}` + (r.det ? ` ${mdCell(r.det)}` : '')).join('; ');
    if (tiRows.length > 8) ti += `; +${tiRows.length - 8} more`;
  } else if (offline) ti = 'Not queried (offline mode)';
  else if (toolsRun.tiquery) ti = 'No match in the queried sources';
  else ti = 'Not queried';
  lines.push(`| **Threat Intel Matches** | ${ti} |`);
  if (flagged.length) {
    lines.push(`| **VirusTotal** | ⚠ ${flagged.length} of ${order.length} file(s) flagged malicious: ` +
      flagged.map(f => link(f.filename, f.anchor)).join(', ') + ' |');
  } else if (offline) lines.push('| **VirusTotal** | Not queried (offline mode) |');
  else if (toolsRun.tiquery || toolsRun.fileanalyzer) lines.push('| **VirusTotal** | No file flagged malicious |');
  const platforms = [];
  for (const k of topKeys) {
    const pl = platformFor(groups.get(k)[0].filetype, fmtByKey.get(k));
    if (pl && !platforms.includes(pl)) platforms.push(pl);
  }
  if (platforms.length) lines.push(`| **Target Platform** | ${mdCell(platforms.join(', '))} |`);
  if (single) {
    const p0 = groups.get(topKeys[0])[0];
    lines.push(`| **Primary Artifact** | ${link(p0.filename, anchorByKey.get(topKeys[0]))}` + (p0.sha256 ? ` — SHA-256 \`${p0.sha256}\`` : '') + ' |');
  }
  const pk = packerFindings.map(p => `${link(p.filename, p.anchor)} — ${mdCell(p.verdict)}`)
    .concat(obfuscationFindings.map(o => `\`${o.filename}\` — ${o.maxLayers} layers of base64 (mStrings)`));
  lines.push(`| **Packing / Obfuscation** | ${pk.length ? pk.join('; ') : 'None detected'} |`);
  if (revokedCerts.length) {
    lines.push('| **Code Signing** | ⚠ certificate REVOKED (Apple OCSP): ' + revokedCerts.map(r => link(r.filename, r.anchor)).join(', ') + ' |');
  }
  if (order.length !== perFileResults.length) {
    lines.push(`| **Files** | ${order.length} unique across ${perFileResults.length} paths (${perFileResults.length - order.length} duplicate instance(s) collapsed) |`);
  } else {
    lines.push(`| **Files** | ${order.length} |`);
  }
  lines.push('');

  // ── Component Inventory ──
  lines.push('## Component Inventory', '', '| Role | File Name | File Type | Notes |', '|---|---|---|---|');
  for (const key of order) {
    const members = groups.get(key);
    const pf = members[0];
    const anchor = anchorByKey.get(key);
    const role = pf.unpacked_from
      ? 'Recovered payload' + (pf.unpack_source ? ` (${pf.unpack_source})` : '')
      : (single ? 'Primary artifact' : 'Analyzed file');
    const notes = [];
    if (pf.unpacked_from) notes.push(`unpacked from \`${pf.unpacked_from}\``);
    if (members.length > 1) notes.push('also found as ' + members.slice(1).map(m => `\`${m.filename}\``).join(', '));
    const nflags = flagFindings.filter(f => f.anchor === anchor).length;
    if (nflags) notes.push(`${nflags} tool flag(s)`);
    lines.push(`| ${mdCell(role)} | ${link(pf.filename, anchor)} | ${mdCell(fmtByKey.get(key) || pf.filetype)} | ${mdCell(notes.join('; '))} |`);
  }
  lines.push('');

  // ── Capabilities ──
  lines.push(
    '## Capabilities',
    '',
    '_ATT&CK techniques from mStrings rules, Unpack, and tool flags (`assets/flag_attack_map.yaml`). ' +
    'These are rule hits: evidence to corroborate, not confirmed behavior. Hits from a bundler\'s ' +
    'bootloader or runtime describe the wrapper, not the sample._',
    '',
    '- **MITRE ATT&CK matrix:** open this case in the MalChela PWA (Cases → ⊞ MITRE) for the interactive Enterprise matrix and an ATT&CK Navigator layer',
  );
  if (mitreTotal) lines.push(`- **${mitreTotal} MITRE ATT&CK rule hit(s)** (mstrings; ${mitreStrings} matched strings)`);
  if (techs.size) {
    const ref = attackReference();
    const tacOrder = ref ? ref.tactics.map(t => t.shortname) : [];
    const tacName = ref ? new Map(ref.tactics.map(t => [t.shortname, t.name])) : new Map();
    const idx = (s) => { const i = tacOrder.indexOf(s); return i < 0 ? 99 : i; };
    const rows = [...techs.values()].sort((a, b) =>
      (Math.min(...[...a.tactics].map(idx), 99) - Math.min(...[...b.tactics].map(idx), 99)) || a.id.localeCompare(b.id));
    lines.push('', '| Tactic | Technique | Evidence | Files |', '|---|---|---|---|');
    for (const t of rows) {
      const tacs = [...t.tactics].sort((a, b) => idx(a) - idx(b)).map(s => tacName.get(s) || s).join(', ');
      const ev = t.evidence.slice(0, 3).join('; ') + (t.evidence.length > 3 ? `; +${t.evidence.length - 3} more` : '');
      const low = t.high ? '' : ' _(low confidence)_';
      lines.push(`| ${mdCell(tacs)} | ${t.id} ${mdCell(t.name)}${low} | ${mdCell(ev)} | ${t.files.map(f => link(f.name, f.anchor)).join(', ')} |`);
    }
  } else {
    lines.push('', '_No ATT&CK techniques matched._');
  }
  lines.push('');

  // ── Indicators of Compromise ──
  lines.push(
    '## Indicators of Compromise',
    '',
    '_Strings the tools extracted that match indicator patterns. Before listing one in a report, ' +
    'confirm the sample uses it: strings from packed, encrypted, or anti-analysis data (a sandbox ' +
    'IP blocklist, for example) are not indicators on their own. Public DNS resolvers are listed ' +
    'separately in each mStrings report and are not C2._',
    '',
    '| Type | Indicator | Context |',
    '|---|---|---|',
  );
  for (const key of order) {
    const pf = groups.get(key)[0];
    if (!pf.sha256) continue;
    const role = pf.unpacked_from ? 'recovered payload' : (single ? 'primary artifact' : 'analyzed file');
    lines.push(`| Hash Values | \`${pf.sha256}\` | ${role} — ${link(pf.filename, anchorByKey.get(key))}` + (pf.md5 ? `; MD5 \`${pf.md5}\`` : '') + ' |');
  }
  const ips = [], urls = [], domains = [];
  for (const { ioc, anchor, fname } of netIocs) {
    const d = defang(ioc);
    if (IPV4_RE.test(ioc.trim())) ips.push({ ioc: d, anchor, fname });
    else if (ioc.includes('://')) urls.push({ ioc: d, anchor, fname });
    else domains.push({ ioc: d, anchor, fname });
  }
  const urlHosts = [];
  for (const u of urls) {
    const host = u.ioc.split('://').pop().split('/')[0].split(':')[0];
    if (IPV4_RE.test(host)) continue; // an IP host is already under IP Addresses
    if (host && !urlHosts.some(h => h.ioc === host) && !domains.some(d => d.ioc === host)) urlHosts.push({ ioc: host, anchor: u.anchor, fname: u.fname });
  }
  const iocRows = (kind, items, note = '') => {
    items.some((it, i) => {
      if (i >= SUMMARY_ROW_CAP) {
        lines.push(`| ${kind} | _+${items.length - SUMMARY_ROW_CAP} more_ | see the mStrings reports below |`);
        return true;
      }
      const rep = ipReputation && ipReputation.ips.get(it.ioc.replace(/\[\.\]/g, '.').replace(/\[:\]/g, ':'));
      const repText = rep && rep.summary ? `; ${rep.flagged ? '⚠ ' : ''}${mdCell(rep.summary)}` : '';
      lines.push(`| ${kind} | \`${mdCell(it.ioc)}\` | mStrings — ${link(it.fname, it.anchor)}${note ? `; ${note}` : ''}${repText} |`);
      return false;
    });
  };
  iocRows('IP Addresses', ips);
  for (const l of ipLists) {
    const shown = l.ips.slice(0, 3).map(x => `\`${mdCell(x)}\``).join(', ') + (l.ips.length > 3 ? ', …' : '');
    lines.push(`| IP Address List | ${l.count} addresses stored together at ${l.range}: ${shown} | ` +
      `possible anti-analysis blocklist or C2 pool, not counted as IP indicators — mStrings — ${link(l.fname, l.anchor)} |`);
  }
  iocRows('Domain Names', domains.concat(urlHosts));
  iocRows('Network Artifacts', urls, 'URL');
  iocRows('Host Artifacts', fsIocs);
  if (!(ips.length || urls.length || domains.length || ipLists.length)) lines.push('| Network | _none extracted_ | |');
  lines.push('');

  // ── Analysis Details ──
  lines.push(
    '## Analysis Details',
    '',
    '_Static analysis only: MalChela never executes a sample, so behavioral, memory, and dynamic ' +
    "code analysis were not performed. Every tool's full output follows, one section per file " +
    '(Static Properties Analysis)._',
    '',
  );
  if (flagFindings.length) {
    lines.push(`**Tool flags:** ${flagFindings.length} across ${new Set(flagFindings.map(f => f.filename)).size} file(s)`, '');
    for (const f of flagFindings) lines.push(`- ${link(f.filename, f.anchor)} (${f.tool}): ${f.text}`);
    lines.push('');
  }
  for (const members of dupGroups) {
    lines.push(`- **Duplicate content:** ${members.map(m => `\`${m.filename}\``).join(', ')} share SHA256 \`${members[0].sha256}\``);
  }
  if (dupGroups.length) lines.push('');

  for (const key of order) {
    const members = groups.get(key);
    const primary = members[0];
    lines.push(`<a id="${anchorByKey.get(key)}"></a>`, `## ${primary.filename}`, '');
    if (members.length > 1) {
      lines.push(`- **Also found as:** ${members.slice(1).map(m => `\`${m.filename}\``).join(', ')} — identical content, tool output shown once`);
    }
    if (primary.unpacked_from) {
      lines.push(`- **Unpacked from:** \`${primary.unpacked_from}\`` + (primary.unpack_source ? ` (${primary.unpack_source})` : ''));
    }
    lines.push(`- **Path:** \`${primary.filepath}\``, `- **Type:** ${primary.filetype}`);
    if (primary.sha256) lines.push(`- **SHA256:** \`${primary.sha256}\``);
    if (primary.md5) lines.push(`- **MD5:** \`${primary.md5}\``);
    lines.push('');
    if (!primary.tool_runs.length) {
      lines.push('_No suggested tools for this file type._', '');
      continue;
    }
    for (const run of primary.tool_runs) {
      lines.push(`### ${run.success ? '✓' : '✕'} ${run.label} (\`${run.tool}\`)`, '');
      if (run.success && run.markdown) lines.push(demoteMarkdownHeadings(run.markdown), '');
      else if (run.success) lines.push('```', run.output || '(no output)', '```', '');
      else lines.push(`**Error:** ${run.error || 'Tool run failed.'}`, '');
    }
  }

  // ── Appendix: Analysis Environment ──
  const ran = Object.entries(toolsRun).filter(([t]) => t).sort().map(([t, n]) => `${t} (${n})`).join(', ');
  lines.push(
    '## Appendix: Analysis Environment',
    '',
    '|  |  |',
    '|---|---|',
    `| **Toolkit** | MalChela v${MALCHELA_VERSION} — Analyze (MCP plugin) |`,
    '| **Analysis Depth** | Static only — samples were never executed or emulated |',
    `| **Tools Run** | ${mdCell(ran) || 'none'} |`,
    `| **Network Lookups** | ${offline ? 'Off (offline mode)' : 'Threat intel and NSRL lookups by hash; samples are never uploaded'} |`,
    `| **IP Reputation** | ${ipRepNote(ipReputation)} |`,
    `| **Host** | ${mdCell(`${process.platform} ${process.arch}`)} |`,
    `| **Generated** | ${new Date().toISOString().slice(0, 19)} |`,
    '',
  );
  return lines.join('\n');
}

const OVER_CAP_LIST_LIMIT = 40; // beyond mismatches, cap the plain listing so the
                                 // response stays a reasonable size for the caller

function buildOverCapSummary(target, scanResults, extractionNote) {
  const mismatches = scanResults.filter(r => r.extension_mismatch);
  const rest = scanResults.filter(r => !r.extension_mismatch);

  const describe = r => {
    const tools = (r.suggested_tools || [])
      .filter(p => Array.isArray(p) && p.length === 2)
      .map(p => p[0]);
    return `- \`${r.filepath}\` (${r.filetype || 'unknown'})` +
      (tools.length ? ` — suggested: ${tools.join(', ')}` : '');
  };

  const lines = [
    `Analyze found ${scanResults.length} file(s) at ${target} — over the auto-run cap ` +
      `(${ANALYZE_MAX_FILES}), so suggested tools were not auto-run.`,
  ];
  if (extractionNote) lines.push(`_${extractionNote}_`);
  lines.push('', 'Call fileanalyzer/mstrings/macho_info/etc. yourself on whichever files below matter, ' +
    'or call fileminer directly on the target for the complete list.', '');

  if (mismatches.length) {
    lines.push(`## Extension mismatches (${mismatches.length}) — start here`, '', ...mismatches.map(describe), '');
  }

  const shown = rest.slice(0, OVER_CAP_LIST_LIMIT);
  lines.push(`## Other files (${rest.length})`, '', ...shown.map(describe));
  if (rest.length > shown.length) {
    lines.push(`- …and ${rest.length - shown.length} more — call fileminer directly on ${target} for the full list.`);
  }

  return lines.join('\n');
}

// If target is a .zip (the only way to get a directory-based sample like a
// .app bundle into a system through a file-only upload path), extract it
// into a sibling '<stem>_extracted' directory and return that as the new
// analyze target, plus a note for the rollup. Tries no password first, then
// the same common malware-zip passwords Extract Samples uses. Shells out to
// `unzip` (present on virtually every macOS/Linux host, including the
// Raspberry Pi / REMnux hosts MalChela runs on) rather than adding a zip
// npm dependency, mirroring the same reasoning as the Python route's use of
// the zipfile stdlib instead of 7z. Returns { target: targetPath, note: null }
// unchanged if target isn't a .zip.
const ZIP_PASSWORDS = [null, 'infected', 'malware', 'virus']; // null tried first = no password

function maybeExtractZip(targetPath) {
  if (!targetPath.toLowerCase().endsWith('.zip')) {
    return { target: targetPath, note: null };
  }

  const filename = basename(targetPath);
  const stem = filename.slice(0, -4);
  const extractDir = `${dirname(targetPath)}/${stem}_extracted`;

  for (const pwd of ZIP_PASSWORDS) {
    try { rmSync(extractDir, { recursive: true, force: true }); } catch { /* didn't exist */ }
    const unzipArgs = [...(pwd !== null ? ['-P', pwd] : []), '-q', targetPath, '-d', extractDir];
    try {
      execFileSync('unzip', unzipArgs, { timeout: 30000 });
      const note = `Auto-extracted \`${filename}\`` + (pwd ? ` (password: \`${pwd}\`)` : '');
      return { target: extractDir, note };
    } catch {
      continue; // wrong password (or extraction failed) — try the next one
    }
  }

  throw new Error(
    `${filename} is password-protected with a password not in the common list ` +
    `(infected/malware/virus). Extract it manually with Extract Samples first.`
  );
}

// If target is a .dmg or .pkg, shell out to dpp_extract to walk
// UDIF -> HFS+/APFS -> XAR -> PBZX/CPIO and return the extracted directory
// as the new analyze target, plus a note for the rollup. Ports
// server/malchela_server.py's _maybe_extract_dpp(). Returns
// { target: targetPath, note: null } unchanged if target isn't a .dmg/.pkg.
function maybeExtractDpp(targetPath) {
  const ext = targetPath.toLowerCase().slice(targetPath.lastIndexOf('.'));
  if (ext !== '.dmg' && ext !== '.pkg') {
    return { target: targetPath, note: null };
  }

  const filename = basename(targetPath);
  const stem = filename.slice(0, filename.length - ext.length);
  const extractDir = `${dirname(targetPath)}/${stem}_extracted`;
  try { rmSync(extractDir, { recursive: true, force: true }); } catch { /* didn't exist */ }

  const binary = `${RELEASE_DIR}/dpp_extract`;
  if (!existsSync(binary)) {
    throw new Error(`Binary not found: ${binary}\nBuild MalChela first: cd ${MALCHELA_DIR} && ./release.sh`);
  }

  let output;
  try {
    output = execFileSync(binary, [targetPath, '-o', extractDir, '--json'], {
      cwd: MALCHELA_DIR, encoding: 'utf8', timeout: DPP_EXTRACT_TIMEOUT_MS,
    });
  } catch (err) {
    throw new Error(`dpp_extract failed to run: ${err.message}`);
  }

  let summary;
  try {
    summary = JSON.parse(output);
  } catch (e) {
    throw new Error(`Could not parse dpp_extract output: ${e.message}`);
  }
  if (!summary.success) {
    throw new Error(summary.error || `dpp_extract could not unpack ${filename}`);
  }

  let note = `Auto-extracted \`${filename}\` via dpp_extract — ${summary.note || ''}`.trim();
  if (summary.skipped?.length) {
    note += ` (${summary.skipped.length} entries skipped — see dpp_extract output for detail)`;
  }
  return { target: summary.extracted_dir, note };
}

// Dispatch to the right auto-extraction step for Analyze's target based on
// file type: .zip (a directory-based sample) or .dmg/.pkg (an Apple disk
// image / installer). Mirrors server/malchela_server.py's
// _maybe_extract_container().
function maybeExtractContainer(targetPath) {
  const zipResult = maybeExtractZip(targetPath);
  if (zipResult.note !== null) return zipResult;
  return maybeExtractDpp(targetPath);
}

const NESTED_CONTAINER_EXTS = new Set(['.zip', '.dmg', '.pkg']);
const MAX_NESTED_EXTRACTIONS = 5; // guard against zip bombs / deeply nested archives

// maybeExtractContainer only ever runs on Analyze's top-level target —
// FileMiner has no suggested_tools branch for a raw .zip/.dmg/.pkg found
// mid-scan (by design: containers are meant to be unwrapped once, up front,
// not per-file), so a container discovered while walking a directory just
// shows suggested_tools: [] and silently gets skipped. That's routine for a
// sample shipped as a lone .zip inside its own folder (nothing else to find
// until it's extracted) — no signal about the sample, just a gap in dispatch.
//
// Extracts any such container in place (reusing the same helpers the
// top-level target uses) and folds a fresh fileminer scan of the extracted
// directory into scanResults, breadth-first, so a container nested inside an
// extracted container also gets unwrapped. Capped at MAX_NESTED_EXTRACTIONS
// total extractions per Analyze run as a guard against zip bombs or
// pathological nesting; a password not in the common list is left as-is
// (surfaces as an unanalyzed file, same as today, rather than failing the
// whole Analyze run). Mutates scanResults in place, returns extraction notes.
function expandNestedContainers(scanResults) {
  const notes = [];
  const queue = [...scanResults];
  let extractedCount = 0;
  const seenDirs = new Set();

  while (queue.length && extractedCount < MAX_NESTED_EXTRACTIONS) {
    const res = queue.shift();
    if (res.suggested_tools && res.suggested_tools.length) continue;
    const ext = extname(res.filepath || '').toLowerCase();
    if (!NESTED_CONTAINER_EXTS.has(ext)) continue;

    let extractedDir, note;
    try {
      ({ target: extractedDir, note } = maybeExtractContainer(res.filepath));
    } catch {
      continue; // e.g. zip password not in the common list — leave as-is
    }
    if (note === null) continue;
    const resolved = realpathSync(extractedDir);
    if (seenDirs.has(resolved)) continue;
    seenDirs.add(resolved);
    extractedCount++;
    notes.push(note);

    const fmBinary = `${RELEASE_DIR}/fileminer`;
    const fmArgs = [extractedDir, '--no-prompt'];
    if (currentCase) fmArgs.push('--case', currentCase);
    let fmOutput;
    try {
      fmOutput = execFileSync(fmBinary, fmArgs, {
        cwd: MALCHELA_DIR, encoding: 'utf8', timeout: FILEMINER_TIMEOUT_MS, maxBuffer: ANALYZE_MAX_BUFFER,
      });
    } catch {
      continue;
    }
    let fmData;
    try { fmData = JSON.parse(fmOutput); } catch { continue; }
    const newResults = fmData.results || [];
    scanResults.push(...newResults);
    queue.push(...newResults);
  }

  return notes;
}

// Run unpack once against every executable fileminer suggested it for, and
// fold each recovered payload back into scanResults as its own file so the
// per-file dispatch analyses the real payload, not just the packer stub.
// unpack recurses internally (depth/size capped there), so payloads it
// returns are not re-unpacked. Only runs that found something are kept
// (--only-if-found keeps clean binaries from leaving case reports). Mirrors
// server/malchela_server.py's _expand_packed_executables().
const UNPACK_MAX_CANDIDATES = 25;
// Tools still run on a universal binary after it is split into slices (hash
// lookups describe the distributed file; content tools run on the slices).
const CONTAINER_TOOLS = new Set(['tiquery', 'nsrlquery']);

function expandPackedExecutables(scanResults) {
  const notes = [];
  const runs = new Map(); // original filepath -> Unpack tool_run
  const binary = `${RELEASE_DIR}/unpack`;
  if (!existsSync(binary)) return { notes, runs };
  const candidates = scanResults
    .filter(r => (r.suggested_tools || []).some(p => Array.isArray(p) && p[1] === 'unpack'))
    .slice(0, UNPACK_MAX_CANDIDATES);

  for (const res of candidates) {
    const cmdArgs = [res.filepath, '--json', '-o', '-m', '--only-if-found'];
    if (currentCase) cmdArgs.push('--case', currentCase);
    let summary;
    try {
      const out = execFileSync(binary, cmdArgs, {
        cwd: MALCHELA_DIR, encoding: 'utf8', timeout: UNPACK_TIMEOUT_MS, maxBuffer: ANALYZE_MAX_BUFFER,
      });
      summary = JSON.parse(out);
    } catch {
      continue;
    }
    if (!summary.success || !summary.significant) continue;

    runs.set(res.filepath, {
      label: 'Unpack', tool: 'unpack', success: true,
      output: summary.verdict || '', error: '', markdown: readToolMarkdown('unpack', currentCase, res.filepath),
      // Universal Mach-O split into slices: the slices get the full tool run,
      // the container only its hash lookups (see the dispatch loop).
      splitContainer: ((summary.tree || {}).verdicts || []).some(v => v.id === 'fat_macho'),
    });
    notes.push(`Unpacked \`${res.filename}\`: ${summary.verdict}.`);

    for (const p of summary.payloads || []) {
      if (!p.path || !existsSync(p.path)) continue;
      const fmArgs = [p.path, '--no-prompt'];
      if (currentCase) fmArgs.push('--case', currentCase);
      let fmData;
      try {
        fmData = JSON.parse(execFileSync(`${RELEASE_DIR}/fileminer`, fmArgs, {
          cwd: MALCHELA_DIR, encoding: 'utf8', timeout: FILEMINER_TIMEOUT_MS, maxBuffer: ANALYZE_MAX_BUFFER,
        }));
      } catch {
        continue;
      }
      const resolved = realpathSync(p.path);
      for (const nr of fmData.results || []) {
        if (pathsMatch(nr.filepath, resolved)) {
          nr.unpacked_from = res.filename;
          nr.unpack_source = p.source || '';
          scanResults.push(nr);
        }
      }
    }
  }
  return { notes, runs };
}

function runAnalyze(rawTargetPath) {
  if (!existsSync(rawTargetPath)) {
    throw new Error(`Path does not exist: ${rawTargetPath}`);
  }

  const { target: targetPath, note: extractionNote } = maybeExtractContainer(rawTargetPath);

  const fmBinary = `${RELEASE_DIR}/fileminer`;
  if (!existsSync(fmBinary)) {
    throw new Error(
      `Binary not found: ${fmBinary}\n` +
      `Build MalChela first: cd ${MALCHELA_DIR} && ./release.sh`
    );
  }

  // fileminer scans a single file directly when given one, rather than its
  // whole containing directory — pointing Analyze at a file dropped into a
  // large folder (Downloads, an inbox) used to trigger a full recursive scan
  // (hash + type-ID) of every other file in that folder too.
  const singleFileMode = statSync(targetPath).isFile();

  const fmArgs = [targetPath, '--no-prompt'];
  if (currentCase) fmArgs.push('--case', currentCase);

  let fmOutput;
  try {
    fmOutput = execFileSync(fmBinary, fmArgs, {
      cwd: MALCHELA_DIR, encoding: 'utf8', timeout: FILEMINER_TIMEOUT_MS, maxBuffer: ANALYZE_MAX_BUFFER,
    });
  } catch (err) {
    throw new Error(`fileminer failed to run: ${err.message}`);
  }

  let fmData;
  try {
    fmData = JSON.parse(fmOutput);
  } catch (e) {
    throw new Error(`Could not parse fileminer output: ${e.message}`);
  }

  let scanResults = fmData.results || [];

  let finalExtractionNote = extractionNote;
  let resolvedTarget = null;
  if (singleFileMode) {
    resolvedTarget = realpathSync(targetPath);
    scanResults = scanResults.filter(r => pathsMatch(r.filepath, resolvedTarget));
    if (scanResults.length === 0) {
      throw new Error(
        "Selected file was not found in fileminer's scan results " +
        '(it may be a hidden/skipped file type).'
      );
    }
  } else {
    const nestedNotes = expandNestedContainers(scanResults);
    if (nestedNotes.length) {
      finalExtractionNote = [extractionNote, ...nestedNotes].filter(Boolean).join(' ');
    }
  }

  const { notes: unpackNotes, runs: unpackRuns } = expandPackedExecutables(scanResults);
  if (unpackNotes.length) {
    finalExtractionNote = [finalExtractionNote, ...unpackNotes].filter(Boolean).join(' ');
  }

  if (scanResults.length > ANALYZE_MAX_FILES) {
    // Too many files to auto-run every suggested tool on every one — routine
    // for a dpp-extracted PKG payload (a trojanized installer commonly
    // bundles the full legitimate app it trojanized alongside the injected
    // malicious file(s); EvilQuest: 624 files for one Mach-O of actual
    // interest) but can happen pointed straight at a folder too. The web UI
    // hands this off to File Miner's interactive table; there's no browser
    // here, so return the same information directly as text — mismatched
    // files first — so the calling agent can call fileanalyzer/mstrings/
    // macho_info/etc. itself on whichever files matter, or call fileminer
    // directly on targetPath for the complete un-truncated list.
    return buildOverCapSummary(targetPath, scanResults, finalExtractionNote);
  }

  const perFileResults = [];
  for (const res of scanResults) {
    const filepath = res.filepath || '';
    const sha256   = res.sha256 || '';
    const md5      = res.md5 || '';
    const suggested = res.suggested_tools || [];

    const toolRuns = [];
    if (unpackRuns.has(filepath)) toolRuns.push(unpackRuns.get(filepath));
    for (const pair of suggested) {
      if (!Array.isArray(pair) || pair.length !== 2) continue;
      const [label, slug] = pair;
      if (slug === 'unpack') continue; // already run (once, recursively) by expandPackedExecutables
      if (unpackRuns.get(filepath)?.splitContainer && !CONTAINER_TOOLS.has(slug)) continue; // analysed per-slice

      const arg = slug === 'tiquery' ? sha256 : slug === 'nsrlquery' ? md5 : filepath;
      if (!arg) {
        toolRuns.push({ label, tool: slug, success: false, output: '', error: 'Missing hash required for this tool.' });
        continue;
      }

      const binary = `${RELEASE_DIR}/${slug}`;
      if (!existsSync(binary)) {
        toolRuns.push({ label, tool: slug, success: false, output: '', error: `Binary not found: ${binary}` });
        continue;
      }

      // Always save a markdown report — case or not — so the rollup can embed
      // each tool's actual formatted output (headers, tables) instead of raw
      // CLI stdout. This is Analyze's own internal read-back, independent of
      // the -t default every other MCP tool call uses via buildCommand.
      const cmdArgs = [arg, '-o', '-m'];
      if (currentCase) cmdArgs.push('--case', currentCase);
      // OCSP revocation needs network access, so it's skipped in offline
      // mode, and scoped to the top-level binary only — a single bundle can
      // embed 90+ signed frameworks/helpers, each of which would otherwise
      // fire its own OCSP query.
      if (slug === 'codesign_check' && !isOfflineMode() && isTopLevelBinary(filepath, singleFileMode, resolvedTarget)) {
        cmdArgs.push('--check-revocation');
      }

      try {
        const output = execFileSync(binary, cmdArgs, {
          cwd: MALCHELA_DIR, encoding: 'utf8', timeout: ANALYZE_TIMEOUT_MS, maxBuffer: ANALYZE_MAX_BUFFER,
        }).trim();
        const markdown = readToolMarkdown(slug, currentCase, filepath);
        toolRuns.push({ label, tool: slug, success: true, output, error: '', markdown });
      } catch (err) {
        const detail = err.stdout
          ? `${err.message}\n\nSTDOUT:\n${err.stdout}\n\nSTDERR:\n${err.stderr}`
          : err.message;
        toolRuns.push({ label, tool: slug, success: false, output: '', error: detail });
      }
    }

    perFileResults.push({
      filename: res.filename || '', filepath, filetype: res.filetype || '',
      sha256, md5, tool_runs: toolRuns,
      unpacked_from: res.unpacked_from || '', unpack_source: res.unpack_source || '',
    });
  }

  const ipReputation = lookupIpReputation(perFileResults);
  const rollup = buildAnalyzeRollup(targetPath, perFileResults, finalExtractionNote, ipReputation);
  const ts = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '').replace('T', '_');
  // The "analyze" subfolder matters, not just cosmetically: registerCaseOutput
  // below records the entry's path as "analyze/<filename>", so the file has
  // to actually live there for the PWA's case browser to resolve the link.
  const rollupDir = currentCase
    ? `${MALCHELA_DIR}/saved_output/cases/${currentCase}/analyze`
    : `${MALCHELA_DIR}/saved_output/analyze`;
  mkdirSync(rollupDir, { recursive: true });
  const rollupPath = `${rollupDir}/malchela_summary_${ts}.md`;
  writeFileSync(rollupPath, rollup);

  if (currentCase) {
    registerCaseOutput('analyze', currentCase, targetPath, rollupPath);
  }

  const fileCount = perFileResults.length;
  const toolCount = perFileResults.reduce((n, f) => n + f.tool_runs.length, 0);
  const failCount = perFileResults.reduce((n, f) => n + f.tool_runs.filter(r => !r.success).length, 0);
  const summary = [
    `Analyze complete — ${fileCount} file(s), ${toolCount} tool run(s)` +
      (failCount ? `, ${failCount} failed` : '') + '.',
    currentCase ? `Saved to case: ${currentCase}` : '(no case active — results not saved to disk beyond the rollup below)',
    `Rollup: ${rollupPath}`,
    '',
    rollup,
  ].join('\n');

  return summary;
}

// ── Server ────────────────────────────────────────────────────────────────────
const server = new Server(
  { name: 'malchela', version: MALCHELA_VERSION },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS.map(t => ({
    name: t.name,
    description: `[${t.category}] ${t.description}`,
    inputSchema: t.inputSchema,
  })),
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  const tool = TOOLS.find(t => t.name === name);
  if (!tool) {
    return {
      content: [{ type: 'text', text: `Unknown tool: ${name}` }],
      isError: true,
    };
  }

  // Handle set_case — no binary execution, just update session state
  if (name === 'set_case') {
    const sanitized = sanitizeCaseName(args.case_name);
    if (!sanitized) {
      return {
        content: [{
          type: 'text',
          text: `Invalid case name: "${args.case_name}". Case names may only contain letters, numbers, hyphens, underscores, and dots (no "..").`,
        }],
        isError: true,
      };
    }
    currentCase = sanitized;
    return {
      content: [{
        type: 'text',
        text: `Case set to "${currentCase}". All tool output will be saved to saved_output/cases/${currentCase}/. You may now run analysis tools.`,
      }],
    };
  }

  // The report template needs no case.
  if (name === 'report_template') {
    try {
      return { content: [{ type: 'text', text: reportTemplateText() }] };
    } catch (err) {
      return { content: [{ type: 'text', text: `Report template not found in ${REPORT_TEMPLATE_DIR}: ${err.message}` }], isError: true };
    }
  }

  // First analysis tool call — no case selected yet, prompt for selection
  if (currentCase === null) {
    const casesDir = `${MALCHELA_DIR}/saved_output/cases`;
    let existingCases = [];
    try {
      existingCases = readdirSync(casesDir)
        .filter(f => { try { return statSync(`${casesDir}/${f}`).isDirectory(); } catch { return false; } });
    } catch { /* directory may not exist yet */ }

    const caseList = existingCases.length > 0
      ? `Existing cases: ${existingCases.join(', ')}`
      : 'No existing cases found.';

    return {
      content: [{
        type: 'text',
        text: [
          'CASE_SELECTION_REQUIRED',
          caseList,
          '',
          `Ask the user: "Which case should I save results to? ${caseList} Or enter a new case name to create one."`,
          'Then call set_case with the chosen name, and re-run the analysis tool.',
        ].join('\n'),
      }],
    };
  }

  if (name === 'save_report') {
    try {
      const path = saveReport(args || {});
      return { content: [{ type: 'text', text: `Report saved to ${path} and registered in case "${currentCase}".` }] };
    } catch (err) {
      return { content: [{ type: 'text', text: `Error saving report: ${err.message}` }], isError: true };
    }
  }

  // Handle analyze — custom orchestration (fileminer scan + auto-dispatch +
  // rollup), not a single binary invocation, so it bypasses buildCommand.
  if (name === 'analyze') {
    try {
      const summary = runAnalyze(args.path);
      return { content: [{ type: 'text', text: summary }] };
    } catch (err) {
      return {
        content: [{ type: 'text', text: `Error running analyze:\n${err.message}` }],
        isError: true,
      };
    }
  }

  try {
    const { bin, args: cmdArgs } = buildCommand(name, args);
    const result = execFileSync(bin, cmdArgs, {
      cwd: MALCHELA_DIR,
      encoding: 'utf8',
      timeout: name === 'unpack' ? UNPACK_TIMEOUT_MS : TIMEOUT_MS,
      env: {
        ...process.env,
      },
    });

    return { content: [{ type: 'text', text: result || '(no output)' }] };

  } catch (err) {
    const detail = err.stdout
      ? `${err.message}\n\nSTDOUT:\n${err.stdout}\n\nSTDERR:\n${err.stderr}`
      : err.message;
    return {
      content: [{ type: 'text', text: `Error running ${name}:\n${detail}` }],
      isError: true,
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
