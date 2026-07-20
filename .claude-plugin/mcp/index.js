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
import { execSync } from 'child_process';
import {
  existsSync, readdirSync, statSync, mkdirSync, writeFileSync, readFileSync,
  realpathSync, openSync, closeSync, unlinkSync,
} from 'fs';
import { dirname } from 'path';
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
      'One-shot auto-triage: runs fileminer against a file, folder, or .app bundle, then ' +
      'automatically dispatches every tool fileminer suggests for every file found (no need ' +
      'to call fileminer yourself and manually decide which follow-up tools to run). Writes a ' +
      'combined rollup report alongside the individual per-tool reports. Best entry point for ' +
      'a single sample or small bundle (limit 25 files) — use fileminer + MZHash/MZCount/XMZHash ' +
      'directly for corpus-scale scans. Requires an active case (set_case first).',
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
      'Multi-source threat intel hash lookup across MalwareBazaar, VirusTotal, ' +
      'AlienVault OTX, and InQuest Labs. Returns a combined results matrix with ' +
      'detection counts, malware families, pulse counts, and source links. ' +
      'Use --json for machine-readable output. Requires API keys in api/*.txt.',
    inputSchema: {
      type: 'object',
      properties: {
        hash:    { type: 'string', description: 'MD5, SHA1, or SHA256 hash to query' },
        sources: {
          type: 'string',
          description: 'Comma-separated source IDs to query (mb,vt,otx,iq,os). Default: mb,vt,otx,iq',
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
];

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
      const bundleExec = execSync(
        `plutil -extract CFBundleExecutable raw -o - "${infoPlist}"`,
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
        return `"${binary}" "${targetPath}" --case "${currentCase}" -o -t`;
      }
      const out = args.output ? ` -o "${args.output}"` : '';
      return `"${binary}" "${targetPath}"${out}`;
    }
    case 'folder': {
      if (toolName === 'mzhash' && args.algorithms?.length) {
        const flags = args.algorithms.map(a => `-a ${a}`).join(' ');
        return `"${binary}" "${args.folderpath}" -- ${flags}`;
      }
      return `"${binary}" "${args.folderpath}"`;
    }
    case 'hash': {
      const caseFlag = currentCase ? ` --case "${currentCase}" -o -t` : '';
      if (toolName === 'tiquery') {
        const srcFlag = args.sources ? ` --sources "${args.sources}"` : '';
        return `"${binary}" "${args.hash}"${srcFlag} --json${caseFlag}`;
      }
      return `"${binary}" "${args.hash}"${caseFlag}`;
    }
    default:
      throw new Error(`Unknown input_type for tool: ${toolName}`);
  }
}

// ── Case manifest registration ───────────────────────────────────────────────
// Mirrors common_config::register_case_output() (Rust) / _register_cli_case_output()
// (Python web server) so a file written directly by this MCP process — the
// analyze rollup, which no single Rust binary produces — still shows up in
// case.yaml. The Rust-side tools this dispatches (macho_info, mstrings,
// codesign_check, plist_analyzer, fileanalyzer, tiquery) already register
// their own per-tool reports internally; this only covers the rollup file.

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
      execSync('sleep 0.1');
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
          manifest = null;
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
const ANALYZE_MAX_BUFFER = 50 * 1024 * 1024; // fileminer's JSON dump easily exceeds execSync's 1MB default

function pathsMatch(candidate, resolvedTarget) {
  if (!candidate) return false;
  try {
    return realpathSync(candidate) === resolvedTarget;
  } catch {
    return candidate === resolvedTarget;
  }
}

// Read back the .md report a tool just wrote (Analyze always requests -o -m,
// case or not) so the rollup can embed genuinely formatted content instead of
// raw CLI stdout. Picks the most-recently-modified report_*.md in the tool's
// output dir; safe because dispatch is fully sequential — nothing else writes
// there between this tool's run and this read.
function readToolMarkdown(tool, caseName) {
  const toolDir = caseName
    ? `${MALCHELA_DIR}/saved_output/cases/${caseName}/${tool}`
    : `${MALCHELA_DIR}/saved_output/${tool}`;
  if (!existsSync(toolDir)) return '';
  const mdFiles = readdirSync(toolDir)
    .filter(f => f.startsWith('report_') && f.endsWith('.md'))
    .map(f => `${toolDir}/${f}`)
    .sort((a, b) => statSync(a).mtimeMs - statSync(b).mtimeMs);
  return mdFiles.length ? readFileSync(mdFiles[mdFiles.length - 1], 'utf8') : '';
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
const MD_MITRE_ROW = /^\|\s*(\d+)\s*\|[^|]*\|[^|]*\|\s*([^|]+?)\s*\|[^|]*\|[^|]*\|\s*$/gm;

function extractMitreTactics(markdown) {
  let rawTotal = 0;
  const tactics = {};
  let m;
  MD_MITRE_ROW.lastIndex = 0;
  while ((m = MD_MITRE_ROW.exec(markdown)) !== null) {
    const count = parseInt(m[1], 10);
    rawTotal += count;
    for (const tactic of m[2].split(',')) {
      const t = tactic.trim();
      if (t) tactics[t] = (tactics[t] || 0) + count;
    }
  }
  return { rawTotal, tactics };
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
// list under their own 'Flags / Indicators' heading; codesign_check's
// markdown just wraps its raw colorized stdout in a code fence, where the
// same kind of finding shows up as a '⚠  ...' line instead (its "No
// suspicious indicators" clean case uses '✓', so it's naturally excluded
// here) — scoped to codesign_check specifically so this pattern can't match
// some other tool's content.
const MD_FLAG_BULLET = /^-\s*\*\*\[!\]\*\*\s*(.+)$/gm;
const CODESIGN_WARN_LINE = /^\s*⚠\s+(.+)$/gm;

function extractFlags(tool, markdown) {
  const pattern = tool === 'codesign_check' ? CODESIGN_WARN_LINE : MD_FLAG_BULLET;
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

// Files are grouped by SHA256 for display: duplicate content saved under
// different names (common with carved/exported network artifacts) gets one
// write-up instead of the same tool output repeated verbatim per filename.
// This only changes what's shown here — every path was still dispatched and
// still has its own saved report and case.yaml entry.
function buildAnalyzeRollup(target, perFileResults) {
  const groups = new Map();
  const order = [];
  for (const f of perFileResults) {
    const key = f.sha256 || f.filepath;
    if (!groups.has(key)) { groups.set(key, []); order.push(key); }
    groups.get(key).push(f);
  }

  const flagged = [];
  const dupGroups = [];
  const mitreTactics = {};
  let mitreTotal = 0;
  const malwareTags = [];
  const malwareTagsSeen = new Set();
  const flagFindings = []; // { filename, tool, text }
  const fsIocs = [];
  const fsIocsSeen = new Set();
  const netIocs = [];
  const netIocsSeen = new Set();
  for (const key of order) {
    const members = groups.get(key);
    const isFlagged = flagVerdict(members[0].tool_runs).flagged;
    if (isFlagged) flagged.push(members[0].filename);
    if (members.length > 1) dupGroups.push(members);
    for (const run of members[0].tool_runs) {
      if (run.tool === 'mstrings' && run.success && run.markdown) {
        const { rawTotal, tactics } = extractMitreTactics(run.markdown);
        mitreTotal += rawTotal;
        for (const [tactic, count] of Object.entries(tactics)) {
          mitreTactics[tactic] = (mitreTactics[tactic] || 0) + count;
        }
        const { fs, net } = extractMstringsIocs(run.markdown);
        for (const ioc of fs) { if (!fsIocsSeen.has(ioc)) { fsIocsSeen.add(ioc); fsIocs.push(ioc); } }
        for (const ioc of net) { if (!netIocsSeen.has(ioc)) { netIocsSeen.add(ioc); netIocs.push(ioc); } }
      }
      if (isFlagged && run.tool === 'tiquery' && run.success && run.markdown) {
        for (const tag of extractTiqueryTags(run.markdown)) {
          if (!malwareTagsSeen.has(tag)) { malwareTagsSeen.add(tag); malwareTags.push(tag); }
        }
      }
      if (run.success && run.markdown && ['macho_info', 'plist_analyzer', 'codesign_check'].includes(run.tool)) {
        for (const text of extractFlags(run.tool, run.markdown)) {
          flagFindings.push({ filename: members[0].filename, tool: run.tool, text });
        }
      }
    }
  }

  const lines = [
    `# MalChela Summary — ${target}`,
    '',
    `Generated: ${new Date().toISOString()}`,
    `Files analyzed: ${perFileResults.length}`,
    '',
    '## Triage Summary',
    '',
  ];
  if (order.length !== perFileResults.length) {
    lines.push(
      `- **${order.length} unique file(s)** across ${perFileResults.length} path(s) ` +
      `(${perFileResults.length - order.length} duplicate instance(s) collapsed below)`
    );
  } else {
    lines.push(`- **${order.length} file(s)** analyzed`);
  }
  if (flagged.length) {
    lines.push(`- **⚠ ${flagged.length} flagged malicious** (VirusTotal): ` + flagged.map(n => `\`${n}\``).join(', '));
  } else {
    lines.push('- No files flagged malicious by VirusTotal');
  }
  if (malwareTags.length) {
    lines.push('- **Malware tags** (tiquery): ' + malwareTags.map(t => `\`${t}\``).join(', '));
  }
  if (mitreTotal) {
    const byTactic = Object.entries(mitreTactics).sort((a, b) => b[1] - a[1]);
    const breakdown = byTactic.map(([t, c]) => `${t} (${c})`).join(', ');
    lines.push(`- **${mitreTotal} MITRE ATT&CK finding(s)** (mstrings), by tactic: ${breakdown}`);
  }
  if (fsIocs.length) {
    lines.push('- **Filesystem IOCs** (mstrings): ' + fsIocs.map(i => `\`${i}\``).join(', '));
  }
  if (netIocs.length) {
    lines.push('- **Network IOCs** (mstrings): ' + netIocs.map(i => `\`${i}\``).join(', '));
  }
  if (flagFindings.length) {
    const flaggedFiles = new Set(flagFindings.map(f => f.filename)).size;
    lines.push(`- **${flagFindings.length} flag(s)/indicator(s)** across ${flaggedFiles} file(s):`);
    for (const { filename, tool, text } of flagFindings) {
      lines.push(`  - \`${filename}\` (${tool}): ${text}`);
    }
  }
  for (const members of dupGroups) {
    const names = members.map(m => `\`${m.filename}\``).join(', ');
    lines.push(`- **Duplicate content:** ${names} share SHA256 \`${members[0].sha256}\``);
  }
  lines.push('');

  for (const key of order) {
    const members = groups.get(key);
    const primary = members[0];
    lines.push(`## ${primary.filename}`, '');
    if (members.length > 1) {
      const otherNames = members.slice(1).map(m => `\`${m.filename}\``).join(', ');
      lines.push(`- **Also found as:** ${otherNames} — identical content, tool output shown once`);
    }
    lines.push(`- **Path:** \`${primary.filepath}\``);
    lines.push(`- **Type:** ${primary.filetype}`);
    if (primary.sha256) lines.push(`- **SHA256:** \`${primary.sha256}\``);
    if (primary.md5) lines.push(`- **MD5:** \`${primary.md5}\``);
    lines.push('');
    if (!primary.tool_runs.length) {
      lines.push('_No suggested tools for this file type._', '');
      continue;
    }
    for (const run of primary.tool_runs) {
      lines.push(`### ${run.success ? '✓' : '✕'} ${run.label} (\`${run.tool}\`)`, '');
      if (run.success && run.markdown) {
        lines.push(demoteMarkdownHeadings(run.markdown), '');
      } else if (run.success) {
        // Fallback for the rare case the .md read-back came up empty (tool
        // didn't actually write one) — raw stdout, code-fenced.
        lines.push('```', run.output || '(no output)', '```', '');
      } else {
        lines.push(`**Error:** ${run.error || 'Tool run failed.'}`, '');
      }
    }
  }
  return lines.join('\n');
}

function runAnalyze(targetPath) {
  if (!existsSync(targetPath)) {
    throw new Error(`Path does not exist: ${targetPath}`);
  }

  const fmBinary = `${RELEASE_DIR}/fileminer`;
  if (!existsSync(fmBinary)) {
    throw new Error(
      `Binary not found: ${fmBinary}\n` +
      `Build MalChela first: cd ${MALCHELA_DIR} && ./release.sh`
    );
  }

  const singleFileMode = statSync(targetPath).isFile();
  const scanDir = singleFileMode ? dirname(targetPath) : targetPath;

  const fmArgs = [`"${scanDir}"`, '--no-prompt'];
  if (currentCase) fmArgs.push('--case', `"${currentCase}"`);

  let fmOutput;
  try {
    fmOutput = execSync(`"${fmBinary}" ${fmArgs.join(' ')}`, {
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

  if (singleFileMode) {
    const resolvedTarget = realpathSync(targetPath);
    scanResults = scanResults.filter(r => pathsMatch(r.filepath, resolvedTarget));
    if (scanResults.length === 0) {
      throw new Error(
        "Selected file was not found in fileminer's scan results " +
        '(it may be a hidden/skipped file type).'
      );
    }
  }

  if (scanResults.length > ANALYZE_MAX_FILES) {
    throw new Error(
      `${scanResults.length} files found — Analyze is meant for a single sample or small bundle ` +
      `(limit ${ANALYZE_MAX_FILES} files). For corpus-scale scans, use MZHash/MZCount/XMZHash instead.`
    );
  }

  const perFileResults = [];
  for (const res of scanResults) {
    const filepath = res.filepath || '';
    const sha256   = res.sha256 || '';
    const md5      = res.md5 || '';
    const suggested = res.suggested_tools || [];

    const toolRuns = [];
    for (const pair of suggested) {
      if (!Array.isArray(pair) || pair.length !== 2) continue;
      const [label, slug] = pair;

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
      const cmdArgs = [`"${arg}"`, '-o', '-m'];
      if (currentCase) cmdArgs.push('--case', `"${currentCase}"`);

      try {
        const output = execSync(`"${binary}" ${cmdArgs.join(' ')}`, {
          cwd: MALCHELA_DIR, encoding: 'utf8', timeout: ANALYZE_TIMEOUT_MS, maxBuffer: ANALYZE_MAX_BUFFER,
        }).trim();
        const markdown = readToolMarkdown(slug, currentCase);
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
    });
  }

  const rollup = buildAnalyzeRollup(targetPath, perFileResults);
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
  { name: 'malchela', version: '1.0.0' },
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
    currentCase = args.case_name;
    return {
      content: [{
        type: 'text',
        text: `Case set to "${currentCase}". All tool output will be saved to saved_output/cases/${currentCase}/. You may now run analysis tools.`,
      }],
    };
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
    const cmd = buildCommand(name, args);
    const result = execSync(cmd, {
      cwd: MALCHELA_DIR,
      encoding: 'utf8',
      timeout: TIMEOUT_MS,
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
