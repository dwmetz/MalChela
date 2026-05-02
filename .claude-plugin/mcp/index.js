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
 *         "MALCHELA_DIR": "/Users/dmetz/GitHub/MalChela",
 *         "VT_API_KEY": "your-vt-key",
 *         "MB_API_KEY": "your-mb-key"
 *       }
 *     }
 *   }
 * }
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { execSync } from 'child_process';
import { existsSync } from 'fs';

const MALCHELA_DIR = process.env.MALCHELA_DIR || (() => {
  throw new Error(
    'MALCHELA_DIR environment variable is not set.\n' +
    'Set it to the root of your local MalChela installation.\n' +
    'Example: export MALCHELA_DIR=/home/user/MalChela'
  );
})();
const RELEASE_DIR  = `${MALCHELA_DIR}/target/release`;
const TIMEOUT_MS   = 60000;

// ── Tool definitions — sourced directly from tools.yaml ──────────────────────
const TOOLS = [

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
      'deeper investigation.',
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
    name: 'malhash',
    category: 'Threat Intel',
    input_type: 'hash',
    description:
      'Queries a hash against both VirusTotal and MalwareBazaar. Returns detection ' +
      'ratio, AV verdicts, first/last seen dates, and sample metadata. ' +
      'Requires VT_API_KEY env var; MB_API_KEY optional.',
    inputSchema: {
      type: 'object',
      properties: {
        hash: { type: 'string', description: 'MD5, SHA1, or SHA256 hash to query' },
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
      const out = args.output ? ` -o "${args.output}"` : '';
      return `"${binary}" "${args.filepath}"${out}`;
    }
    case 'folder': {
      if (toolName === 'mzhash' && args.algorithms?.length) {
        const flags = args.algorithms.map(a => `-a ${a}`).join(' ');
        return `"${binary}" "${args.folderpath}" -- ${flags}`;
      }
      return `"${binary}" "${args.folderpath}"`;
    }
    case 'hash': {
      if (toolName === 'tiquery') {
        const srcFlag = args.sources ? ` --sources "${args.sources}"` : '';
        return `"${binary}" "${args.hash}"${srcFlag} --json`;
      }
      return `"${binary}" "${args.hash}"`;
    }
    default:
      throw new Error(`Unknown input_type for tool: ${toolName}`);
  }
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