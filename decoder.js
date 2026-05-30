#!/usr/bin/env node

/**
 * ============================================================
 * CTF-JS-Decoder — JavaScript Deobfuscation CLI Tool
 * Author  : Senior JavaScript Security Engineer
 * License : MIT
 * Purpose : Decode and deobfuscate obfuscated JavaScript
 * commonly found in CTF challenges. Uses Node.js
 * native `vm` module for sandboxed execution —
 * never a bare global eval().
 * ============================================================
 */

'use strict';

const vm   = require('vm');
const fs   = require('fs');
const path = require('path');

// ─────────────────────────────────────────────
//  ANSI COLOR / STYLE HELPERS
// ─────────────────────────────────────────────

const C = {
  reset:   '\x1b[0m',
  bold:    '\x1b[1m',
  dim:     '\x1b[2m',

  // Foreground
  black:   '\x1b[30m',
  red:     '\x1b[31m',
  green:   '\x1b[32m',
  yellow:  '\x1b[33m',
  blue:    '\x1b[34m',
  magenta: '\x1b[35m',
  cyan:    '\x1b[36m',
  white:   '\x1b[37m',

  // Bright foreground
  bRed:    '\x1b[91m',
  bGreen:  '\x1b[92m',
  bYellow: '\x1b[93m',
  bBlue:   '\x1b[94m',
  bMagenta:'\x1b[95m',
  bCyan:   '\x1b[96m',
  bWhite:  '\x1b[97m',
};

/** Wrap text in ANSI codes, auto-reset at end. */
const paint = (style, text) => `${style}${text}${C.reset}`;

// ─────────────────────────────────────────────
//  BANNER
// ─────────────────────────────────────────────

function printBanner() {
  const line = paint(C.bCyan, '═'.repeat(62));
  console.log('\n' + line);
  console.log(paint(C.bYellow + C.bold, `
     ██████╗████████╗███████╗      ██╗███████╗
    ██╔════╝╚══██╔══╝██╔════╝      ██║██╔════╝
    ██║        ██║   █████╗        ██║███████║
    ██║        ██║   ██╔══╝   ██   ██║╚════██║
    ╚██████╗   ██║   ██║      ╚█████╔╝███████║
     ╚═════╝   ╚═╝   ╚═╝       ╚════╝ ╚══════╝
  `));
  console.log(paint(C.bMagenta + C.bold,
    '          JS  D E C O D E R  —  CTF Edition'));
  console.log(paint(C.dim + C.cyan,
    '      Sandboxed · Safe · Smart · Beautiful'));
  console.log('\n' + line + '\n');
}

// ─────────────────────────────────────────────
//  LOGGING HELPERS
// ─────────────────────────────────────────────

const log = {
  info:    (msg) => console.log(`  ${paint(C.bCyan,   '  ℹ')}  ${paint(C.white, msg)}`),
  success: (msg) => console.log(`  ${paint(C.bGreen,  '  ✔')}  ${paint(C.bGreen, msg)}`),
  warn:    (msg) => console.log(`  ${paint(C.bYellow, '  ⚠')}  ${paint(C.yellow, msg)}`),
  error:   (msg) => console.log(`  ${paint(C.bRed,    '  ✖')}  ${paint(C.red, msg)}`),
  step:    (n, total, msg) =>
    console.log(`  ${paint(C.bBlue, `[${n}/${total}]`)}  ${paint(C.cyan, msg)}`),
  result:  (label, value) =>
    console.log(`\n  ${paint(C.bold + C.bMagenta, label)}\n  ${paint(C.dim, '─'.repeat(58))}\n${paint(C.bWhite, value)}\n`),
};

// ─────────────────────────────────────────────
//  CLI ARGUMENT PARSER
//  Supports: --input <file>  --output <file>  --timeout <ms>
//            --help          --verbose
// ─────────────────────────────────────────────

/**
 * Minimal zero-dependency CLI argument parser.
 * Returns a plain object of key→value pairs plus a `_` array for
 * positional arguments.
 */
function parseArgs(argv) {
  const args = { _: [], verbose: false, timeout: 5000 };
  let i = 0;
  while (i < argv.length) {
    const token = argv[i];
    if (token.startsWith('--')) {
      const key = token.slice(2);
      const next = argv[i + 1];
      if (!next || next.startsWith('--')) {
        // Boolean flag
        args[key] = true;
        i++;
      } else {
        args[key] = next;
        i += 2;
      }
    } else {
      args._.push(token);
      i++;
    }
  }
  return args;
}

// ─────────────────────────────────────────────
//  USAGE HELP
// ─────────────────────────────────────────────

function printHelp() {
  console.log(`
  ${paint(C.bold + C.bCyan, 'USAGE')}
    node decoder.js [options]

  ${paint(C.bold + C.bCyan, 'OPTIONS')}
    ${paint(C.bYellow, '--input  <file>')}      Path to the obfuscated JS file     (required)
    ${paint(C.bYellow, '--output <file>')}      Write decoded result to this file  (optional, default: stdout)
    ${paint(C.bYellow, '--timeout <ms>')}        vm execution timeout in ms         (default: 5000)
    ${paint(C.bYellow, '--verbose')}            Print extra diagnostic information
    ${paint(C.bYellow, '--help')}               Show this help message

  ${paint(C.bold + C.bCyan, 'EXAMPLES')}
    node decoder.js --input encoded.txt
    node decoder.js --input jsfuck.txt   --output decoded.js
    node decoder.js --input packed.js    --output result.js --timeout 10000
    node decoder.js --input obf.js       --verbose
  `);
}

// ─────────────────────────────────────────────
//  DETECTION HELPERS
//  Heuristics to classify the obfuscation type
//  before attempting to decode it.
// ─────────────────────────────────────────────

/**
 * Determine the most likely obfuscation type for a given code string.
 * Returns a human-readable label and a confidence tag used by the
 * decoder pipeline to pick the right strategy.
 *
 * @param {string} code - Raw obfuscated source
 * @returns {{ label: string, tag: string }}
 */
function detectType(code) {
  const trimmed = code.trim();

  // JSFuck: only uses [ ] ( ) ! +
  if (/^[\[\]()!+\s]+$/.test(trimmed)) {
    return { label: 'JSFuck  ([]()!+ charset)', tag: 'jsfuck' };
  }

  // Jother / JJencode variant — uses $ and _ heavily
  if (/^[\$_\[\]()!+'".,;:\s]+$/.test(trimmed)) {
    return { label: 'Jother / JJencode  ($_ charset)', tag: 'jother' };
  }

  // Dean Edwards p,a,c,k,e,d packer
  if (/eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*[,r]/.test(trimmed)) {
    return { label: 'Dean Edwards p,a,c,k,e,d  (eval packer)', tag: 'packed' };
  }

  // Generic eval-based packer (any eval(function(...) pattern)
  if (/eval\s*\(\s*function\s*\(/.test(trimmed)) {
    return { label: 'Generic eval() packer', tag: 'eval_packer' };
  }

  // Hexadecimal string obfuscation  e.g.  \x68\x65\x6c\x6c\x6f
  if (/\\x[0-9a-fA-F]{2}/.test(trimmed) && (trimmed.match(/\\x[0-9a-fA-F]{2}/g) || []).length > 5) {
    return { label: 'Hex-escape string  (\\xNN)', tag: 'hex_escape' };
  }

  // Unicode escape  e.g.  \u0068\u0065\u006c
  if (/\\u[0-9a-fA-F]{4}/.test(trimmed) && (trimmed.match(/\\u[0-9a-fA-F]{4}/g) || []).length > 5) {
    return { label: 'Unicode-escape string  (\\uNNNN)', tag: 'unicode_escape' };
  }

  // Array-rotation + shift obfuscation (common in obfuscator.io output)
  if (/\bvar\s+\w+\s*=\s*\[/.test(trimmed) &&
      /\.\s*split\s*\(/.test(trimmed) &&
      /\bpush\b/.test(trimmed) && /\bshift\b/.test(trimmed)) {
    return { label: 'Array-rotation obfuscation  (push/shift)', tag: 'array_rotation' };
  }

  // Base64-encoded eval payload
  if (/eval\s*\(\s*atob\s*\(/.test(trimmed) || /eval\s*\(\s*Buffer\s*\.from\s*\(/.test(trimmed)) {
    return { label: 'Base64-encoded eval payload  (atob/Buffer)', tag: 'base64_eval' };
  }

  // Obfuscator.io style: large hex / decimal encoded string arrays
  if (/\bvar\s+\w+\s*=\s*\[(?:'[^']*'(?:,'[^']*')+|"[^"]*"(?:,"[^"]*")+)\]/.test(trimmed)) {
    return { label: 'String-array obfuscation  (obfuscator.io style)', tag: 'string_array' };
  }

  return { label: 'Unknown / generic JS  (attempting vm execution)', tag: 'unknown' };
}

// ─────────────────────────────────────────────
//  SANDBOXED VM RUNNER
//  The core security boundary: NEVER use global eval().
//  vm.runInNewContext provides an isolated V8 context.
// ─────────────────────────────────────────────

/**
 * Execute a snippet of code inside a Node.js vm sandbox.
 *
 * The sandbox object exposes only the bare minimum:
 * - console.log → captured into `output` array
 * - A no-op `process` shim to prevent accidental access
 *
 * The code is wrapped so that the LAST expression value is captured,
 * and any console.log calls are intercepted.
 *
 * @param {string} code         - Code to run
 * @param {number} timeoutMs    - Maximum execution time in ms
 * @returns {{ result: string, logs: string[] }}
 */
function runInSandbox(code, timeoutMs = 5000) {
  const logs = [];

  // Build a minimal, safe sandbox context
  const sandbox = {
    // Intercept console output
    console: {
      log:   (...args) => logs.push(args.map(String).join(' ')),
      warn:  (...args) => logs.push('[warn] ' + args.map(String).join(' ')),
      error: (...args) => logs.push('[error] ' + args.map(String).join(' ')),
      info:  (...args) => logs.push('[info] ' + args.map(String).join(' ')),
    },
    // Minimal Buffer shim for base64 payloads
    Buffer,
    // Shim atob / btoa (available in Node ≥ 16 globals anyway, but be explicit)
    atob: (b64) => Buffer.from(b64, 'base64').toString('utf8'),
    btoa: (str) => Buffer.from(str).toString('base64'),
    // Block dangerous globals explicitly
    process:       { env: {}, argv: [], exit: () => {} },
    require:       undefined,
    __dirname:     undefined,
    __filename:    undefined,
    module:        undefined,
    exports:       undefined,
    global:        undefined,
    globalThis:    undefined,
  };

  // Contextify the sandbox once — this is what vm.runInNewContext does
  // internally, but we create it explicitly for clarity.
  vm.createContext(sandbox);

  // Wrap user code: capture the final expression value via assignment
  const wrapped = `__result__ = (function(){ return (${code}); })();`;

  try {
    vm.runInContext(wrapped, sandbox, { timeout: timeoutMs });
  } catch (_) {
    // Fallback if formatting as statement blocks fails
    try {
      const exprWrapped = `__result__ = ${code};`;
      vm.runInContext(exprWrapped, sandbox, { timeout: timeoutMs });
    } catch (__) {
      // Final resilient fallback for complex anonymous blocks
      const rawWrapped = `__result__ = eval(${JSON.stringify(code)});`;
      vm.runInContext(rawWrapped, sandbox, { timeout: timeoutMs });
    }
  }

  const result = typeof sandbox.__result__ !== 'undefined' && sandbox.__result__ !== null
    ? String(sandbox.__result__)
    : '';

  return { result, logs };
}

// ─────────────────────────────────────────────
//  STAGE DECODERS
//  Each function handles one obfuscation type.
//  They all return { decoded: string, method: string }.
// ─────────────────────────────────────────────

/**
 * JSFuck / Jother decoder.
 * These dialects encode JS as pure expressions using a tiny charset.
 * The safest approach is controlled sandboxed execution.
 */
function decodeJsFuck(code, timeoutMs) {
  const { result, logs } = runInSandbox(code, timeoutMs);
  const decoded = result || logs.join('\n');
  return { decoded, method: 'vm.runInNewContext (JSFuck/Jother expression)' };
}

/**
 * Dean Edwards p,a,c,k,e,d unpacker.
 * Intercepts the inner eval() call instead of executing it.
 */
function decodePackedEval(code, timeoutMs) {
  // Replace eval( with a capture so we get the unpacked source
  const patched = code.replace(/\beval\s*\(/, '__captured__ = (');

  const sandbox = {};
  vm.createContext(sandbox);

  vm.runInContext(patched, sandbox, { timeout: timeoutMs });

  if (sandbox.__captured__) {
    return {
      decoded: String(sandbox.__captured__),
      method: 'eval() intercept via __captured__ variable',
    };
  }

  // Fallback: run normally and capture console output
  const { result, logs } = runInSandbox(code, timeoutMs);
  return {
    decoded: result || logs.join('\n'),
    method: 'vm.runInNewContext fallback (packed)',
  };
}

/**
 * Hex-escape decoder  \xNN → UTF-8 chars.
 * Uses JSON.parse on a quoted version of the string for correctness.
 */
function decodeHexEscape(code) {
  // Try to unescape all \xNN sequences directly
  const decoded = code.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );
  return { decoded, method: 'Regex \\xNN → fromCharCode' };
}

/**
 * Unicode-escape decoder  \uNNNN → chars.
 */
function decodeUnicodeEscape(code) {
  const decoded = code.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );
  return { decoded, method: 'Regex \\uNNNN → fromCharCode' };
}

/**
 * Generic / unknown obfuscation.
 * Attempts plain sandboxed execution and captures any output.
 *
 * Priority order for the decoded result:
 * 1. The return value of the executed code  (covers IIFEs that return strings)
 * 2. Anything written to console.log()
 * 3. A fallback message if nothing was captured
 */
function decodeGeneric(code, timeoutMs) {
  const { result, logs } = runInSandbox(code, timeoutMs);

  // Prefer a non-empty return value — this is what IIFEs like
  //      (function(){ var arr=[...]; return arr[0]+arr[1]+... }())
  // produce. Only fall back to console output when result is empty.
  const decoded = result
    || logs.join('\n')
    || '[No output captured — inspect the source manually]';

  return {
    decoded,
    method: 'vm.runInNewContext generic execution (return-value capture)',
  };
}

// ─────────────────────────────────────────────
//  MULTI-PASS PIPELINE
//  Run up to N decode passes until the output
//  stabilises (stops changing) or we hit maxPasses.
// ─────────────────────────────────────────────

/**
 * Dispatch a single decode pass based on the detected obfuscation tag.
 *
 * @param {string} code
 * @param {string} tag   - Obfuscation type tag from detectType()
 * @param {number} timeoutMs
 * @returns {{ decoded: string, method: string }}
 */
function dispatchDecode(code, tag, timeoutMs) {
  switch (tag) {
    case 'jsfuck':
    case 'jother':
      return decodeJsFuck(code, timeoutMs);

    case 'packed':
    case 'eval_packer':
      return decodePackedEval(code, timeoutMs);

    case 'hex_escape':
      return decodeHexEscape(code);

    case 'unicode_escape':
      return decodeUnicodeEscape(code);

    case 'base64_eval':
    case 'string_array':
    case 'array_rotation':
    case 'unknown':
    default:
      return decodeGeneric(code, timeoutMs);
  }
}

/**
 * Iterative multi-pass decoder.
 * Some payloads are double/triple encoded.  We keep decoding until the
 * output is identical to the input (fixed point) or we exceed maxPasses.
 *
 * @param {string} code
 * @param {object} opts
 * @param {number} opts.timeoutMs
 * @param {number} opts.maxPasses
 * @param {boolean} opts.verbose
 * @returns {{ final: string, passes: Array<{pass,tag,method,preview}> }}
 */
function multiPassDecode(code, { timeoutMs = 5000, maxPasses = 6, verbose = false } = {}) {
  let current = code;
  const passes = [];

  for (let pass = 1; pass <= maxPasses; pass++) {
    const { label, tag } = detectType(current);

    log.step(pass, maxPasses, `Detected: ${paint(C.bYellow, label)}`);

    let decoded, method;
    try {
      // 🛡️ التعديل النهائي والذكي: منع التدمير بالـ Regex إذا كانت الرموز المشفرة مدمجة داخل دوال رياضية أو مصفوفات معقدة
      if ((tag === 'hex_escape' || tag === 'unicode_escape') && (current.includes('function') || current.includes('=>'))) {
        ({ decoded, method } = decodeGeneric(current, timeoutMs));
      } else {
        ({ decoded, method } = dispatchDecode(current, tag, timeoutMs));
      }
    } catch (err) {
      log.warn(`Pass ${pass} failed: ${err.message}`);
      break;
    }

    const preview = decoded.slice(0, 120).replace(/\n/g, '↵');
    passes.push({ pass, tag, method, preview });

    if (verbose) {
      log.info(`Method : ${method}`);
      log.info(`Preview: ${paint(C.dim, preview)}`);
    }

    // Fixed-point check — if nothing changed, stop iterating
    if (decoded === current) {
      log.info(`Output stabilised after ${pass} pass(es).`);
      break;
    }

    // Always commit the decoded result before deciding whether to stop.
    // This ensures an IIFE's return value (e.g. string-array obfuscation)
    // is never discarded — even when the tag is 'unknown'.
    current = decoded;

    // Stop if the output is trivially short or looks like a plain value
    // (no more obfuscation patterns to unwind).
    if (decoded.length < 2) {
      break;
    }

    // Smart-check: If we successfully extracted a clean CTF Flag or a clear raw value,
    // don't let it loop or drop into fallback messages.
    if (decoded.includes('CTF{') || decoded.includes('](') || decoded.length < 150) {
      if (decoded !== '[No output captured — inspect the source manually]') {
        break;
      }
    }
  }

  return { final: current, passes };
}

// ─────────────────────────────────────────────
//  FILE I/O HELPERS
// ─────────────────────────────────────────────

function readFile(filePath) {
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Input file not found: ${resolved}`);
  }
  return fs.readFileSync(resolved, 'utf8');
}

function writeFile(filePath, content) {
  const resolved = path.resolve(filePath);
  fs.writeFileSync(resolved, content, 'utf8');
  return resolved;
}

// ─────────────────────────────────────────────
//  MAIN ENTRY POINT
// ─────────────────────────────────────────────

function main() {
  printBanner();

  const args = parseArgs(process.argv.slice(2));

  // ── Help ──────────────────────────────────
  if (args.help) {
    printHelp();
    process.exit(0);
  }

  // ── Validate required arguments ───────────
  if (!args.input) {
    log.error('Missing required argument: --input <file>');
    printHelp();
    process.exit(1);
  }

  const timeoutMs = parseInt(args.timeout, 10) || 5000;
  const verbose   = Boolean(args.verbose);

  // ── Read input ────────────────────────────
  log.info(`Reading input file: ${paint(C.bCyan, args.input)}`);
  let code;
  try {
    code = readFile(args.input);
  } catch (err) {
    log.error(err.message);
    process.exit(1);
  }

  log.info(`Payload size: ${paint(C.bYellow, `${code.length.toLocaleString()} bytes`)}`);
  log.info(`VM timeout  : ${paint(C.bYellow, `${timeoutMs} ms`)}`);
  console.log();

  // ── Decode ────────────────────────────────
  let final, passes;
  const start = Date.now();

  try {
    ({ final, passes } = multiPassDecode(code, { timeoutMs, maxPasses: 6, verbose }));
  } catch (err) {
    log.error(`Decoding failed: ${err.message}`);
    if (verbose) console.error(err.stack);
    process.exit(1);
  }

  const elapsed = Date.now() - start;

  console.log();
  log.success(`Finished in ${elapsed} ms over ${passes.length} pass(es).`);

  // ── Output ────────────────────────────────
  if (args.output) {
    try {
      const outPath = writeFile(args.output, final);
      log.success(`Decoded output written to: ${paint(C.bCyan, outPath)}`);
    } catch (err) {
      log.error(`Failed to write output: ${err.message}`);
      process.exit(1);
    }
  } else {
    log.result('DECODED OUTPUT', final);
  }

  // ── Summary table ─────────────────────────
  if (verbose && passes.length > 0) {
    console.log(`\n  ${paint(C.bold + C.bBlue, 'PASS SUMMARY')}`);
    console.log(`  ${paint(C.dim, '─'.repeat(58))}`);
    for (const p of passes) {
      console.log(
        `  ${paint(C.bCyan, `Pass ${p.pass}`)}  ` +
        `${paint(C.bYellow, p.tag.padEnd(20))}  ` +
        `${paint(C.dim, p.preview.slice(0, 40))}`
      );
    }
    console.log();
  }
}

// ─────────────────────────────────────────────
//  Run
// ─────────────────────────────────────────────
main();