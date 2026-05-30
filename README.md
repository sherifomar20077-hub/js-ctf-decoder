# CTF-JS-Decoder

```
   ██████╗████████╗███████╗      ██╗███████╗
  ██╔════╝╚══██╔══╝██╔════╝      ██║██╔════╝
  ██║        ██║   █████╗        ██║███████╗
  ██║        ██║   ██╔══╝   ██   ██║╚════██║
  ╚██████╗   ██║   ██║      ╚█████╔╝███████║
   ╚═════╝   ╚═╝   ╚═╝       ╚════╝ ╚══════╝
         JS  D E C O D E R  —  CTF Edition
```

> **A professional, production-ready Node.js CLI tool for decoding and deobfuscating JavaScript found in CTF challenges — powered by sandboxed VM execution, never a bare `eval()`.**

---

## Features

| Category | Detail |
|---|---|
| **Obfuscation Types** | JSFuck, Jother/JJencode, Dean Edwards p,a,c,k,e,d packer, generic `eval()` packers, hex `\xNN` escapes, unicode `\uNNNN` escapes, base64 `atob()` / `Buffer` payloads, string-array (obfuscator.io) obfuscation |
| **Safety** | Uses Node.js native `vm.runInNewContext` — **never** a bare `eval()`. Dangerous globals (`require`, `process`, `module`, etc.) are explicitly blocked in the sandbox |
| **Multi-Pass** | Iteratively re-decodes up to 6 passes until the output stabilises — handles double/triple-encoded payloads |
| **Auto-Detection** | Heuristic fingerprinting identifies the obfuscation type before decoding |
| **Configurable Timeout** | VM execution timeout (default 5 s) prevents infinite-loop payloads from hanging |
| **Beautiful UX** | ASCII art banner, ANSI colour output, per-step progress messages, optional verbose pass summary |
| **Zero Dependencies** | Pure Node.js standard library — nothing to `npm install` |

---

## Prerequisites

| Requirement | Version |
|---|---|
| **Node.js** | ≥ 16.x (uses `atob`, `Buffer`, and `vm` from stdlib) |
| **npm / npx** | Any recent version (only needed if you want to add dev tools) |
| **OS** | Linux · macOS · Windows (tested on all three) |

Check your Node version:

```bash
node --version   # should print v16.x or higher
```

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/ctf-js-decoder.git
cd ctf-js-decoder

# 2. (Optional) Make the script directly executable on Unix
chmod +x decoder.js
```

No `npm install` required — this tool has **zero external dependencies**.

---

## Usage

### Basic syntax

```bash
node decoder.js --input <obfuscated-file> [options]
```

### Options

| Flag | Description | Default |
|---|---|---|
| `--input <file>` | Path to the obfuscated JS / text file | *(required)* |
| `--output <file>` | Write decoded result to this file | stdout |
| `--timeout <ms>` | VM execution timeout in milliseconds | `5000` |
| `--verbose` | Print per-pass diagnostic information | `false` |
| `--help` | Show help message | — |

---

## Examples

### 1 — Decode a JSFuck payload and print to terminal

```bash
node decoder.js --input jsfuck_challenge.txt
```

### 2 — Decode a Dean Edwards packed script, save to file

```bash
node decoder.js --input packed.js --output decoded.js
```

### 3 — Decode a hex-escape blob with extended timeout and verbose output

```bash
node decoder.js --input hex_obf.js --timeout 10000 --verbose
```

### 4 — Pipe output to another tool

```bash
node decoder.js --input mystery.js | prettier --parser babel
```

---

## Supported Obfuscation Types

### JSFuck
Uses only six characters: `[ ] ( ) ! +`. Each character maps to a JS expression that evaluates to a primitive.

```
Input:  [][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+ ...
Output: alert("Hello, World!")
```

### Dean Edwards p,a,c,k,e,d

The classic packer from the mid-2000s. The tool intercepts the inner `eval()` call to extract the unpacked source without executing it.

```js
eval(function(p,a,c,k,e,d){...}('alert|Hello',5,5,...))
// → alert("Hello")
```

### Hex / Unicode Escape Strings

String literals with `\xNN` or `\uNNNN` sequences are decoded character by character via regex substitution.

```js
\x61\x6c\x65\x72\x74\x28\x22\x48\x69\x22\x29
// → alert("Hi")
```

### Base64 Eval (`atob` / `Buffer`)

```js
eval(atob("YWxlcnQoIkhlbGxvISIp"))
// → alert("Hello!")
```

### String-Array (obfuscator.io style)

Large encoded string arrays with accessor functions and rotation steps are unwound through multi-pass sandboxed execution.

---

## How It Works — Architecture

```
  ┌──────────────────────────────────────────────────────────┐
  │  CLI Argument Parser  (parseArgs)                        │
  └───────────────────────────┬──────────────────────────────┘
                              │ raw code string
                              ▼
  ┌──────────────────────────────────────────────────────────┐
  │  Obfuscation Detector  (detectType)                      │
  │  Regex heuristics → obfuscation tag                      │
  └───────────────────────────┬──────────────────────────────┘
                              │ tag
                              ▼
  ┌──────────────────────────────────────────────────────────┐
  │  Multi-Pass Decode Pipeline  (multiPassDecode)           │
  │  ┌────────────────────────────────────────────────────┐  │
  │  │  Pass N → dispatchDecode(tag) → decoded string     │  │
  │  │  If decoded ≠ current → re-detect → Pass N+1       │  │
  │  │  If decoded = current → fixed point → stop         │  │
  │  └────────────────────────────────────────────────────┘  │
  └───────────────────────────┬──────────────────────────────┘
                              │ final string
                              ▼
              stdout  ──or──  output file
```

### The Sandbox (Security Core)

```
  ┌─────────────────────────────────────────────┐
  │  vm.createContext(sandbox)                  │
  │                                             │
  │  Allowed:  console, Buffer, atob, btoa      │
  │  Shimmed:  process (no-op)                  │
  │  Blocked:  require, module, global,         │
  │            globalThis, __dirname, exports   │
  └─────────────────────────────────────────────┘
              │
              │  vm.runInContext(code, sandbox, { timeout })
              ▼
        Isolated V8 context
        (cannot escape to host process)
```

---

## Security Notes

- **No `eval()`** is ever called on the host context. All execution is confined to `vm.runInContext` with an explicit, hand-crafted sandbox.
- The `timeout` option prevents runaway loops (e.g. a challenge containing `while(true){}`).
- `require`, `process`, `module`, `global`, `globalThis`, `__dirname`, and `__filename` are all explicitly set to `undefined` inside the sandbox so a malicious payload cannot escape the VM.
- This tool is intended for **CTF / research / educational use**. Always run it on payloads you own or have permission to analyse.

---

## Project Structure

```
ctf-js-decoder/
├── decoder.js          # Main CLI tool (single file, zero dependencies)
└── README.md           # This file
```

---

## Roadmap

- [ ] `--format` flag to auto-run Prettier/js-beautify on output
- [ ] Support for obfuscated HTML files (extract `<script>` blocks first)
- [ ] `--mode batch` to decode an entire directory of files
- [ ] Plugin system for community-contributed decoders
- [ ] Web UI wrapper (Express + WebSocket live decode)

---

## Contributing

Pull requests are welcome! Please:

1. Fork the repository and create a feature branch.
2. Add a test case in `tests/` (if a `tests/` folder exists) or describe it in the PR.
3. Keep the tool dependency-free in `decoder.js`.
4. Run `node decoder.js --help` and verify the tool still starts cleanly.

---

## License

[MIT](LICENSE) — free for personal and commercial use.

---

## Acknowledgements

- **Dean Edwards** — for the original `p,a,c,k,e,d` packer whose pattern this tool specifically detects and unwinds.
- **aemkei** — creator of JSFuck.
- The broader **CTF community** for endlessly creative obfuscation challenges.
