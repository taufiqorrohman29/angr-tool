# angr-tool

**CLI Binary Analysis & Decompiler** powered by [angr](https://angr.io/)

A powerful command-line reverse engineering toolkit that wraps angr's capabilities into an easy-to-use CLI.

## Installation

```bash
# Basic install
pip install -e .

# Full install (DOT export, assembly patching)
pip install -e ".[full]"
```

## Quick Start

```bash
# Binary info
angr-tool info ./binary

# Check security protections
angr-tool checksec ./binary

# Disassemble a function
angr-tool disasm ./binary -f main

# Decompile to pseudocode
angr-tool decompile ./binary -f main

# Decompile all functions to file
angr-tool decompile ./binary --all -o output.c

# Extract strings
angr-tool strings ./binary --filter password

# Cross-reference analysis
angr-tool xrefs ./binary -f printf

# Symbolic execution solver (CTF!)
angr-tool solve ./binary --find 0x401234 --avoid 0x401000
```

## Commands

### Analysis
| Command | Description |
|---------|-------------|
| `info` | Binary metadata (arch, sections, imports, exports, segments) |
| `checksec` | Security protections (NX, PIE, Canary, RELRO, Fortify) |
| `strings` | Extract printable strings (ASCII, UTF-16) |
| `symsearch` | Search symbols by pattern |
| `hexdump` | Hex dump at address or section |

### Reverse Engineering
| Command | Description |
|---------|-------------|
| `disasm` | Disassemble functions or address ranges |
| `decompile` | Decompile to C-like pseudocode |
| `cfg` | Control Flow Graph analysis |
| `callgraph` | Function call graph + DOT export |
| `xrefs` | Cross-reference analysis |

### Exploitation
| Command | Description |
|---------|-------------|
| `solve` | Symbolic execution constraint solver (Veritesting, DFS, LoopSeer) |
| `patch` | Binary patching (NOP, hex bytes, assembly cross-arch) |

### Advanced Vulnerability Research (AVR)
| Command | Description |
|---------|-------------|
| `audit` | Static & Dynamic Taint Analysis (Buffer Overflow, Format String) |
| `autopwn` | Automated exploit generation & ROP chains |
| `heap`  | Dynamic Heap Memory tracker (UAF, Double-Free) |

## Global Options

Most commands support these options:

| Flag | Description |
|------|-------------|
| `--json` | Output in JSON format (for scripting) |
| `-o, --output FILE` | Save output to file |
| `--pdb PATH` | Load PDB / external debug info |
| `--base-addr HEX` | Rebase binary at address |
| `--libs` | Auto-load shared libraries |

## Examples

### Security Audit
```bash
angr-tool checksec ./target_binary
angr-tool info ./target_binary --json | jq .
```

### CTF Challenge
```bash
# Find the flag
angr-tool strings ./challenge --filter flag
angr-tool decompile ./challenge -f main
angr-tool solve ./challenge --find 0x401234 --avoid 0x401000

# Patch a jump
angr-tool patch ./challenge -a 0x401050 --nop 2 -o patched
```

### Full Analysis
```bash
# Analyze everything
angr-tool info ./binary
angr-tool checksec ./binary
angr-tool decompile ./binary --all -o decompiled.c
angr-tool callgraph ./binary --dot callgraph.dot
angr-tool strings ./binary -o strings.txt
```

### JSON Output for Scripting
```bash
angr-tool info ./binary --json > info.json
angr-tool strings ./binary --json | python3 -m json.tool
```

### Debug Symbols (PDB)
```bash
angr-tool info ./program.exe --pdb ./program.pdb
angr-tool decompile ./program.exe --pdb ./program.pdb -f main
```

## Architecture

```
angr_tool/
├── __init__.py
├── main.py              # CLI entry point, command registration
├── core/
│   ├── loader.py        # Binary loading + CFG generation
│   ├── formatter.py     # Output formatting (text/JSON/file)
│   └── utils.py         # Shared utilities
└── commands/
    ├── info.py          # Binary metadata
    ├── checksec.py      # Security checks
    ├── disasm.py        # Disassembly
    ├── decompile.py     # Decompilation
    ├── cfg.py           # Control flow graph
    ├── callgraph.py     # Call graph
    ├── strings.py       # String extraction
    ├── symsearch.py     # Symbol search
    ├── xrefs.py         # Cross-references
    ├── hexdump.py       # Hex dump
    ├── solve.py         # Symbolic execution
    ├── patch.py         # Binary patching
    ├── audit.py         # Automated vuln discovery & taint analysis
    ├── autopwn.py       # Auto exploit & ROP generator
    └── heap.py          # Heap vulnerability tracker
```

## uthor

**taufiqorrohman29** — v0.0.1
