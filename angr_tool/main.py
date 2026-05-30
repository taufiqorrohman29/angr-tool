"""
angr-tool: CLI Binary Analysis & Decompiler
Entry point — registers all subcommands.
"""

import click
from angr_tool import __version__
from angr_tool.commands.info      import cmd_info
from angr_tool.commands.disasm    import cmd_disasm
from angr_tool.commands.decompile import cmd_decompile
from angr_tool.commands.cfg       import cmd_cfg
from angr_tool.commands.strings   import cmd_strings
from angr_tool.commands.symsearch import cmd_symsearch
from angr_tool.commands.checksec  import cmd_checksec
from angr_tool.commands.xrefs     import cmd_xrefs
from angr_tool.commands.solve     import cmd_solve
from angr_tool.commands.hexdump   import cmd_hexdump
from angr_tool.commands.callgraph import cmd_callgraph
from angr_tool.commands.patch     import cmd_patch
from angr_tool.commands.audit     import cmd_audit
from angr_tool.commands.autopwn   import cmd_autopwn
from angr_tool.commands.heap      import cmd_heap

@click.group()
@click.version_option(version=__version__, prog_name="angr-tool")
def cli():
    """
    \b
     █████╗ ███╗   ██╗ ██████╗ ██████╗       ████████╗ ██████╗  ██████╗ ██╗
    ██╔══██╗████╗  ██║██╔════╝ ██╔══██╗      ╚══██╔══╝██╔═══██╗██╔═══██╗██║
    ███████║██╔██╗ ██║██║  ███╗██████╔╝         ██║   ██║   ██║██║   ██║██║
    ██╔══██║██║╚██╗██║██║   ██║██╔══██╗         ██║   ██║   ██║██║   ██║██║
    ██║  ██║██║ ╚████║╚██████╔╝██║  ██║         ██║   ╚██████╔╝╚██████╔╝███████╗
    ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝         ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
    Binary Analysis & Decompiler — powered by angr

    \b
    ┌──────────────────────────────────────────────────────────────────────────┐
    │  ANALYSIS COMMANDS                                                       │
    ├──────────────┬───────────────────────────────────────────────────────────┤
    │  info        │  Show binary metadata (arch, sections, imports, exports)  │
    │  checksec    │  Check security protections (NX, PIE, Canary, RELRO)      │
    │  strings     │  Extract printable strings (ASCII, UTF-16)                │
    │  symsearch   │  Search symbols / functions by name pattern               │
    │  hexdump     │  Hex dump at address or section                           │
    ├──────────────┼───────────────────────────────────────────────────────────┤
    │  REVERSE ENGINEERING                                                     │
    ├──────────────┼───────────────────────────────────────────────────────────┤
    │  disasm      │  Disassemble functions or address ranges                  │
    │  decompile   │  Decompile to C-like pseudocode                           │
    │  cfg         │  Control Flow Graph analysis                              │
    │  callgraph   │  Function call graph analysis + DOT export                │
    │  xrefs       │  Cross-reference analysis (callers, string refs)          │
    ├──────────────┼───────────────────────────────────────────────────────────┤
    │  EXPLOITATION                                                            │
    ├──────────────┼───────────────────────────────────────────────────────────┤
    │  solve       │  Symbolic execution solver (angr SimulationManager)       │
    │  patch       │  Binary patching (NOP, bytes, assembly)                   │
    ├──────────────┼───────────────────────────────────────────────────────────┤
    │  ADVANCED    │                                                           │
    ├──────────────┼───────────────────────────────────────────────────────────┤
    │  audit       │  Scan for vulnerabilities (BoF, Format String)            │
    │  autopwn     │  Automated exploit generation (ROP chains)                │
    │  heap        │  Static heap vulnerability tracker (UAF, double frees)    │
    └──────────────┴───────────────────────────────────────────────────────────┘

    \b
    Global Options (available on most commands):
      --json          Output in JSON format
      -o, --output    Save output to file
      --pdb PATH      Load PDB / external debug info
      --base-addr HEX Rebase binary at address
      --libs          Auto-load shared libraries

    \b
    Quick Examples:
      angr-tool info ./binary
      angr-tool checksec ./binary
      angr-tool disasm ./binary -f main
      angr-tool decompile ./binary -f main --json
      angr-tool decompile ./binary --all -o decompiled.c
      angr-tool cfg ./binary -f main --dot cfg.dot
      angr-tool strings ./binary --filter flag
      angr-tool xrefs ./binary -f printf
      angr-tool hexdump ./binary --section .rodata
      angr-tool callgraph ./binary -f main --dot cg.dot
      angr-tool solve ./binary --find 0x401234 --avoid 0x401000
      angr-tool patch ./binary -a 0x401000 --nop 5 -o patched
    """
    pass


# Register subcommands — Analysis
cli.add_command(cmd_info,       name="info")
cli.add_command(cmd_checksec,   name="checksec")
cli.add_command(cmd_strings,    name="strings")
cli.add_command(cmd_symsearch,  name="symsearch")
cli.add_command(cmd_hexdump,    name="hexdump")

# Register subcommands — Reverse Engineering
cli.add_command(cmd_disasm,     name="disasm")
cli.add_command(cmd_decompile,  name="decompile")
cli.add_command(cmd_cfg,        name="cfg")
cli.add_command(cmd_callgraph,  name="callgraph")
cli.add_command(cmd_xrefs,      name="xrefs")

# Register subcommands — Exploitation
cli.add_command(cmd_solve,      name="solve")
cli.add_command(cmd_patch,      name="patch")

# Register subcommands - Advanced
cli.add_command(cmd_audit,      name="audit")
cli.add_command(cmd_autopwn,    name="autopwn")
cli.add_command(cmd_heap,       name="heap")

def main():
    cli()


if __name__ == "__main__":
    main()
