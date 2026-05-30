"""Command: symsearch — search symbols/functions by name pattern."""

import click
import fnmatch
from ..core.loader import load_binary, get_cfg
from ..core.formatter import OutputFormatter


@click.command("symsearch")
@click.argument("binary", type=click.Path(exists=True))
@click.argument("pattern")
@click.option("--libs", is_flag=True, default=False, help="Auto-load shared libraries")
@click.option("--imports-only", is_flag=True, default=False, help="Search only in imports")
@click.option("--exports-only", is_flag=True, default=False, help="Search only in exports")
@click.option("--pdb", "debug_info", default=None, type=click.Path(), help="Path to PDB / external debug info")
@click.option("--base-addr", default=None, help="Base address for rebasing (hex)")
@click.option("--json", "json_mode", is_flag=True, default=False, help="Output in JSON format")
@click.option("-o", "--output", "output_file", default=None, type=click.Path(), help="Save output to file")
def cmd_symsearch(binary, pattern, libs, imports_only, exports_only, debug_info, base_addr, json_mode, output_file):
    """Search symbols and functions by name pattern (supports wildcards e.g. *malloc*)."""
    fmt = OutputFormatter(json_mode=json_mode, output_file=output_file)

    base = int(base_addr, 0) if base_addr else None
    fmt.info(f"Loading: {binary}")
    proj = load_binary(binary, auto_load_libs=libs, debug_info=debug_info, base_addr=base)
    loader = proj.loader

    results = []

    # Search in CFG functions (skip if only looking for imports/exports)
    if not imports_only and not exports_only:
        cfg = get_cfg(proj)
        for func in cfg.kb.functions.values():
            if not func.name:
                continue
            if fnmatch.fnmatch(func.name.lower(), f"*{pattern.lower()}*"):
                kind = "PLT" if func.is_plt else ("SimProc" if func.is_simprocedure else "Function")
                results.append({
                    "addr": hex(func.addr),
                    "name": func.name,
                    "kind": kind,
                    "source": "CFG",
                })

    # Search in loader symbols
    for sym in loader.main_object.symbols:
        if not sym.name:
            continue
        if not fnmatch.fnmatch(sym.name.lower(), f"*{pattern.lower()}*"):
            continue

        # Filter based on flags
        if imports_only and not sym.is_import:
            continue
        if exports_only and not sym.is_export:
            continue

        # Avoid duplicates from CFG search
        if any(r["name"] == sym.name for r in results):
            continue

        kind = "export" if sym.is_export else "import" if sym.is_import else "symbol"
        results.append({
            "addr": hex(sym.rebased_addr) if sym.rebased_addr else "N/A",
            "name": sym.name,
            "kind": kind,
            "source": "Symbols",
        })

    fmt.header(f"Symbol Search: '{pattern}' ({len(results)} found)")

    if not results:
        fmt.error("No matches found.")
        fmt.finalize()
        return

    if not json_mode:
        fmt.table_header("Address", "Type", "Source", "Name", widths=[18, 12, 10, 40])
    for r in sorted(results, key=lambda x: x["name"]):
        if not json_mode:
            fmt.table_row(
                r["addr"], r["kind"], r["source"], r["name"],
                widths=[18, 12, 10, 40],
                colors=["green", "cyan", "bright_black", None],
            )

    fmt.add_json_list("results", results)
    fmt.finalize()
