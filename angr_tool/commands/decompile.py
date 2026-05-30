"""Command: decompile — decompile to C-like pseudocode using angr's Decompiler."""

import click
from ..core.loader import load_binary, get_cfg
from ..core.formatter import OutputFormatter
from ..core.utils import parse_address, find_function, print_function_list


@click.command("decompile")
@click.argument("binary", type=click.Path(exists=True))
@click.option("-f", "--function", "func_name", default=None, help="Function to decompile")
@click.option("-a", "--addr", default=None, help="Function address (hex, e.g. 0x401000)")
@click.option("--all", "decompile_all", is_flag=True, default=False, help="Decompile all non-library functions")
@click.option("--libs", is_flag=True, default=False, help="Auto-load shared libraries")
@click.option("--pdb", "debug_info", default=None, type=click.Path(), help="Path to PDB / external debug info")
@click.option("--base-addr", default=None, help="Base address for rebasing (hex)")
@click.option("--json", "json_mode", is_flag=True, default=False, help="Output in JSON format")
@click.option("-o", "--output", "output_file", default=None, type=click.Path(), help="Save output to file")
def cmd_decompile(binary, func_name, addr, decompile_all, libs, debug_info, base_addr, json_mode, output_file):
    """Decompile binary to pseudocode (C-like)."""
    fmt = OutputFormatter(json_mode=json_mode, output_file=output_file)

    base = int(base_addr, 0) if base_addr else None
    fmt.info(f"Loading: {binary}")
    proj = load_binary(binary, auto_load_libs=libs, debug_info=debug_info, base_addr=base)

    if func_name or addr:
        fmt.info("Running optimized CFGFast for single function...")
        # Disable indirect jump resolution for speed if we just need a single function
        cfg = get_cfg(proj, normalize=True, resolve_indirect_jumps=False)
    else:
        fmt.info("Running full CFGFast analysis...")
        cfg = get_cfg(proj, normalize=True)

    all_decompiled = []

    if func_name:
        target = find_function(cfg, func_name)
        if target is None:
            fmt.error(f"Function '{func_name}' not found.")
            print_function_list(cfg)
            fmt.finalize()
            return
        code = _decompile_func(proj, target, cfg=cfg, fmt=fmt, json_mode=json_mode)
        if code:
            all_decompiled.append({"name": target.name, "addr": hex(target.addr), "code": code})

    elif addr:
        target_addr = parse_address(addr)
        func = cfg.kb.functions.get(target_addr)
        if func is None:
            fmt.error(f"No function found at {hex(target_addr)}.")
            fmt.finalize()
            return
        code = _decompile_func(proj, func, cfg=cfg, fmt=fmt, json_mode=json_mode)
        if code:
            all_decompiled.append({"name": func.name, "addr": hex(func.addr), "code": code})

    elif decompile_all:
        funcs = [f for f in cfg.kb.functions.values() if not f.is_simprocedure and not f.is_plt]
        funcs = sorted(funcs, key=lambda f: f.addr)
        fmt.info(f"Decompiling {len(funcs)} functions...")
        for func in funcs:
            code = _decompile_func(proj, func, cfg=cfg, fmt=fmt, json_mode=json_mode)
            if code:
                all_decompiled.append({"name": func.name, "addr": hex(func.addr), "code": code})

    else:
        # Default: list all functions
        funcs = [f for f in cfg.kb.functions.values() if not f.is_simprocedure and not f.is_plt]
        funcs = sorted(funcs, key=lambda f: f.addr)

        fmt.header(f"Functions found ({len(funcs)})")
        func_list = []
        if not json_mode:
            fmt.table_header("Address", "Name", widths=[18, 35])
        for func in funcs:
            if not json_mode:
                fmt.table_row(hex(func.addr), func.name, widths=[18, 35], colors=["green", "cyan"])
            func_list.append({"name": func.name, "addr": hex(func.addr)})

        fmt.add_json_list("functions", func_list)

        if not json_mode:
            click.echo(click.style(
                f"\n  Pilih fungsi yang mau didecompile:\n"
                f"    angr-tool decompile {binary} -f main\n"
                f"    angr-tool decompile {binary} -a 0x4015a0\n"
                f"    angr-tool decompile {binary} --all   (semua sekaligus)",
                fg="yellow"
            ))

    if json_mode and all_decompiled:
        fmt.add_json_list("decompiled", all_decompiled)

    fmt.finalize()


def _decompile_func(proj, func, cfg=None, fmt=None, json_mode=False):
    """Decompile a single function, return the code string (or None)."""
    if not json_mode:
        click.echo(click.style(f"\n{'='*60}", fg="yellow"))
        click.echo(click.style(f"  Function: {func.name} @ {hex(func.addr)}", fg="yellow", bold=True))
        click.echo(click.style(f"{'='*60}", fg="yellow"))
    try:
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        if dec.codegen is not None:
            code = dec.codegen.text
            if not json_mode:
                _syntax_highlight(code)
            return code
        else:
            if fmt:
                fmt.error(f"Decompiler returned no output for {func.name}.")
            return None
    except Exception as e:
        if fmt:
            fmt.error(f"Decompilation failed for {func.name}: {e}")
        return None


def _syntax_highlight(code: str):
    """Basic syntax highlighting for decompiled C code."""
    keywords = {
        "int", "void", "char", "unsigned", "long", "short", "return",
        "if", "else", "while", "for", "do", "switch", "case", "break",
        "continue", "struct", "typedef", "static", "const", "goto",
        "float", "double", "bool", "true", "false", "NULL", "sizeof",
    }
    lines = code.split("\n")
    for line in lines:
        tokens = line.split(" ")
        highlighted = []
        for token in tokens:
            t = token.strip("()*{};,")
            if t in keywords:
                highlighted.append(click.style(token, fg="magenta", bold=True))
            elif token.startswith("0x") or (token.lstrip("-").isdigit()):
                highlighted.append(click.style(token, fg="green"))
            elif token.startswith("//"):
                highlighted.append(click.style(token, fg="bright_black"))
            else:
                highlighted.append(token)
        click.echo("  " + " ".join(highlighted))
