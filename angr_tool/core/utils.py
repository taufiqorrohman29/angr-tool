"""Shared utility functions for angr-tool."""

import click
import sys


def parse_address(addr_str: str) -> int:
    """
    Parse an address string, auto-detecting hex/dec/oct.
    Supports: 0x401000, 401000 (decimal), 0o777 (octal), 0b1010 (binary)
    """
    try:
        return int(addr_str, 0)
    except ValueError:
        # Try as hex without prefix
        try:
            return int(addr_str, 16)
        except ValueError:
            click.echo(click.style(f"[!] Invalid address: {addr_str}", fg="red"), err=True)
            sys.exit(1)


def find_function(cfg, name: str):
    """Find a function in CFG by exact name match."""
    for func in cfg.kb.functions.values():
        if func.name == name:
            return func
    return None


def find_function_fuzzy(cfg, pattern: str):
    """Find functions in CFG by partial name match (case-insensitive)."""
    import fnmatch
    results = []
    for func in cfg.kb.functions.values():
        if func.name and fnmatch.fnmatch(func.name.lower(), f"*{pattern.lower()}*"):
            results.append(func)
    return results


def list_functions(cfg, show_all: bool = False, limit: int = 50, exclude_sim: bool = True, exclude_plt: bool = False):
    """
    Get sorted list of functions from CFG.

    Args:
        cfg: CFG analysis result
        show_all: If True, return all functions regardless of limit
        limit: Max number of functions to return (if show_all=False)
        exclude_sim: Exclude SimProcedures
        exclude_plt: Exclude PLT stubs
    """
    funcs = []
    for f in cfg.kb.functions.values():
        if exclude_sim and f.is_simprocedure:
            continue
        if exclude_plt and f.is_plt:
            continue
        funcs.append(f)
    funcs = sorted(funcs, key=lambda f: f.addr)
    if not show_all and len(funcs) > limit:
        return funcs[:limit], len(funcs)
    return funcs, len(funcs)


def print_function_list(cfg, show_all: bool = False, limit: int = 50):
    """Print a formatted list of functions."""
    funcs, total = list_functions(cfg, show_all=show_all, limit=limit, exclude_plt=True)
    click.echo(click.style(f"\nAvailable functions ({total}):", fg="yellow"))
    for f in funcs:
        click.echo(f"  {f.name}")
    if not show_all and len(funcs) < total:
        click.echo(f"  ... and {total - len(funcs)} more. Use --show-all to see all.")


def format_size(size_bytes: int) -> str:
    """Format byte count to human readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024*1024):.1f} MB"
    else:
        return f"{size_bytes / (1024*1024*1024):.1f} GB"
