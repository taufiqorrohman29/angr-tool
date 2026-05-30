"""Core binary loader using angr — supports PDB, DWARF, and rebasing."""

import os
import sys
import angr
import click


def load_binary(
    binary_path: str,
    auto_load_libs: bool = False,
    base_addr: int = None,
    debug_info: str = None,
) -> angr.Project:
    """
    Load a binary file into angr Project.

    Args:
        binary_path: Path to the binary file
        auto_load_libs: Whether to auto-load shared libraries
        base_addr: Optional base address for rebasing (useful for shellcode/firmware)
        debug_info: Optional path to PDB or external DWARF debug info

    Returns:
        angr.Project instance
    """
    if not os.path.isfile(binary_path):
        click.echo(click.style(f"[!] File not found: {binary_path}", fg="red"), err=True)
        sys.exit(1)

    load_options = {}
    main_opts = {}

    if base_addr is not None:
        main_opts["base_addr"] = base_addr
    else:
        # Default base_addr for PIE binaries to prevent 0x0 mapping
        main_opts["base_addr"] = 0x400000

    if debug_info:
        if not os.path.isfile(debug_info):
            click.echo(
                click.style(f"[~] Debug info file not found: {debug_info}", fg="yellow"),
                err=True,
            )
        else:
            main_opts["debug_info"] = debug_info

    if main_opts:
        load_options["main_opts"] = main_opts

    try:
        project = angr.Project(
            binary_path,
            auto_load_libs=auto_load_libs,
            load_options=load_options if load_options else None,
        )
        return project
    except Exception as e:
        click.echo(click.style(f"[!] Failed to load binary: {e}", fg="red"), err=True)
        sys.exit(1)


def get_cfg(
    project: angr.Project,
    fast: bool = True,
    normalize: bool = True,
    show_progressbar: bool = False,
    resolve_indirect_jumps: bool = True,
):
    """
    Generate Control Flow Graph.

    Args:
        project: angr Project instance
        fast: If True use CFGFast (faster), else CFGEmulated (slower, more accurate)
        normalize: Normalize the CFG (required for decompilation)
        show_progressbar: Show progress bar during analysis
        resolve_indirect_jumps: Resolve indirect jumps (turn off for speed)

    Returns:
        CFG analysis result
    """
    if fast:
        return project.analyses.CFGFast(
            normalize=normalize,
            show_progressbar=show_progressbar,
            resolve_indirect_jumps=resolve_indirect_jumps,
        )
    else:
        return project.analyses.CFGEmulated(
            normalize=normalize,
            show_progressbar=show_progressbar,
            resolve_indirect_jumps=resolve_indirect_jumps,
        )
