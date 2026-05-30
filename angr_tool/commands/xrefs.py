"""Command: xrefs — cross-reference analysis."""

import click
from ..core.loader import load_binary, get_cfg
from ..core.formatter import OutputFormatter
from ..core.utils import parse_address, find_function


@click.command("xrefs")
@click.argument("binary", type=click.Path(exists=True))
@click.option("-f", "--function", "func_name", default=None, help="Find callers of this function")
@click.option("-a", "--addr", default=None, help="Find references to this address (hex)")
@click.option("--string", "search_str", default=None, help="Find xrefs to a string value")
@click.option("--libs", is_flag=True, default=False, help="Auto-load shared libraries")
@click.option("--pdb", "debug_info", default=None, type=click.Path(), help="Path to PDB / external debug info")
@click.option("--base-addr", default=None, help="Base address for rebasing (hex)")
@click.option("--json", "json_mode", is_flag=True, default=False, help="Output in JSON format")
@click.option("-o", "--output", "output_file", default=None, type=click.Path(), help="Save output to file")
def cmd_xrefs(binary, func_name, addr, search_str, libs, debug_info, base_addr, json_mode, output_file):
    """Cross-reference analysis — find who calls a function or references an address."""
    fmt = OutputFormatter(json_mode=json_mode, output_file=output_file)

    base = int(base_addr, 0) if base_addr else None
    fmt.info(f"Loading: {binary}")
    proj = load_binary(binary, auto_load_libs=libs, debug_info=debug_info, base_addr=base)

    fmt.info("Running CFGFast analysis...")
    cfg = get_cfg(proj)

    if func_name:
        _xrefs_to_function(proj, cfg, func_name, fmt, json_mode)
    elif addr:
        target_addr = parse_address(addr)
        _xrefs_to_addr(proj, cfg, target_addr, fmt, json_mode)
    elif search_str:
        _xrefs_to_string(proj, cfg, search_str, fmt, json_mode)
    else:
        fmt.error("Please specify -f <function>, -a <address>, or --string <text>")
        fmt.finalize()
        return

    fmt.finalize()


def _xrefs_to_function(proj, cfg, func_name, fmt, json_mode):
    """Find all callers of a function."""
    target = find_function(cfg, func_name)
    if target is None:
        fmt.error(f"Function '{func_name}' not found.")
        return

    fmt.header(f"Cross-references TO {func_name}() @ {hex(target.addr)}")

    callers = []
    # Walk all functions and check if they call the target
    for func in cfg.kb.functions.values():
        if func.addr == target.addr:
            continue
        try:
            # Check if this function has a call to target in its graph
            for node in func.transition_graph.nodes():
                if hasattr(node, "addr") and node.addr == target.addr:
                    callers.append({
                        "caller": func.name,
                        "caller_addr": hex(func.addr),
                        "from_node": hex(node.addr) if hasattr(node, "addr") else "unknown",
                    })
                    break
        except Exception:
            pass

    # Also check predecessors in CFG graph
    for node in cfg.graph.nodes():
        if hasattr(node, "addr") and node.addr == target.addr:
            for pred in cfg.graph.predecessors(node):
                pred_func = cfg.kb.functions.get(getattr(pred, "function_address", None))
                caller_name = pred_func.name if pred_func else "unknown"
                if not any(c["caller_addr"] == hex(pred.addr) for c in callers):
                    callers.append({
                        "caller": caller_name,
                        "caller_addr": hex(pred.addr),
                        "from_node": hex(pred.addr),
                    })

    if not callers:
        fmt.line("No cross-references found.")
    else:
        if not json_mode:
            fmt.table_header("Caller Function", "Address", widths=[30, 18])
        for c in callers:
            if not json_mode:
                fmt.table_row(c["caller"], c["caller_addr"], widths=[30, 18], colors=["cyan", "green"])

    fmt.add_json_data("target", func_name)
    fmt.add_json_data("target_addr", hex(target.addr))
    fmt.add_json_list("callers", callers)


def _xrefs_to_addr(proj, cfg, target_addr, fmt, json_mode):
    """Find all references to a specific address."""
    fmt.header(f"Cross-references TO {hex(target_addr)}")

    refs = []
    for node in cfg.graph.nodes():
        for succ in cfg.graph.successors(node):
            if hasattr(succ, "addr") and succ.addr == target_addr:
                func = cfg.kb.functions.get(getattr(node, "function_address", None))
                func_name = func.name if func else "unknown"
                refs.append({
                    "from_addr": hex(node.addr),
                    "from_func": func_name,
                })

    if not refs:
        fmt.line("No cross-references found.")
    else:
        if not json_mode:
            fmt.table_header("From Function", "From Address", widths=[30, 18])
        for r in refs:
            if not json_mode:
                fmt.table_row(r["from_func"], r["from_addr"], widths=[30, 18], colors=["cyan", "green"])

    fmt.add_json_data("target_addr", hex(target_addr))
    fmt.add_json_list("references", refs)


def _xrefs_to_string(proj, cfg, search_str, fmt, json_mode):
    """Find references to a string value in the binary."""
    import re

    fmt.header(f"Cross-references TO string: \"{search_str}\"")

    # First, find the string address(es) in binary
    main_obj = proj.loader.main_object
    string_addrs = []

    pattern = re.compile(search_str.encode("ascii", errors="replace"))
    for sec in main_obj.sections:
        if sec.memsize == 0:
            continue
        try:
            data = proj.loader.memory.load(sec.vaddr, sec.memsize)
            for m in pattern.finditer(data):
                str_addr = sec.vaddr + m.start()
                string_addrs.append(str_addr)
        except Exception:
            continue

    if not string_addrs:
        fmt.line(f"String \"{search_str}\" not found in binary.")
        return

    fmt.line(f"Found string at {len(string_addrs)} location(s):")
    for sa in string_addrs:
        fmt.line(f"  {hex(sa)}")

    # Now look for references to these addresses in the code
    refs = []
    for func in cfg.kb.functions.values():
        if func.is_simprocedure:
            continue
        try:
            for block_addr in func.block_addrs:
                block = proj.factory.block(block_addr)
                # Check if any instruction references the string address
                for insn in block.capstone.insns:
                    for str_addr in string_addrs:
                        if hex(str_addr) in insn.op_str or str(str_addr) in insn.op_str:
                            refs.append({
                                "func": func.name,
                                "func_addr": hex(func.addr),
                                "insn_addr": hex(insn.address),
                                "instruction": f"{insn.mnemonic} {insn.op_str}",
                                "string_addr": hex(str_addr),
                            })
        except Exception:
            continue

    if refs:
        fmt.header(f"Code references ({len(refs)})")
        if not json_mode:
            fmt.table_header("Function", "Insn Address", "Instruction", widths=[25, 18, 35])
        for r in refs:
            if not json_mode:
                fmt.table_row(r["func"], r["insn_addr"], r["instruction"], widths=[25, 18, 35], colors=["cyan", "green", None])
    else:
        fmt.line("No code references found (string may be referenced indirectly).")

    fmt.add_json_data("search_string", search_str)
    fmt.add_json_list("string_locations", [hex(a) for a in string_addrs])
    fmt.add_json_list("code_references", refs)
