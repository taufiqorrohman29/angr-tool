"""Command: callgraph — call graph analysis and export."""

import click
from ..core.loader import load_binary, get_cfg
from ..core.formatter import OutputFormatter
from ..core.utils import find_function


@click.command("callgraph")
@click.argument("binary", type=click.Path(exists=True))
@click.option("-f", "--function", "func_name", default=None, help="Show callgraph rooted at this function")
@click.option("--depth", default=3, show_default=True, help="Maximum call depth to display")
@click.option("--dot", default=None, type=click.Path(), help="Export callgraph as DOT file")
@click.option("--libs", is_flag=True, default=False, help="Auto-load shared libraries")
@click.option("--pdb", "debug_info", default=None, type=click.Path(), help="Path to PDB / external debug info")
@click.option("--base-addr", default=None, help="Base address for rebasing (hex)")
@click.option("--json", "json_mode", is_flag=True, default=False, help="Output in JSON format")
@click.option("-o", "--output", "output_file", default=None, type=click.Path(), help="Save output to file")
def cmd_callgraph(binary, func_name, depth, dot, libs, debug_info, base_addr, json_mode, output_file):
    """Analyze and display function call graph."""
    fmt = OutputFormatter(json_mode=json_mode, output_file=output_file)

    base = int(base_addr, 0) if base_addr else None
    fmt.info(f"Loading: {binary}")
    proj = load_binary(binary, auto_load_libs=libs, debug_info=debug_info, base_addr=base)

    fmt.info("Running CFGFast analysis...")
    cfg = get_cfg(proj)

    # Build callgraph from function transitions
    callgraph = {}
    for func in cfg.kb.functions.values():
        if func.is_simprocedure:
            continue
        callees = []
        try:
            for call_site_addr, callee_addr in func.get_call_target(None) if hasattr(func, 'get_call_target') else []:
                callee = cfg.kb.functions.get(callee_addr)
                if callee:
                    callees.append(callee.name)
        except Exception:
            pass

        # Alternative: walk transition graph
        try:
            for node in func.transition_graph.nodes():
                if hasattr(node, "addr"):
                    target_func = cfg.kb.functions.get(node.addr)
                    if target_func and target_func.addr != func.addr:
                        if target_func.name not in callees:
                            callees.append(target_func.name)
        except Exception:
            pass

        if callees:
            callgraph[func.name] = {
                "addr": hex(func.addr),
                "calls": sorted(set(callees)),
            }

    if func_name:
        # Show callgraph for specific function
        target = find_function(cfg, func_name)
        if target is None:
            fmt.error(f"Function '{func_name}' not found.")
            fmt.finalize()
            return

        fmt.header(f"Call Graph from {func_name}() @ {hex(target.addr)}")
        visited = set()
        tree = _build_call_tree(func_name, callgraph, depth, visited)

        if not json_mode:
            _print_tree(tree, fmt)
        fmt.add_json_data("root", func_name)
        fmt.add_json_data("call_tree", tree)
    else:
        # Show full callgraph summary
        fmt.header(f"Call Graph ({len(callgraph)} calling functions)")

        if not json_mode:
            fmt.table_header("Function", "Calls", widths=[30, 50])
        cg_list = []
        for func_name_key, data in sorted(callgraph.items()):
            calls = data["calls"]
            if not json_mode:
                calls_str = ", ".join(calls[:5])
                if len(calls) > 5:
                    calls_str += f" (+{len(calls)-5} more)"
                fmt.table_row(func_name_key, calls_str, widths=[30, 50], colors=["cyan", None])
            cg_list.append({"name": func_name_key, "addr": data["addr"], "calls": calls})


        fmt.add_json_list("callgraph", cg_list)

    # Export to DOT
    if dot:
        try:
            _export_dot(callgraph, dot, func_name)
            fmt.success(f"DOT file written to: {dot}")
        except Exception as e:
            fmt.error(f"Failed to export DOT: {e}")

    fmt.finalize()


def _build_call_tree(func_name, callgraph, max_depth, visited, current_depth=0):
    """Build a call tree dict recursively."""
    if current_depth >= max_depth or func_name in visited:
        return {"name": func_name, "children": []}

    visited.add(func_name)
    children = []

    if func_name in callgraph:
        for callee in callgraph[func_name]["calls"]:
            child_tree = _build_call_tree(callee, callgraph, max_depth, visited, current_depth + 1)
            children.append(child_tree)

    return {"name": func_name, "children": children}


def _print_tree(tree, fmt, prefix="", is_last=True):
    """Pretty-print a call tree with box-drawing characters."""
    connector = "└── " if is_last else "├── "
    name = tree["name"]

    if prefix == "":
        click.echo(click.style(f"  {name}", fg="cyan", bold=True))
    else:
        click.echo(f"  {prefix}{click.style(connector, fg='bright_black')}{click.style(name, fg='cyan')}")

    children = tree.get("children", [])
    for i, child in enumerate(children):
        extension = "    " if is_last else "│   "
        new_prefix = prefix + ("" if prefix == "" else extension)
        if prefix == "":
            new_prefix = ""
        _print_tree(child, fmt, new_prefix + ("    " if is_last else "│   ") if prefix else "  ", i == len(children) - 1)


def _export_dot(callgraph, dot_path, root_func=None):
    """Export callgraph as DOT file."""
    with open(dot_path, "w") as f:
        f.write("digraph callgraph {\n")
        f.write("  rankdir=TB;\n")
        f.write("  node [shape=box, style=rounded, fontname=\"Consolas\"];\n")
        f.write("  edge [fontsize=10];\n")

        for func_name, data in callgraph.items():
            if root_func and func_name != root_func:
                # Only include if reachable from root (simplified: include all for now)
                pass
            for callee in data["calls"]:
                f.write(f'  "{func_name}" -> "{callee}";\n')

        f.write("}\n")
