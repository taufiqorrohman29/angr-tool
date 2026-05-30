"""Command: cfg — display Control Flow Graph info."""

import click
from ..core.loader import load_binary, get_cfg
from ..core.formatter import OutputFormatter
from ..core.utils import find_function


@click.command("cfg")
@click.argument("binary", type=click.Path(exists=True))
@click.option("-f", "--function", "func_name", default=None, help="Show CFG for a specific function")
@click.option("--fast/--emulated", default=True, show_default=True, help="Use CFGFast or CFGEmulated")
@click.option("--libs", is_flag=True, default=False, help="Auto-load shared libraries")
@click.option("--dot", default=None, type=click.Path(), help="Export CFG as DOT file (e.g. cfg.dot)")
@click.option("--pdb", "debug_info", default=None, type=click.Path(), help="Path to PDB / external debug info")
@click.option("--base-addr", default=None, help="Base address for rebasing (hex)")
@click.option("--json", "json_mode", is_flag=True, default=False, help="Output in JSON format")
@click.option("-o", "--output", "output_file", default=None, type=click.Path(), help="Save output to file")
def cmd_cfg(binary, func_name, fast, libs, dot, debug_info, base_addr, json_mode, output_file):
    """Analyze and display Control Flow Graph."""
    fmt = OutputFormatter(json_mode=json_mode, output_file=output_file)

    base = int(base_addr, 0) if base_addr else None
    fmt.info(f"Loading: {binary}")
    proj = load_binary(binary, auto_load_libs=libs, debug_info=debug_info, base_addr=base)

    mode = "CFGFast" if fast else "CFGEmulated"
    fmt.info(f"Running {mode}...")
    cfg = get_cfg(proj, fast=fast)

    # Summary stats
    all_funcs = list(cfg.kb.functions.values())
    real_funcs = [f for f in all_funcs if not f.is_simprocedure and not f.is_plt]
    plt_funcs = [f for f in all_funcs if f.is_plt]
    sim_funcs = [f for f in all_funcs if f.is_simprocedure]

    fmt.header("CFG Summary", section_key="summary")
    fmt.kv("Analysis mode", mode, section_key="summary")
    fmt.kv("Total functions", len(all_funcs), section_key="summary")
    fmt.kv("Real functions", len(real_funcs), section_key="summary")
    fmt.kv("PLT stubs", len(plt_funcs), section_key="summary")
    fmt.kv("SimProcedures", len(sim_funcs), section_key="summary")
    fmt.kv("Total CFG nodes", len(cfg.graph.nodes()), section_key="summary")
    fmt.kv("Total CFG edges", len(cfg.graph.edges()), section_key="summary")

    if func_name:
        # Detail for specific function
        target = find_function(cfg, func_name)
        if target is None:
            fmt.error(f"Function '{func_name}' not found.")
            fmt.finalize()
            return

        fmt.header(f"CFG for {func_name}() @ {hex(target.addr)}", section_key="function_cfg")
        fmt.kv("Blocks", len(list(target.blocks)), section_key="function_cfg")
        fmt.kv("Is Leaf", target.is_leaf, section_key="function_cfg")
        fmt.kv("Returning", target.returning, section_key="function_cfg")
        fmt.kv("Has loops", target.has_loop, section_key="function_cfg")

        block_list = []
        if not json_mode:
            click.echo(click.style(f"\n  Basic Blocks:", fg="cyan"))
        for node in cfg.graph.nodes():
            if hasattr(node, "function_address") and node.function_address == target.addr:
                preds = list(cfg.graph.predecessors(node))
                succs = list(cfg.graph.successors(node))
                if not json_mode:
                    click.echo(f"    [{hex(node.addr)}]  pred={len(preds)}  succ={len(succs)}")
                block_list.append({
                    "addr": hex(node.addr),
                    "predecessors": len(preds),
                    "successors": len(succs),
                })
        fmt.add_json_list("basic_blocks", block_list, section_key="function_cfg")

    else:
        # List all real functions
        fmt.header(f"Functions ({len(real_funcs)})", section_key="functions")
        func_list = []
        if not json_mode:
            fmt.table_header("Address", "Name", "Blocks", "Returning", widths=[18, 30, 8, 10])
        for func in sorted(real_funcs, key=lambda f: f.addr):
            blocks = len(list(func.blocks))
            ret = "yes" if func.returning else "no"
            if not json_mode:
                fmt.table_row(hex(func.addr), func.name, str(blocks), ret, widths=[18, 30, 8, 10])
            func_list.append({
                "addr": hex(func.addr),
                "name": func.name,
                "blocks": blocks,
                "returning": func.returning,
            })
        fmt.add_json_list("functions", func_list)

    if dot:
        try:
            import networkx as nx
            nx.drawing.nx_pydot.write_dot(cfg.graph, dot)
            fmt.success(f"DOT file written to: {dot}")
        except ImportError:
            fmt.error("Install networkx and pydot for DOT export: pip install networkx pydot")
        except Exception as e:
            fmt.error(f"Failed to export DOT: {e}")

    fmt.finalize()
