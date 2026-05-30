"""Command: disasm — disassemble functions or address ranges."""

import click
from ..core.loader import load_binary, get_cfg
from ..core.formatter import OutputFormatter
from ..core.utils import parse_address, find_function, print_function_list


@click.command("disasm")
@click.argument("binary", type=click.Path(exists=True))
@click.option("-f", "--function", "func_name", default=None, help="Function name to disassemble")
@click.option("-a", "--addr", default=None, help="Start address (hex, e.g. 0x401000)")
@click.option("-n", "--count", default=50, show_default=True, help="Number of instructions to disassemble")
@click.option("--show-all", is_flag=True, default=False, help="Show all functions when listing")
@click.option("--libs", is_flag=True, default=False, help="Auto-load shared libraries")
@click.option("--pdb", "debug_info", default=None, type=click.Path(), help="Path to PDB / external debug info")
@click.option("--base-addr", default=None, help="Base address for rebasing (hex)")
@click.option("--json", "json_mode", is_flag=True, default=False, help="Output in JSON format")
@click.option("-o", "--output", "output_file", default=None, type=click.Path(), help="Save output to file")
def cmd_disasm(binary, func_name, addr, count, show_all, libs, debug_info, base_addr, json_mode, output_file):
    """Disassemble a function or address range in the binary."""
    fmt = OutputFormatter(json_mode=json_mode, output_file=output_file)

    base = int(base_addr, 0) if base_addr else None
    fmt.info(f"Loading: {binary}")
    proj = load_binary(binary, auto_load_libs=libs, debug_info=debug_info, base_addr=base)

    if func_name:
        # Disassemble by function name
        cfg = get_cfg(proj)
        target_func = find_function(cfg, func_name)

        if target_func is None:
            fmt.error(f"Function '{func_name}' not found.")
            print_function_list(cfg, show_all=show_all)
            fmt.finalize()
            return

        start_addr = target_func.addr
        fmt.header(f"Disassembly of {func_name}() @ {hex(start_addr)}")

        all_insns = []
        # Walk all blocks in function
        for block_addr in sorted(target_func.block_addrs):
            try:
                b = proj.factory.block(block_addr)
                _collect_block(b, fmt, all_insns, json_mode)
            except Exception:
                pass

        if json_mode:
            fmt.add_json_data("function", func_name)
            fmt.add_json_data("address", hex(start_addr))
            fmt.add_json_list("instructions", all_insns)

    elif addr:
        start = parse_address(addr)
        fmt.header(f"Disassembly @ {hex(start)} ({count} insns)")

        block = proj.factory.block(start, num_inst=count)
        all_insns = []
        _collect_block(block, fmt, all_insns, json_mode)

        if json_mode:
            fmt.add_json_data("address", hex(start))
            fmt.add_json_list("instructions", all_insns)

    else:
        # Default: disassemble entry point
        fmt.header(f"Disassembly @ entry point {hex(proj.entry)}")

        block = proj.factory.block(proj.entry, num_inst=count)
        all_insns = []
        _collect_block(block, fmt, all_insns, json_mode)

        if json_mode:
            fmt.add_json_data("address", hex(proj.entry))
            fmt.add_json_list("instructions", all_insns)

    fmt.finalize()


def _collect_block(block, fmt, all_insns, json_mode):
    """Print and/or collect instructions from a basic block."""
    for insn in block.capstone.insns:
        if json_mode:
            all_insns.append({
                "address": hex(insn.address),
                "bytes": insn.bytes.hex(),
                "mnemonic": insn.mnemonic,
                "operands": insn.op_str,
            })
        else:
            addr_str = click.style(f"  {hex(insn.address)}", fg="green")
            bytes_str = click.style(f"  {insn.bytes.hex():<20}", fg="bright_black")
            mnem_str = click.style(f"{insn.mnemonic:<10}", fg="cyan")
            op_str = insn.op_str
            click.echo(f"{addr_str}{bytes_str}{mnem_str} {op_str}")
