"""Command: hexdump — hex dump of binary memory regions."""

import click
from ..core.loader import load_binary
from ..core.formatter import OutputFormatter
from ..core.utils import parse_address


@click.command("hexdump")
@click.argument("binary", type=click.Path(exists=True))
@click.option("-a", "--addr", default=None, help="Start address (hex)")
@click.option("-n", "--count", default=256, show_default=True, help="Number of bytes to dump")
@click.option("--section", default=None, help="Dump entire section (e.g. .text, .rodata)")
@click.option("--width", default=16, show_default=True, help="Bytes per row")
@click.option("--libs", is_flag=True, default=False, help="Auto-load shared libraries")
@click.option("--pdb", "debug_info", default=None, type=click.Path(), help="Path to PDB / external debug info")
@click.option("--base-addr", default=None, help="Base address for rebasing (hex)")
@click.option("--json", "json_mode", is_flag=True, default=False, help="Output in JSON format")
@click.option("-o", "--output", "output_file", default=None, type=click.Path(), help="Save output to file")
def cmd_hexdump(binary, addr, count, section, width, libs, debug_info, base_addr, json_mode, output_file):
    """Hex dump of binary memory at an address or section."""
    fmt = OutputFormatter(json_mode=json_mode, output_file=output_file)

    base = int(base_addr, 0) if base_addr else None
    fmt.info(f"Loading: {binary}")
    proj = load_binary(binary, auto_load_libs=libs, debug_info=debug_info, base_addr=base)

    if section:
        # Dump an entire section
        main_obj = proj.loader.main_object
        target_sec = None
        for s in main_obj.sections:
            if s.name == section:
                target_sec = s
                break
        if target_sec is None:
            fmt.error(f"Section '{section}' not found.")
            avail = [s.name for s in main_obj.sections if s.name]
            click.echo(f"Available: {', '.join(avail)}")
            fmt.finalize()
            return

        start_addr = target_sec.vaddr
        dump_size = target_sec.memsize
        fmt.header(f"Hexdump of section {section} ({dump_size} bytes @ {hex(start_addr)})")
    elif addr:
        start_addr = parse_address(addr)
        dump_size = count
        fmt.header(f"Hexdump @ {hex(start_addr)} ({dump_size} bytes)")
    else:
        # Default: dump from entry point
        start_addr = proj.entry
        dump_size = count
        fmt.header(f"Hexdump @ entry point {hex(start_addr)} ({dump_size} bytes)")

    try:
        data = proj.loader.memory.load(start_addr, dump_size)
    except Exception as e:
        fmt.error(f"Failed to read memory at {hex(start_addr)}: {e}")
        fmt.finalize()
        return

    if json_mode:
        hex_rows = []
        for offset in range(0, len(data), width):
            row_data = data[offset:offset + width]
            hex_str = " ".join(f"{b:02x}" for b in row_data)
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in row_data)
            hex_rows.append({
                "addr": hex(start_addr + offset),
                "hex": hex_str,
                "ascii": ascii_str,
            })
        fmt.add_json_data("start_addr", hex(start_addr))
        fmt.add_json_data("size", dump_size)
        fmt.add_json_list("rows", hex_rows)
    else:
        for offset in range(0, len(data), width):
            row_data = data[offset:offset + width]
            addr_part = click.style(f"  {hex(start_addr + offset):<12}", fg="green")

            hex_parts = []
            for i, b in enumerate(row_data):
                hex_parts.append(f"{b:02x}")
                if i == width // 2 - 1:
                    hex_parts.append("")  # extra space at midpoint
            hex_str = " ".join(hex_parts)
            # Pad if last row is short
            expected_len = width * 3 + 1  # approximate
            hex_part = click.style(f"{hex_str:<{expected_len}}", fg="cyan")

            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in row_data)
            ascii_part = click.style(f"|{ascii_str}|", fg="yellow")

            click.echo(f"{addr_part}{hex_part} {ascii_part}")

    fmt.finalize()
