"""Command: strings — extract printable strings from binary sections."""

import re
import click
from ..core.loader import load_binary
from ..core.formatter import OutputFormatter


@click.command("strings")
@click.argument("binary", type=click.Path(exists=True))
@click.option("-n", "--min-length", default=4, show_default=True, help="Minimum string length")
@click.option("--filter", "filter_str", default=None, help="Filter strings containing this pattern")
@click.option("--section", default=None, help="Only search in specific section (e.g. .rodata)")
@click.option("--encoding", default="ascii", show_default=True,
              type=click.Choice(["ascii", "utf-8", "utf-16le", "utf-16be"]),
              help="String encoding to search for")
@click.option("--libs", is_flag=True, default=False, help="Auto-load shared libraries")
@click.option("--pdb", "debug_info", default=None, type=click.Path(), help="Path to PDB / external debug info")
@click.option("--base-addr", default=None, help="Base address for rebasing (hex)")
@click.option("--json", "json_mode", is_flag=True, default=False, help="Output in JSON format")
@click.option("-o", "--output", "output_file", default=None, type=click.Path(), help="Save output to file")
def cmd_strings(binary, min_length, filter_str, section, encoding, libs, debug_info, base_addr, json_mode, output_file):
    """Extract printable strings from binary sections."""
    fmt = OutputFormatter(json_mode=json_mode, output_file=output_file)

    base = int(base_addr, 0) if base_addr else None
    fmt.info(f"Loading: {binary}")
    proj = load_binary(binary, auto_load_libs=libs, debug_info=debug_info, base_addr=base)

    loader = proj.loader
    main_obj = loader.main_object

    # Determine which sections to search
    if section:
        sections = [s for s in main_obj.sections if s.name == section]
        if not sections:
            fmt.error(f"Section '{section}' not found.")
            avail = [s.name for s in main_obj.sections]
            click.echo(f"Available sections: {', '.join(avail)}")
            fmt.finalize()
            return
    else:
        sections = list(main_obj.sections)

    found = []

    if encoding == "ascii" or encoding == "utf-8":
        printable = re.compile(rb'[ -~]{' + str(min_length).encode() + rb',}')
        for sec in sections:
            if sec.memsize == 0:
                continue
            try:
                data = proj.loader.memory.load(sec.vaddr, sec.memsize)
            except Exception:
                continue

            matches = printable.finditer(data)
            for m in matches:
                s = m.group().decode("ascii", errors="replace")
                addr = sec.vaddr + m.start()
                found.append((addr, sec.name, s))

    elif encoding.startswith("utf-16"):
        byte_order = "le" if encoding.endswith("le") else "be"
        for sec in sections:
            if sec.memsize == 0:
                continue
            try:
                data = proj.loader.memory.load(sec.vaddr, sec.memsize)
            except Exception:
                continue

            # Search for UTF-16 strings (alternating ASCII + null bytes)
            if byte_order == "le":
                pattern = re.compile(b'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + b',}')
            else:
                pattern = re.compile(b'(?:\x00[\x20-\x7e]){' + str(min_length).encode() + b',}')

            matches = pattern.finditer(data)
            for m in matches:
                try:
                    s = m.group().decode(f"utf-16-{byte_order}", errors="replace")
                    addr = sec.vaddr + m.start()
                    found.append((addr, sec.name, s))
                except Exception:
                    continue

    # Apply filter
    if filter_str:
        found = [(a, sn, s) for a, sn, s in found if filter_str.lower() in s.lower()]

    fmt.header(f"Strings ({len(found)} found)")

    string_list = []
    if not json_mode:
        fmt.table_header("Address", "Section", "String", widths=[18, 15, 40])

    for addr, sec_name, s in sorted(found, key=lambda x: x[0]):
        if not json_mode:
            addr_str = click.style(f"  {hex(addr):<18}", fg="green")
            sec_str = click.style(f"{sec_name:<15}", fg="bright_black")
            click.echo(f"{addr_str}{sec_str}{s}")
        string_list.append({"addr": hex(addr), "section": sec_name, "string": s})

    fmt.add_json_list("strings", string_list)
    fmt.finalize()
