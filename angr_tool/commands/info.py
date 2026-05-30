"""Command: info — show binary metadata, sections, imports, exports."""

import click
from ..core.loader import load_binary
from ..core.formatter import OutputFormatter


@click.command("info")
@click.argument("binary", type=click.Path(exists=True))
@click.option("--libs", is_flag=True, default=False, help="Also load shared libraries")
@click.option("--pdb", "debug_info", default=None, type=click.Path(), help="Path to PDB / external debug info file")
@click.option("--base-addr", default=None, help="Base address for rebasing (hex)")
@click.option("--json", "json_mode", is_flag=True, default=False, help="Output in JSON format")
@click.option("-o", "--output", "output_file", default=None, type=click.Path(), help="Save output to file")
def cmd_info(binary, libs, debug_info, base_addr, json_mode, output_file):
    """Show info & metadata of a binary file."""
    fmt = OutputFormatter(json_mode=json_mode, output_file=output_file)

    base = int(base_addr, 0) if base_addr else None
    fmt.info(f"Loading: {binary}")
    proj = load_binary(binary, auto_load_libs=libs, debug_info=debug_info, base_addr=base)

    loader = proj.loader

    # --- Binary Info ---
    fmt.header("Binary Info", section_key="binary_info")
    fmt.kv("Binary", binary, section_key="binary_info")
    fmt.kv("Architecture", proj.arch.name, section_key="binary_info")
    fmt.kv("Bits", proj.arch.bits, section_key="binary_info")
    fmt.kv("Endian", proj.arch.memory_endness, section_key="binary_info")
    fmt.kv("Entry point", hex(proj.entry), section_key="binary_info")
    fmt.kv("OS", loader.main_object.os, section_key="binary_info")
    fmt.kv("File type", type(loader.main_object).__name__, section_key="binary_info")
    fmt.kv("Min addr", hex(loader.min_addr), section_key="binary_info")
    fmt.kv("Max addr", hex(loader.max_addr), section_key="binary_info")

    # File size
    import os
    if os.path.isfile(binary):
        size = os.path.getsize(binary)
        from ..core.utils import format_size
        fmt.kv("File size", format_size(size), section_key="binary_info")

    # --- Segments ---
    try:
        segments = loader.main_object.segments
        if segments:
            fmt.header(f"Segments ({len(segments)})", section_key="segments")
            seg_list = []
            if not json_mode:
                fmt.table_header("Addr", "Size", "Flags", widths=[18, 12, 20])
            for seg in segments:
                flags = ""
                if hasattr(seg, "is_readable") and seg.is_readable:
                    flags += "R"
                if hasattr(seg, "is_writable") and seg.is_writable:
                    flags += "W"
                if hasattr(seg, "is_executable") and seg.is_executable:
                    flags += "X"
                if not json_mode:
                    fmt.table_row(hex(seg.vaddr), seg.memsize, flags, widths=[18, 12, 20])
                seg_list.append({"addr": hex(seg.vaddr), "size": seg.memsize, "flags": flags})
            fmt.add_json_list("segments", seg_list)
    except Exception:
        pass

    # --- Imports ---
    try:
        imports = list(loader.main_object.imports.keys())
        if imports:
            fmt.header(f"Imports ({len(imports)})", section_key="imports")
            fmt.add_json_list("imports", sorted(imports))
            if not json_mode:
                for imp in sorted(imports):
                    fmt.line(imp)
    except Exception:
        pass

    # --- Exports ---
    try:
        exports = [sym.name for sym in loader.main_object.symbols if sym.is_export and sym.name]
        if exports:
            fmt.header(f"Exports ({len(exports)})", section_key="exports")
            fmt.add_json_list("exports", sorted(exports))
            if not json_mode:
                for exp in sorted(exports):
                    fmt.line(exp)
    except Exception:
        pass

    # --- Sections ---
    try:
        sections = loader.main_object.sections
        if sections:
            fmt.header(f"Sections ({len(sections)})", section_key="sections")
            sec_list = []
            if not json_mode:
                fmt.table_header("Name", "Addr", "Size", widths=[20, 18, 10])
            for sec in sections:
                if not json_mode:
                    fmt.table_row(sec.name, hex(sec.vaddr), sec.memsize, widths=[20, 18, 10])
                sec_list.append({"name": sec.name, "addr": hex(sec.vaddr), "size": sec.memsize})
            fmt.add_json_list("sections", sec_list)
    except Exception:
        pass

    # --- Loaded Objects ---
    fmt.header("Loaded Objects", section_key="loaded_objects")
    obj_list = []
    for obj in loader.all_objects:
        obj_str = str(obj)
        fmt.line(obj_str)
        obj_list.append(obj_str)
    fmt.add_json_list("loaded_objects", obj_list)

    fmt.finalize()
