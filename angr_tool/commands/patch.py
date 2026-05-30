"""Command: patch — binary patching (NOP, byte overwrite, etc.)."""

import os
import shutil
import click
from ..core.loader import load_binary
from ..core.formatter import OutputFormatter
from ..core.utils import parse_address


@click.command("patch")
@click.argument("binary", type=click.Path(exists=True))
@click.option("-a", "--addr", required=True, help="Address to patch (hex)")
@click.option("--bytes", "patch_bytes", default=None, help="Hex bytes to write (e.g. '90 90 90' or '9090')")
@click.option("--nop", default=None, type=int, help="NOP N bytes at address")
@click.option("--asm", default=None, help="Assembly instruction to patch (e.g. 'jmp 0x401000')")
@click.option("-o", "--output", "output_file", required=True, type=click.Path(), help="Output patched file (required)")
@click.option("--libs", is_flag=True, default=False, help="Auto-load shared libraries")
@click.option("--pdb", "debug_info", default=None, type=click.Path(), help="Path to PDB / external debug info")
def cmd_patch(binary, addr, patch_bytes, nop, asm, output_file, libs, debug_info):
    """Patch a binary file at a specific address."""
    fmt = OutputFormatter()

    fmt.info(f"Loading: {binary}")
    proj = load_binary(binary, auto_load_libs=libs, debug_info=debug_info)

    patch_addr = parse_address(addr)

    # Calculate file offset from virtual address
    main_obj = proj.loader.main_object
    try:
        file_offset = _va_to_file_offset(main_obj, patch_addr)
    except ValueError as e:
        fmt.error(str(e))
        return

    # Determine patch bytes
    if nop:
        # Architecture-specific NOP
        if proj.arch.name in ("AMD64", "X86"):
            raw_bytes = b"\x90" * nop
        elif "ARM" in proj.arch.name:
            if proj.arch.bits == 32:
                nop_insn = b"\x00\x00\xa0\xe1"  # MOV R0, R0 (ARM NOP)
                raw_bytes = nop_insn * (nop // 4) + b"\x00" * (nop % 4)
            else:
                raw_bytes = b"\x1f\x20\x03\xd5" * (nop // 4)  # NOP (AArch64)
                raw_bytes += b"\x00" * (nop % 4)
        elif "MIPS" in proj.arch.name:
            raw_bytes = b"\x00\x00\x00\x00" * (nop // 4)
            raw_bytes += b"\x00" * (nop % 4)
        else:
            raw_bytes = b"\x00" * nop
        fmt.info(f"NOP {nop} bytes at {hex(patch_addr)} (arch: {proj.arch.name})")

    elif patch_bytes:
        raw_bytes = bytes.fromhex(patch_bytes.replace(" ", ""))
        fmt.info(f"Patching {len(raw_bytes)} bytes at {hex(patch_addr)}")

    elif asm:
        # Assemble using keystone if available
        try:
            from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KS_MODE_32, KS_ARCH_ARM, KS_ARCH_ARM64, KS_ARCH_MIPS, KS_MODE_ARM, KS_MODE_LITTLE_ENDIAN
            arch_map = {
                "AMD64": (KS_ARCH_X86, KS_MODE_64),
                "X86": (KS_ARCH_X86, KS_MODE_32),
                "ARMEL": (KS_ARCH_ARM, KS_MODE_ARM),
                "ARMHF": (KS_ARCH_ARM, KS_MODE_ARM),
                "AARCH64": (KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN),
                "MIPS32": (KS_ARCH_MIPS, KS_MODE_32),
            }
            if proj.arch.name not in arch_map:
                fmt.error(f"Assembly patching not supported for {proj.arch.name}. Supported so far: {', '.join(arch_map.keys())}. Use --bytes instead.")
                return
            ks_arch, ks_mode = arch_map[proj.arch.name]
            ks = Ks(ks_arch, ks_mode)
            encoding, _ = ks.asm(asm, patch_addr)
            raw_bytes = bytes(encoding)
            fmt.info(f"Assembled: {asm} -> {raw_bytes.hex()}")
        except ImportError:
            fmt.error("Assembly patching requires 'keystone-engine'. Install: pip install keystone-engine")
            return
        except Exception as e:
            fmt.error(f"Assembly failed: {e}")
            return
    else:
        fmt.error("Specify one of: --bytes, --nop, or --asm")
        return

    # Show what we're replacing
    fmt.header("Patch Details")
    fmt.kv("VA Address", hex(patch_addr))
    fmt.kv("File Offset", hex(file_offset))
    fmt.kv("Patch Size", f"{len(raw_bytes)} bytes")
    fmt.kv("New Bytes", raw_bytes.hex())

    # Show original bytes
    try:
        orig_data = proj.loader.memory.load(patch_addr, len(raw_bytes))
        fmt.kv("Original", orig_data.hex())
    except Exception:
        pass

    # Copy original file and apply patch
    try:
        shutil.copy2(binary, output_file)

        with open(output_file, "r+b") as f:
            f.seek(file_offset)
            f.write(raw_bytes)

        fmt.success(f"Patched binary saved to: {output_file}")

        # Make executable
        os.chmod(output_file, 0o755)

    except Exception as e:
        fmt.error(f"Patching failed: {e}")


def _va_to_file_offset(main_obj, va):
    """Convert virtual address to file offset."""
    try:
        for seg in main_obj.segments:
            seg_start = seg.vaddr
            seg_end = seg.vaddr + seg.memsize
            if seg_start <= va < seg_end:
                offset_in_seg = va - seg.vaddr
                file_offset = seg.offset + offset_in_seg
                return file_offset
    except Exception:
        pass

    # Fallback: try sections
    try:
        for sec in main_obj.sections:
            if sec.vaddr <= va < sec.vaddr + sec.memsize:
                offset_in_sec = va - sec.vaddr
                file_offset = sec.offset + offset_in_sec
                return file_offset
    except Exception:
        pass

    raise ValueError(f"Cannot map virtual address {hex(va)} to file offset. "
                     f"Address may be outside any segment/section.")
