"""Command: checksec — check binary security protections."""

import click
from ..core.loader import load_binary
from ..core.formatter import OutputFormatter


@click.command("checksec")
@click.argument("binary", type=click.Path(exists=True))
@click.option("--libs", is_flag=True, default=False, help="Auto-load shared libraries")
@click.option("--json", "json_mode", is_flag=True, default=False, help="Output in JSON format")
@click.option("-o", "--output", "output_file", default=None, type=click.Path(), help="Save output to file")
def cmd_checksec(binary, libs, json_mode, output_file):
    """Check binary security protections (NX, PIE, Canary, RELRO, etc.)."""
    fmt = OutputFormatter(json_mode=json_mode, output_file=output_file)

    fmt.info(f"Loading: {binary}")
    proj = load_binary(binary, auto_load_libs=libs)
    main_obj = proj.loader.main_object

    fmt.header("Security Protections", section_key="checksec")

    checks = {}

    # --- NX (No-Execute / DEP) ---
    nx = _check_nx(main_obj)
    checks["NX"] = nx
    _print_check(fmt, "NX (No-Execute)", nx, json_mode, "checksec")

    # --- PIE (Position Independent Executable) ---
    pie = _check_pie(proj, main_obj)
    checks["PIE"] = pie
    _print_check(fmt, "PIE", pie, json_mode, "checksec")

    # --- Stack Canary ---
    canary = _check_canary(proj)
    checks["Canary"] = canary
    _print_check(fmt, "Stack Canary", canary, json_mode, "checksec")

    # --- RELRO ---
    relro = _check_relro(main_obj)
    checks["RELRO"] = relro
    _print_check(fmt, "RELRO", relro, json_mode, "checksec")

    # --- Fortify Source ---
    fortify = _check_fortify(proj)
    checks["Fortify"] = fortify
    _print_check(fmt, "Fortify Source", fortify, json_mode, "checksec")

    # --- RPATH / RUNPATH ---
    rpath = _check_rpath(main_obj)
    checks["RPATH"] = rpath
    _print_check(fmt, "RPATH/RUNPATH", rpath, json_mode, "checksec")

    # --- Stripped ---
    stripped = _check_stripped(main_obj)
    checks["Stripped"] = stripped
    _print_check(fmt, "Stripped", stripped, json_mode, "checksec")

    # Summary
    fmt.header("Summary", section_key="summary")
    secure_count = sum(1 for v in checks.values() if v.get("secure", False))
    total = len(checks)
    fmt.kv("Secure", f"{secure_count}/{total}", section_key="summary")

    if secure_count == total:
        fmt.success("All protections enabled!")
    elif secure_count >= total // 2:
        fmt.warning("Some protections are missing.")
    else:
        fmt.error("Binary has weak protections!")

    fmt.finalize()


def _print_check(fmt, name, result, json_mode, section_key):
    """Print a single security check result."""
    enabled = result.get("enabled", False)
    detail = result.get("detail", "")

    if json_mode:
        fmt.add_json_data(name, result, section_key=section_key)
        return

    if enabled:
        icon = click.style("✓", fg="green", bold=True)
        status = click.style(f"Enabled", fg="green")
    else:
        icon = click.style("✗", fg="red", bold=True)
        status = click.style(f"Disabled", fg="red")

    detail_str = f"  ({detail})" if detail else ""
    click.echo(f"  {icon}  {name:<20} {status}{detail_str}")


def _check_nx(main_obj) -> dict:
    """Check if NX (No-Execute) is enabled."""
    try:
        if hasattr(main_obj, "execstack"):
            nx_enabled = not main_obj.execstack
            return {"enabled": nx_enabled, "secure": nx_enabled, "detail": "Stack not executable" if nx_enabled else "Executable stack"}

        # Check GNU_STACK segment
        for seg in getattr(main_obj, "segments", []):
            seg_type = getattr(seg, "type", None)
            if seg_type and "GNU_STACK" in str(seg_type):
                is_exec = getattr(seg, "is_executable", False)
                return {"enabled": not is_exec, "secure": not is_exec}

        return {"enabled": False, "secure": False, "detail": "Cannot determine"}
    except Exception:
        return {"enabled": False, "secure": False, "detail": "Check failed"}


def _check_pie(proj, main_obj) -> dict:
    """Check if PIE (Position Independent Executable) is enabled."""
    try:
        if hasattr(main_obj, "pic"):
            return {"enabled": main_obj.pic, "secure": main_obj.pic, "detail": "Position Independent" if main_obj.pic else "Fixed base"}
        # Heuristic: if entry is low address, likely not PIE
        return {"enabled": proj.entry < 0x10000, "secure": proj.entry < 0x10000, "detail": f"Entry: {hex(proj.entry)}"}
    except Exception:
        return {"enabled": False, "secure": False, "detail": "Check failed"}


def _check_canary(proj) -> dict:
    """Check for stack canary by looking for __stack_chk_fail import."""
    try:
        imports = list(proj.loader.main_object.imports.keys())
        has_canary = any("stack_chk" in imp for imp in imports)
        return {"enabled": has_canary, "secure": has_canary, "detail": "__stack_chk_fail found" if has_canary else "No canary symbols"}
    except Exception:
        return {"enabled": False, "secure": False, "detail": "Check failed"}


def _check_relro(main_obj) -> dict:
    """Check RELRO (Relocation Read-Only) status."""
    try:
        has_gnu_relro = False
        has_bind_now = False

        for seg in getattr(main_obj, "segments", []):
            seg_type = getattr(seg, "type", None)
            if seg_type and "GNU_RELRO" in str(seg_type):
                has_gnu_relro = True

        # Check for BIND_NOW in dynamic section
        if hasattr(main_obj, "dynamic") and main_obj.dynamic:
            for entry in main_obj.dynamic.get("DT_FLAGS", []):
                if "BIND_NOW" in str(entry):
                    has_bind_now = True
            if "DT_BIND_NOW" in main_obj.dynamic:
                has_bind_now = True

        if has_gnu_relro and has_bind_now:
            return {"enabled": True, "secure": True, "detail": "Full RELRO"}
        elif has_gnu_relro:
            return {"enabled": True, "secure": False, "detail": "Partial RELRO"}
        else:
            return {"enabled": False, "secure": False, "detail": "No RELRO"}
    except Exception:
        return {"enabled": False, "secure": False, "detail": "Check failed"}


def _check_fortify(proj) -> dict:
    """Check for Fortify Source by looking for _chk function variants."""
    try:
        imports = list(proj.loader.main_object.imports.keys())
        fortified = [imp for imp in imports if "_chk" in imp and "stack" not in imp]
        if fortified:
            return {"enabled": True, "secure": True, "detail": f"{len(fortified)} fortified functions"}
        return {"enabled": False, "secure": False, "detail": "No fortified functions"}
    except Exception:
        return {"enabled": False, "secure": False, "detail": "Check failed"}


def _check_rpath(main_obj) -> dict:
    """Check for RPATH/RUNPATH (potential hijacking vector)."""
    try:
        has_rpath = False
        if hasattr(main_obj, "dynamic") and main_obj.dynamic:
            if "DT_RPATH" in main_obj.dynamic or "DT_RUNPATH" in main_obj.dynamic:
                has_rpath = True

        # No RPATH = more secure (no hijacking)
        return {"enabled": has_rpath, "secure": not has_rpath, "detail": "RPATH set (hijack risk)" if has_rpath else "No RPATH"}
    except Exception:
        return {"enabled": False, "secure": True, "detail": "No RPATH"}


def _check_stripped(main_obj) -> dict:
    """Check if binary is stripped."""
    try:
        symbols = list(main_obj.symbols)
        # If very few symbols, likely stripped
        named = [s for s in symbols if s.name and not s.name.startswith("_")]
        is_stripped = len(named) < 5
        return {"enabled": is_stripped, "secure": is_stripped, "detail": f"{len(symbols)} symbols" if not is_stripped else "Stripped"}
    except Exception:
        return {"enabled": False, "secure": False, "detail": "Check failed"}
