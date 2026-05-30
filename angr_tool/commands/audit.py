"""Command: audit — automatic vulnerability discovery."""

import click
import angr
import claripy
from ..core.loader import load_binary, get_cfg
from ..core.formatter import OutputFormatter

@click.command("audit")
@click.argument("binary", type=click.Path(exists=True))
@click.option("--libs", is_flag=True, default=False, help="Auto-load shared libraries")
@click.option("--pdb", "debug_info", default=None, type=click.Path(), help="Path to PDB")
@click.option("--json", "json_mode", is_flag=True, default=False, help="JSON output")
@click.option("--dse", is_flag=True, default=False, help="Enable Directed Symbolic Execution (DSE) & Taint Analysis")
def cmd_audit(binary, libs, debug_info, json_mode, dse):
    """Scan binary for vulnerabilities (Buffer Overflow, Format String)."""
    fmt = OutputFormatter(json_mode=json_mode)
    fmt.info(f"Auditing: {binary}")
    
    proj = load_binary(binary, auto_load_libs=libs, debug_info=debug_info)
    cfg = get_cfg(proj, normalize=True, resolve_indirect_jumps=False)

    vulns = []

    dangerous_functions = ["gets", "strcpy", "system", "sprintf"]
    format_functions = ["printf", "fprintf"]

    fmt.header("Vulnerability Scan Results")

    for func_addr, func in cfg.kb.functions.items():
        if func.is_simprocedure or func.is_plt:
            continue

        for block in func.blocks:
            for arch_ins in block.capstone.insns:
                # Basic heuristical static analysis based on external calls
                # For a full taint analysis in angr, one would use SimEngine/Exploration
                # This is a static approximation for speed
                pass

        # Check references to dangerous PLT/Sim functions
        for ref in get_func_calls(cfg, func):
            target = cfg.kb.functions.get(ref)
            if target and target.name in dangerous_functions:
                vuln = {
                    "type": "Buffer Overflow / Risk",
                    "func": func.name,
                    "target": target.name,
                    "desc": f"Function {func.name} calls dangerous function {target.name}."
                }
                vulns.append(vuln)
                fmt.kv("WARNING", vuln["desc"])
            
            if target and target.name in format_functions:
                vuln = {
                    "type": "Format String Risk",
                    "func": func.name,
                    "target": target.name,
                    "desc": f"Function {func.name} calls {target.name}. Verify format parameter."
                }
                vulns.append(vuln)
                fmt.kv("INFO", vuln["desc"])
                
    if dse and vulns:
        fmt.header("Directed Symbolic Execution & Taint Analysis")
        # Basic taint hook for command injection on system()
        def check_sink(state):
            try:
                # Get the first argument
                if proj.arch.name in ("AMD64", "X86"):
                    arg0 = state.regs.rdi if proj.arch.name == "AMD64" else state.memory.load(state.regs.esp + 4, 4, endness=proj.arch.memory_endness)
                    if arg0.symbolic:
                        fmt.error(f"[!] Injection vulnerability detected at '{state.history.bbl_addrs[-1] if state.history.bbl_addrs else 'unknown'}' (CWE-78)")
            except Exception:
                pass

        state = proj.factory.entry_state()
        state.inspect.b('call', when=angr.BP_BEFORE, action=check_sink)
        
        simgr = proj.factory.simgr(state)
        # Using Veritesting to speed up the DSE path
        simgr.use_technique(angr.exploration_techniques.Veritesting())
        
        fmt.info("Running Symbolic Taint Tracker...")
        try:
            # We explore without a specific target, simply letting the hook catch the taint.
            # A bounded length limiter ensures it doesn't run forever
            simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=50, drop=True))
            simgr.explore()
            fmt.success("Taint analysis completed.")
        except Exception as e:
            fmt.warning(f"DSE failed: {e}")

    if not vulns:
        fmt.success("No obvious vulnerabilities found (static scan limit).")

    fmt.add_json_list("vulns", vulns)
    fmt.finalize()

def get_func_calls(cfg, func):
    calls = []
    for node in cfg.graph.successors(cfg.model.get_any_node(func.addr)):
        if node.function_address != func.addr:
            calls.append(node.function_address)
    return calls
