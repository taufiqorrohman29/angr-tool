"""Command: heap — static heap vulnerability tracker (UAF, double free)."""

import click
import angr
from ..core.loader import load_binary, get_cfg
from ..core.formatter import OutputFormatter

@click.command("heap")
@click.argument("binary", type=click.Path(exists=True))
@click.option("--libs", is_flag=True, default=False, help="Auto-load shared libraries")
@click.option("--dynamic", is_flag=True, default=False, help="Use dynamic symbolic execution for robust tracking")
def cmd_heap(binary, libs, dynamic):
    """Analyze heap functions for Use-After-Free or Double-Free conditions."""
    fmt = OutputFormatter()
    fmt.info(f"Heap Analyzer starting (Dynamic={dynamic}): {binary}")

    proj = load_binary(binary, auto_load_libs=libs)
    cfg = get_cfg(proj, normalize=True, resolve_indirect_jumps=False)

    fmt.header("Heap Tracking Results")

    total_mallocs = 0
    total_frees = 0
    
    # Very basic static trace
    for func_addr, func in cfg.kb.functions.items():
        if func.is_simprocedure or func.is_plt:
            continue
            
        calls = get_func_calls(cfg, func)
        mallocs = [cfg.kb.functions[ref].name for ref in calls if cfg.kb.functions[ref].name in ('malloc', 'calloc', 'realloc')]
        frees = [cfg.kb.functions[ref].name for ref in calls if cfg.kb.functions[ref].name == 'free']
        
        if mallocs or frees:
            fmt.kv(f"Function {func.name}", f"malloc: {len(mallocs)}, free: {len(frees)}")
            total_mallocs += len(mallocs)
            total_frees += len(frees)

    fmt.info(f"Total Mallocs identified: {total_mallocs}")
    fmt.info(f"Total Frees identified: {total_frees}")

    if total_frees > total_mallocs:
        fmt.warning("More frees than mallocs found — possible Double Free.")
    elif total_mallocs > total_frees:
        fmt.warning("More mallocs than frees found — possible Memory Leak.")
    else:
        fmt.success("Heap operations seem balanced (statically).")
        
    if dynamic:
        fmt.header("Dynamic Heap Analysis (SimStatePlugin)")
        try:
            # Reigster the heap tracker
            class HeapTracker(angr.SimStatePlugin):
                def __init__(self):
                    super().__init__()
                    self.allocated = set()
                    self.freed = set()
                @angr.SimStatePlugin.memo
                def copy(self, memo):
                    h = HeapTracker()
                    h.allocated = set(self.allocated)
                    h.freed = set(self.freed)
                    return h
            
            angr.SimStatePlugin.register_default('heap_tracker', HeapTracker)
            
            # Start dynamic tracking
            state = proj.factory.entry_state()
            
            def check_is_free(s):
                try:
                    last_ins = proj.factory.block(s.addr).instruction_addrs[-1]
                    sym = proj.loader.find_symbol(last_ins)
                    if sym and "free" in sym.name:
                        return True
                    return False
                except Exception:
                    return False

            def hook_free(state):
                try:
                    # In x64 standard Calling Convention, RDI is the first arg
                    if proj.arch.name == "AMD64":
                        ptr_val = state.solver.eval(state.regs.rdi)
                    else: # x86
                        ptr_val = state.solver.eval(state.memory.load(state.regs.esp + 4, 4, endness=proj.arch.memory_endness))
                        
                    if ptr_val in state.heap_tracker.freed:
                        fmt.error(f"[!!!] DOUBLE FREE DETECTED on pointer {hex(ptr_val)} at instruction {state.history.bbl_addrs[-1] if state.history.bbl_addrs else 'unknown'}")
                    state.heap_tracker.freed.add(ptr_val)
                    state.heap_tracker.allocated.discard(ptr_val)
                except Exception:
                    pass
            
            state.inspect.b('call', when=angr.BP_BEFORE, action=lambda s: hook_free(s) if check_is_free(s) else None)
            
            simgr = proj.factory.simgr(state)
            simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=50, drop=True))
            simgr.explore()
            fmt.success("Dynamic heap analysis completed.")
        except Exception as e:
            fmt.warning(f"Failed dynamic execution: {e}")

    fmt.finalize()

def get_func_calls(cfg, func):
    calls = []
    for node in cfg.graph.successors(cfg.model.get_any_node(func.addr)):
        if node.function_address != func.addr:
            calls.append(node.function_address)
    return calls
