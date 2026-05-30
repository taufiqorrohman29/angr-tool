"""Command: solve — symbolic execution constraint solver using angr's SimulationManager."""

import click
import sys
from ..core.loader import load_binary
from ..core.formatter import OutputFormatter
from ..core.utils import parse_address


@click.command("solve")
@click.argument("binary", type=click.Path(exists=True))
@click.option("--find", "find_addrs", multiple=True, help="Target address(es) to reach (hex, repeatable)")
@click.option("--avoid", "avoid_addrs", multiple=True, help="Address(es) to avoid (hex, repeatable)")
@click.option("--stdin-len", default=32, show_default=True, help="Length of symbolic stdin")
@click.option("--argv", "sym_argv", default=None, help="Symbolic argv (comma-separated lengths, e.g. '10,20')")
@click.option("--timeout", default=300, show_default=True, help="Maximum seconds for exploration")
@click.option("--max-steps", default=1000, show_default=True, help="Max execution steps per path (prevents memory explosion)")
@click.option("--start", "start_addr", default=None, help="Start address (hex, default: entry point)")
@click.option("--strategy", default="bfs", show_default=True,
              type=click.Choice(["bfs", "dfs", "explorer", "veritesting", "dfs-lazy"]),
              help="Exploration strategy (advanced modes: veritesting, dfs-lazy)")
@click.option("--libs", is_flag=True, default=False, help="Auto-load shared libraries")
@click.option("--pdb", "debug_info", default=None, type=click.Path(), help="Path to PDB / external debug info")
@click.option("--json", "json_mode", is_flag=True, default=False, help="Output in JSON format")
@click.option("-o", "--output", "output_file", default=None, type=click.Path(), help="Save output to file")
def cmd_solve(binary, find_addrs, avoid_addrs, stdin_len, sym_argv, timeout, max_steps, start_addr,
              strategy, libs, debug_info, json_mode, output_file):
    """Symbolic execution solver — find inputs that reach target addresses."""
    fmt = OutputFormatter(json_mode=json_mode, output_file=output_file)

    if not find_addrs:
        fmt.error("At least one --find address is required.")
        fmt.error("Usage: angr-tool solve ./binary --find 0x401234 --avoid 0x401000")
        fmt.finalize()
        return

    fmt.info(f"Loading: {binary}")
    proj = load_binary(binary, auto_load_libs=libs, debug_info=debug_info)

    import angr
    import claripy

    # Parse addresses
    find_list = [parse_address(a) for a in find_addrs]
    avoid_list = [parse_address(a) for a in avoid_addrs]

    fmt.header("Solve Configuration", section_key="config")
    fmt.kv("Find", ", ".join(hex(a) for a in find_list), section_key="config")
    fmt.kv("Avoid", ", ".join(hex(a) for a in avoid_list) if avoid_list else "None", section_key="config")
    fmt.kv("Strategy", strategy, section_key="config")
    fmt.kv("Timeout", f"{timeout}s", section_key="config")
    fmt.kv("Max Steps", str(max_steps), section_key="config")

    # Create initial state
    if start_addr:
        start = parse_address(start_addr)
        fmt.kv("Start", hex(start), section_key="config")
    else:
        start = None

    # Setup symbolic input
    if sym_argv:
        # Symbolic argv
        lengths = [int(l.strip()) for l in sym_argv.split(",")]
        sym_args = []
        for i, length in enumerate(lengths):
            sym_arg = claripy.BVS(f"argv_{i}", length * 8)
            sym_args.append(sym_arg)

        state = proj.factory.entry_state(
            addr=start,
            args=[binary] + sym_args,
        )
        fmt.kv("Input mode", f"Symbolic argv ({len(lengths)} args)", section_key="config")
    else:
        # Symbolic stdin
        sym_stdin = claripy.BVS("stdin", stdin_len * 8)
        state = proj.factory.entry_state(
            addr=start,
            stdin=sym_stdin,
        )
        fmt.kv("Input mode", f"Symbolic stdin ({stdin_len} bytes)", section_key="config")

    # Advanced Optimization: Lazy Solves
    if "lazy" in strategy:
        state.options.add(angr.options.LAZY_SOLVES)
        fmt.kv("Optimization", "LAZY_SOLVES enabled", section_key="config")

    # Create simulation manager
    simgr = proj.factory.simulation_manager(state)

    # Add length limiter to prevent path explosion memory leaks
    length_limiter = angr.exploration_techniques.LengthLimiter(max_length=max_steps, drop=True)
    simgr.use_technique(length_limiter)
    
    # Advanced Optimization: Veritesting
    if strategy == "veritesting":
        simgr.use_technique(angr.exploration_techniques.Veritesting())
        fmt.kv("Optimization", "Veritesting (Static State Merging) enabled", section_key="config")

    if "dfs" in strategy:
        simgr.use_technique(angr.exploration_techniques.DFS())

    # Advanced Optimization: LoopSeer
    try:
        cfg = proj.analyses.CFGFast(resolve_indirect_jumps=False)
        simgr.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=5))
        fmt.kv("Optimization", "LoopSeer enabled (bound=5)", section_key="config")
    except Exception as e:
        fmt.warning(f"Failed to load LoopSeer: {e}")

    fmt.info(f"Starting exploration ({strategy})...")

    # Set exploration strategy
    try:
        import signal

        timed_out = [False]

        def timeout_handler(signum, frame):
            timed_out[0] = True
            raise TimeoutError("Exploration timed out")

        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)

        simgr.explore(
            find=find_list,
            avoid=avoid_list,
        )

        signal.alarm(0)  # Cancel alarm

    except TimeoutError:
        fmt.warning(f"Exploration timed out after {timeout}s")
    except Exception as e:
        fmt.error(f"Exploration failed: {e}")
        fmt.finalize()
        return

    # Results
    fmt.header("Results", section_key="results")
    fmt.kv("Found states", len(simgr.found), section_key="results")
    fmt.kv("Avoided states", len(simgr.avoid) if hasattr(simgr, 'avoid') else 0, section_key="results")
    fmt.kv("Active states", len(simgr.active), section_key="results")
    fmt.kv("Deadended", len(simgr.deadended), section_key="results")

    solutions = []
    if simgr.found:
        fmt.success(f"Found {len(simgr.found)} solution(s)!")
        for i, found_state in enumerate(simgr.found):
            fmt.header(f"Solution #{i+1}")

            solution = {"index": i + 1}

            # Try to extract stdin solution
            try:
                if sym_argv:
                    for j, sym_arg in enumerate(sym_args):
                        val = found_state.solver.eval(sym_arg, cast_to=bytes)
                        decoded = val.decode("latin-1", errors="replace")
                        fmt.kv(f"argv[{j+1}]", repr(decoded))
                        solution[f"argv_{j+1}"] = decoded
                else:
                    stdin_data = found_state.posix.dumps(0)
                    decoded = stdin_data.decode("latin-1", errors="replace")
                    fmt.kv("stdin (raw)", repr(stdin_data))
                    fmt.kv("stdin (text)", decoded)
                    solution["stdin_raw"] = repr(stdin_data)
                    solution["stdin_text"] = decoded
            except Exception as e:
                fmt.warning(f"Could not extract input: {e}")
                solution["error"] = str(e)

            # Show stdout if available
            try:
                stdout = found_state.posix.dumps(1)
                if stdout:
                    fmt.kv("stdout", stdout.decode("latin-1", errors="replace"))
                    solution["stdout"] = stdout.decode("latin-1", errors="replace")
            except Exception:
                pass

            solutions.append(solution)
    else:
        fmt.error("No solutions found.")

    fmt.add_json_list("solutions", solutions)
    fmt.finalize()
