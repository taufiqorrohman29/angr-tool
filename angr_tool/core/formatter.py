"""Output formatter — supports text, JSON, and file output."""

import click
import json
import sys


class OutputFormatter:
    """
    Centralized output handler that supports:
    - Text output (default, with colors)
    - JSON output (--json flag)
    - File output (-o/--output flag)
    """

    def __init__(self, json_mode: bool = False, output_file: str = None):
        self.json_mode = json_mode
        self.output_file = output_file
        self._data = {}  # Collected data for JSON output
        self._sections = []  # Ordered section names
        self._file_handle = None

        if output_file:
            try:
                self._file_handle = open(output_file, "w", encoding="utf-8")
            except IOError as e:
                click.echo(click.style(f"[!] Cannot open output file: {e}", fg="red"), err=True)
                sys.exit(1)

    def _write(self, text: str, err: bool = False):
        """Write text to appropriate destination."""
        if self._file_handle and not err:
            # Strip ANSI codes for file output
            import re
            clean = re.sub(r'\x1b\[[0-9;]*m', '', text)
            self._file_handle.write(clean + "\n")
        else:
            click.echo(text, err=err)

    def header(self, title: str, section_key: str = None):
        """Print a section header."""
        if self.json_mode:
            if section_key:
                self._sections.append(section_key)
                self._data[section_key] = {}
            return
        self._write(click.style(f"\n=== {title} ===", fg="yellow", bold=True))

    def info(self, message: str):
        """Print an info/status message."""
        if self.json_mode:
            return
        self._write(click.style(f"[*] {message}", fg="cyan"))

    def success(self, message: str):
        """Print a success message."""
        if self.json_mode:
            return
        self._write(click.style(f"[+] {message}", fg="green"))

    def error(self, message: str):
        """Print an error message."""
        if self.json_mode:
            self._data["error"] = message
            return
        self._write(click.style(f"[!] {message}", fg="red"), err=True)

    def warning(self, message: str):
        """Print a warning message."""
        if self.json_mode:
            return
        self._write(click.style(f"[~] {message}", fg="yellow"), err=True)

    def kv(self, key: str, value, section_key: str = None):
        """Print a key-value pair."""
        if self.json_mode:
            if section_key and section_key in self._data:
                self._data[section_key][key] = value
            else:
                self._data[key] = value
            return
        self._write(f"  {key:<16}: {value}")

    def line(self, text: str):
        """Print a plain line."""
        if self.json_mode:
            return
        self._write(f"  {text}")

    def table_header(self, *columns, widths=None):
        """Print a table header row."""
        if self.json_mode:
            return
        if widths is None:
            widths = [20] * len(columns)
        header = "  " + "".join(f"{col:<{w}}" for col, w in zip(columns, widths))
        separator = "  " + "".join(f"{'-'*w}" for w in widths)
        self._write(header)
        self._write(separator)

    def table_row(self, *values, widths=None, colors=None):
        """Print a table row with optional coloring."""
        if self.json_mode:
            return
        if widths is None:
            widths = [20] * len(values)
        if colors is None:
            colors = [None] * len(values)

        parts = []
        for val, w, color in zip(values, widths, colors):
            s = f"{val:<{w}}"
            if color:
                s = click.style(s, fg=color)
            parts.append(s)
        self._write("  " + "".join(parts))

    def add_json_list(self, key: str, items: list, section_key: str = None):
        """Add a list to JSON output."""
        if section_key and section_key in self._data:
            self._data[section_key][key] = items
        else:
            self._data[key] = items

    def add_json_data(self, key: str, value, section_key: str = None):
        """Add arbitrary data to JSON output."""
        if section_key and section_key in self._data:
            self._data[section_key][key] = value
        else:
            self._data[key] = value

    def code_block(self, code: str, language: str = "c"):
        """Print a code block (for decompiled output, etc.)."""
        if self.json_mode:
            self._data.setdefault("code", []).append(code)
            return
        for line in code.split("\n"):
            self._write(f"  {line}")

    def finalize(self):
        """Finalize output: flush JSON or close file."""
        if self.json_mode:
            output = json.dumps(self._data, indent=2, default=str)
            if self._file_handle:
                self._file_handle.write(output)
            else:
                click.echo(output)

        if self._file_handle:
            self._file_handle.close()
            if not self.json_mode:
                click.echo(click.style(f"\n[+] Output saved to: {self.output_file}", fg="green"), err=True)
