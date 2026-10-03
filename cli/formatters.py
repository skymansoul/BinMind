import sys
from typing import Any, Dict, Iterable, List

# ANSI — windows terminal supports these since Win10 1511
_RESET  = '\033[0m'
_BOLD   = '\033[1m'
_RED    = '\033[91m'
_GREEN  = '\033[92m'
_YELLOW = '\033[93m'
_BLUE   = '\033[94m'
_GRAY   = '\033[90m'

# Auto-detect if we should use colors
_NO_COLOR = not sys.stdout.isatty() or 'NO_COLOR' in __import__('os').environ


def colorize(text: str, color: str) -> str:
    if _NO_COLOR:
        return text
    return f'{color}{text}{_RESET}'


def severity_color(severity: str) -> str:
    return {
        'Critical': _RED,
        'High': _YELLOW,
        'Medium': _YELLOW,
        'Low': _BLUE,
    }.get(severity, _GRAY)


def print_table(headers: List[str], rows: List[List[str]],
                sep: str = '  '):
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))

    # header line
    header = sep.join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    print(header)
    print('-' * len(header))

    for row in rows:
        line = sep.join(str(c).ljust(col_widths[i])
                        for i, c in enumerate(row)
                        if i < len(col_widths))
        print(line)


def print_finding(vuln: Dict, idx: int = 0):
    sev = vuln.get('severity', 'Unknown')
    typ = vuln.get('type', vuln.get('vuln_type', '?'))
    desc = vuln.get('description', 'no details')
    func = vuln.get('_function', vuln.get('function', '?'))

    label = f'#{idx}' if idx else ''

    color = severity_color(sev)
    print(f"  {label} {colorize(f'[{sev}]', color)} {typ}")
    print(f"      function : {func}")
    print(f"      {desc[:200]}")
    if vuln.get('cwe'):
        print(f"      cwe      : {vuln['cwe']}")
    print()


def print_summary_box(title: str, items: Iterable[tuple]):
    width = max(len(t[0]) for t in items) + 2 if items else 40
    width = max(width, len(title) + 4)

    print(f'  {_BOLD}{title}{_RESET}')
    print(f'  {"─" * width}')
    for key, val in items:
        print(f'  {key.ljust(width - 2)} {val}')
    print()
