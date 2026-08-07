"""Debug TPV _check_pair with detailed state tracking."""
from __future__ import annotations
import sys, re
from pathlib import Path
from collections import deque
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.lpvra_types import build_simple_cfg
from analysis.uaf_temporal_scanner import TemporalScanner
from analysis.uaf_temporal_path_types import PtrState

code = """char *p = malloc(64);
free(p);
p = malloc(64);
*p = 1;"""

lines = code.splitlines()
blocks, adj = build_simple_cfg(lines)
scan = TemporalScanner()

# Manually simulate _check_pair(fvar='p', fl=2, fcol=5, uvar='p', ul=4, ucol=1)
fvar, fl, fcol = 'p', 2, 5
uvar, ul, ucol = 'p', 4, 1
free_block = use_block = 0

alias_map = {}
state = {}
same_eval = False
b = blocks[0]

# Simulate BFS
for si, stmt in enumerate(b['stmts']):
    s = stmt.strip()
    stmt_line = b['start'] + si + 1
    print(f"  Line {stmt_line}: '{s}'")

    fm = TemporalScanner._FREE_RE.search(s)
    if fm:
        fv = fm.group(1)
        state[fv] = PtrState.FREED
        print(f"    -> FREE: state[{fv}] = FREED")

    am = TemporalScanner._ALLOC_RE.search(s)
    if am:
        av = am.group(1)
        state[av] = PtrState.ALLOCATED
        print(f"    -> ALLOC: state[{av}] = ALLOCATED")

    if stmt_line == ul:
        print(f"    -> REACHED USE LINE {ul}")
        print(f"    -> state = {state}")
        fv_val = state.get(fvar, PtrState.UNKNOWN)
        uv_val = state.get(uvar, PtrState.UNKNOWN)
        print(f"    -> fvar={fvar} state={fv_val.value} | uvar={uvar} state={uv_val.value}")
        is_uaf = fv_val == PtrState.FREED or uv_val == PtrState.FREED
        print(f"    -> is_uaf = {is_uaf}")
        break
