"""Debug TPV free→malloc→use detection."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.lpvra_types import build_simple_cfg
from analysis.uaf_temporal_scanner import TemporalScanner
from analysis.uaf_temporal_path_verifier import TemporalPathVerifier
from analysis.uaf_temporal_path_types import PtrState

code = """char *p = malloc(64);
free(p);
p = malloc(64);
*p = 1;"""

lines = code.splitlines()
blocks, adj = build_simple_cfg(lines)
for b in blocks:
    stmts = [s.strip() for s in b['stmts']]
    print(f"Block {b['id']}: start={b['start']} end={b['end']} stmts={stmts}")
print(f"adj={adj}")

# Check alloc matches per line
for i, line in enumerate(lines, 1):
    am = TemporalScanner._ALLOC_RE.search(line)
    fm = TemporalScanner._FREE_RE.search(line)
    if am:
        print(f"Line {i}: ALLOC match var={am.group(1)}")
    if fm:
        print(f"Line {i}: FREE match var={fm.group(1)}")

# Run TPV with detailed output
tpv = TemporalPathVerifier(max_paths=128)
results = tpv.verify(code)
for r in results:
    print(f"verdict={r.verdict.value} fvar={r.ptr_var} fl={r.free_line} ul={r.use_line}")
    print(f"  safe={r.safe_paths} uaf={r.uaf_paths} total={r.total_paths} reason={r.reason}")
