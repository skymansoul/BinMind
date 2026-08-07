"""Debug TPV _mark_freed calls - fixed."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.uaf_temporal_path_verifier import TemporalPathVerifier
from analysis.uaf_temporal_path_types import PtrState

# Monkey-patch _mark_freed (static method)
orig_mark_freed = TemporalPathVerifier._mark_freed

def patched_mark_freed(state, v, alias_map):
    print(f"  _mark_freed(v='{v}')")
    print(f"    state before: {dict((k,x.value) for k,x in state.items())}")
    orig_mark_freed(state, v, alias_map)
    print(f"    state after: {dict((k,x.value) for k,x in state.items())}")

TemporalPathVerifier._mark_freed = staticmethod(patched_mark_freed)

code = """char *p = malloc(64);
free(p);
p = malloc(64);
*p = 1;"""

tpv = TemporalPathVerifier(max_paths=128)
results = tpv.verify(code)
for r in results:
    print(f"\nRESULT: verdict={r.verdict.value} fvar={r.ptr_var} fl={r.free_line} ul={r.use_line} safe={r.safe_paths} uaf={r.uaf_paths}")
