"""Debug TPV _check_pair actual execution."""
from __future__ import annotations
import sys, re
from pathlib import Path
from collections import deque
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

# Monkey-patch _is_uaf_state to add logging
orig_is_uaf = TemporalPathVerifier._is_uaf_state
def patched_is_uaf(self, state, fvar, uvar, alias_map):
    result = orig_is_uaf(self, state, fvar, uvar, alias_map)
    print(f"  _is_uaf_state: fvar={fvar} uvar={uvar} state={dict((k,v.value) for k,v in state.items())} result={result}")
    return result
TemporalPathVerifier._is_uaf_state = patched_is_uaf

tpv = TemporalPathVerifier(max_paths=128)
results = tpv.verify(code)
for r in results:
    print(f"RESULT: verdict={r.verdict.value} fvar={r.ptr_var} fl={r.free_line} ul={r.use_line} safe={r.safe_paths} uaf={r.uaf_paths} total={r.total_paths}")
