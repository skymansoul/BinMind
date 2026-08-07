"""Debug vfree_map construction."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.uaf_temporal_scanner import TemporalScanner
from analysis.uaf_interprocedural import InterprocSummarizer
from analysis.lpvra_types import build_simple_cfg

code = """char *p = malloc(64);
free(p);
p = malloc(64);
*p = 1;"""

lines = code.splitlines()
scan = TemporalScanner()

# Replicate verify() logic
frees = scan.find_frees(lines)
print(f"find_frees: {frees}")

summarizer = InterprocSummarizer()
vfrees, valiases = summarizer.propagate(code)
print(f"vfrees: {vfrees}")
print(f"valiases: {valiases}")

all_frees = list(frees) + vfrees
print(f"all_frees: {all_frees}")

# Build vfree_map as in _check_pair
vfree_map = {}
for vf_l, vf_c, vf_v in all_frees:
    if vf_l <= len(lines):
        stripped = TemporalScanner._strip_comments(lines[vf_l - 1]).strip()
        has_real_free = bool(TemporalScanner._FREE_RE.search(stripped))
        print(f"  vf_l={vf_l} vf_c={vf_c} vf_v={vf_v} stripped='{stripped}' has_real_free={has_real_free}")
        if not has_real_free:
            vfree_map.setdefault(vf_l, vf_v)
print(f"vfree_map: {vfree_map}")
