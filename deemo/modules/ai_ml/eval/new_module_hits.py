# 新模块命中统计: 在72+回归样本上记录各新阶段(参数等式/路径守卫/循环累积)
# 实际过滤了哪些alloc-copy对, 量化三模块的独立贡献
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

BASE = Path(__file__).parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))
BUILD = BASE / "tests" / "regression" / "build"

from src.disasm.objdump_parser import ObjdumpParser
from src.detect.heap_overflow_filter import HeapOverflowFilter
from analysis.heap_fp_filter import HeapFalsePositiveFilter


class Instrumented(HeapFalsePositiveFilter):
    """记录每个新阶段触发点的过滤器"""
    def __init__(self):
        super().__init__()
        self.stage_hits = defaultdict(list)

    def evaluate(self, alloc_idx, copy_idx, alloc_func, copy_func,
                 instructions, bb_boundaries, cfg_edges):
        d, ev = super().evaluate(alloc_idx, copy_idx, alloc_func, copy_func,
                                 instructions, bb_boundaries, cfg_edges)
        if d.value != 'false_positive':
            return d, ev
        basis = '; '.join(ev.decision_basis)
        for k, tag in (("param_equality", "L5参数等式"),
                       ("PPSR", "L6路径守卫"),
                       ("loop_cumulative", "L7循环累积"),
                       ("same_source", "同源"),
                       ("DCG", "DCG"),
                       ("guard", "L5守卫收缩")):
            if k in basis:
                self.stage_hits[tag].append(copy_idx)
        return d, ev


def main():
    inst = Instrumented()
    total = 0
    per_bin = defaultdict(list)
    for exe in sorted(BUILD.glob("*_O0.exe")):
        sample = exe.stem.replace("_O0", "")
        r = subprocess.run(["objdump", "-d", "-M", "intel", str(exe)],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            continue
        funcs = ObjdumpParser()._parse_output(r.stdout)
        for finfo in funcs:
            if len(finfo.instructions) < 3:
                continue
            try:
                old = HeapOverflowFilter().analyze_function(
                    finfo.instructions, finfo.bb_boundaries,
                    finfo.cfg_edges, finfo.name)
            except Exception:
                continue
            for o in old:
                if o.alloc_site is None or o.copy_site is None:
                    continue
                af = next((a for a in ('malloc', 'calloc', 'realloc', 'alloca')
                           if a in finfo.instructions[o.alloc_site].lower()), None)
                if af is None:
                    continue
                before = dict(inst.stage_hits)
                try:
                    inst.evaluate(o.alloc_site, o.copy_site, af, o.sink_func,
                                  finfo.instructions, finfo.bb_boundaries,
                                  finfo.cfg_edges)
                except Exception:
                    continue
                after = dict(inst.stage_hits)
                for k in after:
                    if after[k] and k not in before:
                        per_bin[sample].append(k)
                total += 1

    print(f"[new_module_hits] 扫描 {total} 个alloc-copy对")
    for k, v in sorted(inst.stage_hits.items()):
        print(f"  {k:12s} 触发过滤 {len(v)} 次")
    print("  按样本命中: ")
    for s, tags in sorted(per_bin.items()):
        if tags:
            print(f"    {s}: {sorted(set(tags))}")
    (Path(__file__).parent / "new_module_hits.json").write_text(
        json.dumps({"stage_hits": {k: len(v) for k, v in inst.stage_hits.items()},
                    "per_sample": {s: sorted(set(t)) for s, t in per_bin.items()}},
                   indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
