# 新模块消融实验: 逐项禁用参数等式/路径守卫/循环累积, 量化各自误报压制贡献
# 输入: tests/deep_suite/build/*.exe; 输出: eval/deep_ablation.json + 控制台表格
import json
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))
EVAL = Path(__file__).parent
BUILD = BASE / "tests" / "deep_suite" / "build"

_HEAP_POS = ('confirmed', 'likely', 'new_finding', 'heap_cross_func')
_CONFIGS = {
    "baseline(no new modules)": dict(enable_param_eq=False,
                                     enable_path_resolver=False,
                                     enable_loop_bound=False),
    "- param_equality": dict(enable_param_eq=False),
    "- path_resolver": dict(enable_path_resolver=False),
    "- loop_bound": dict(enable_loop_bound=False),
    "full(all 7 stages)": {},
}


def exp(s): return s.startswith("tp_")


def run_config(flags: dict):
    from src.disasm.objdump_parser import ObjdumpParser
    from src.detect.pipeline_bridge import DetectionPipeline
    from analysis.heap_fp_filter import HeapFalsePositiveFilter
    import time
    tp = fp = tn = fn = 0
    hits = {}
    t0 = time.perf_counter()
    for exe in sorted(BUILD.glob("*.exe")):
        sample = exe.stem.rsplit("_", 1)[0]
        opt = exe.stem.rsplit("_", 1)[-1]
        if opt != "O0":
            continue
        e = exp(sample)
        r = subprocess.run(["objdump", "-d", "-M", "intel", str(exe)],
                           capture_output=True, text=True, timeout=60)
        funcs = ObjdumpParser()._parse_output(r.stdout) if r.returncode == 0 else []
        pipe = DetectionPipeline()
        # 用带开关的过滤器替换默认, pipeline_bridge硬编码默认配置, 故直接测evaluate
        from src.detect.heap_overflow_filter import HeapOverflowFilter
        f = HeapFalsePositiveFilter(**flags)
        det = False
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
                try:
                    d, ev = f.evaluate(o.alloc_site, o.copy_site, af, o.sink_func,
                                       finfo.instructions, finfo.bb_boundaries,
                                       finfo.cfg_edges)
                except Exception:
                    continue
                basis = '; '.join(ev.decision_basis)
                if d.value == 'true_positive':
                    det = True
                    for k in ('param_equality', 'PPSR', 'loop_cumulative',
                              'same_source', 'DCG'):
                        if k.lower() in basis.lower():
                            hits[k] = hits.get(k, 0) + 1
        if e and det:
            tp += 1
        elif e and not det:
            fn += 1
        elif not e and not det:
            tn += 1
        else:
            fp += 1
    elapsed = (time.perf_counter() - t0)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "hits": hits,
            "time_s": round(elapsed, 1)}


def main():
    results = {}
    for name, flags in _CONFIGS.items():
        r = run_config(flags)
        results[name] = r
        print(f"{name:28s} TP={r['tp']} FP={r['fp']} TN={r['tn']} FN={r['fn']} "
              f"FPR={r['fp']/max(1, r['fp']+r['tn']):.0%} "
              f"recall={r['tp']/max(1, r['tp']+r['fn']):.0%}")
    (EVAL / "deep_ablation.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
