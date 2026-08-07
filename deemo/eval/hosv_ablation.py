#!/usr/bin/env python3
"""
HOSV 逐阶段消融实验 — 量化各维度对堆溢出检测精度的增量贡献.

七种配置: A→G 逐维度启用, F=完整HOSV, G=+APAS别名闭包.
详细检查逻辑在 hosv_ablation_checks.py, 运行器在 hosv_ablation_runner.py.
"""
from __future__ import annotations
import json, os, sys, time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_DEEMO_ROOT = Path(__file__).parent.parent
if str(_DEEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(_DEEMO_ROOT))

from analysis.heap_overflow_types import (
    HoVerdict, HoResult)
from analysis.heap_overflow_src_patterns import (
    _skip_block_comments, _is_comment_or_empty, _base_var)
from analysis.heap_overflow_src_phases import find_allocs, find_writes
from analysis.heap_overflow_src_checks import (
    targets_same_heap_obj, alloc_has_guard,
    check_strcat_accumulation, check_loop_accumulation,
    check_chunk_relation, check_struct_array_oob)
from analysis.heap_overflow_src_interproc import (
    resolve_factory_allocs, resolve_cross_func_writes)
from analysis.heap_size_constraint_graph import HeapSizeConstraintGraph
from analysis.heap_overflow_src_apas import (
    build_alias_closure, resolve_alias,
    resolve_write_offset, struct_write_check)
from analysis.heap_overflow_src_apas_writes import (
    find_alias_writes, find_struct_field_writes)
from eval.hosv_ablation_checks import (
    AblationChecksMixin, _vuln, _safe, _uncertain)
from eval.hosv_ablation_runner import (
    CONFIGS, load_gt, read_source, classify, metrics,
    write_latex, OUTPUT_DIR)


class AblationVerifier(AblationChecksMixin):
    """可配置的 HOSV 消融验证器.

    通过 flags 控制各维度启用/禁用, 测试各维度对精度/召回的增量贡献.
    """

    def __init__(self, *,
                 enable_allocator: bool = True,
                 enable_guard: bool = True,
                 enable_constraint_graph: bool = True,
                 enable_interproc: bool = True,
                 enable_accumulation: bool = True,
                 enable_apas: bool = True):
        self._alloc = enable_allocator
        self._guard = enable_guard
        self._cgraph_en = enable_constraint_graph
        self._interproc = enable_interproc
        self._accum = enable_accumulation
        self._apas = enable_apas
        self._cgraph = HeapSizeConstraintGraph()

    def verify(self, source: str) -> List[HoResult]:
        raw = source.splitlines()
        valid = {ln for ln, _ in _skip_block_comments(raw)}
        lines = raw
        results: List[HoResult] = []

        allocs = find_allocs(lines, valid)
        if self._interproc:
            allocs.extend(resolve_factory_allocs(lines, allocs))
        if not allocs:
            return results

        alloc_vars = {a.var for a in allocs}
        alias_map = {v: v for v in alloc_vars}
        if self._apas:
            alias_map = build_alias_closure(lines, alloc_vars)
            for a in allocs:
                alias_map.setdefault(a.var, a.var)

        writes = find_writes(lines, allocs, valid)
        if self._apas:
            for w in writes:
                w.target = resolve_alias(w.target, alias_map)
            writes.extend(find_alias_writes(
                lines, alias_map, alloc_vars, valid))
            writes.extend(find_struct_field_writes(
                lines, alloc_vars, valid))
            for w in writes:
                if w.kind == 'memcpy' and w.offset == 0:
                    w.offset = resolve_write_offset(w, lines)

        if self._interproc:
            writes.extend(resolve_cross_func_writes(lines, allocs, writes))

        if self._cgraph_en:
            self._cgraph.clear()
            self._cgraph.extract_from_source(lines)
            self._cgraph.build_closure()

        rgrows = {a.var: (a.line, a.size_const) for a in allocs
                  if a.kind == 'realloc' and a.size_const > 0}

        for a in allocs:
            ag, au = (False, -1)
            if self._guard:
                ag, au = alloc_has_guard(a, lines)
            for w in writes:
                match = False
                if self._apas:
                    if w.target == a.var:
                        match = True
                    elif alias_map.get(w.target) == a.var:
                        match = True
                else:
                    match = targets_same_heap_obj(a, w, lines)
                if not match:
                    continue
                if w.kind == 'loop_write' and w.line < a.line:
                    continue
                es = self._eff_size(a, w, rgrows)
                if es == -998:
                    continue
                r = self._check(a, w, lines, ag, au, es)
                if r:
                    results.append(r)

        if self._accum:
            results.extend(check_strcat_accumulation(allocs, writes, lines))
            results.extend(check_loop_accumulation(allocs, writes, lines))
            results.extend(check_chunk_relation(allocs, writes, lines))
        return self._dedup(results)

    def _check(self, a, w, lines, ag, au, sc=-999) -> Optional[HoResult]:
        sz = sc if sc != -999 else a.size_const
        r = check_struct_array_oob(a, w, lines, sz)
        if r:
            return r
        if w.kind == 'struct_write':
            if self._apas:
                return struct_write_check(a, w, lines, sz)
            if a.size_const >= 0:
                return _safe(a, w, a.size_const, w.write_size,
                             f"sizeof={a.size_const}")
        if w.write_size == -1 and w.kind in ('strcpy', 'strcat', 'sprintf'):
            if sz >= 0:
                return _vuln(a, w, sz, -1, f"unbounded {w.kind}")
        if w.write_size == -1 and w.kind == 'loop_write' and sz >= 0:
            r = self._loop_write(a, w, lines, sz)
            if r:
                return r
        if w.write_size >= 0 and sz >= 0 and not (
                w.kind == 'ptr_write' and w.offset < 0):
            return self._bounded(a, w, sz, ag)
        if a.size_const < 0 and w.write_size >= 0:
            r = self._var_alloc(a, w, ag, au)
            if r:
                return r
        if a.size_const >= 0 and w.write_size == -2:
            return _uncertain(a, w, a.size_const, "expression write size")
        if sz >= 0 and w.write_size < 0 and w.kind in (
                'memcpy', 'memset', 'read', 'fread', 'ptr_write'):
            return _vuln(a, w, sz, -1, f"{w.kind}(unknown size)")
        if w.kind == 'ptr_write' and sz >= 0:
            return self._ptr_write(a, w, lines, sz)
        if a.size_const < 0 and w.write_size < 0:
            return self._double_var(a, w, lines, ag, au)
        return None

    @staticmethod
    def _eff_size(a, w, rgrows):
        if a.kind != 'malloc' or a.var not in rgrows:
            return a.size_const
        rl, rsz = rgrows[a.var]
        if w.line > rl and rsz < a.size_const:
            return -998
        if w.line > rl and rsz >= a.size_const:
            return rsz
        return a.size_const

    @staticmethod
    def _dedup(results):
        sev = {HoVerdict.VULN: 0, HoVerdict.UNCERTAIN: 1, HoVerdict.SAFE: 2}
        seen = set()
        out = []
        for r in sorted(results,
                        key=lambda x: (sev.get(x.verdict, 9), -x.confidence)):
            k = (r.alloc_line, r.write_line, r.var_name)
            if k not in seen:
                seen.add(k)
                out.append(r)
        return out


def main():
    gt = load_gt()
    samples = gt["samples"]
    configs_results: Dict[str, Dict] = {}
    for cn, flags in CONFIGS.items():
        configs_results[cn] = {"verdicts": [], "details": [], "flags": flags}

    print(f"HOSV Ablation on {len(samples)} samples\n")
    header = f"{'Sample':<36} {'Exp':<6}"
    for cn in CONFIGS:
        header += f" {cn.split('_')[0]:<5}"
    print(header)
    print("-" * (42 + 6 * len(CONFIGS)))

    for name, info in sorted(samples.items()):
        expected = info["expected_vuln"]
        source = read_source(name)
        if not source:
            continue
        exp_str = "VULN" if expected else "SAFE"
        row = f"  {name:<34} {exp_str:<6}"
        for cn, flags in CONFIGS.items():
            verifier = AblationVerifier(**flags)
            results = verifier.verify(source)
            label = classify(results, expected)
            configs_results[cn]["verdicts"].append(label)
            configs_results[cn]["details"].append({
                "sample": name, "verdict": label,
                "findings": len(results),
                "vuln_count": sum(1 for r in results
                                  if r.verdict == HoVerdict.VULN),
            })
            row += f" {label:<5}"
        print(row)

    print(f"\n{'=' * 70}\nHOSV Ablation Summary\n{'=' * 70}")
    for cn, cd in configs_results.items():
        m = metrics(cd["verdicts"])
        cd["metrics"] = m
        print(f"  {cn:<25}: P={m['P']:.4f} R={m['R']:.4f} "
              f"F1={m['F1']:.4f} FPR={m['FPR']:.4f} "
              f"(TP={m['TP']} FP={m['FP']} TN={m['TN']} FN={m['FN']})")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out_json = OUTPUT_DIR / "hosv_ablation.json"
    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(configs_results, f, indent=2, ensure_ascii=False)
    out_tex = OUTPUT_DIR / "hosv_ablation_table.tex"
    write_latex(configs_results, out_tex)
    print(f"\nJSON: {out_json}")
    print(f"LaTeX: {out_tex}")


if __name__ == "__main__":
    main()
