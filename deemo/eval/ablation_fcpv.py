#!/usr/bin/env python3
"""
FCPV消融实验 — Baseline vs +FCPV vs +FCPV+PCFC vs +FCPV+PCFC+Rule9.

四组配置:
  B0. Baseline: EnhancedFmtDetector仅IR级检测 (旧管线)
  B1. +FCPV: 源码级约束传播验证器(关闭PCFC和规则9)
  B2. +FCPV+PCFC: 加路径条件过滤(函数边界感知)
  B3. +FCPV+PCFC+Rule9: 加snprintf %s透传规则(完整管线)

通过monkey-patch控制各组件开关, 不修改功能代码.
输出: eval/results/ablation_fcpv.json + ablation_fcpv.csv + 图表
"""
import sys
from pathlib import Path

from eval.ablation_fcpv_helpers import (
    FMT_EXPECTED, FMT_SAMPLES_DIR, CONFIGS,
    compute_metrics, print_table, save_results, generate_chart,
)


def _run_baseline(c_file: str) -> bool:
    """B0: EnhancedFmtDetector only (IR级)."""
    from core.source_ir_extractor import extract_from_file as extract_ir
    from core.format_string_enhanced import EnhancedFmtDetector
    ir = extract_ir(c_file)
    if not ir:
        return False
    detector = EnhancedFmtDetector()
    candidates = detector.detect(ir)
    if not candidates:
        return False
    top = candidates[0]
    return top.verdict in ('CONFIRMED', 'UNCERTAIN')


def _run_fcpv(source: str) -> bool:
    """B1: FCPV without PCFC and without Rule9."""
    import core.fcpv_safety_solver as solver_mod
    orig_solve = solver_mod.FcpvSafetySolver._solve_candidate

    def _solve_no_rule9(self, c):
        sink = c.sink
        from core.fcpv_constraint_types import (
            SinkType, SafetyLabel)
        if sink.sink_type == SinkType.CONSTANT:
            return (SafetyLabel.SAFE, 0.95,
                    f'constant: "{sink.constant_text[:40]}"')
        var = sink.var
        if var in self._literal_vars:
            lit = self._literal_vars[var]
            if self._DANGER_SPEC_RE.search(lit):
                return (SafetyLabel.VULN, 0.90,
                        f'literal %n: "{lit[:30]}"')
        has_taint = len(c.taints) > 0
        has_sanitize = len(c.sanitizers) > 0
        has_cross = len(c.cross_funcs) > 0
        if not has_taint and not has_cross:
            if self._is_clean_var(var):
                return (SafetyLabel.SAFE, 0.80,
                        f'clean var: "{var}"')
        if has_taint:
            if has_sanitize:
                san = c.sanitizers[0]
                if self._sanitize_is_safe(san):
                    return (SafetyLabel.SAFE, 0.85,
                            f'sanitized: {san.sanitizer}')
                return (SafetyLabel.VULN, 0.90,
                        f'unsafe sanitize: %n')
            t = c.taints[0]
            chain_str = '->'.join(c.var_chain[:5])
            return (SafetyLabel.VULN, 0.90,
                    f'tainted: "{t.source}"@{t.source_line} via {chain_str}')
        if has_cross:
            for cf in c.cross_funcs:
                if cf.caller_arg in self._collector.tainted_set:
                    return (SafetyLabel.VULN, 0.85,
                            f'cross-func: {cf.caller_arg}->{cf.callee}')
        return (SafetyLabel.UNCERTAIN, 0.40,
                f'unknown: "{var}"')

    solver_mod.FcpvSafetySolver._solve_candidate = _solve_no_rule9
    try:
        from core.fcpv_pipeline import fcpv_filter
        result = fcpv_filter(source)
        vuln = result.get('vuln', [])
        uncertain = result.get('uncertain', [])
        return len(vuln) > 0 or len(uncertain) > 0
    finally:
        solver_mod.FcpvSafetySolver._solve_candidate = orig_solve


def _run_fcpv_pcfc(source: str) -> bool:
    """B2: FCPV+PCFC without Rule9."""
    import core.fcpv_safety_solver as solver_mod
    orig_solve = solver_mod.FcpvSafetySolver._solve_candidate

    def _solve_no_rule9(self, c):
        from core.fcpv_constraint_types import SinkType, SafetyLabel
        sink = c.sink
        if sink.sink_type == SinkType.CONSTANT:
            return (SafetyLabel.SAFE, 0.95,
                    f'constant: "{sink.constant_text[:40]}"')
        var = sink.var
        if var in self._literal_vars:
            lit = self._literal_vars[var]
            if self._DANGER_SPEC_RE.search(lit):
                return (SafetyLabel.VULN, 0.90,
                        f'literal %n: "{lit[:30]}"')
        has_taint = len(c.taints) > 0
        has_sanitize = len(c.sanitizers) > 0
        has_cross = len(c.cross_funcs) > 0
        if not has_taint and not has_cross:
            if self._is_clean_var(var):
                return (SafetyLabel.SAFE, 0.80,
                        f'clean var: "{var}"')
        if has_taint:
            if has_sanitize:
                san = c.sanitizers[0]
                if self._sanitize_is_safe(san):
                    return (SafetyLabel.SAFE, 0.85,
                            f'sanitized: {san.sanitizer}')
                return (SafetyLabel.VULN, 0.90, 'unsafe sanitize')
            t = c.taints[0]
            return (SafetyLabel.VULN, 0.90,
                    f'tainted: "{t.source}"@{t.source_line}')
        if has_cross:
            for cf in c.cross_funcs:
                if cf.caller_arg in self._collector.tainted_set:
                    return (SafetyLabel.VULN, 0.85,
                            f'cross: {cf.caller_arg}->{cf.callee}')
        return (SafetyLabel.UNCERTAIN, 0.40, f'unknown: "{var}"')

    solver_mod.FcpvSafetySolver._solve_candidate = _solve_no_rule9
    try:
        from core.fcpv_pipeline import fcpv_filter
        from core.pcfc_verifier import filter_fmt_by_pcfc
        from core.fcpv_constraint_types import SafetyLabel
        result = fcpv_filter(source)
        vuln = result.get('vuln', [])
        uncertain = result.get('uncertain', [])
        if vuln:
            filtered, _ = filter_fmt_by_pcfc(source, vuln)
            remaining = [c for c in filtered if c.label == SafetyLabel.VULN]
            return len(remaining) > 0 or len(uncertain) > 0
        return len(uncertain) > 0
    finally:
        solver_mod.FcpvSafetySolver._solve_candidate = orig_solve


def _run_full(source: str) -> bool:
    """B3: 完整管线 FCPV+PCFC+Rule9."""
    from core.fcpv_pipeline import fcpv_filter
    from core.pcfc_verifier import filter_fmt_by_pcfc
    from core.fcpv_constraint_types import SafetyLabel
    result = fcpv_filter(source)
    vuln = result.get('vuln', [])
    uncertain = result.get('uncertain', [])
    if vuln:
        filtered, _ = filter_fmt_by_pcfc(source, vuln)
        remaining = [c for c in filtered if c.label == SafetyLabel.VULN]
        return len(remaining) > 0 or len(uncertain) > 0
    return len(uncertain) > 0


def run_fcpv_ablation():
    results = []

    for sample_dir in sorted(FMT_SAMPLES_DIR.iterdir()):
        if not sample_dir.is_dir():
            continue
        vuln_c = sample_dir / 'vuln.c'
        if not vuln_c.exists():
            continue
        name = sample_dir.name
        expected = FMT_EXPECTED.get(name)
        if expected is None:
            continue

        source = vuln_c.read_text(encoding='utf-8', errors='replace')
        c_file = str(vuln_c)

        b0 = _run_baseline(c_file)
        b1 = _run_fcpv(source)
        b2 = _run_fcpv_pcfc(source)
        b3 = _run_full(source)

        row = {
            "sample": name, "expected_vuln": expected,
            "Baseline": b0, "+FCPV": b1,
            "+FCPV+PCFC": b2, "+FCPV+PCFC+Rule9": b3,
        }
        for cfg in CONFIGS:
            det = row[cfg]
            if expected:
                row[f"{cfg}_verdict"] = "VULN" if det else "MISS"
            else:
                row[f"{cfg}_verdict"] = "FP" if det else "SAFE"
        results.append(row)

        print(f"  {name}: B0={row['Baseline_verdict']} "
              f"+FCPV={row['+FCPV_verdict']} "
              f"+PCFC={row['+FCPV+PCFC_verdict']} "
              f"+Rule9={row['+FCPV+PCFC+Rule9_verdict']}")

    metrics = compute_metrics(results)
    return results, metrics


if __name__ == '__main__':
    print("[FCPV Ablation] Baseline vs +FCPV vs +FCPV+PCFC vs +FCPV+PCFC+Rule9")
    print("[1/3] Running on 15 format string samples...")
    results, metrics = run_fcpv_ablation()
    print_table(results, metrics)
    save_results(results, metrics)
    print("\n[2/3] Generating chart...")
    generate_chart(metrics)
    print("[3/3] Done.")
