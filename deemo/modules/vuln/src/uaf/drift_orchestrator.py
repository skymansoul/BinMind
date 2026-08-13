"""DRIFT UAF检测编排器 — objdump→解析→对象身份追踪→free-use验证→过滤→时间路径验证.

管线:
  1. objdump反汇编
  2. 指令效应分析 (pointer_kill_set.analyze_insn_effects)
  3. 对象身份追踪 (object_identity.ObjIdTracker)
  4. free-use对验证 (free_use_validator.FreeUseValidator)
  5. 多阶段FP过滤 (drift_fp_filter.DriftFPFilter)
  6. 时间路径验证 (temporal_path_verifier.TemporalPathVerifier)

与旧版UnifiedUAFDetector的区别:
  旧版: 前向/后向双引擎 + 盲目的free-use配对 → 大量FP
  新版: 对象身份感知 + 数据流验证 → 消除"不同对象同一寄存器"的FP

创建: 2025-02-06
更新: 2025-02-06 集成时间路径验证
"""
import os
import sys
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

_cur_dir = os.path.dirname(os.path.abspath(__file__))
if _cur_dir not in sys.path:
    sys.path.insert(0, _cur_dir)

from .object_identity import HeapObject, ObjectIdentity, ObjIdTracker
from .free_use_validator import (
    FreeUseValidator, ValidatedUAFFinding, filter_infeasible_paths)
from .drift_fp_filter import (
    DriftFPFilter, DriftFilterReport, FilterDecision, FilterPhase)
from .temporal_path_verifier import TemporalPathVerifier


@dataclass
class DriftReport:
    """DRIFT分析报告."""
    binary_path: str = ""
    raw_findings: int = 0
    valid_findings: int = 0
    confirmed: int = 0
    likely: int = 0
    uncertain: int = 0
    filtered_fp: int = 0
    temporal_filtered: int = 0   # 时间路径验证过滤数
    fp_reduction_pct: float = 0.0
    double_free_count: int = 0
    total_objects: int = 0
    total_allocs: int = 0
    total_frees: int = 0
    elapsed_sec: float = 0.0
    findings: List[dict] = field(default_factory=list)
    disasm_error: str = ""


def analyze_uaf(binary_path: str, timeout_s: int = 60) -> DriftReport:
    """DRIFT统一入口: 反汇编→对象追踪→free-use验证→过滤."""
    t0 = time.time()
    report = DriftReport(binary_path=binary_path)

    # objdump
    asm_lines = _disassemble(binary_path, timeout_s)
    if not asm_lines:
        report.elapsed_sec = round(time.time() - t0, 3)
        report.disasm_error = "objdump failed"
        return report

    # 3: 对象身份追踪 + free-use验证 (FreeUseValidator内部调用)
    validator = FreeUseValidator()
    validated, tracker = validator.validate(asm_lines)

    # 过滤不可行路径 (re-alloc覆盖)
    validated = filter_infeasible_paths(validated, asm_lines)

    report.raw_findings = len(validated)
    report.double_free_count = sum(1 for v in validated if v.double_free)
    report.total_objects = tracker.stats()['total_objects']
    report.total_allocs = sum(1 for o in tracker.objects.values())
    report.total_frees = sum(1 for o in tracker.objects.values() if o.freed_at >= 0)

    # FP过滤
    findings_dicts = [v.to_dict() for v in validated]
    fp_filter = DriftFPFilter()
    filter_report = fp_filter.run_pipeline(
        findings_dicts, asm_lines,
        list(tracker.objects.values()))

    report.valid_findings = len(validated)
    report.confirmed = filter_report.confirmed
    report.likely = filter_report.likely
    report.uncertain = filter_report.uncertain
    report.filtered_fp = filter_report.filtered_fp
    report.fp_reduction_pct = filter_report.fp_reduction_pct
    report.elapsed_sec = round(time.time() - t0, 3)

    # 时间路径验证 — 消除free后寄存器被覆盖的FP
    temporal_verifier = TemporalPathVerifier()
    filtered_findings = temporal_verifier.verify(asm_lines, findings_dicts)
    report.temporal_filtered = len(findings_dicts) - len(filtered_findings)

    # 汇总findings (从时间验证后的结果)
    for v in validated:
        r = _find_filter_result(v, filter_report)
        # 检查时间路径验证结果
        tv_match = next(
            (tf for tf in filtered_findings
             if tf.get('use_line') == v.use_line and tf.get('free_line') == v.free_line),
            None)
        tv_found = tv_match is not None
        tv_verified = tv_match.get('temporal_verified', False) if tv_match else False
        tv_skipped = tv_match.get('temporal_skipped', False) if tv_match else False

        decision = r.decision.value if r else 'uncertain'
        if not tv_found and decision != 'uncertain':
            decision = 'temporal_filtered'
        elif tv_skipped and decision in ('confirmed_uaf', 'likely_uaf'):
            # 时间验证无法进行 → 降级为uncertain
            decision = 'temporal_skipped'

        report.findings.append({
            'obj_id': v.obj_id,
            'alloc_func': v.alloc_func,
            'free_line': v.free_line,
            'use_line': v.use_line,
            'use_reg': v.use_reg,
            'distance': v.instruction_distance,
            'double_free': v.double_free,
            'confidence': tv_match.get('confidence', v.confidence) if tv_match else v.confidence,
            'decision': decision,
            'phase': r.decisive_phase.value if r else 'object_identity',
            'reasoning': r.reasoning if r else '',
            'evidence': tv_match.get('temporal_evidence', v.evidence) if tv_match else v.evidence,
            'temporal_verified': tv_verified,
            'temporal_skipped': tv_skipped,
            'double_free_verified': tv_match.get('double_free_verified', False) if tv_match else False,
        })

    return report


def _find_filter_result(validated: ValidatedUAFFinding,
                        report: DriftFilterReport):
    """在过滤报告中查找对应的结果."""
    for r in report.results:
        if (r.finding.get('use_line') == validated.use_line and
                r.finding.get('free_line') == validated.free_line):
            return r
    return None


def _disassemble(elf_path: str, timeout_s: int = 30) -> List[str]:
    """反汇编二进制 → 行列表."""
    for tool in ['objdump', 'llvm-objdump']:
        try:
            proc = subprocess.run(
                [tool, '-d', '-M', 'intel', elf_path],
                capture_output=True, text=True, timeout=timeout_s,
                encoding='utf-8', errors='replace')
            if proc.returncode == 0 and len(proc.stdout) > 100:
                return proc.stdout.split('\n')
        except Exception:
            continue
    return []


# smoke test
def _smoke():
    """自检管线: 编译UAF示例→分析."""
    import tempfile
    c_code = '''
    #include <stdlib.h>
    void unsafe_free_use() {
        int *p = (int*)malloc(100);
        free(p);
        *p = 42;  // UAF
    }
    int main() {
        unsafe_free_use();
        return 0;
    }
    '''
    with tempfile.NamedTemporaryFile(
            suffix='.c', mode='w', delete=False) as f:
        f.write(c_code)
        c_path = f.name
    bin_path = c_path + '.exe'

    try:
        rc = subprocess.run(
            ['gcc', '-O0', '-g', '-o', bin_path, c_path],
            capture_output=True, timeout=30)
        if rc.returncode == 0:
            r = analyze_uaf(bin_path)
            print(f"[DRIFT smoke] {r.raw_findings} raw, "
                  f"{r.confirmed} confirmed, {r.filtered_fp} filtered "
                  f"({r.fp_reduction_pct}%), {r.elapsed_sec:.3f}s "
                  f"objs={r.total_objects}")
            for f in r.findings[:3]:
                print(f"  {f['obj_id']}: free@{f['free_line']} "
                      f"use@{f['use_line']} via {f['use_reg']} "
                      f"[{f['decision']}]")
        else:
            print("[DRIFT smoke] gcc failed, skipping")
    except Exception as e:
        print(f"[DRIFT smoke] {e}")
    finally:
        for p in (c_path, bin_path):
            if os.path.isfile(p):
                try: os.unlink(p)
                except Exception: pass


if __name__ == '__main__':
    _smoke()
