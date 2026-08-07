#!/usr/bin/env python3
"""拆分27个超过300行的测试文件。策略: 提取样本数据到helper文件 或 按类拆分为part1/part2。"""
import os, re

T = r"C:\Users\Administrator\Desktop\BinMind\deemo\tests"

def read(path):
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return f.read()

def write(path, content):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

def count_lines(path):
    return len(read(path).splitlines())

# ═══════════════════════════════════════════════════════════════
# 1. pipeline_integration_test.py (509 lines) — 提取样本数据
# ═══════════════════════════════════════════════════════════════
print("1. pipeline_integration_test.py ...")
content = read(f"{T}/pipeline_integration_test.py")
# 提取SyntheticSample类 + _ho_samples + _uaf_samples + _int_samples 到helper
helper = '''"""
管道集成测试 — 合成样本数据与度量计算。
"""
from __future__ import annotations
import textwrap
from typing import Dict, List


class SyntheticSample:
    """合成测试样本: 含IR和预期结果。"""

    def __init__(self, name: str, vuln_type: str, ir_text: str,
                 expected_tp: bool = True, expected_label: str = '',
                 ground_truth: str = ''):
        self.name = name
        self.vuln_type = vuln_type
        self.ir_text = ir_text
        self.expected_tp = expected_tp
        self.expected_label = expected_label or ('TP' if expected_tp else 'FP')
        self.ground_truth = ground_truth or self.expected_label


def _ho_samples() -> List[SyntheticSample]:
    return [
        SyntheticSample('ho_tp_01', 'heap_overflow',
            textwrap.dedent("""\\
            func main:
              v0 = malloc(64)
              [v0 + 0x40] = v1
              return 0
            """), expected_tp=True, ground_truth='TP'),
        SyntheticSample('ho_tp_02', 'heap_overflow',
            textwrap.dedent("""\\
            func process:
              v0 = malloc(128)
              dword [v0 + 0x80] = 0
              return 0
            """), expected_tp=True, ground_truth='TP'),
        SyntheticSample('ho_tp_03', 'heap_overflow',
            textwrap.dedent("""\\
            func loop_write:
              v0 = malloc(256)
              cmp i, 512
              v0[i] = 'A'
              return 0
            """), expected_tp=True, ground_truth='TP'),
        SyntheticSample('ho_fp_01', 'heap_overflow',
            textwrap.dedent("""\\
            func safe_write_small_offset:
              v0 = malloc(256)
              [v0 + 0x20] = 0
              return 0
            """), expected_tp=False, ground_truth='FP'),
        SyntheticSample('ho_fp_02', 'heap_overflow',
            textwrap.dedent("""\\
            func no_heap_at_all:
              v0 = malloc(64)
              free(v0)
              return 0
            """), expected_tp=False, ground_truth='FP'),
        SyntheticSample('ho_fp_03', 'heap_overflow',
            textwrap.dedent("""\\
            func dynamic_not_static:
              v0 = malloc(count)
              [v0 + 0x00] = 0
              return 0
            """), expected_tp=False, ground_truth='FP'),
    ]


def _uaf_samples() -> List[SyntheticSample]:
    return [
        SyntheticSample('uaf_tp_01', 'uaf',
            textwrap.dedent("""\\
            func use_after_free:
              p = malloc(128)
              free(p)
              p->field = 42
              return 0
            """), expected_tp=True, ground_truth='TP'),
        SyntheticSample('uaf_tp_02', 'uaf',
            textwrap.dedent("""\\
            func double_free:
              p = malloc(64)
              free(p)
              free(p)
              return 0
            """), expected_tp=True, ground_truth='TP'),
        SyntheticSample('uaf_fp_01', 'uaf',
            textwrap.dedent("""\\
            func safe_realloc:
              p = malloc(128)
              free(p)
              p = malloc(256)
              p->field = 42
              return 0
            """), expected_tp=False, ground_truth='FP'),
        SyntheticSample('uaf_fp_02', 'uaf',
            textwrap.dedent("""\\
            func alias_realloc:
              p = malloc(64)
              q = p
              free(p)
              q = malloc(128)
              q->field = 42
              return 0
            """), expected_tp=False, ground_truth='FP'),
    ]


def _int_samples() -> List[SyntheticSample]:
    return [
        SyntheticSample('int_tp_01', 'int_overflow',
            textwrap.dedent("""\\
            func mul_overflow:
              count = atoi(argv[1])
              size = count * sizeof(int)
              buf = malloc(size)
              memcpy(buf, src, count * sizeof(int))
              return 0
            """), expected_tp=True, ground_truth='TP'),
        SyntheticSample('int_fp_01', 'int_overflow',
            textwrap.dedent("""\\
            func safe_mul:
              count = atoi(argv[1])
              if count > 1024:
                return NULL
              size = count * sizeof(int)
              buf = malloc(size)
              memcpy(buf, src, size)
              return buf
            """), expected_tp=False, ground_truth='FP'),
    ]


def compute_metrics(results: List[Dict]) -> Dict:
    """从检测结果计算 TP/FP/TN/FN + Precision/Recall/F1。"""
    tp = sum(1 for r in results if r['actual'] == 'TP' and r['predicted'] == 'TP')
    fp = sum(1 for r in results if r['actual'] == 'FP' and r['predicted'] == 'TP')
    tn = sum(1 for r in results if r['actual'] == 'FP' and r['predicted'] == 'FP')
    fn = sum(1 for r in results if r['actual'] == 'TP' and r['predicted'] == 'FP')

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fn_rate = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0

    return {
        'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'fp_rate': round(fp_rate, 4),
        'fn_rate': round(fn_rate, 4),
        'accuracy': round(accuracy, 4),
        'total': tp + fp + tn + fn,
    }
'''
write(f"{T}/pipeline_integration_samples.py", helper)

# 重写主文件，引用helper
main_file = '''"""
管道集成验证 — 在合成和真实样本上运行完整检测管线, 生成量化指标。

验证维度:
  1. 堆溢出 VFG 管道: 6阶段级联, 约束推理过滤
  2. UAF 别名追踪: 别名组构建, 真假UAF区分
  3. Int溢出范围传播: 区间推断, 溢出阈值判定
  4. 格式字符串多级置信度: 贝叶斯融合

输出: TP/FP/TN/FN + Precision/Recall/F1/FP率 矩阵
"""

from __future__ import annotations
import json
import os
import sys
import time
from typing import Dict, List, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from tests.pipeline_integration_samples import (
    SyntheticSample, _ho_samples, _uaf_samples, _int_samples, compute_metrics
)


# ── 堆溢出管线测试 ──────────────────────────────────────────────

def test_heap_overflow_pipeline(samples: List[SyntheticSample]) -> Tuple[List[Dict], Dict]:
    """运行完整的6阶段堆溢出管线。"""
    results = []
    pipeline_available = False

    try:
        from core.heap_overflow_pipeline import detect_heap_overflows_full
        pipeline_available = True
    except ImportError:
        pass

    try:
        from core.heap_overflow_detector import detect_heap_overflow
    except ImportError:
        detect_heap_overflow = None

    for sample in samples:
        ir_lines = [l.strip() for l in sample.ir_text.strip().split('\\n') if l.strip()]
        candidates = []
        stats = {}

        if pipeline_available:
            candidates, stats = detect_heap_overflows_full(
                ir_lines, sample.ir_text)
        elif detect_heap_overflow:
            candidates = detect_heap_overflow(ir_lines, sample.ir_text)
            stats = {'stage_detect': len(candidates)}

        predicted = 'TP' if len(candidates) > 0 else 'FP'
        conf = max([c.confidence for c in candidates]) if candidates else 0.0

        results.append({
            'name': sample.name,
            'type': sample.vuln_type,
            'actual': sample.ground_truth,
            'predicted': predicted,
            'confidence': conf,
            'candidate_count': len(candidates),
            'pipeline_stats': {k: v for k, v in stats.items()
                               if isinstance(v, (int, float, str))},
        })

    return results, compute_metrics(results)


# ── UAF管线测试 ──────────────────────────────────────────────

def test_uaf_pipeline(samples: List[SyntheticSample]) -> Tuple[List[Dict], Dict]:
    """运行UAF别名追踪增强检测。"""
    results = []

    try:
        from core.uaf_analyzer import detect_uaf_deep, detect_double_free_deep
        uaf_available = True
    except ImportError:
        uaf_available = False

    try:
        from core.uaf_alias_tracker import UafAliasTracker
        alias_available = True
    except ImportError:
        alias_available = False

    for sample in samples:
        candidates = []

        if uaf_available:
            uaf = detect_uaf_deep(sample.ir_text, sample.name)
            df = detect_double_free_deep(sample.ir_text, sample.name)
            candidates = uaf + df

        if alias_available and candidates:
            ir_lines = [l.strip() for l in sample.ir_text.strip().split('\\n')
                        if l.strip()]
            tracker = UafAliasTracker()
            tracker.analyze(ir_lines)
            candidates = tracker.filter_uaf_candidates(candidates)

        predicted = 'TP' if len(candidates) > 0 else 'FP'
        conf = max([c.get('confidence', 0.0) for c in candidates]) if candidates else 0.0

        results.append({
            'name': sample.name,
            'type': sample.vuln_type,
            'actual': sample.ground_truth,
            'predicted': predicted,
            'confidence': conf,
            'candidate_count': len(candidates),
        })

    return results, compute_metrics(results)


# ── Int溢出管线测试 ──────────────────────────────────────────────

def test_int_overflow_pipeline(samples: List[SyntheticSample]) -> Tuple[List[Dict], Dict]:
    """运行Int溢出范围传播检测。"""
    results = []

    try:
        from core.int_overflow_detector import IntOverflowDetector
        detector = IntOverflowDetector()
    except ImportError:
        detector = None

    try:
        from core.int_range_propagator import filter_by_range
        range_available = True
    except ImportError:
        range_available = False

    for sample in samples:
        candidates = []
        if detector:
            candidates = detector.detect(sample.ir_text, sample.name)

        cand_dicts = []
        for c in candidates:
            cand_dicts.append({
                'expression': c.expression,
                'confidence': c.confidence,
            })

        if range_available and cand_dicts:
            cand_dicts = filter_by_range(cand_dicts, sample.ir_text)

        predicted = 'TP' if len(cand_dicts) > 0 else 'FP'
        conf = max([c.get('confidence', 0.0) for c in cand_dicts]) if cand_dicts else 0.0

        results.append({
            'name': sample.name,
            'type': sample.vuln_type,
            'actual': sample.ground_truth,
            'predicted': predicted,
            'confidence': conf,
            'candidate_count': len(cand_dicts),
        })

    return results, compute_metrics(results)


# ── 格式字符串管线测试 ──────────────────────────────────────────────

def test_format_string_pipeline() -> Tuple[List[Dict], Dict]:
    """运行格式字符串检测 — 仅对真实二进制文件, 合成样本标记为skip。"""
    samples_status = {
        'fmt_tp_01': 'skip (requires ELF binary)',
        'fmt_tp_02': 'skip (requires ELF binary)',
        'fmt_fp_01': 'skip (requires ELF binary)',
    }

    can_import = True
    try:
        from core.format_string_detector import detect_format_string_vulns
    except ImportError:
        can_import = False

    results = [{
        'name': name,
        'type': 'format_string',
        'actual': 'N/A',
        'predicted': status.split()[0],
        'confidence': 0.0,
        'candidate_count': 0,
        'module_available': can_import,
    } for name, status in samples_status.items()]

    return results, {'note': 'format_string requires real ELF binaries; module_available=' + str(can_import)}


# ── 主运行器 ──────────────────────────────────────────────

def run_all() -> Dict:
    """运行所有管道, 生成综合报告。"""
    t0 = time.perf_counter()
    all_results = {}
    all_metrics = {}

    pipelines = [
        ('heap_overflow', test_heap_overflow_pipeline, _ho_samples()),
        ('uaf', test_uaf_pipeline, _uaf_samples()),
        ('int_overflow', test_int_overflow_pipeline, _int_samples()),
        ('format_string', test_format_string_pipeline, None),
    ]

    for name, fn, samples in pipelines:
        try:
            if samples:
                res, met = fn(samples)
            else:
                res, met = fn()
            all_results[name] = res
            all_metrics[name] = met
        except Exception as e:
            all_results[name] = []
            all_metrics[name] = {'error': str(e)}

    total_tp = sum(m.get('TP', 0) for m in all_metrics.values())
    total_fp = sum(m.get('FP', 0) for m in all_metrics.values())
    total_tn = sum(m.get('TN', 0) for m in all_metrics.values())
    total_fn = sum(m.get('FN', 0) for m in all_metrics.values())

    overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    overall_f1 = (2 * overall_precision * overall_recall /
                  (overall_precision + overall_recall)
                  if (overall_precision + overall_recall) > 0 else 0.0)
    overall_fp_rate = total_fp / (total_fp + total_tn) if (total_fp + total_tn) > 0 else 0.0

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)

    report = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'elapsed_ms': elapsed_ms,
        'per_type': all_metrics,
        'overall': {
            'TP': total_tp, 'FP': total_fp, 'TN': total_tn, 'FN': total_fn,
            'total': total_tp + total_fp + total_tn + total_fn,
            'precision': round(overall_precision, 4),
            'recall': round(overall_recall, 4),
            'f1': round(overall_f1, 4),
            'fp_rate': round(overall_fp_rate, 4),
        },
        'per_sample': all_results,
    }

    return report


# ── 输出 ──────────────────────────────────────────────

def print_report(report: Dict):
    """格式化打印报告。"""
    sep = '=' * 64
    print(sep)
    print(f"  BinMind Pipeline Integration Test  ({report['timestamp']})")
    print(sep)

    for vtype, metrics in report['per_type'].items():
        if 'error' in metrics:
            print(f"\\n  [{vtype}] ERROR: {metrics['error']}")
            continue
        if 'note' in metrics:
            print(f"\\n  [{vtype}] NOTE: {metrics['note']}")
            continue
        if 'TP' not in metrics:
            continue
        print(f"\\n  --- {vtype} ---")
        print(f"  TP={metrics['TP']}  FP={metrics['FP']}  "
              f"TN={metrics['TN']}  FN={metrics['FN']}")
        print(f"  Precision={metrics['precision']:.3f}  "
              f"Recall={metrics['recall']:.3f}  "
              f"F1={metrics['f1']:.3f}  "
              f"FPR={metrics['fp_rate']:.3f}")

    ov = report['overall']
    print(f"\\n  --- OVERALL ---")
    print(f"  TP={ov['TP']}  FP={ov['FP']}  TN={ov['TN']}  FN={ov['FN']}  "
          f"Total={ov['total']}")
    print(f"  Precision={ov['precision']:.3f}  Recall={ov['recall']:.3f}  "
          f"F1={ov['f1']:.3f}  FPR={ov['fp_rate']:.3f}")
    print(f"\\n  Elapsed: {report['elapsed_ms']}ms")
    print(sep)

    print(f"\\n  Per-sample details:")
    for vtype, samples in report['per_sample'].items():
        if not samples:
            continue
        print(f"\\n  [{vtype}]")
        for s in samples:
            status = 'OK' if s['actual'] == s['predicted'] else 'MISMATCH'
            print(f"    {s['name']:20s}  actual={s['actual']:3s}  "
                  f"pred={s['predicted']:3s}  conf={s['confidence']:.2f}  "
                  f"candidates={s['candidate_count']}  [{status}]")

    print(sep)
    _print_fp_analysis(report)


def _print_fp_analysis(report: Dict):
    """分析FP削减效果。"""
    print(f"\\n  FP Reduction Analysis:")
    ho = report['per_type'].get('heap_overflow', {})
    uaf = report['per_type'].get('uaf', {})
    io = report['per_type'].get('int_overflow', {})

    for name, m in [('Heap Overflow', ho), ('UAF', uaf), ('Int Overflow', io)]:
        if not m or 'FP' not in m or 'TN' not in m:
            continue
        total_fp_tn = m['FP'] + m['TN']
        if total_fp_tn > 0:
            fp_pct = m['FP'] / total_fp_tn * 100
            print(f"    {name:20s}: {fp_pct:.0f}% FPR  "
                  f"({m['FP']} FP / {total_fp_tn} non-TP samples)")


def save_report(report: Dict, path: str = ''):
    """保存报告到JSON。"""
    if not path:
        path = os.path.join(BASE_DIR, 'tests', 'pipeline_integration_results.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)
    print(f"\\n  Report saved: {path}")


if __name__ == '__main__':
    report = run_all()
    print_report(report)
    save_report(report)
'''
write(f"{T}/pipeline_integration_test.py", main_file)
print(f"  -> pipeline_integration_test.py + pipeline_integration_samples.py")


# ═══════════════════════════════════════════════════════════════
# 2-27: 使用通用策略按类拆分
# ═══════════════════════════════════════════════════════════════
# 对于有多个TestClass的文件: 按类拆分为part1+part2
# 对于样本字符串: 提取到_samples.py
# 策略: 读取文件 → 找到类边界 → 拆分 → 写入

import importlib

# 定义每个文件的拆分策略
# 格式: (filename, strategy, split_info)
# strategy: 'extract_samples' | 'split_classes'
# split_info for extract_samples: 要提取的变量名列表
# split_info for split_classes: 第一个part包含的类名列表

splits = [
    # 2. test_fuzz_integration.py (431) — 拆分8个test class为2个文件
    ('test_fuzz_integration.py', 'split_classes', {
        'part1_classes': ['TestFuzzIntegrationConstants', 'TestFuzzManagerValidation', 'TestFuzzManagerHarnessGeneration', 'TestFuzzManagerStatus'],
        'part2_classes': ['TestFuzzManagerProcessCommands', 'TestListAvailableFuzzers', 'TestCreateFuzzManager', 'TestFuzzManagerCrashMonitoring'],
    }),
    # 3. test_rop_grader.py (430) — 拆分7个test class
    ('test_rop_grader.py', 'split_classes', {
        'part1_classes': ['TestGradingConfig', 'TestROPGadget', 'TestGadgetChain', 'TestGadgetCategory', 'TestGadgetQuality'],
        'part2_classes': ['TestROPGadgetGrader', 'TestROPGadgetGraderFunctions'],
    }),
    # 4. run_uaf_benchmark.py (474) — 拆分scanner和report
    ('run_uaf_benchmark.py', 'split_classes', {
        'part1_classes': [],  # 按行号拆: dataclass+scanner
        'split_line': 235,  # UafScanner结尾 ~ line 235, 后面是evaluate+run+report
    }),
    # 5. test_stack_pivot.py (429) — 拆分6个test class
    ('test_stack_pivot.py', 'split_classes', {
        'part1_classes': ['TestGadgetInfo', 'TestStackPivotGadget', 'TestPivotChain', 'TestExploitWithPivot'],
        'part2_classes': ['TestStackPivotGenerator', 'TestStackPivotGeneratorEdgeCases', 'TestConvenienceFunction'],
    }),
    # 6. test_constraint_solver_manager.py (456) — 拆分6个test class
    ('test_constraint_solver_manager.py', 'split_classes', {
        'part1_classes': ['TestTDigest', 'TestSolverTracing', 'TestSolverPoolHealth'],
        'part2_classes': ['TestCrossSolverConsensus', 'TestConstraintSolverManager'],
    }),
    # 7. test_attack_mapper.py (507) — 拆分6个test class
    ('test_attack_mapper.py', 'split_classes', {
        'part1_classes': ['TestATTACKTechnique', 'TestVulnerabilityMapping', 'TestATTACKMapper'],
        'part2_classes': ['TestATTACKMapperEdgeCases', 'TestConvenienceFunctions', 'TestATTACKMapperDataIntegrity'],
    }),
    # 8. test_nuclei_generator.py (453) — 拆分3个test class
    ('test_nuclei_generator.py', 'split_classes', {
        'part1_classes': ['TestNucleiTemplateGenerator'],
        'part2_classes': ['TestHttpRequest', 'TestMatchCondition'],
    }),
    # 9. regression_harness.py (421) — 按行号拆: data+detectors vs runner
    ('regression_harness.py', 'split_classes', {
        'split_line': 248,
    }),
    # 10. test_pcfc_regression.py (400) — CORE: 提取样本字符串
    ('test_pcfc_regression.py', 'extract_samples', {
        'samples_prefix': 'pcfc',
    }),
    # 11. test_multi_stage_orchestrator.py (444) — 拆分9个test class
    ('test_multi_stage_orchestrator.py', 'split_classes', {
        'part1_classes': ['TestEnums', 'TestVulnerabilityNode', 'TestExploitChainStep', 'TestExploitChain', 'TestMultiStageOrchestrator'],
        'part2_classes': ['TestConvenienceFunctions', 'TestCapabilityGraph', 'TestEstimations', 'TestRiskAssessment', 'TestCleanup'],
    }),
    # 12. test_binary_signing.py (412) — 拆分4个test class
    ('test_binary_signing.py', 'split_classes', {
        'part1_classes': ['TestBinarySignature', 'TestHomologyMatch', 'TestBinarySigner'],
        'part2_classes': ['TestHomologySearcher', 'TestConvenienceFunctions'],
    }),
    # 13. test_memory_forensics.py (442) — 拆分5个test class
    ('test_memory_forensics.py', 'split_classes', {
        'part1_classes': ['TestMemoryForensicsAnalyzer'],
        'part2_classes': ['TestSensitiveData', 'TestRegistryKey', 'TestForensicsResult'],
    }),
    # 14. test_concolic_execution.py (437) — 拆分6个test class
    ('test_concolic_execution.py', 'split_classes', {
        'part1_classes': ['TestConcolicMode', 'TestConcolicStatus', 'TestConcolicSeed', 'TestConcolicPath', 'TestConcolicResult'],
        'part2_classes': ['TestConcolicExecutor', 'TestConcolicConvenienceFunctions', 'TestConcolicIntegration'],
    }),
    # 15. test_kernel_analysis.py (437) — 拆分6个test class
    ('test_kernel_analysis.py', 'split_classes', {
        'part1_classes': ['TestKernelBinaryFormatDetection', 'TestKernelDangerousFunctions', 'TestKernelPrompts'],
        'part2_classes': ['TestKernelExploitGenerator', 'TestKernelCommandLineArgs', 'TestForceKernelMode'],
    }),
    # 16. test_vuln_db_external.py (446) — 拆分2个test class
    ('test_vuln_db_external.py', 'split_classes', {
        'part1_classes': ['TestVulDBExternalQueries'],
        'part2_classes': ['TestVulDBWithMocks'],
    }),
    # 17. test_nn_model_scanner.py (427) — 拆分9个test class
    ('test_nn_model_scanner.py', 'split_classes', {
        'part1_classes': ['TestModelFormat', 'TestThreatCategory', 'TestSeverity', 'TestModelMetadata', 'TestSuspiciousPattern', 'TestSecurityFinding'],
        'part2_classes': ['TestONNXParser', 'TestTFLiteParser', 'TestBackdoorDetector', 'TestSubgraphAnalyzer', 'TestSerializationAttackDetector', 'TestNNModelScanner', 'TestIntegration'],
    }),
    # 18. test_repack_detector.py (388) — 拆分test class
    ('test_repack_detector.py', 'split_classes', {
        'part1_classes': ['TestRepackConfig', 'TestRepackResult', 'TestSectionInfo', 'TestAnomaly'],
        'part2_classes': ['TestRepackDetector', 'TestConvenienceFunctions'],
    }),
    # 19. test_cj_enhanced.py (368) — CORE: 提取样本数据
    ('test_cj_enhanced.py', 'extract_cj_samples', {}),
    # 20. test_sbom_exporter.py (337) — 拆分test class
    ('test_sbom_exporter.py', 'split_classes', {
        'part1_classes': ['TestSBOMComponent', 'TestSBOMDocument', 'TestSBOMExporter'],
        'part2_classes': ['TestConvenienceFunctions'],
    }),
    # 21. test_differential_tester.py (409) — 拆分test class
    ('test_differential_tester.py', 'split_classes', {
        'part1_classes': ['TestInputGenerator'],
        'part2_classes': ['TestDifferentialTester', 'TestOracleComparator', 'TestDiffResult', 'TestStandaloneDiffTester'],
    }),
    # 22. test_self_healing_rewriter.py (349) — 拆分test class
    ('test_self_healing_rewriter.py', 'split_classes', {
        'part1_classes': ['TestProtectionStrategyGenerator', 'TestCVEInfo', 'TestProtectionRule'],
        'part2_classes': ['TestFridaInstrumenter', 'TestDynamoRioInstrumenter', 'TestPerformanceValidator', 'TestSelfHealingRewriter', 'TestConvenienceFunctions'],
    }),
    # 23. test_binary_lifecycle.py (380) — 拆分test class
    ('test_binary_lifecycle.py', 'split_classes', {
        'part1_classes': ['TestBinarySignature', 'TestSecurityMetrics', 'TestAnalysisRecord', 'TestTrendData'],
        'part2_classes': ['TestBinaryLifecycleManager', 'TestConvenienceFunctions'],
    }),
    # 24. test_exploit_transpiler.py (313) — 拆分test class
    ('test_exploit_transpiler.py', 'split_classes', {
        'part1_classes': ['TestArchitecture', 'TestGadgetInfo', 'TestRegisterMapping', 'TestTranspileResult'],
        'part2_classes': ['TestExploitTranspiler', 'TestConvenienceFunction'],
    }),
    # 25. test_fstp_regression.py (311) — CORE: 提取样本字符串
    ('test_fstp_regression.py', 'extract_fstp_samples', {}),
    # 26. gen_uaf_samples.py (306) — 拆分C源码样本数据
    ('gen_uaf_samples.py', 'extract_gen_uaf_data', {}),
    # 27. test_mte_simulator.py (357) — 拆分test class
    ('test_mte_simulator.py', 'split_classes', {
        'part1_classes': ['TestTagSpace', 'TestMTEState'],
        'part2_classes': ['TestMTEViolation', 'TestMTEReport', 'TestMTEAnalyzer'],
    }),
]


def split_by_classes(filepath, info):
    """按类名拆分文件为part1和part2."""
    content = read(filepath)
    lines = content.split('\\n')

    # 找到import区域结束位置
    import_end = 0
    in_multiline_import = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if in_multiline_import:
            if ')' in stripped and not stripped.endswith('\\'):
                in_multiline_import = False
            continue
        if stripped.startswith('import ') or stripped.startswith('from '):
            import_end = i + 1
            if '(' in stripped and ')' not in stripped:
                in_multiline_import = True
            continue
        if stripped.startswith('#') or stripped == '' or stripped.startswith('_MOD_DEBUG'):
            import_end = i + 1
            continue
        # 非导入、非注释、非空行 → 导入区域结束
        if not stripped.startswith('import') and not stripped.startswith('from'):
            break

    # 收集导入
    import_lines = lines[:import_end]
    body_lines = lines[import_end:]

    part1_classes = info.get('part1_classes', [])
    part2_classes = info.get('part2_classes', [])

    if 'split_line' in info:
        # 按行号拆分
        split_line = info['split_line']
        part1_content = '\\n'.join(lines[:split_line])
        part2_content = '\\n'.join(lines[split_line:])
        return part1_content, part2_content

    # 找到每个类的起始行（在body中）
    class_starts = {}
    for i, line in enumerate(body_lines):
        m = re.match(r'^class\s+(\w+)', line)
        if m:
            class_starts[m.group(1)] = i

    # 也找非类顶层代码（函数、变量、if __name__等）
    # 分配类到part1或part2
    part1_cls_set = set(part1_classes)
    part2_cls_set = set(part2_classes)

    if not part1_cls_set and not part2_cls_set:
        # 如果没有指定类，均分
        all_classes = sorted(class_starts.keys())
        mid = len(all_classes) // 2
        part1_cls_set = set(all_classes[:mid])
        part2_cls_set = set(all_classes[mid:])

    # 找每个类的范围
    all_class_names = sorted(class_starts.keys(), key=lambda c: class_starts[c])

    def get_class_range(cls_name):
        cls_idx = class_starts[cls_name]
        # 找下一个类的起始
        next_idx = len(body_lines)
        for cn in all_class_names:
            ci = class_starts[cn]
            if ci > cls_idx:
                next_idx = min(next_idx, ci)
        return cls_idx, next_idx

    # 收集非类顶层代码 (fixtures, __main__等)
    non_class_lines_before = []  # 类之前的非类代码
    non_class_lines_after = []   # 类之后的非类代码 (__main__等)

    # 找第一个类之前的代码
    first_class_idx = min(class_starts.values()) if class_starts else len(body_lines)

    # 构建part1和part2
    part1_body = []
    part2_body = []

    # 类之前的代码（fixtures等）放入part1
    pre_class = body_lines[:first_class_idx]
    # 找__main__和后面的代码
    main_idx = None
    for i in range(len(body_lines) - 1, -1, -1):
        if body_lines[i].strip().startswith("if __name__"):
            main_idx = i
            break

    # 收集每个类的代码
    part1_class_code = []
    part2_class_code = []

    for cls_name in all_class_names:
        start, end = get_class_range(cls_name)
        cls_code = '\\n'.join(body_lines[start:end])
        if cls_name in part1_cls_set:
            part1_class_code.append(cls_code)
        elif cls_name in part2_cls_set:
            part2_class_code.append(cls_code)
        else:
            # 未指定的类，放入part1
            part1_class_code.append(cls_code)

    # 类之前的代码（fixtures、模块级变量等）
    pre_class_code = '\\n'.join(pre_class)

    # 构建完整文件
    part1 = '\\n'.join(import_lines) + '\\n\\n' + pre_class_code + '\\n\\n' + '\\n\\n'.join(part1_class_code)
    part2 = '\\n'.join(import_lines) + '\\n\\n' + '\\n\\n'.join(part2_class_code)

    # __main__ 放在part2
    if main_idx is not None:
        main_code = '\\n'.join(body_lines[main_idx:])
        # 从part2的body末尾移除__main__（如果有的话），然后追加
        # 简单处理：确保part2有__main__
        if '__main__' not in part2:
            part2 += '\\n\\n' + main_code
        # 从part1移除__main__
        if '__main__' in part1:
            part1 = part1.split("if __name__")[0].rstrip()

    return part1, part2


for entry in splits:
    filename = entry[0]
    strategy = entry[1]
    info = entry[2]
    filepath = os.path.join(T, filename)
    basename = filename.replace('.py', '')

    if strategy == 'split_classes':
        print(f"{filename}: splitting by classes ...")
        part1, part2 = split_by_classes(filepath, info)
        write(filepath, part1.rstrip() + '\\n')
        write(os.path.join(T, f"{basename}_part2.py"), part2.rstrip() + '\\n')
        l1 = count_lines(filepath)
        l2 = count_lines(os.path.join(T, f"{basename}_part2.py"))
        print(f"  -> {filename} ({l1}) + {basename}_part2.py ({l2})")

    elif strategy == 'extract_samples' and info.get('samples_prefix') == 'pcfc':
        print(f"{filename}: extracting PCFC samples ...")
        content = read(filepath)
        # 提取_check_case函数和run_all中的样本字符串到helper
        # 保留_check_case + 样本 → pcfc_samples.py, 主文件引用
        lines_list = content.split('\\n')
        # _check_case定义 (28-58行)
        check_case_code = '\\n'.join(lines_list[27:58])
        # run_all中的_check_case调用 (67-395)
        run_all_body = '\\n'.join(lines_list[60:395])

        samples_file = '''#!/usr/bin/env python3
"""PCFC样本数据 — 路径条件感知回归测试用例及检查函数."""
import sys
sys.path.insert(0, r"C:\\Users\\Administrator\\Desktop\\BinMind")
sys.path.insert(0, r"C:\\Users\\Administrator\\Desktop\\BinMind\\deemo")

from core.fcpv_pipeline import fcpv_filter
from core.pcfc_pipeline import fcpv_pcfc_filter
from core.fcpv_constraint_types import SafetyLabel

passed = 0
failed = 0
fp_filtered = 0
tp_preserved = 0


def _check_case(name, source, expected_vuln):
    """运行FCPV-only和FCPV+PCFC对比测试."""
    global passed, failed, fp_filtered, tp_preserved

    r_fcpv = fcpv_filter(source)
    r_pcfc = fcpv_pcfc_filter(source)

    fcpv_vuln = r_fcpv["has_vuln"]
    pcfc_vuln = r_pcfc["has_vuln"]

    ok = (pcfc_vuln == expected_vuln)
    if ok:
        passed += 1
        if expected_vuln:
            tp_preserved += 1
        else:
            fp_filtered += 1
        pcfc_label = "VULN" if pcfc_vuln else "SAFE"
        print(f"  [PASS] {name}: {pcfc_label}")
    else:
        failed += 1
        exp = "VULN" if expected_vuln else "SAFE"
        pcfc_label = "VULN" if pcfc_vuln else "SAFE"
        reason = r_pcfc["vuln"][0].reason if r_pcfc["vuln"] else "N/A"
        print(f"  [FAIL] {name}: got {pcfc_label}, expected {exp}")
        print(f"         reason: {reason}")


''' + 'def run_all():\\n'
        # 继续提取run_all的调用部分
        samples_file += '    global passed, failed, fp_filtered, tp_preserved\\n'
        samples_file += '    passed = 0\\n    failed = 0\\n    fp_filtered = 0\\n    tp_preserved = 0\\n\\n'

        # 从原文件run_all函数体中提取_check_case调用
        in_run_all = False
        for line in lines_list:
            stripped = line.strip()
            if stripped.startswith('def run_all():'):
                in_run_all = True
                continue
            if in_run_all and stripped.startswith('_check_case('):
                samples_file += '    ' + stripped + '\\n'

        samples_file += '''
    print(f"\\n{'='*60}")
    print(f"PCFC回归测试: {passed} passed, {failed} failed, "
          f"{passed+failed} total")
    print(f"FP过滤: {fp_filtered}, TP保留: {tp_preserved}")
    print(f"{'='*60}")
    return failed == 0


if __name__ == '__main__':
    ok = run_all()
    sys.exit(0 if ok else 1)
'''
        write(os.path.join(T, 'test_pcfc_regression_samples.py'), samples_file)

        # 主文件变为精简版引用
        main_pcfc = '''#!/usr/bin/env python3
"""PCFC路径条件感知回归测试 —验证PCFC过滤FCPV误报且不引入漏报."""
import sys
sys.path.insert(0, r"C:\\Users\\Administrator\\Desktop\\BinMind")
sys.path.insert(0, r"C:\\Users\\Administrator\\Desktop\\BinMind\\deemo")

from tests.test_pcfc_regression_samples import run_all

if __name__ == '__main__':
    ok = run_all()
    sys.exit(0 if ok else 1)
'''
        write(filepath, main_pcfc)
        l1 = count_lines(filepath)
        l2 = count_lines(os.path.join(T, 'test_pcfc_regression_samples.py'))
        print(f"  -> {filename} ({l1}) + test_pcfc_regression_samples.py ({l2})")

    elif strategy == 'extract_cj_samples':
        print(f"{filename}: extracting CJ test cases ...")
        content = read(filepath)
        # 提取fm_boundary_tests + interproc_tests + interval_domain_tests 到helper
        lines_list = content.split('\\n')

        # 主文件保留imports + _check_case + run_all + __main__
        # Helper包含3个测试函数
        helper = '''#!/usr/bin/env python3
"""CJ增强测试用例 — FM边界推理 + 跨函数约束传播 + 区间域抽象解释."""
import sys
sys.path.insert(0, r"C:\\Users\\Administrator\\Desktop\\BinMind")
sys.path.insert(0, r"C:\\Users\\Administrator\\Desktop\\BinMind\\deemo")

from core.cj_constraint_types import (
    ConstraintType, LinearConstraint, ConstraintSystem, SolverVerdict,
)
from core.cj_solver import ConstraintJoinSolver

passed = 0
failed = 0


def _check_case(name, sys_obj, expected_verdict):
    global passed, failed
    solver = ConstraintJoinSolver("x86_64")
    result = solver.solve(sys_obj)
    ok = result.verdict == expected_verdict
    if ok:
        passed += 1
        print(f"  [PASS] {name}: {result.verdict.value} — {result.reason}")
    else:
        failed += 1
        print(f"  [FAIL] {name}: got {result.verdict.value}, expected {expected_verdict.value}")
        print(f"         reason: {result.reason}")


'''

        # 提取3个测试函数
        in_func = False
        func_name = None
        func_lines = []
        for line in lines_list:
            stripped = line.strip()
            if stripped.startswith('def fm_boundary_tests('):
                in_func = True
                func_name = 'fm_boundary_tests'
            elif stripped.startswith('def interproc_tests('):
                in_func = True
                func_name = 'interproc_tests'
            elif stripped.startswith('def interval_domain_tests('):
                in_func = True
                func_name = 'interval_domain_tests'
            elif stripped.startswith('def run_all('):
                break

            if in_func:
                helper += line + '\\n'

        helper += '''
def run_all():
    global passed, failed
    passed = 0
    failed = 0

    fm_boundary_tests()
    interproc_tests()
    interval_domain_tests()

    print(f"\\n{'='*60}")
    print(f"CJ增强回归测试: {passed} passed, {failed} failed, {passed+failed} total")
    print(f"{'='*60}")
    return failed == 0


if __name__ == '__main__':
    ok = run_all()
    sys.exit(0 if ok else 1)
'''
        write(os.path.join(T, 'test_cj_enhanced_samples.py'), helper)

        main_cj = '''#!/usr/bin/env python3
"""CJ增强回归测试 — 引用样本数据."""
import sys
sys.path.insert(0, r"C:\\Users\\Administrator\\Desktop\\BinMind")
sys.path.insert(0, r"C:\\Users\\Administrator\\Desktop\\BinMind\\deemo")

from tests.test_cj_enhanced_samples import run_all

if __name__ == '__main__':
    ok = run_all()
    sys.exit(0 if ok else 1)
'''
        write(filepath, main_cj)
        l1 = count_lines(filepath)
        l2 = count_lines(os.path.join(T, 'test_cj_enhanced_samples.py'))
        print(f"  -> {filename} ({l1}) + test_cj_enhanced_samples.py ({l2})")

    elif strategy == 'extract_fstp_samples':
        print(f"{filename}: extracting FSTP samples ...")
        content = read(filepath)
        lines_list = content.split('\\n')

        # 提取样本字符串常量和benchmark函数到_samples
        sample_vars = []
        sample_code = []
        test_code = []
        in_sample = False

        for line in lines_list:
            stripped = line.strip()
            # 检测样本变量赋值
            if stripped.startswith(('CONST_', 'USER_INPUT_', 'SANITIZED_', 'EDGE_', 'FMT_SPEC_')):
                if '=' in stripped and not stripped.startswith('def '):
                    var_name = stripped.split('=')[0].strip()
                    sample_vars.append(var_name)
                    in_sample = True
                    sample_code.append(line)
                    continue
            if in_sample:
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    in_sample = False
                    sample_code.append(line)
                    test_code.append('')
                    continue
                if stripped and not stripped.startswith(' ') and not stripped.startswith('"') and not stripped.startswith("'") and '=' not in stripped:
                    in_sample = False
                if in_sample:
                    sample_code.append(line)
                    continue
            test_code.append(line)

        # 更简洁: 提取所有模块级变量+benchmark函数到_samples, 主文件保留测试类
        # 找到class定义开始的位置
        first_class = 0
        for i, line in enumerate(lines_list):
            if line.strip().startswith('class Test'):
                first_class = i
                break

        # 模块级代码(imports+samples)到helper
        module_code = '\\n'.join(lines_list[:first_class])

        # 也提取run_fstp_benchmark函数
        benchmark_start = None
        for i, line in enumerate(lines_list):
            if 'def run_fstp_benchmark' in line:
                benchmark_start = i
                break

        helper_content = module_code + '\\n'
        if benchmark_start is not None:
            helper_content += '\\n' + '\\n'.join(lines_list[benchmark_start:]) + '\\n'

        # 去除helper中可能的class定义
        helper_lines = helper_content.split('\\n')
        clean_helper = []
        skip_until_next_def = False
        for hl in helper_lines:
            if hl.strip().startswith('class Test'):
                skip_until_next_def = True
                continue
            if skip_until_next_def:
                if hl.strip().startswith('def ') or hl.strip().startswith('class '):
                    skip_until_next_def = False
                else:
                    continue
            clean_helper.append(hl)
        helper_content = '\\n'.join(clean_helper)

        write(os.path.join(T, 'test_fstp_regression_samples.py'), helper_content)

        # 主文件: imports + 引用samples + 测试类
        fstp_main = '''"""
FSTP 回归测试 — 格式说明符语义感知污点传播.
"""

from __future__ import annotations

import importlib.util, os, sys, unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from tests.test_fstp_regression_samples import (
    CONST_FMT, CONST_PURE, CONST_FORMATTED,
    USER_INPUT_SCANF, USER_INPUT_FGETS, USER_INPUT_RECV, USER_INPUT_ARGV,
    SANITIZED_STRREPLACE, SANITIZED_SANITIZE, SANITIZED_G_STRDUP_PRINTF,
    SANITIZED_ESCAPE_FORMAT,
    EDGE_SNPRINTF_CHAIN, EDGE_ASSIGN_CHAIN, EDGE_NO_FORMAT_INPUT,
    EDGE_WRAPPER_PATTERN,
    FMT_SPEC_WRITE_CAPABLE, FMT_SPEC_READ_ONLY,
    SemClass, FstpVerdict, FmtSemanticTaintPropagator,
)

'''
        # 追加测试类
        fstp_main += '\\n'.join(test_code[first_class:])
        # 去除重复的class定义后的import部分
        write(filepath, fstp_main)
        l1 = count_lines(filepath)
        l2 = count_lines(os.path.join(T, 'test_fstp_regression_samples.py'))
        print(f"  -> {filename} ({l1}) + test_fstp_regression_samples.py ({l2})")

    elif strategy == 'extract_gen_uaf_data':
        print(f"{filename}: extracting C source data ...")
        content = read(filepath)
        lines_list = content.split('\\n')

        # 提取C_SOURCES字典到helper
        sources_start = None
        sources_end = None
        for i, line in enumerate(lines_list):
            if 'C_SOURCES' in line and '=' in line and '{' in line:
                sources_start = i
            if sources_start and sources_end is None:
                if line.strip() == '}' or line.strip().endswith('}'):
                    sources_end = i + 1

        if sources_start and sources_end:
            helper = '\\n'.join(lines_list[sources_start:sources_end]) + '\\n'
            write(os.path.join(T, 'gen_uaf_samples_data.py'),
                  '"""UAF样本C源码数据."""\\n\\n' + helper)

            # 重写主文件引用
            main_content = lines_list[:sources_start] + [
                'from tests.gen_uaf_samples_data import C_SOURCES', ''
            ] + lines_list[sources_end:]
            write(filepath, '\\n'.join(main_content))

        l1 = count_lines(filepath)
        l2 = count_lines(os.path.join(T, 'gen_uaf_samples_data.py'))
        print(f"  -> {filename} ({l1}) + gen_uaf_samples_data.py ({l2})")

print("\\n=== 拆分完成，验证行数 ===")
for entry in splits:
    filename = entry[0]
    filepath = os.path.join(T, filename)
    basename = filename.replace('.py', '')
    main_lines = count_lines(filepath)
    part2_path = os.path.join(T, f"{basename}_part2.py")
    if os.path.exists(part2_path):
        part2_lines = count_lines(part2_path)
        status = "OK" if main_lines <= 300 and part2_lines <= 300 else "OVER"
        print(f"  {status} {filename}: main={main_lines}, part2={part2_lines}")
    else:
        # 查找_samples或_data文件
        for suffix in ['_samples.py', '_data.py']:
            alt = os.path.join(T, basename + suffix)
            if os.path.exists(alt):
                alt_lines = count_lines(alt)
                status = "OK" if main_lines <= 300 and alt_lines <= 300 else "OVER"
                print(f"  {status} {filename}: main={main_lines}, helper={alt_lines}")
                break
        else:
            status = "OK" if main_lines <= 300 else "OVER"
            print(f"  {status} {filename}: {main_lines}")
