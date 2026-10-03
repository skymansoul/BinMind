"""
管道集成测试 - 合成样本数据与度量计算。
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
            textwrap.dedent("""\
            func main:
              v0 = malloc(64)
              [v0 + 0x40] = v1
              return 0
            """), expected_tp=True, ground_truth='TP'),
        SyntheticSample('ho_tp_02', 'heap_overflow',
            textwrap.dedent("""\
            func process:
              v0 = malloc(128)
              dword [v0 + 0x80] = 0
              return 0
            """), expected_tp=True, ground_truth='TP'),
        SyntheticSample('ho_tp_03', 'heap_overflow',
            textwrap.dedent("""\
            func loop_write:
              v0 = malloc(256)
              cmp i, 512
              v0[i] = 'A'
              return 0
            """), expected_tp=True, ground_truth='TP'),
        SyntheticSample('ho_fp_01', 'heap_overflow',
            textwrap.dedent("""\
            func safe_write_small_offset:
              v0 = malloc(256)
              [v0 + 0x20] = 0
              return 0
            """), expected_tp=False, ground_truth='FP'),
        SyntheticSample('ho_fp_02', 'heap_overflow',
            textwrap.dedent("""\
            func no_heap_at_all:
              v0 = malloc(64)
              free(v0)
              return 0
            """), expected_tp=False, ground_truth='FP'),
        SyntheticSample('ho_fp_03', 'heap_overflow',
            textwrap.dedent("""\
            func dynamic_not_static:
              v0 = malloc(count)
              [v0 + 0x00] = 0
              return 0
            """), expected_tp=False, ground_truth='FP'),
    ]


def _uaf_samples() -> List[SyntheticSample]:
    return [
        SyntheticSample('uaf_tp_01', 'uaf',
            textwrap.dedent("""\
            func use_after_free:
              p = malloc(128)
              free(p)
              p->field = 42
              return 0
            """), expected_tp=True, ground_truth='TP'),
        SyntheticSample('uaf_tp_02', 'uaf',
            textwrap.dedent("""\
            func double_free:
              p = malloc(64)
              free(p)
              free(p)
              return 0
            """), expected_tp=True, ground_truth='TP'),
        SyntheticSample('uaf_fp_01', 'uaf',
            textwrap.dedent("""\
            func safe_realloc:
              p = malloc(128)
              free(p)
              p = malloc(256)
              p->field = 42
              return 0
            """), expected_tp=False, ground_truth='FP'),
        SyntheticSample('uaf_fp_02', 'uaf',
            textwrap.dedent("""\
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
            textwrap.dedent("""\
            func mul_overflow:
              count = atoi(argv[1])
              size = count * sizeof(int)
              buf = malloc(size)
              memcpy(buf, src, count * sizeof(int))
              return 0
            """), expected_tp=True, ground_truth='TP'),
        SyntheticSample('int_fp_01', 'int_overflow',
            textwrap.dedent("""\
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
