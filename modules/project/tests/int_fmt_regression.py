# 整数溢出 + 格式化字符串回归测试
# 统一入口: 发现样本→编译→检测→计算指标→输出报告
# 设计遵循与 regression_harness.py 和 uaf_regression.py 相同的模式
from __future__ import annotations
import sys, os, json, time, subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

_PROJ_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJ_ROOT))

from analysis.integer_overflow_detector import IntegerOverflowDetector
from analysis.format_string_detector import FormatStringDetector
from analysis.instruction_parser import InstructionParser


@dataclass
class SampleResult:
    name: str
    category: str          # int_overflow / fmtstr
    expected_type: str     # vulnerable / safe
    detected: bool
    num_findings: int
    findings_summary: str
    is_tp: bool = False
    is_fp: bool = False
    is_tn: bool = False
    is_fn: bool = False


def discover_binaries(build_dir: str = "cve_samples/build") -> List[Path]:
    bd = _PROJ_ROOT / build_dir
    if not bd.exists():
        return []
    return sorted([f for f in bd.iterdir()
                   if f.suffix == '.exe' and f.is_file()])


def classify_sample(name: str) -> Tuple[str, str]:
    """返回: (category, expected_type)."""
    n = name.lower()
    # 格式字符串样本
    if n.startswith('fmt'):
        if 'safe' in n or 'printf_constant' in n or 'puts_safe' in n:
            return ('fmtstr', 'safe')
        else:
            return ('fmtstr', 'vulnerable')
    # 整数溢出样本
    if n.startswith('int'):
        if 'safe' in n:
            return ('int_overflow', 'safe')
        else:
            return ('int_overflow', 'vulnerable')
    return ('unknown', 'unknown')


def objdump_binary(binary_path: str) -> Tuple[List[str], List[int], Dict[int, str]]:
    """反汇编并提取纯净指令文本 (模仿SampleScanner.disassemble).

    返回: (instruction_lines, addresses, labels).
    每行指令文本不含opcode字节 — 如 'add eax,0x20'.
    """
    import re
    proc = subprocess.run(
        ['objdump', '-d', '-M', 'intel', binary_path],
        capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        return [], [], {}
    instr_lines = []
    instr_addrs = []
    labels = {}
    pending_label = None
    for line in proc.stdout.split('\n'):
        stripped = line.strip()
        label_m = re.match(r'^[0-9a-f]+\s+<([\w@.]+)>:', stripped)
        if label_m:
            pending_label = label_m.group(1)
            if '@' in pending_label:
                pending_label = pending_label.split('@')[0]
            continue
        if not re.match(r'^[0-9a-f]+:\t', stripped):
            continue
        addr_m = re.match(r'^([0-9a-f]+):\t', stripped)
        addr = int(addr_m.group(1), 16) if addr_m else 0
        tab_parts = stripped.split('\t')
        if len(tab_parts) >= 2:
            instr_text = tab_parts[-1].strip()
            if instr_text:
                if pending_label:
                    labels[len(instr_lines)] = pending_label
                    pending_label = None
                instr_lines.append(instr_text)
                instr_addrs.append(addr)
    return instr_lines, instr_addrs, labels


def build_func_map(instr_lines: List[str],
                   labels: Dict[int, str]) -> Dict[str, Tuple[int, int]]:
    """从纯净指令行和标签构建函数边界图."""
    func_map = {}
    current_func = '_entry_'
    start = 0
    for i, line in enumerate(instr_lines):
        if i in labels:
            if current_func != '_entry_':
                func_map[current_func] = (start, i)
            current_func = labels[i]
            start = i
        if line.strip().startswith('ret'):
            if current_func not in func_map:
                func_map[current_func] = (start, i)
            current_func = f'func_{i}'
            start = i + 1
    if current_func not in func_map and start < len(instr_lines):
        func_map[current_func] = (start, len(instr_lines) - 1)
    return func_map


def run_int_overflow_detector(instructions: List[str],
                              func_map: Dict) -> List:
    det = IntegerOverflowDetector()
    return det.analyze(instructions, func_map)


def run_fmtstr_detector(instructions: List[str],
                        func_map: Dict) -> List:
    det = FormatStringDetector()
    return det.analyze(instructions, func_map)


def compute_metrics(results: List[SampleResult]) -> Dict:
    tp = sum(1 for r in results if r.is_tp)
    fp = sum(1 for r in results if r.is_fp)
    tn = sum(1 for r in results if r.is_tn)
    fn = sum(1 for r in results if r.is_fn)
    total = tp + fp + tn + fn
    return {
        'total': total, 'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
        'recall': tp / max(tp + fn, 1),
        'precision': tp / max(tp + fp, 1),
        'fpr': fp / max(fp + tn, 1),
        'f1': 2 * tp / max(2 * tp + fp + fn, 1),
    }


def main():
    print("=" * 65)
    print("  整数溢出 + 格式化字符串 回归测试")
    print("=" * 65)

    binaries = discover_binaries()
    # 筛选出int和fmt样本
    target_binaries = [b for b in binaries
                       if classify_sample(b.stem)[0] in
                       ('int_overflow', 'fmtstr')]

    if not target_binaries:
        print("[ERROR] 未找到整数溢出或格式化字符串样本文件")
        print("  先编译: cd cve_samples/int_overflow && for f in *.c; do")
        print("    gcc -O2 -o ../build/${f%.c}.exe $f; done")
        return

    print(f"\n发现 {len(target_binaries)} 个目标样本:\n")

    results: List[SampleResult] = []
    int_results: List[SampleResult] = []
    fmt_results: List[SampleResult] = []

    for binary in target_binaries:
        name = binary.stem
        category, expected = classify_sample(name)
        instructions, addrs, labels = objdump_binary(str(binary))
        if not instructions:
            print(f"  [SKIP] {name}: objdump失败")
            continue

        func_map = build_func_map(instructions, labels)

        if category == 'int_overflow':
            findings = run_int_overflow_detector(instructions, func_map)
            detector = 'IntegerOverflowDetector'
        elif category == 'fmtstr':
            findings = run_fmtstr_detector(instructions, func_map)
            detector = 'FormatStringDetector'
        else:
            continue

        # 有效 finding 口径: FP 抑制标记 (is_false_positive) 不计入
        detected = any(not getattr(f, 'is_false_positive', False)
                       for f in findings)
        is_vuln = expected == 'vulnerable'

        if is_vuln and detected:
            verdict = "TP OK"
        elif is_vuln and not detected:
            verdict = "FN !!"
        elif not is_vuln and detected:
            verdict = "FP !!"
        else:
            verdict = "TN OK"

        sr = SampleResult(
            name=name, category=category, expected_type=expected,
            detected=detected, num_findings=len(findings),
            findings_summary=', '.join(
                f.mode.name if hasattr(f, 'mode') else str(f)[:40]
                for f in findings[:3]),
            is_tp=is_vuln and detected,
            is_fp=not is_vuln and detected,
            is_tn=not is_vuln and not detected,
            is_fn=is_vuln and not detected,
        )
        results.append(sr)
        if category == 'int_overflow':
            int_results.append(sr)
        else:
            fmt_results.append(sr)

        fcnt = len(findings)
        print(f"  [{verdict}] {name:35s} {expected:12s} "
              f"-> {fcnt:2d} findings  [{detector}]")
        if findings:
            for f in findings[:2]:
                detail = (f.detail[:100] if hasattr(f, 'detail')
                          else str(f)[:100])
                print(f"         {detail}")

# 汇总指标
    print(f"\n{'='*65}")
    print(f"  指标汇总")
    print(f"{'='*65}")

    for label, subset in [("整数溢出", int_results),
                           ("格式化字符串", fmt_results),
                           ("合计", results)]:
        m = compute_metrics(subset)
        if m['total'] == 0:
            continue
        print(f"\n  [{label}] n={m['total']}")
        print(f"    Recall={m['recall']:.1%}  Precision={m['precision']:.1%}"
              f"  FPR={m['fpr']:.1%}  F1={m['f1']:.3f}")
        print(f"    TP={m['TP']}  FP={m['FP']}  TN={m['TN']}  FN={m['FN']}")

# 导出JSON
    export = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'categories': {
            'int_overflow': compute_metrics(int_results),
            'fmtstr': compute_metrics(fmt_results),
            'combined': compute_metrics(results),
        },
        'samples': [
            {
                'name': r.name, 'category': r.category,
                'expected': r.expected_type,
                'detected': r.detected,
                'num_findings': r.num_findings,
                'verdict': ('TP' if r.is_tp else 'FP' if r.is_fp
                            else 'TN' if r.is_tn else 'FN'),
            }
            for r in results
        ]
    }

    out_path = _PROJ_ROOT / "eval_output" / "int_fmt_regression_report.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(export, f, indent=2, ensure_ascii=False)
    print(f"\n报告: {out_path}")

    return results


if __name__ == '__main__':
    main()
