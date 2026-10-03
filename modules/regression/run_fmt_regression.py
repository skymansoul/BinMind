"""
格式化字符串回归测试 — 伪 IR 级检测器验证.

对 samples/format_string 下每个样本:
  objdump 反汇编 → asm_to_pseudo_ir → hfp_fmt 检测
统计 TP/FP/FN/TN. 判定口径:
  VULN/LEAK 检出视为"检出" (漏洞样本)
  SAFE 视为未检出 (安全样本)
"""

import json
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(BASE))

from hfp.alloc_aware_fmt import detect_from_asm  # noqa: E402

FMT_SAFE = {'safe_01_static_fmt', 'safe_02_param_fmt',
            'safe_03_snprintf'}


def main() -> int:
    root = BASE / 'samples' / 'format_string'
    results = []
    for d in sorted(root.iterdir()):
        exe = d / 'vuln.exe'
        if not exe.exists():
            continue
        proc = subprocess.run(['objdump', '-d', '-M', 'intel', str(exe)],
                              capture_output=True, text=True, timeout=60)
        findings = detect_from_asm(proc.stdout)
        name = d.name
        vuln = name not in FMT_SAFE
        detected = any(f.verdict in ('VULN', 'LEAK') for f in findings)
        verdict = 'TP' if (vuln and detected) else \
            ('FN' if vuln else ('FP' if detected else 'TN'))
        verdicts = ','.join(f.verdict for f in findings)
        results.append((name, verdict, verdicts))
        print(f'{name:32s} {verdict} verdicts={verdicts}')

    tp = sum(1 for _, v, _ in results if v == 'TP')
    fp = sum(1 for _, v, _ in results if v == 'FP')
    fn = sum(1 for _, v, _ in results if v == 'FN')
    tn = sum(1 for _, v, _ in results if v == 'TN')
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    summary = {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
               'recall': round(recall, 4), 'fpr': round(fpr, 4)}
    (BASE / 'results' / 'regression_fmt.json').write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf-8')
    print('summary:', summary)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())