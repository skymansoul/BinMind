"""
UAF 回归测试 — 复用 HFP 编译/调度框架, 检测器换用 core.uaf_detector.

UAF 检测输入是反编译伪代码文本 (core.uaf_detector 接口),
而非伪 IR. 本模块把 objdump 反汇编经 asm_translator 翻译的
伪 IR 拼接为代码文本, 喂给 UAFDetector.detect(), 统计
TP/FP/FN/TN.

  安全对照 (TN): safe_01_null_after_free / safe_02_refcount /
  safe_03_no_use — 期望 0 检出.
"""

from __future__ import annotations

import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
DEEMO = BASE.parent / 'deemo'

sys.path.insert(0, str(BASE))
sys.path.insert(0, str(DEEMO))

from regression.sample_compiler import SampleCompiler  # noqa: E402

UAF_SAFE = {'safe_01_null_after_free', 'safe_02_refcount',
            'safe_03_no_use'}


def detect_uaf(asm_path: str) -> list:
    """经伪 IR 调用 hfp_uaf 检测器 (二进制级生命周期分析)."""
    from hfp.hfp_uaf import detect_from_asm
    text = Path(asm_path).read_text(encoding='utf-8', errors='replace')
    return detect_from_asm(text)


def main() -> int:
    root = BASE / 'samples' / 'uaf'
    results = []
    for d in sorted(root.iterdir()):
        if not (d / 'vuln.exe').exists():
            continue
        asm = d / 'vuln.asm'
        if not asm.exists():
            import subprocess
            proc = subprocess.run(
                ['objdump', '-d', '-M', 'intel', str(d / 'vuln.exe')],
                capture_output=True, text=True, timeout=60)
            asm.write_text(proc.stdout, encoding='utf-8', errors='replace')
        findings = detect_uaf(str(asm))
        name = d.name
        vuln = name not in UAF_SAFE
        detected = len(findings) > 0
        verdict = 'TP' if (vuln and detected) else \
            ('FN' if vuln else ('FP' if detected else 'TN'))
        results.append((name, verdict, len(findings)))
        print(f'{name:32s} {verdict} findings={len(findings)}')

    tp = sum(1 for _, v, _ in results if v == 'TP')
    fp = sum(1 for _, v, _ in results if v == 'FP')
    fn = sum(1 for _, v, _ in results if v == 'FN')
    tn = sum(1 for _, v, _ in results if v == 'TN')
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    summary = {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
               'recall': round(recall, 4), 'fpr': round(fpr, 4)}
    import json
    (BASE / 'results' / 'regression_uaf.json').write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf-8')
    print('summary:', summary)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())