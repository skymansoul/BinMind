# 创建: 2025-09-27 08:15
# 一键执行完整检测流水线: 编译 → 扫描 → 解析 → 绘图

"""端到端检测流水线。

执行顺序:
  1. compile_samples.py — 编译所有CVE样本(debug+release)
  2. scan_scheduler.py — 批量扫描生成结果JSON
  3. result_parser.py  — 计算TP/FP/FN/TN指标 + 导出LaTeX
  4. bar_chart.py      — 绘制对比柱状图

仅依赖Python标准库 + matplotlib(可选，绘图模块内部容错)。
"""

import os
import sys
import subprocess
import json
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def run_step(script: str, args: list = None) -> int:
    """运行单个步骤，返回退出码。"""
    path = os.path.join(BASE_DIR, script)
    cmd = [sys.executable, path] + (args or [])
    print(f"\n{'='*55}\n  STEP: {script} {' '.join(args or [])}\n{'='*55}")
    t0 = time.time()
    rc = subprocess.run(cmd, cwd=BASE_DIR).returncode
    elapsed = time.time() - t0
    status = "OK" if rc == 0 else f"FAIL({rc})"
    print(f"  [{status}] {script} ({elapsed:.1f}s)")
    return rc


def main():
    configs = ["debug"]
    if "--release" in sys.argv:
        configs.append("release")

    steps = [
        ("compile", ["compile_samples.py"] + configs),
        ("scan",    ["scan_scheduler.py"]),
        ("parse",   ["result_parser.py"]),
        ("chart",   ["bar_chart.py"]),
    ]

    results = {}
    for label, cmd_parts in steps:
        rc = run_step(cmd_parts[0], cmd_parts[1:])
        results[label] = rc
        if rc != 0 and label != "chart":  # chart失败不阻断
            print(f"\nPipeline stopped at {label} (exit code {rc})")
            return rc

    # 汇总
    print(f"\n{'='*55}\n  PIPELINE COMPLETE\n{'='*55}")
    for label, rc in results.items():
        print(f"  {label:12s}: {'PASS' if rc == 0 else 'FAIL'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
