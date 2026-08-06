# created: 2026-08-07
# 回归测试编译调度——遍历sample目录，调用各compile.sh生成目标ELF
# 输出: build/目录下的编译产物 + compile_log.json

import subprocess
import json
import os
import sys
import time
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Optional

SAMPLES_ROOT = Path(__file__).parent / "samples"
BUILD_ROOT = Path(__file__).parent / "build"


@dataclass
class CompileResult:
    sample_name: str
    cve_id: str
    vuln_type: str
    opt_level: str            # O0 or O3
    success: bool
    binary_path: str = ""
    compile_time_ms: float = 0.0
    error_msg: str = ""


def discover_samples() -> List[Path]:
    """扫描samples/目录, 返回包含compile.sh的子目录列表"""
    samples = []
    for item in sorted(SAMPLES_ROOT.iterdir()):
        if item.is_dir() and (item / "compile.sh").exists():
            samples.append(item)
    return samples


def run_compile(sample_dir: Path) -> List[CompileResult]:
    """对单个sample执行compile.sh, 对O0和O3分别生成编译结果"""
    results = []
    sample_name = sample_dir.name
    cve_id = sample_name.split("_")[0]
    vuln_type = infer_vuln_type(sample_name)

    for opt in ["O0", "O3"]:
        out_dir = BUILD_ROOT / sample_name / opt
        out_dir.mkdir(parents=True, exist_ok=True)
        binary_path = out_dir / "target"

        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                ["bash", str(sample_dir / "compile.sh"), opt, str(binary_path)],
                capture_output=True, text=True, timeout=60,
                cwd=str(sample_dir))
            success = proc.returncode == 0
            error_msg = proc.stderr[:500] if proc.stderr else ""
        except subprocess.TimeoutExpired:
            success = False
            error_msg = "compile.sh timed out after 60s"
        except FileNotFoundError:
            success = False
            error_msg = "bash not found in PATH"

        elapsed = (time.perf_counter() - t0) * 1000
        results.append(CompileResult(
            sample_name=sample_name, cve_id=cve_id,
            vuln_type=vuln_type, opt_level=opt,
            success=success,
            binary_path=str(binary_path) if success else "",
            compile_time_ms=elapsed, error_msg=error_msg))
    return results


def infer_vuln_type(dirname: str) -> str:
    """从目录名推断漏洞类型"""
    lower = dirname.lower()
    if any(k in lower for k in ('uaf', 'use_after_free')):
        return 'use_after_free'
    if any(k in lower for k in ('overflow', 'heap')):
        return 'buffer_overflow'
    if any(k in lower for k in ('format', 'string')):
        return 'format_string'
    if 'heartbleed' in lower:
        return 'buffer_overflow'
    return 'unknown'


def main():
    samples = discover_samples()
    if not samples:
        print("错误: 未找到任何sample目录(需包含compile.sh)")
        sys.exit(1)

    BUILD_ROOT.mkdir(parents=True, exist_ok=True)
    all_results = []

    for sample_dir in samples:
        print(f"编译 {sample_dir.name} ...")
        results = run_compile(sample_dir)
        for r in results:
            status = "OK" if r.success else f"FAIL: {r.error_msg[:80]}"
            print(f"  [{r.opt_level}] {status}")
        all_results.extend(results)

    # 统计
    ok = sum(1 for r in all_results if r.success)
    total = len(all_results)
    print(f"\n编译完成: {ok}/{total} 成功")

    # 写日志
    log_path = BUILD_ROOT / "compile_log.json"
    with open(log_path, 'w') as f:
        json.dump([asdict(r) for r in all_results], f, indent=2)
    print(f"日志: {log_path}")

    return 0 if ok == total else 1


if __name__ == '__main__':
    sys.exit(main())
