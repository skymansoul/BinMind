# 扫描调度模块 —— 对编译产物调用检测引擎, 收集原始输出。
# 独立于编译和结果解析, 支持超时控制和并发。
# 创建: 2026-08-14

import json, os, subprocess, sys, time
from dataclasses import dataclass, field
from typing import Optional

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


@dataclass
class ScanResult:
    sample_name: str
    binary_path: str
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_sec: float
    error: str = ""


def run_scan(binary_path: str, sample_name: str = "",
              timeout_sec: int = 120) -> ScanResult:
    """对单个二进制运行检测引擎。"""
    if not os.path.exists(binary_path):
        return ScanResult(sample_name, binary_path, False, -1,
                         "", "", 0.0, "文件不存在")

    t0 = time.time()
    try:
        # 调用扫描器: python -c 加载core模块直接分析
        scan_script = (
            f"import sys; sys.path.insert(0, '{PROJECT_ROOT}');"
            f"from core.stack_overflow_analyzer import analyze_stack_overflow;"
            f"from core.format_string_detector import detect_format_string_vulns;"
            f"from core.heap_use_analyzer import HeapUseAnalyzer;"
            f"from core.heap_overflow_detector import detect_heap_overflow;"
            f"r1=analyze_stack_overflow('{binary_path}','');"
            f"r2=detect_format_string_vulns('{binary_path}');"
            f"r3=HeapUseAnalyzer().analyze('{binary_path}');"
            f"import json; print(json.dumps({{'stack':r1,'fmt':r2,'heap':r3}},default=str))"
        )
        proc = subprocess.run(
            [sys.executable, "-c", scan_script],
            capture_output=True, text=True, timeout=timeout_sec,
            cwd=PROJECT_ROOT, env={**os.environ, "PYTHONPATH": PROJECT_ROOT},
        )
        dt = time.time() - t0
        return ScanResult(sample_name, binary_path, True,
                         proc.returncode, proc.stdout, proc.stderr, dt)
    except subprocess.TimeoutExpired:
        dt = time.time() - t0
        return ScanResult(sample_name, binary_path, False, -1,
                         "", f"超时({timeout_sec}s)", dt,
                         f"扫描超时>{timeout_sec}s")
    except Exception as e:
        dt = time.time() - t0
        return ScanResult(sample_name, binary_path, False, -1,
                         "", "", dt, str(e))


def run_all(binaries: dict, timeout_sec: int = 120) -> list:
    """批量扫描: {sample_name: binary_path} → [ScanResult]。
    binaries 格式来自 compile_samples.compile_all() 的输出。
    """
    results = []
    for name, info in binaries.items():
        if not isinstance(info, dict):
            continue
        if info.get("success") and info.get("binary_path"):
            result = run_scan(info["binary_path"], name, timeout_sec)
        else:
            result = ScanResult(name, "", False, -1, "", "",
                               0.0, info.get("error", "编译失败"))
        results.append(result)
    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        result = run_scan(sys.argv[1], os.path.basename(sys.argv[1]))
        print(json.dumps({
            "sample": result.sample_name,
            "success": result.success,
            "exit_code": result.exit_code,
            "duration_sec": round(result.duration_sec, 2),
            "error": result.error,
        }, indent=2, ensure_ascii=False))
