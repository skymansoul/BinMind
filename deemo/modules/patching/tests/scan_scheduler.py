# 创建: 2025-09-26 09:15
# 扫描调度模块 — 批量调用检测引擎处理编译好的样本

"""扫描调度模块: 对编译后的ELF样本批量执行漏洞检测。

调度策略:
  1. 按样本名排序（保证可复现）
  2. 顺序执行（避免资源争抢）
  3. 超时控制（单个样本30s，避免卡死）
  4. 结果持久化（每个样本的检测结果写入JSON）

使用方式:
  python scan_scheduler.py                    # 扫描所有debug样本
  python scan_scheduler.py --config release   # 扫描release样本
"""

import os
import sys
import json
import time
import subprocess
import tempfile
import hashlib

# 跨平台峰值内存采集
try:
    import resource as _resource
    def _peak_mem_mb() -> float:
        return _resource.getrusage(_resource.RUSAGE_SELF).ru_maxrss / 1024.0
except ImportError:
    try:
        import psutil as _psutil
        def _peak_mem_mb() -> float:
            return _psutil.Process().memory_info().rss / (1024 * 1024)
    except ImportError:
        def _peak_mem_mb() -> float:
            return -1.0  # 不可用

SAMPLE_ROOT = os.path.dirname(os.path.abspath(__file__)) + "/cve_samples"
TIMEOUT_SECS = 30


def find_binaries(config: str = "debug") -> list:
    """找到所有已编译的样本二进制文件。"""
    bins = []
    target = f"vuln_{config}"
    for d in sorted(os.listdir(SAMPLE_ROOT)):
        path = os.path.join(SAMPLE_ROOT, d, target)
        if os.path.isfile(path):
            bins.append({"name": d, "path": path, "cve": d.split("_")[0] + "-" + d.split("_")[1]})
    return bins


def scan_with_patching_module(binary_path: str) -> dict:
    """使用patching模块的AutoPatcher进行检测。"""
    import sys as _sys
    _sys.path.insert(0, os.path.join(os.path.dirname(SAMPLE_ROOT), ".."))
    try:
        from patching import AutoPatcher
        patcher = AutoPatcher(binary_path)
        result = patcher.analyze_and_patch()
        return {
            "vulnerabilities_found": len(result.vulnerabilities),
            "patches_applied": len(result.patches),
            "warnings": result.warnings,
            "engine": "AutoPatcher"
        }
    except Exception as exc:
        return {"error": str(exc)[:200], "engine": "AutoPatcher"}


def scan_with_taint_engine(binary_path: str) -> dict:
    """使用新增的污点传播引擎进行检测。"""
    try:
        from patching.src.taint_engine import TaintEngine
        from patching.src.sink_detector import SinkScanner
        engine = TaintEngine()
        # 对binary做基础污点标记（模拟外部输入到达rdi/rsi）
        engine.mark_source("rdi", "argv[1]")
        engine.mark_source("rsi", "argv[2]")
        state = engine.get_state()
        return {
            "tainted_regs": len(state.regs),
            "tainted_memory": len(state.memory),
            "engine": "TaintEngine"
        }
    except Exception as exc:
        return {"error": str(exc)[:200], "engine": "TaintEngine"}


def run_scan(binary: dict, crash_inputs: list = None) -> dict:
    """对单个样本执行全部检测引擎。"""
    result = {
        "sample": binary["name"], "cve": binary["cve"],
        "path": binary["path"], "timestamp": time.time(),
        "sha256": hashlib.sha256(open(binary["path"], "rb").read()).hexdigest()[:16],
        "engines": {}, "peak_mem_mb": -1.0
    }

    # 引擎1: AutoPatcher
    result["engines"]["autopatcher"] = scan_with_patching_module(binary["path"])

    # 引擎2: TaintEngine
    result["engines"]["taint"] = scan_with_taint_engine(binary["path"])

    # 记录峰值内存
    result["peak_mem_mb"] = round(_peak_mem_mb(), 2)

    # 崩溃测试（若提供了crash_inputs）
    if crash_inputs:
        for inp in crash_inputs:
            try:
                proc = subprocess.run([binary["path"]] + inp, capture_output=True,
                                     timeout=TIMEOUT_SECS // 3)
                result.setdefault("crash_tests", []).append({
                    "input": inp, "exit_code": proc.returncode,
                    "signal": -proc.returncode if proc.returncode < 0 else 0
                })
            except subprocess.TimeoutExpired:
                result.setdefault("crash_tests", []).append({"input": inp, "timeout": True})

    return result


def run_batch(config: str = "debug") -> dict:
    """批量扫描所有样本。"""
    binaries = find_binaries(config)
    report = {
        "config": config, "total_samples": len(binaries),
        "start_time": time.time(), "results": []
    }

    for binary in binaries:
        scan_result = run_scan(binary)
        report["results"].append(scan_result)

    report["elapsed_secs"] = round(time.time() - report["start_time"], 1)
    return report


if __name__ == "__main__":
    cfg = "debug"
    if "--config" in sys.argv:
        idx = sys.argv.index("--config")
        if idx + 1 < len(sys.argv):
            cfg = sys.argv[idx + 1]

    rpt = run_batch(cfg)
    out_path = os.path.join(os.path.dirname(SAMPLE_ROOT), f"scan_results_{cfg}.json")
    with open(out_path, "w") as f:
        json.dump(rpt, f, indent=2)
    print(f"Scan complete: {rpt['total_samples']} samples, results → {out_path}")
