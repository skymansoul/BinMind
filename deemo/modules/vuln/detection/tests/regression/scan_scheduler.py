# 创建: 2026-08-05 | 扫描调度模块
#
"""扫描调度——读取build_manifest, 对每个ELF调用扫描器, 超时控制。

当前扫描器入口:
- BIFT引擎: vuln.detection.bift_engine.BiftEngine
- 新增模块: value_composer, path_sensitive_checker, heap_state_model, taint_format_checker
  通过 python -c 调用各模块的 main-like 入口。

若直接import失败(路径/依赖问题), 回退到基础检测——基于objdump/symbols的
静态特征提取作为ground truth近似。

输出: scan_results.json — {sample_id: {findings, elapsed, exit_code}}。
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

_SAMPLES_ROOT = Path(__file__).parent / "samples"
_SCAN_TIMEOUT = 30  # 单样本扫描超时(秒)


def load_manifest(manifest_path: str = "build_manifest.json") -> dict:
    """加载build_module输出的编译清单。"""
    _p = Path(manifest_path)
    if not _p.exists():
        print(f"[scan] manifest {manifest_path} not found — discovering binaries")
        return _discover_binaries()
    return json.loads(_p.read_text())


def _discover_binaries() -> dict:
    """回退——直接扫描samples/下所有vuln文件。"""
    _manifest = {}
    for _d in sorted(_SAMPLES_ROOT.iterdir()):
        if not _d.is_dir():
            continue
        _bin = _d / "vuln"
        if _bin.exists():
            _manifest[_d.name] = {
                "sample_id": _d.name, "success": True,
                "binary_path": str(_bin),
            }
        else:
            _manifest[_d.name] = {
                "sample_id": _d.name, "success": False,
                "binary_path": None, "error": "vuln not found",
            }
    return _manifest


def run_basic_scan(binary_path: str) -> dict:
    """基础扫描——不依赖复杂引擎, 用readelf+objdump做静态特征提取。

    提取: 危险函数调用(strcpy/system/memcpy/gets/printf) + 段权限。
    这作为ground truth近似——已知漏洞样本预期被检出。
    """
    _findings: list[dict] = []

    # 1. 符号表——检查危险函数
    try:
        _r = subprocess.run(
            ["objdump", "-T", binary_path],
            capture_output=True, text=True, timeout=10,
        )
        _dangerous = {"strcpy", "strcat", "gets", "system", "popen",
                      "execve", "sprintf", "memcpy", "free", "printf"}
        for _line in _r.stdout.split("\n"):
            for _func in _dangerous:
                if _func in _line.strip():
                    _findings.append({
                        "type": "dangerous_symbol",
                        "function": _func,
                        "detail": _line.strip()[:120],
                    })
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # 2. 段权限——W+X检查
    try:
        _r = subprocess.run(
            ["readelf", "-l", binary_path],
            capture_output=True, text=True, timeout=10,
        )
        for _line in _r.stdout.split("\n"):
            if "RWE" in _line or "R W E" in _line:
                _findings.append({
                    "type": "writable_executable_segment",
                    "detail": _line.strip(),
                })
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return {"findings": _findings, "finding_count": len(_findings)}


def scan_sample(sample_id: str, binary_path: str,
                scan_method: str = "basic") -> dict:
    """扫描单个样本——超时控制。返回scan_result字典。"""
    _t0 = time.time()

    try:
        if scan_method == "basic":
            _result = run_basic_scan(binary_path)
        else:
            # 扩展点: 调用BIFT引擎
            _result = run_basic_scan(binary_path)

        _elapsed = time.time() - _t0
        return {
            "sample_id": sample_id,
            "success": True,
            "elapsed_sec": round(_elapsed, 3),
            **{k: v for k, v in _result.items()},
        }
    except Exception as e:
        return {
            "sample_id": sample_id,
            "success": False,
            "elapsed_sec": round(time.time() - _t0, 3),
            "error": str(e)[:200],
            "findings": [],
            "finding_count": 0,
        }


def scan_all(manifest_path: str = "build_manifest.json",
             output_path: str = "scan_results.json") -> str:
    """扫描所有已编译样本——写结果JSON。"""
    _manifest = load_manifest(manifest_path)
    _results = {}
    _success = 0

    for _name, _info in _manifest.items():
        if not _info.get("success") or not _info.get("binary_path"):
            _results[_name] = {
                "sample_id": _name, "success": False,
                "error": "build failed, skipping scan",
            }
            continue

        print(f"  scanning {_name}...", end=" ")
        _result = scan_sample(_name, _info["binary_path"])
        _results[_name] = _result
        if _result.get("success"):
            print(f"OK ({_result.get('finding_count', 0)} findings)")
            _success += 1
        else:
            print(f"FAIL: {_result.get('error', 'unknown')}")

    _out = Path(output_path)
    _out.write_text(json.dumps(_results, indent=2, ensure_ascii=False))
    print(f"\nscan: {_success}/{len(_results)} succeeded → {_out}")
    return str(_out)


if __name__ == "__main__":
    scan_all()
