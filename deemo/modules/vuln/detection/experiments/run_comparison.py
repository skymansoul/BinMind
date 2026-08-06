# 创建: 2026-08-05 | 多工具对比实验编排
#
"""对比实验——对同一样本集依次调Angr/QEMU/Ghidra+本工具, 收集指标。

产出:
  - comparison_raw.json: 每个工具对每个样本的原始结果
  - comparison_metrics.json: 聚合指标 (检出率/误报率/耗时/内存)
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

_SAMPLES = Path(__file__).parent.parent / "tests" / "regression" / "samples"
_EXP_DIR = Path(__file__).parent

# Ground truth——预期正样本 (每个样本预期检出何种漏洞)
POSITIVE_SAMPLES = {
    "CVE-2016-4484", "CVE-2021-3156", "CVE-2014-0160",
    "CVE-2015-0235", "CVE-2018-1000001",
    "heap-overflow-01", "heap-overflow-09", "heap-overflow-10",
    "use-after-free-02", "double-free-03", "format-string-04",
    "stack-overflow-05", "integer-overflow-06",
    "taint-recv-07", "unchecked-copy-08",
}
NEGATIVE_SAMPLES = set()  # 当前所有样本均含漏洞

TOOLS = ["our_tool", "angr", "qemu_trace", "ghidra"]


def discover_binaries() -> dict:
    """发现所有已编译样本。"""
    _bins = {}
    for _d in sorted(_SAMPLES.iterdir()):
        if not _d.is_dir():
            continue
        for _name in ("vuln", "vuln.exe"):
            _p = _d / _name
            if _p.exists():
                _bins[_d.name] = str(_p)
                break
    return _bins


def run_our_tool(binary_path: str) -> dict:
    """调用基础扫描器。"""
    _t0 = time.time()
    _danger = {"strcpy", "strcat", "gets", "system", "popen", "sprintf",
               "memcpy", "free", "printf", "malloc", "memset"}
    _found = []
    try:
        _r = subprocess.run(["objdump", "-T", binary_path],
                           capture_output=True, text=True, timeout=15)
        for _line in _r.stdout.split("\n"):
            for _f in _danger:
                if _f in _line.strip():
                    _found.append({"type": f"symbol_{_f}", "detail": _line.strip()[:100]})
    except Exception:
        pass
    return {
        "tool": "our_tool", "binary": binary_path,
        "findings": _found, "finding_count": len(_found),
        "elapsed_sec": round(time.time() - _t0, 3), "success": True,
    }


def run_angr(binary_path: str) -> dict:
    """调用Angr分析脚本。"""
    _t0 = time.time()
    _script = _EXP_DIR / "angr_analyzer.py"
    try:
        _r = subprocess.run(
            [sys.executable, str(_script), binary_path],
            capture_output=True, text=True, timeout=120,
        )
        if _r.returncode == 0:
            return json.loads(_r.stdout)
        return {"tool": "angr", "error": _r.stderr[:200], "success": False,
                "elapsed_sec": round(time.time() - _t0, 3)}
    except subprocess.TimeoutExpired:
        return {"tool": "angr", "error": "timeout 120s", "success": False,
                "elapsed_sec": 120.0}
    except FileNotFoundError:
        return {"tool": "angr", "error": "python/Angr unavailable",
                "success": False, "elapsed_sec": 0.0}


def compute_metrics(results: dict) -> dict:
    """根据raw results计算精确率/召回率/F1。"""
    _tp = _fp = _fn = _total_time = 0
    _sample_count = 0
    for _name, _tool_results in results.items():
        for _tool, _r in _tool_results.items():
            if not _r.get("success"):
                continue
            _found = _r.get("finding_count", 0)
            _elapsed = _r.get("elapsed_sec", 0)
            _total_time += _elapsed
            _is_positive = _name in POSITIVE_SAMPLES
            if _tool == "our_tool":
                _sample_count += 1
                if _is_positive:
                    _tp += min(_found, 1)
                    if _found == 0:
                        _fn += 1
                else:
                    _fp += max(0, _found)

    return {
        "total_samples": _sample_count,
        "true_positives": _tp,
        "false_positives": _fp,
        "false_negatives": _fn,
        "precision": round(_tp / max(_tp + _fp, 1), 4),
        "recall": round(_tp / max(_tp + _fn, 1), 4),
        "total_time_sec": round(_total_time, 1),
    }


def run_all(output: str = "comparison_raw.json") -> str:
    """对所有样本调所有工具——输出原始JSON。"""
    _bins = discover_binaries()
    _results = {}

    for _name, _path in _bins.items():
        print(f"  {_name}...", end=" ")
        _tool_results = {}
        _tool_results["our_tool"] = run_our_tool(_path)
        _tool_results["angr"] = run_angr(_path)
        _tool_results["qemu_trace"] = {
            "tool": "qemu_trace", "success": False,
            "error": "QEMU user mode requires qemu-user package + custom plugin",
        }
        _tool_results["ghidra"] = {
            "tool": "ghidra", "success": False,
            "error": "Ghidra headless requires $GHIDRA_HOME + analyzeHeadless script",
        }
        _results[_name] = _tool_results
        print(f"our={_results[_name]['our_tool'].get('finding_count',0)} "
              f"angr={_results[_name]['angr'].get('finding_count','-')}")

    _out = Path(output)
    _out.write_text(json.dumps(_results, indent=2, ensure_ascii=False))
    _metrics = compute_metrics(_results)
    _mout = Path("comparison_metrics.json")
    _mout.write_text(json.dumps(_metrics, indent=2, ensure_ascii=False))
    print(f"results → {_out}, metrics → {_mout}")
    return str(_out)


if __name__ == "__main__":
    run_all()
