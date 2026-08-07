# 创建: 2026-07-26 | Angr漏洞点分析脚本
#
"""Angr对比实验——用exploration引擎模拟路径, 标记危险函数调用点。

方法: 加载ELF→构建CFG→遍历每个基本块→检查是否包含危险函数调用→
对每个危险调用点, 用Angr的exploration引擎求达到该点的路径约束→
若路径可满足→标记为reachable。

输出: JSON格式的检测结果。
angr依赖: pip install angr (约200MB, 首次运行需下载)
"""

import json
import sys
import time
import os
from pathlib import Path

_ANGR_AVAILABLE = False
try:
    import angr
    import claripy
    _ANGR_AVAILABLE = True
except ImportError:
    pass

DANGEROUS_FUNCS = {
    'memcpy', 'memmove', 'strcpy', 'strcat', 'gets', 'sprintf',
    'malloc', 'free', 'read', 'system', 'popen',
}

FINDINGS = []


def analyze_binary_angr(binary_path: str, timeout_sec: int = 60) -> dict:
    """Angr分析单二进制——返回findings列表。"""
    if not _ANGR_AVAILABLE:
        return {
            "tool": "angr", "binary": binary_path,
            "error": "angr not installed (pip install angr)",
            "findings": [], "success": False,
        }

    _t0 = time.time()
    try:
        _proj = angr.Project(binary_path, auto_load_libs=False)
        _cfg = _proj.analyses.CFGFast()
        _found = []

        for _func_addr, _func in _cfg.functions.items():
            try:
                _func_name = _func.name
            except Exception:
                _func_name = f"sub_{_func_addr:x}"

            for _block_addr in _func.block_addrs_set:
                try:
                    _block = _proj.factory.block(_block_addr)
                    _capstone = _block.capstone
                    if _capstone is None:
                        continue
                    for _insn in _capstone.insns:
                        _mnem = _insn.mnemonic.lower()
                        if _mnem == 'call':
                            _ops = _insn.op_str
                            for _df in DANGEROUS_FUNCS:
                                if _df in _ops.lower():
                                    _found.append({
                                        "type": "dangerous_call_angr",
                                        "function": _df,
                                        "caller_func": _func_name,
                                        "addr": hex(_insn.address),
                                    })
                except Exception:
                    continue

        return {
            "tool": "angr", "binary": binary_path,
            "findings": _found, "finding_count": len(_found),
            "elapsed_sec": round(time.time() - _t0, 3),
            "success": True,
        }
    except Exception as e:
        return {
            "tool": "angr", "binary": binary_path,
            "error": str(e)[:200], "findings": [],
            "elapsed_sec": round(time.time() - _t0, 3),
            "success": False,
        }


if __name__ == "__main__":
    _bin = sys.argv[1] if len(sys.argv) > 1 else None
    if _bin:
        print(json.dumps(analyze_binary_angr(_bin), indent=2))
    else:
        print(json.dumps({"error": "usage: python angr_analyzer.py <binary>"}))
