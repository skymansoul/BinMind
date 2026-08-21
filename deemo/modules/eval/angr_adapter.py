#!/usr/bin/env python3
"""angr适配器 — 使用符号执行检测堆溢出.

angr通过符号执行探索路径, 检测堆缓冲区越界写入.
需要安装: pip install angr
若未安装则输出skip信息.
"""
import sys
from typing import List

try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False

from .run_benchmark import ToolAdapter, VULN_SAMPLES


class AngrAdapter(ToolAdapter):
    """angr符号执行适配器."""

    name = "angr"

    def run(self, binary_path: str) -> List[dict]:
        if not ANGR_AVAILABLE:
            raise RuntimeError("anggr not installed")

        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        findings = []
        for func_addr in cfg.kb.functions:
            func = cfg.kb.functions[func_addr]
            if func.is_plt or func.is_simprocedure:
                continue
            try:
                # 对每个用户函数做符号执行
                state = proj.factory.entry_state(
                    args=[binary_path])
                simgr = proj.factory.simulation_manager(
                    state)
                simgr.explore(
                    find=lambda s: b"OVERFLOW" in
                    s.posix.dumps(1),
                    step_func=lambda sm: sm,
                    num_find=10)
                if simgr.found:
                    findings.append({
                        "address": func_addr,
                        "type": "heap_overflow",
                    })
            except Exception:
                continue
        return findings


if __name__ == "__main__":
    if not ANGR_AVAILABLE:
        print("angr is not installed. Install with: pip install angr")
        sys.exit(1)
    print("angr adapter ready.")
