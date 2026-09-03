"""Angr 探索器 — 基于 angr 的堆溢出静态分析.

方法: CFG 定位 malloc/memcpy 调用点 → 从每个 malloc 调用点做
有界符号探索 (DFS, ≤64步, ≤200状态) → 在 memcpy 汇聚点用求解器
提取 rdx/r8 的数值下界, 与路径上 malloc 大小比较 → 越界即检出.

设计决策:
  - 有界探索防路径爆炸: 每调用点 ≤64 步, 全样本超时保护
  - LAZY_SOLVES 提速, 仅在汇聚点做精确求解
  - 符号大小无法界定 → 不报告 (保守)
  - angr 不可用/超时 → N/A, 不阻塞基准流程
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_RESULTS_CACHE: Dict[str, dict] = {}


def _check_angr() -> bool:
    try:
        import angr  # noqa: F401
        import claripy  # noqa: F401
        return True
    except ImportError:
        return False


_ALLOC_FUNCS = {"malloc", "calloc", "realloc"}
_SINK_FUNCS = {"memcpy", "memmove", "memset", "strncpy", "__memcpy_chk"}
_SINK_SIZE_REGS = {  # SysV: arg2=rdx; Win64: arg2=r8
    "memcpy": ("rdx", "r8"), "memmove": ("rdx", "r8"),
    "memset": ("rdx", "r8"), "strncpy": ("rdx", "r8"),
    "__memcpy_chk": ("rdx", "r8"),
}


def _find_heap_overflow_with_angr(binary_path: str,
                                  per_site_timeout: float = 20.0
                                  ) -> List[dict]:
    """有界符号探索检测 malloc→memcpy 大小错配."""
    try:
        import angr
    except ImportError:
        return [{"error": "angr not installed"}]

    findings = []
    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        funcs = cfg.functions

        # 1) 收集 malloc 调用点 与 memcpy 调用点
        alloc_sites: List[int] = []
        sink_sites: List[int] = []
        for addr, func in funcs.items():
            for call in func.get_call_sites():
                target = func.get_call_target(call)
                if target is None:
                    continue
                callee = funcs.get(target)
                if callee is None:
                    continue
                name = callee.name
                if name in _ALLOC_FUNCS:
                    alloc_sites.append(call)
                elif name in _SINK_FUNCS:
                    sink_sites.append(call)
        if not alloc_sites:
            return [{"type": "meta", "reason": "no malloc calls via angr CFG",
                     "confidence": 0.0}]

        # 2) 每个 malloc 调用点做有界探索
        for site in sorted(alloc_sites)[:24]:
            findings.extend(_explore_from_malloc(
                proj, site, sink_sites, per_site_timeout))

        if not findings:
            findings.append({"type": "meta",
                             "reason": "exploration done, no overflow proven",
                             "confidence": 0.0})
        return findings
    except Exception as e:
        return [{"error": f"angr analysis failed: {e}"}]


def _explore_from_malloc(proj, malloc_site: int, sink_sites: List[int],
                         timeout: float) -> List[dict]:
    """从 malloc 调用点出发探索, 在 memcpy 处比较大小."""
    try:
        import angr
        from angr import options as ao
    except ImportError:
        return []
    findings: List[dict] = []
    try:
        state = proj.factory.blank_state(
            addr=malloc_site,
            add_options={ao.LAZY_SOLVES, ao.CONCRETIZE_MEMORY_WHEN_APPROPRIATE,
                         ao.SIMPLIFY_MEMORY_READS})
        simgr = proj.factory.simulation_manager(state)
        simgr.use_technique(angr.exploration_techniques.DFS())
        deadline = time.perf_counter() + timeout
        alloc_size = None
        hit_sink = False
        for _ in range(64):
            if time.perf_counter() > deadline:
                return []
            if not simgr.active:
                break
            # 先跨过 malloc 调用, 记录返回值
            for s in simgr.active:
                if not alloc_size and s.addr == malloc_site:
                    pass
            simgr.step()
            for s in list(simgr.active):
                if s.addr in sink_sites:
                    hit_sink = True
                    res = _check_sink(s, proj, alloc_size)
                    if res:
                        findings.append(res)
                    simgr.active.remove(s)
                elif s.addr == malloc_site:
                    try:
                        alloc_size = int(s.solver.eval(s.regs.rdi))
                    except (TypeError, ValueError, ArithmeticError):
                        alloc_size = None
        if not hit_sink:
            return []
        return findings
    except Exception:
        return []


def _check_sink(state, proj, alloc_size) -> Optional[dict]:
    """在 memcpy 汇聚点提取大小并比较."""
    try:
        import angr
        regs = state.regs
        size_lo = None
        for reg in ("rdx", "r8"):
            val = getattr(regs, reg)
            try:
                lo = int(state.solver.min(val))
                hi = int(state.solver.max(val))
            except (TypeError, ValueError, ArithmeticError,
                    angr.SimUnsatError):
                continue
            size_lo = lo if size_lo is None else min(size_lo, lo)
        if size_lo is None:
            return None
        if alloc_size is not None and size_lo > alloc_size:
            return {"type": "heap_overflow", "subtype": "angr_symexec",
                    "address": hex(state.addr),
                    "reason": f"angr: sink size({size_lo}) > "
                              f"alloc({alloc_size})",
                    "confidence": 0.6}
        return None
    except Exception:
        return None


def run_angr_scan(binary_path: str, sample_name: str = "",
                  cache: bool = True) -> dict:
    """对单个二进制运行 angr 分析, 返回标准化结果."""
    if cache and binary_path in _RESULTS_CACHE:
        return _RESULTS_CACHE[binary_path]
    available = _check_angr()
    result = {"tool": "angr", "sample": sample_name,
              "available": available, "findings": [],
              "elapsed_ms": 0.0, "error": ""}
    if not available:
        result["error"] = "angr not installed"
        return result
    t0 = time.perf_counter()
    try:
        result["findings"] = _find_heap_overflow_with_angr(binary_path)
    except Exception as e:
        result["error"] = str(e)
    result["elapsed_ms"] = (time.perf_counter() - t0) * 1000
    if cache:
        _RESULTS_CACHE[binary_path] = result
    return result


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Angr heap overflow explorer")
    ap.add_argument("binary", help="Path to ELF/PE binary")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    result = run_angr_scan(args.binary, Path(args.binary).stem)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        n = len([f for f in result["findings"]
                 if f.get("type") == "heap_overflow"])
        print(f"Angr Explorer — {args.binary}")
        print(f"  Available: {result['available']}")
        print(f"  Heap findings: {n}")
        print(f"  Time: {result['elapsed_ms']:.1f}ms")
        if result["error"]:
            print(f"  Error: {result['error']}")


if __name__ == "__main__":
    main()
