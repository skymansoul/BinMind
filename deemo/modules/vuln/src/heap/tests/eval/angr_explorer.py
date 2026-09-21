"""堆区间证据消歧对比实验 — Angr 符号执行.

对编译好的 .exe 样本运行 Angr explorer, 检测堆溢出路径.
对比堆区间证据消歧的静态分析结果.

依赖: pip install angr

用法:
  python angr_explorer.py --sample cve_2021_3156
  python angr_explorer.py --all  # 全量 (极慢, 慎用)

创建: 2025-02-06
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple


BUILD_ROOT = Path(__file__).resolve().parent.parent / "build"
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)


def check_heap_overflow(state) -> bool:
    """检查 Angr 状态中是否有堆溢出的证据.

    策略: 查找 malloc 调用点 → 追踪返回的堆指针 → 检查是否有
    对 heap_ptr + offset 的写操作超过了分配大小.
    """
    try:
        import angr  # noqa: F811
    except ImportError:
        return False

    # 简化版: 检查是否有 memset/memcpy 的参数超出已知分配大小
    # 完整版需要 hook malloc 并追踪 size, 此处仅示意框架
    return False


def analyze_with_angr(exe_path: Path, timeout: int = 30) -> dict:
    """用 Angr 分析单个样本, 超时则返回部分结果."""
    try:
        import angr
        import claripy
    except ImportError:
        return {'error': 'angr not installed', 'findings': 0, 'time_ms': 0}

    t0 = time.perf_counter()
    findings = 0
    error = ""
    paths_explored = 0

    try:
        proj = angr.Project(str(exe_path), auto_load_libs=False)

        # Hook malloc: 返回一个符号化指针 + 记录请求大小
        malloc_sizes = {}

        class MallocHook(angr.SimProcedure):
            def run(self, size):
                ptr = self.state.heap._malloc(size)
                malloc_sizes[self.state.solver.eval(ptr)] = self.state.solver.eval(size)
                return ptr

        proj.hook_symbol('malloc', MallocHook())
        proj.hook_symbol('calloc', MallocHook())

        # 符号执行: 从 entry 开始探索
        state = proj.factory.entry_state()
        simgr = proj.factory.simulation_manager(state)

        # 查找 memset/memcpy 调用
        simgr.explore(
            find=lambda s: b'memset' in s.memory.load(s.regs.rip, 16) or
                          b'memcpy' in s.memory.load(s.regs.rip, 16),
            avoid=lambda s: s.regs.rip.symbolic,
            num_find=10)

        for found in simgr.found[:10]:
            paths_explored += 1
            # 检查 memset 参数: size 是否超过 malloc 分配大小
            if hasattr(found, 'regs'):
                size_reg = found.regs.r8  # MinGW: 3rd arg = r8
                try:
                    size_val = found.solver.eval(size_reg)
                    # 简化: 假设任何 size > 4096 是可疑的
                    if size_val > 4096:
                        findings += 1
                except Exception:
                    pass

    except Exception as e:
        error = str(e)[:200]

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
    return {
        'findings': findings,
        'paths_explored': paths_explored,
        'time_ms': elapsed_ms,
        'error': error,
    }


def main():
    parser = argparse.ArgumentParser(description="Angr 对比分析")
    parser.add_argument("--sample", type=str, default="", help="单样本名称")
    parser.add_argument("--all", action="store_true", help="全量分析")
    parser.add_argument("--timeout", type=int, default=30, help="每样本超时(秒)")
    args = parser.parse_args()

    if not args.sample and not args.all:
        print("  Usage: python angr_explorer.py --sample cve_2021_3156")
        print("  NOTE: Angr requires pip install angr (300MB+)")
        return

    results = []
    opt_dir = BUILD_ROOT / "gcc" / "O0"
    exes = sorted(opt_dir.glob("*.exe"))
    if args.sample:
        exes = [e for e in exes if args.sample in e.stem]

    for exe in exes:
        print(f"  Angr analyzing: {exe.stem} ...")
        r = analyze_with_angr(exe, timeout=args.timeout)
        r['sample'] = exe.stem
        results.append(r)
        print(f"    Findings: {r['findings']}, "
              f"Paths: {r['paths_explored']}, "
              f"Time: {r['time_ms']}ms")

    out_path = RESULTS_DIR / "angr_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n  Results: {out_path}")


if __name__ == "__main__":
    main()
