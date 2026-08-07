# angr 探索器 — 利用 angr CFG 找出可达危险调用点.
#
# 决策逻辑:
#   angr 作为通用二进制分析基准, 其检测能力由 CFG 可达性 + 危险函数
#   调用模式决定. 对每个样本:
#     1. CFGFast 构建控制流图 (auto_load_libs=False).
#     2. 遍历函数, 收集 malloc/calloc/realloc 与 memcpy/memmove 调用点.
#     3. 若某函数内同时存在堆分配与堆写入调用 → 一条"潜在堆溢出"告警.
#   该启发式召回高但误报高 (安全样本同样存在 malloc+memcpy),
#   作为对比组真实反映通用工具的误报水平.
#
# 创建: 2026-05-23

import json
import sys
import time
from typing import Dict, List

ALLOC_FUNCS = {"malloc", "calloc", "realloc", "__libc_malloc", "_Znwm"}
WRITE_FUNCS = {"memcpy", "memmove", "memset", "strcpy", "strncpy",
               "strcat", "sprintf", "snprintf"}


def angr_available() -> bool:
    try:
        import angr  # noqa: F401
        return True
    except Exception:
        return False


def explore(binary: str, timeout_s: int = 120) -> Dict:
    """对单个二进制执行 angr 探索.

    返回: {detected, findings, elapsed_ms, error}
    """
    t0 = time.perf_counter()
    result = {"detected": False, "findings": [], "elapsed_ms": 0.0,
              "error": ""}
    if not angr_available():
        result["error"] = "angr not installed"
        return result

    try:
        import angr
        proj = angr.Project(binary, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
    except Exception as e:
        result["error"] = f"load/cfg failed: {str(e)[:120]}"
        result["elapsed_ms"] = (time.perf_counter() - t0) * 1000
        return result

    # 解析危险函数地址: 优先 CFG 函数名 (angr 已解析 mingw 导入 stub),
    # 其次 loader 导入表, 使 call <addr> 可被识别.
    alloc_addrs = set()
    write_addrs = set()
    try:
        for fn in cfg.functions.values():
            name = (fn.name or "").split("@@")[0].lower()
            if name in ALLOC_FUNCS:
                alloc_addrs.add(fn.addr)
            if name in WRITE_FUNCS:
                write_addrs.add(fn.addr)
    except Exception:
        pass
    try:
        for obj in proj.loader.all_objects:
            for sym_name, symbol in getattr(obj, "imports", {}).items():
                name = sym_name.split("@@")[0].lower()
                if name in ALLOC_FUNCS:
                    alloc_addrs.add(symbol.rebased_addr)
                if name in WRITE_FUNCS:
                    write_addrs.add(symbol.rebased_addr)
    except Exception:
        pass

    def _call_kind(insn) -> str:
        if insn.mnemonic != "call":
            return ""
        target = insn.op_str.strip()
        # 直接地址: call 0x...
        try:
            addr = int(target, 16)
            if addr in alloc_addrs:
                return "alloc"
            if addr in write_addrs:
                return "write"
        except ValueError:
            pass
        name = target.split("<")[-1].rstrip(">").split("@")[0] \
            if "<" in target else target
        name = name.strip().lower()
        if name in ALLOC_FUNCS:
            return "alloc"
        if name in WRITE_FUNCS:
            return "write"
        return ""

    try:
        findings = []
        for func in cfg.functions.values():
            has_alloc = False
            has_write = False
            for block in func.blocks:
                for insn in block.capstone.insns:
                    kind = _call_kind(insn)
                    if kind == "alloc":
                        has_alloc = True
                    if kind == "write":
                        has_write = True
            if has_alloc and has_write:
                findings.append({
                    "function": func.name,
                    "address": func.addr,
                    "has_alloc_call": has_alloc,
                    "has_write_call": has_write,
                })
        result["findings"] = findings
        result["detected"] = len(findings) > 0
    except Exception as e:
        result["error"] = f"explore failed: {str(e)[:120]}"

    result["elapsed_ms"] = (time.perf_counter() - t0) * 1000
    return result


def main():
    if len(sys.argv) < 2:
        print("usage: python angr_explorer.py <binary> [--json]")
        return
    binary = sys.argv[1]
    res = explore(binary)
    if "--json" in sys.argv:
        print(json.dumps(res, indent=2, default=str))
    else:
        print(f"detected={res['detected']} findings={len(res['findings'])} "
              f"time={res['elapsed_ms']:.0f}ms error={res['error']}")


if __name__ == "__main__":
    main()
