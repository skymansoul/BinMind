# angr 探索器 - 利用 angr CFG 找出可达危险调用点.
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


FREE_FUNCS = {"free", "__libc_free", "_ZdlPv", "_ZdaPv", "g_free"}
USE_FUNCS = {"strlen", "puts", "printf", "fprintf", "memcpy", "memmove",
             "memset", "read", "fwrite", "strcmp", "strncmp", "fread"}


def explore_uaf(binary: str, timeout_s: int = 120) -> Dict:
    """UAF 模式 angr 探索: 同函数内 free 后出现 use 调用, 高误报对比基线."""
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

    free_addrs = set()
    use_addrs = set()
    try:
        for fn in cfg.functions.values():
            name = (fn.name or "").split("@@")[0].lower()
            if name in FREE_FUNCS:
                free_addrs.add(fn.addr)
            if name in USE_FUNCS:
                use_addrs.add(fn.addr)
    except Exception:
        pass
    try:
        for obj in proj.loader.all_objects:
            for sym_name, symbol in getattr(obj, "imports", {}).items():
                name = sym_name.split("@@")[0].lower()
                if name in FREE_FUNCS:
                    free_addrs.add(symbol.rebased_addr)
                if name in USE_FUNCS:
                    use_addrs.add(symbol.rebased_addr)
    except Exception:
        pass

    def _kind(insn) -> str:
        if insn.mnemonic != "call":
            return ""
        try:
            addr = int(insn.op_str.strip(), 16)
            if addr in free_addrs:
                return "free"
            if addr in use_addrs:
                return "use"
        except ValueError:
            pass
        name = insn.op_str.split("<")[-1].rstrip(">").split("@")[0] \
            if "<" in insn.op_str else insn.op_str
        name = name.strip().lower()
        if name in FREE_FUNCS:
            return "free"
        if name in USE_FUNCS:
            return "use"
        return ""

    try:
        findings = []
        for func in cfg.functions.values():
            saw_free = False
            saw_use = False
            for block in func.blocks:
                for insn in block.capstone.insns:
                    k = _kind(insn)
                    if k == "free":
                        saw_free = True
                    elif k == "use" and saw_free:
                        saw_use = True
            if saw_free and saw_use:
                findings.append({"function": func.name, "address": func.addr})
        result["findings"] = findings
        result["detected"] = len(findings) > 0
    except Exception as e:
        result["error"] = f"explore failed: {str(e)[:120]}"

    result["elapsed_ms"] = (time.perf_counter() - t0) * 1000
    return result


FMT_FUNCS = {"printf", "fprintf", "sprintf", "snprintf", "vprintf",
             "vfprintf", "vsprintf", "vsnprintf"}


def explore_fmt(binary: str, timeout_s: int = 120) -> Dict:
    """格式化字符串模式 angr 探索: printf 族调用的格式串参数为非寄存器字面量.

    粗粒度: 不验证格式串来源, 寄存器/内存格式串一律命中,
    安全样本 (栈槽常量初始化) 同样误报, 作为通用工具对比基线.
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

    fmt_addrs = set()
    try:
        for fn in cfg.functions.values():
            name = (fn.name or "").split("@@")[0].lower()
            if name in FMT_FUNCS:
                fmt_addrs.add(fn.addr)
    except Exception:
        pass
    try:
        for obj in proj.loader.all_objects:
            for sym_name, symbol in getattr(obj, "imports", {}).items():
                name = sym_name.split("@@")[0].lower()
                if name in FMT_FUNCS:
                    fmt_addrs.add(symbol.rebased_addr)
    except Exception:
        pass

    def _is_fmt(insn) -> bool:
        if insn.mnemonic != "call":
            return False
        try:
            return int(insn.op_str.strip(), 16) in fmt_addrs
        except ValueError:
            pass
        name = insn.op_str.split("<")[-1].rstrip(">").split("@")[0] \
            if "<" in insn.op_str else insn.op_str
        return name.strip().lower() in FMT_FUNCS

    try:
        findings = []
        for func in cfg.functions.values():
            for block in func.blocks:
                for insn in block.capstone.insns:
                    if _is_fmt(insn):
                        findings.append({"function": func.name,
                                         "address": insn.address})
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
