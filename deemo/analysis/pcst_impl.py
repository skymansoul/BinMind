# PCST — Per-Call Semantics Table (按调用点参数语义表).
#
# 核心决策:
#   堆溢出检测误报/漏报的隐蔽来源: 对所有写入函数用统一的参数索引
#   提取size. memcpy(dst,src,n)的size在index2, 而snprintf(dst,n,fmt)
#   的size在index1, fread(ptr,size,nmemb,stream)的实际写量为
#   size*nmemb, read(fd,buf,count)的dst在index1而非index0.
#   统一取index2会拿到snprintf的fmt指针(错误数据流→误报),
#   取index1会低估fread写入量(漏报). 本模块为每个调用点建立
#   函数→参数角色的精确映射, 消除该类系统性误差.
#
# 理论依据:
#   CodeQL 的 ExternalFlowSources/SummaryModels 同样依赖按函数签名
#   建模参数语义; 静态分析精度首先取决于调用点参数角色的正确性.
#
#   本文件实现 PCST 核心管线: 语义表数据 → 语义表查询 → 调用点解析 (C 源码级).


from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

# 语义表

# 写入size实参位置. 值为int(单个实参)或tuple(多个实参相乘, 如fread).
_WRITE_SIZE_ARG: Dict[str, object] = {
    "memcpy": 2, "memmove": 2, "mempcpy": 2, "memccpy": 2,
    "memset": 2, "strncpy": 2, "strncat": 2, "stpncpy": 2,
    "snprintf": 1, "vsnprintf": 1, "vsnprintf_s": 1,
    "read": 2, "pread": 2, "recv": 2, "recvfrom": 2, "recvmsg": 2,
    "fread": (1, 2), "fwrite": (1, 2),
    "bcopy": 2, "bzero": 1, "explicit_bzero": 1,
    "gets_s": 0,
}

# dst指针实参位置.
_WRITE_DST_ARG: Dict[str, int] = {
    "memcpy": 0, "memmove": 0, "mempcpy": 0, "memccpy": 0,
    "memset": 0, "strncpy": 0, "strncat": 0, "stpncpy": 0,
    "snprintf": 0, "vsnprintf": 0,
    "read": 1, "pread": 1, "recv": 1, "recvfrom": 1, "recvmsg": 1,
    "fread": 0, "fwrite": 0,
    "bcopy": 0, "bzero": 0, "explicit_bzero": 0,
}

# 无界写入: 写尺寸由源字符串长度决定, 参数中无size.
_UNSIZED_WRITES: Dict[str, int] = {
    "strcpy": 1, "stpcpy": 1, "strcat": 1, "sprintf": 1,
    "vsprintf": 1, "gets": 0,
}

# 分配函数 → size实参位置 (malloc=0, calloc=(count,size), realloc=1).
_ALLOC_SIZE_ARG: Dict[str, object] = {
    "malloc": 0, "_Znwm": 0, "_Znam": 0, "g_malloc": 0,
    "g_try_malloc": 0, "kzalloc": 0, "kmalloc": 0, "vmalloc": 0,
    "calloc": (0, 1), "g_malloc0": (0, 1),
    "realloc": 1, "g_realloc": 1, "ExAllocatePoolWithTag": 1,
}

_FREE_FUNCS: Dict[str, None] = {
    "free": None, "_ZdlPv": None, "g_free": None, "ExFreePool": None,
    "kfree": None,
}

# 旧统一规则 (基线): dst 恒 index0, size 恒 index2.
LEGACY_DST_INDEX = 0
LEGACY_SIZE_INDEX = 2


# 语义表查询

def write_size_index(func: str) -> Optional[object]:
    """写入函数的size实参位置; 无界写入或无写入返回None."""
    if func in _UNSIZED_WRITES:
        return None
    return _WRITE_SIZE_ARG.get(func)


def write_dst_index(func: str) -> Optional[int]:
    """写入函数的dst实参位置; 无界写dst恒为第0实参."""
    if func in _UNSIZED_WRITES:
        return 0
    return _WRITE_DST_ARG.get(func, 0)


def is_sized_write(func: str) -> bool:
    return func in _WRITE_SIZE_ARG


def is_unsized_write(func: str) -> bool:
    return func in _UNSIZED_WRITES


def is_write_func(func: str) -> bool:
    return func in _WRITE_SIZE_ARG or func in _UNSIZED_WRITES


def is_alloc_func(func: str) -> bool:
    return func in _ALLOC_SIZE_ARG


def alloc_size_indices(func: str) -> Optional[object]:
    return _ALLOC_SIZE_ARG.get(func)


def is_free_func(func: str) -> bool:
    return func in _FREE_FUNCS


# 调用点解析 (C 源码级)

_CALL_RE = re.compile(r"\b(\w+)\s*\(((?:[^()]|\([^()]*\))*)\)")
_ASSIGN_RE = re.compile(
    r"(\w+(?:\s*\*)?\s*)\s*=\s*(?:\(\s*\w+(?:\s*\*)?\s*\)\s*)?"
    r"(malloc|calloc|realloc|g_malloc|g_malloc0|g_realloc|kmalloc|kzalloc|"
    r"vmalloc|_Znwm|_Znam)\s*\(((?:[^()]|\([^()]*\))*)\)")
_STRUCT_MEMBER = re.compile(r"\b\w+\s*->\s*\w+")


def _split_top_level(s: str) -> List[str]:
    """按顶层逗号切分参数 (括号深度跟踪)."""
    args, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(":
            depth += 1
            cur += ch
        elif ch == ")":
            depth -= 1
            cur += ch
        elif ch == "," and depth == 0:
            args.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        args.append(cur.strip())
    return args


def _base_var(expr: str) -> str:
    """归一化指针表达式: 去数组索引/成员访问/指针算术."""
    expr = re.sub(r"\[[^\]]*\]", "", expr)
    expr = re.sub(r"\s*\+\s*\w+", "", expr)
    expr = expr.split("->")[0].split(".")[0].strip()
    return expr


def _pick_arg(args: List[str], idx: int) -> str:
    """按索引取实参, 越界时取末参 (与汇编层 _args 填充一致)."""
    return args[min(idx, len(args) - 1)] if args else ""


def resolve_call_semantics(func: str, args: List[str]) -> Optional[Dict]:
    """按语义表解析单个调用点的 (dst, size) 角色.

    fread(ptr,size,nmemb,stream): size_spec=(1,2) → 实际写量为
    size*nmemb, 仅取index1会低估 (漏报), 取index2会拿到nmemb (低估).
    read(fd,buf,count): dst=index1 — 统一规则取index0会拿fd当缓冲
    (错误数据流→误报).
    """
    if not is_write_func(func):
        return None
    dst_idx = write_dst_index(func)
    size_spec = write_size_index(func)

    dst = _pick_arg(args, dst_idx)

    if size_spec is None:
        size_expr = None
        kind = "unsized"
    elif isinstance(size_spec, tuple):
        factors = [_pick_arg(args, i) for i in size_spec]
        size_expr = " * ".join(factors)
        kind = "sized_product"
    else:
        size_expr = _pick_arg(args, int(size_spec))
        kind = "sized"

    return {
        "func": func,
        "dst": dst,
        "dst_base": _base_var(dst),
        "size_expr": size_expr,
        "kind": kind,
    }


def legacy_semantics(func: str, args: List[str]) -> Optional[Dict]:
    """旧统一规则基线: dst=index0, size=index2.

    返回旧规则会取到的值, 供对照 (snprintf 会取到fmt指针,
    read 会取到fd, fread 会取到nmemb).
    """
    if func not in _WRITE_SIZE_ARG:
        return None
    return {
        "func": func,
        "dst": _pick_arg(args, LEGACY_DST_INDEX),
        "dst_base": _base_var(_pick_arg(args, LEGACY_DST_INDEX)),
        "size_expr": _pick_arg(args, LEGACY_SIZE_INDEX),
        "kind": "legacy",
    }


def pcst_corrections(func: str, args: List[str]) -> Optional[Dict]:
    """对照 PCST 与旧规则的差异; 无差异返回None."""
    pcst = resolve_call_semantics(func, args)
    legacy = legacy_semantics(func, args)
    if not pcst or not legacy:
        return None
    if (pcst["dst_base"] == legacy["dst_base"]
            and pcst["size_expr"] == legacy["size_expr"]):
        return None
    return {"pcst": pcst, "legacy": legacy}


# 尺寸求值 (轻量)

_SIZEOF_MAP = {
    "char": 1, "short": 2, "int": 4, "long": 4, "long long": 8,
    "float": 4, "double": 8, "void*": 4, "size_t": 4, "wchar_t": 2,
}


def _const(expr: str, ranges: Dict[str, float], defines: Dict[str, int]) \
        -> Optional[float]:
    """表达式常量求值: 数字/宏/单变量; 无法求值返回None."""
    expr = expr.strip()
    if not expr:
        return None
    try:
        return float(int(expr))
    except ValueError:
        pass
    if expr in defines:
        return float(defines[expr])
    sm = re.match(r"sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)", expr)
    if sm:
        return float(_SIZEOF_MAP.get(sm.group(1).strip().replace(" ", ""), 4))
    if expr in ranges:
        return ranges[expr]
    return None


def eval_size_bounds(
    size_expr: Optional[str],
    ranges: Dict[str, float],
    defines: Dict[str, int],
) -> Tuple[float, float]:
    """求写量下/上界: 乘积因子逐项求值, 不可求值项按 [0, +∞)."""
    if not size_expr:
        return (0.0, float("inf"))
    total_lo, total_hi = 1.0, 1.0
    for factor in size_expr.split("*"):
        factor = factor.strip()
        if factor.isdigit():
            v = float(int(factor))
            total_lo *= v
            total_hi *= v
            continue
        sm = re.match(r"sizeof\s*\(\s*(\w+(?:\s+\*)?)\s*\)", factor)
        if sm:
            v = float(_SIZEOF_MAP.get(
                sm.group(1).strip().replace(" ", ""), 4))
            total_lo *= v
            total_hi *= v
            continue
        v = _const(factor, ranges, defines)
        if v is not None:
            total_lo *= v
            total_hi *= v
        else:
            total_lo *= 0.0
            total_hi = float("inf")
    return (total_lo, total_hi)


# 分配器模型 (ptmalloc2 最小)

def _usable_size(request: int) -> int:
    """ptmalloc2 用户可用空间: chunk=align(req+8,16), usable=chunk-8,
    下限32."""
    if request <= 0:
        return 0
    chunk = max(32, (request + 8 + 15) & ~15)
    return chunk - 8


# 端到端扫描

def extract_allocs(code: str) -> List[Dict]:
    """提取分配点: 按 _ALLOC_SIZE_ARG 取size实参."""
    allocs = []
    for m in _ASSIGN_RE.finditer(code):
        var = m.group(1).strip()
        func = m.group(2)
        args = _split_top_level(m.group(3))
        spec = alloc_size_indices(func)
        if spec is None:
            continue
        if isinstance(spec, tuple):
            size_expr = " * ".join(_pick_arg(args, i) for i in spec)
        else:
            size_expr = _pick_arg(args, int(spec))
        allocs.append({
            "var": _base_var(var),
            "func": func,
            "size_expr": size_expr,
            "pos": m.start(),
            "line": code[:m.start()].count("\n") + 1,
        })
    return allocs


def extract_writes(code: str) -> List[Dict]:
    """提取写入调用点: 按语义表解析 (dst, size) 角色."""
    writes = []
    for m in _CALL_RE.finditer(code):
        func = m.group(1)
        args = _split_top_level(m.group(2))
        sem = resolve_call_semantics(func, args)
        if sem is None:
            continue
        sem.update({
            "args": args,
            "pos": m.start(),
            "line": code[:m.start()].count("\n") + 1,
        })
        writes.append(sem)
    return writes


def pcst_scan(code: str) -> Tuple[List[Dict], Dict]:
    """PCST 端到端: 语义表解析 + 分配配对 + 对齐判定.

    输出: (发现列表, 统计). 无界写入 (strcpy 等) 的写量交由
    BWR 模块恢复 — 本模块标注 kind=unsized, 供上游决策.
    """
    defines: Dict[str, int] = {}
    for dm in re.finditer(r"#define\s+(\w+)\s+(\d+)\s*$", code, re.MULTILINE):
        try:
            defines[dm.group(1)] = int(dm.group(2))
        except ValueError:
            pass

    ranges: Dict[str, float] = {}
    for rm in re.finditer(
            r"\b(?:int|unsigned|size_t|uint\d+_t)\s+(\w+)\s*=\s*(\d+)\s*;",
            code):
        ranges[rm.group(1)] = float(int(rm.group(2)))
    for rm in re.finditer(r"(\w+)\s*=\s*(\d+)\s*;", code):
        if rm.group(1) not in ranges:
            ranges[rm.group(1)] = float(int(rm.group(2)))

    allocs = extract_allocs(code)
    writes = extract_writes(code)
    alloc_by_var = {a["var"]: a for a in allocs}

    findings = []
    corrections = []
    unsized = 0
    unpaired = 0

    for w in writes:
        if w["kind"] == "unsized":
            unsized += 1
            continue
        alloc = alloc_by_var.get(w["dst_base"])
        if alloc is None:
            unpaired += 1
            continue

        wlo, whi = eval_size_bounds(w["size_expr"], ranges, defines)
        alo, ahi = eval_size_bounds(alloc["size_expr"], ranges, defines)

        if ahi == float("inf"):
            alloc_req = None
        else:
            alloc_req = int(ahi)
        usable = _usable_size(alloc_req) if alloc_req is not None else None

        if usable is None:
            verdict = "uncertain"
            overflow = 0
            confidence = 0.30
            reason = f"分配量未知({alloc['size_expr']})→无法判定"
        elif whi == float("inf"):
            verdict = "suspected"
            overflow = 0
            confidence = 0.50
            reason = f"写量无界({w['size_expr']}), alloc={alloc_req}"
        elif whi <= usable:
            verdict = "safe"
            overflow = 0
            confidence = 0.05
            reason = (f"write≤{int(whi)}B ≤ 对齐后可用{usable}B"
                      f"(请求{alloc_req}B)")
        elif wlo > usable:
            overflow = int(wlo) - usable
            verdict = "overflow"
            confidence = min(0.92, 0.75 + overflow / 1024.0)
            reason = (f"write≥{int(wlo)}B > 可用{usable}B"
                      f"(溢出≥{overflow}B)")
        else:
            verdict = "possible"
            overflow = int(whi) - usable if whi != float("inf") else 0
            confidence = 0.55
            reason = (f"写量区间[{wlo},{whi}] 跨越可用上界{usable}")

        findings.append({
            "type": "heap_overflow" if verdict in ("overflow", "possible")
                    else "heap_write",
            "write_func": w["func"],
            "dst": w["dst"],
            "write_size_expr": w["size_expr"],
            "alloc_func": alloc["func"],
            "alloc_size_expr": alloc["size_expr"],
            "alloc_request": alloc_req,
            "usable": usable,
            "write_bounds": [wlo, whi],
            "verdict": verdict,
            "overflow_bytes": max(overflow, 0),
            "confidence": round(confidence, 2),
            "reason": reason,
            "line": w["line"],
        })

        corr = pcst_corrections(w["func"], w["args"])
        if corr:
            corrections.append({
                "func": w["func"],
                "line": w["line"],
                "pcst_dst": corr["pcst"]["dst"],
                "legacy_dst": corr["legacy"]["dst"],
                "pcst_size": corr["pcst"]["size_expr"],
                "legacy_size": corr["legacy"]["size_expr"],
            })

    findings.sort(key=lambda f: f["confidence"], reverse=True)

    stats = {
        "allocs": len(allocs),
        "write_calls": len(writes),
        "unsized_writes_delegated_to_bwr": unsized,
        "unpaired_writes": unpaired,
        "corrections_vs_legacy": len(corrections),
        "reported": len(findings),
        "method": "PCST-v1.0",
    }

    return findings, stats


def pcst_legacy_report(code: str) -> List[Dict]:
    """仅输出语义表修正对照 (审计用)."""
    corrections = []
    for m in _CALL_RE.finditer(code):
        func = m.group(1)
        args = _split_top_level(m.group(2))
        corr = pcst_corrections(func, args)
        if corr:
            corrections.append({
                "func": func,
                "line": code[:m.start()].count("\n") + 1,
                "pcst_dst": corr["pcst"]["dst"],
                "legacy_dst": corr["legacy"]["dst"],
                "pcst_size": corr["pcst"]["size_expr"],
                "legacy_size": corr["legacy"]["size_expr"],
                "error_mode": _error_mode(func, corr),
            })
    return corrections


def _error_mode(func: str, corr: Dict) -> str:
    """归类旧规则的错误模式."""
    if func in ("read", "pread", "recv", "recvfrom", "recvmsg"):
        return "dst错位: fd/流被当作缓冲"
    if func in ("snprintf", "vsnprintf", "vsnprintf_s"):
        return "size错位: fmt指针被当作size"
    if func in ("fread", "fwrite"):
        return "size低估: 乘积因子丢失"
    return "参数角色偏移"


__all__ = [
    "write_size_index", "write_dst_index",
    "is_sized_write", "is_unsized_write", "is_write_func",
    "is_alloc_func", "alloc_size_indices", "is_free_func",
    "resolve_call_semantics", "legacy_semantics", "pcst_corrections",
    "eval_size_bounds",
    "extract_allocs", "extract_writes",
    "pcst_scan", "pcst_legacy_report",
]
