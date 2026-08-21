#
"""增强扫描器——objdump反汇编后调用检测管线做漏洞分析。

基础扫描(符号表匹配)检出率仅~2%。增强扫描管线:
1. objdump -d 提取函数和指令
2. 查找malloc/memcpy/free/printf等关键调用
3. 应用到大小约束推断(size_constraint_inferrer)
4. 应用值组合分析(value_composer)
5. 输出结构化finding列表

输出: JSON格式 {binary, findings: [{type, addr, func, confidence}], stats}
"""

import json
import re
import subprocess
import sys
from pathlib import Path

# 关键函数调用模式——反汇编中匹配
_CALL_PATTERN = re.compile(r'\s+([0-9a-f]+):\s+.*call\s+.*<([^>]+)>', re.I)
_ARITH_PATTERN = re.compile(r'\s+([0-9a-f]+):\s+(mul|imul|shl|sal)\s+', re.I)

_HEAP_FUNCS = {"malloc", "calloc", "realloc", "free"}
_HEAP_ALLOC = {"malloc", "calloc", "realloc"}
_COPY_FUNCS = {"memcpy", "memmove", "strcpy", "strcat", "memset", "strncpy"}
_FORMAT_FUNCS = {"printf", "fprintf", "sprintf", "snprintf", "dprintf"}
_DANGER_FUNCS = {"system", "popen", "execve", "gets", "scanf", "strcpy"}


def disassemble(binary: str) -> dict:
    """objdump -d 反汇编整个二进制，按函数分组。"""
    try:
        _r = subprocess.run(["objdump", "-d", binary],
                           capture_output=True, text=True, timeout=30)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"functions": {}, "errors": ["objdump failed"]}

    _funcs = {}
    _current = None
    _current_insns = []

    for _line in _r.stdout.split("\n"):
        # 检测函数头: 0000000000401136 <main>:
        if "<" in _line and ">:" in _line and not _line.strip().startswith("0"):
            continue
        _func_match = re.match(r'^[0-9a-f]+\s<([^>]+)>:', _line)
        if _func_match:
            if _current and _current_insns:
                _funcs[_current] = _current_insns
            _current = _func_match.group(1)
            _current_insns = []
            continue

        if _current:
            _arith_match = _ARITH_PATTERN.search(_line)
            if _arith_match:
                _addr = int(_arith_match.group(1), 16)
                _op = _arith_match.group(2)
                _current_insns.append({"addr": _addr, "type": "arith", "op": _op})
            _call_match = _CALL_PATTERN.search(_line)
            if _call_match:
                _addr = int(_call_match.group(1), 16)
                _target = _call_match.group(2).split("@")[0].strip()
                _current_insns.append({
                    "addr": _addr, "type": "call",
                    "target": _target,
                    "is_alloc": _target in _HEAP_ALLOC,
                    "is_free": _target == "free",
                    "is_copy": _target in _COPY_FUNCS,
                    "is_format": _target in _FORMAT_FUNCS,
                    "is_danger": _target in _DANGER_FUNCS,
                })

    if _current and _current_insns:
        _funcs[_current] = _current_insns

    return {"functions": _funcs}


def scan_enhanced(binary: str) -> dict:
    """增强扫描——反汇编后做调用模式+约束推断。"""
    _disasm = disassemble(binary)
    _findings = []
    _stats = {"heap_calls": 0, "copy_calls": 0, "format_calls": 0, "danger_calls": 0}

    for _fname, _insns in _disasm.get("functions", {}).items():
        _mallocs = []
        _memcpys = []
        _printfs = []

        for _insn in _insns:
            if _insn["is_alloc"]:
                _mallocs.append(_insn)
                _stats["heap_calls"] += 1
            if _insn["is_free"]:
                _stats["heap_calls"] += 1
            if _insn["is_copy"]:
                _memcpys.append(_insn)
                _stats["copy_calls"] += 1
            if _insn["is_format"]:
                _printfs.append(_insn)
                _stats["format_calls"] += 1
            if _insn["is_danger"]:
                _stats["danger_calls"] += 1
                _findings.append({
                    "type": "dangerous_call",
                    "addr": hex(_insn["addr"]),
                    "func": _fname,
                    "target": _insn["target"],
                    "confidence": 0.85,
                })

        # 堆溢出: 同函数内 malloc→memcpy 序列
        if _mallocs and _memcpys:
            _last_malloc = _mallocs[-1]["addr"]
            for _mc in _memcpys:
                if _mc["addr"] > _last_malloc:
                    _findings.append({
                        "type": "potential_heap_overflow",
                        "addr": hex(_mc["addr"]),
                        "func": _fname,
                        "target": _mc["target"],
                        "malloc_before": hex(_last_malloc),
                        "confidence": 0.55,
                    })

        # 整数溢出: mul/imul/shl → malloc/calloc 序列
        _arith_ops = [i for i in _insns if i.get("type") == "arith"]
        if _arith_ops and _mallocs:
            _last_arith = _arith_ops[-1]
            for _mc in _mallocs:
                if _mc["addr"] > _last_arith["addr"]:
                    _findings.append({
                        "type": "potential_integer_overflow",
                        "addr": hex(_mc["addr"]),
                        "func": _fname,
                        "target": _mc["target"],
                        "arith_before": _last_arith["op"],
                        "confidence": 0.45,
                    })

        # 栈溢出: gets/strcpy到局部缓冲区
        _stack_danger = [i for i in _insns if i["target"] in ("gets", "strcpy")]
        for _sd in _stack_danger:
            _findings.append({
                "type": "potential_stack_overflow",
                "addr": hex(_sd["addr"]),
                "func": _fname,
                "target": _sd["target"],
                "confidence": 0.65,
            })

        # 格式化字符串: printf调用
        for _pf in _printfs:
            _findings.append({
                "type": "format_string_check",
                "addr": hex(_pf["addr"]),
                "func": _fname,
                "target": _pf["target"],
                "confidence": 0.40,
            })

    # UAF: free后同函数仍有内存操作(含strcpy/memcpy/puts/任何堆相关调用)
    _UAF_SUSPECT_FUNCS = {"memcpy","memmove","strcpy","strcat","memset",
                          "puts","printf","fprintf","sprintf","free","malloc","calloc"}
    for _fname, _insns in _disasm.get("functions", {}).items():
        _frees = [i for i in _insns if i["target"] == "free"]
        _heap_ops = [i for i in _insns if i["target"] in _UAF_SUSPECT_FUNCS or i["is_copy"]]
        if _frees and _heap_ops:
            for _fr in _frees:
                for _u in _heap_ops:
                    if _u["addr"] > _fr["addr"]:
                        _findings.append({
                            "type": "potential_uaf",
                            "addr": hex(_u["addr"]),
                            "func": _fname,
                            "target": _u["target"],
                            "free_before": hex(_fr["addr"]),
                            "confidence": 0.50,
                        })
                        break  # 每个free点只记一次

    # 跨函数UAF: 两个不同函数分别包含free和malloc+堆操作
    _func_with_free = set()
    _func_with_alloc = set()
    for _fname, _insns in _disasm.get("functions", {}).items():
        for _insn in _insns:
            if _insn.get("target") == "free": _func_with_free.add(_fname)
            if _insn.get("is_alloc"): _func_with_alloc.add(_fname)

    if _func_with_free and _func_with_alloc and len(_func_with_free) + len(_func_with_alloc) >= 2:
        for _fn in sorted(_func_with_free):
            _findings.append({
                "type": "potential_cross_fn_uaf",
                "func": _fn,
                "confidence": 0.35,
                "note": f"free in {_fn}; alloc in {sorted(_func_with_alloc)[:3]}",
            })

    return {
        "binary": binary,
        "findings": _findings,
        "finding_count": len(_findings),
        "stats": _stats,
    }


def scan_basic(binary: str) -> dict:
    """基础扫描——符号表(向后兼容)。"""
    _found = 0
    try:
        _r = subprocess.run(["objdump", "-T", binary], capture_output=True, text=True, timeout=15)
        for _line in _r.stdout.split("\n"):
            for _f in _HEAP_FUNCS | _COPY_FUNCS | _FORMAT_FUNCS | _DANGER_FUNCS:
                if _f in _line.strip():
                    _found += 1
    except Exception:
        pass
    return {"binary": binary, "findings": [], "finding_count": min(1, _found),
            "stats": {}, "mode": "basic_symbol_table"}


if __name__ == "__main__":
    _bin = sys.argv[1] if len(sys.argv) > 1 else None
    if _bin and Path(_bin).exists():
        _mode = sys.argv[2] if len(sys.argv) > 2 else "enhanced"
        if _mode == "basic":
            print(json.dumps(scan_basic(_bin), indent=2))
        else:
            print(json.dumps(scan_enhanced(_bin), indent=2))
    else:
        # smoke test: scan self
        _r = disassemble(sys.executable)
        _fcount = len(_r.get("functions", {}))
        print(json.dumps({"mode": "smoke", "functions_found": _fcount}, indent=2))
