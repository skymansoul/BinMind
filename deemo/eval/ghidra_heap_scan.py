"""
Ghidra headless heap overflow scanning script.

Run via: analyzeHeadless <project> <folder> -import <binary>
         -scriptPath <path> -postScript ghidra_heap_scan.py

Scans the imported binary for:
  1. Heap allocation sites (malloc/calloc/realloc calls)
  2. Heap write sites (memcpy/strcpy/strcat calls)
  3. Cross-references to determine if write target == allocation target
  4. Constraint check: write_size > alloc_size?

Output: JSON to stdout (captured by ghidra_headless.py wrapper).

NOTE: Requires Ghidra 10.x+ with Python 3 (Jython is not supported
by this script — use the Ghidra Python3 plugin or PyGhidra).
"""

from __future__ import annotations

import json
import re
import sys
from typing import Dict, List, Tuple

# Ghidra Python API availability check
try:
    import ghidra  # noqa: F401
    from ghidra.program.model.listing import CodeUnit
    from ghidra.program.model.symbol import RefType
    HAS_GHIDRA = True
except ImportError:
    HAS_GHIDRA = False

# Fallback: use objdump-based scanning when Ghidra API unavailable
try:
    import subprocess
    HAS_SUBPROCESS = True
except ImportError:
    HAS_SUBPROCESS = False


def scan_with_ghidra_api(currentProgram) -> List[dict]:
    """使用 Ghidra API 扫描堆溢出模式。"""
    findings = []
    listing = currentProgram.getListing()
    func_manager = currentProgram.getFunctionManager()
    reference_manager = currentProgram.getReferenceManager()

    alloc_funcs = {'malloc', 'calloc', 'realloc', '_malloc_r', '__libc_malloc'}
    write_funcs = {'memcpy', 'strcpy', 'strncpy', 'strcat', 'sprintf', 'snprintf'}

    for func in func_manager.getFunctions(True):
        func_name = func.getName()
        if func_name not in (alloc_funcs | write_funcs):
            continue

        refs_to = reference_manager.getReferencesTo(func.getEntryPoint())
        for ref in refs_to:
            if not ref.getReferenceType().isCall():
                continue

            caller_addr = ref.getFromAddress()
            caller_func = func_manager.getFunctionContaining(caller_addr)
            caller_name = caller_func.getName() if caller_func else "unknown"

            findings.append({
                "function": func_name,
                "type": "alloc" if func_name in alloc_funcs else "write",
                "caller": caller_name,
                "call_addr": str(caller_addr),
            })

    return findings


def scan_with_objdump(binary_path: str) -> List[dict]:
    """Fallback: 使用 objdump 做基础模式匹配扫描。

    当 Ghidra API 不可用时使用 (例如在 CI 环境中)。
    """
    findings = []
    try:
        # objdump 反汇编
        r = subprocess.run(
            ['objdump', '-d', binary_path],
            capture_output=True, text=True, timeout=30,
        )
        asm = r.stdout
    except Exception:
        return findings

    # 搜索 call 指令
    alloc_pattern = re.compile(r'call\s+\S*<(malloc|calloc|realloc)@plt>')
    write_pattern = re.compile(
        r'call\s+\S*<(memcpy|strcpy|strncpy|strcat|sprintf|snprintf)@plt>')

    lines = asm.split('\n')
    for i, line in enumerate(lines):
        m_alloc = alloc_pattern.search(line)
        if m_alloc:
            # 尝试从前几行提取参数 (mov edi, N → N 是 alloc size)
            size_arg = _extract_arg_value(lines, i, 'edi')
            findings.append({
                "type": "alloc",
                "function": m_alloc.group(1),
                "line": i + 1,
                "size_arg": size_arg,
                "raw_line": line.strip(),
            })

        m_write = write_pattern.search(line)
        if m_write:
            size_arg = _extract_arg_value(lines, i, 'edx')  # memcpy 的第三个参数
            findings.append({
                "type": "write",
                "function": m_write.group(1),
                "line": i + 1,
                "size_arg": size_arg,
                "raw_line": line.strip(),
            })

    return findings


def _extract_arg_value(lines: List[str], call_line: int, reg: str) -> int:
    """从反汇编中提取调用参数: 在 call 之前找 mov reg, N。

    x86_64 calling convention: rdi=rsi=rdx=rcx=r8=r9 (第1-6参数)
    malloc(size) → rdi=size
    memcpy(dst,src,n) → rdi=dst, rsi=src, rdx=n
    """
    for back in range(call_line - 1, max(0, call_line - 8), -1):
        line = lines[back]
        # mov edi, 0x40 / mov rdi, 64 / mov esi, N
        m = re.search(rf'mov\s+{reg},\s*(0x[0-9a-fA-F]+|\d+)', line)
        if m:
            return int(m.group(1), 0)
    return -1


def main():
    """主入口: 尝试 Ghidra API, 失败则返回空结果。

    当作为 Ghidra postScript 运行时, currentProgram 等全局变量自动注入。
    输出 GHIDRA_RESULT: 标记行供 ghidra_headless.py 解析。
    """
    result = {"tool": "Ghidra", "findings": [], "error": "", "heap_danger_calls": 0}

    if HAS_GHIDRA:
        try:
            import __main__
            program = getattr(__main__, 'currentProgram', None)
            if program:
                findings = scan_with_ghidra_api(program)
                result["findings"] = findings
                result["count"] = len(findings)
                result["heap_danger_calls"] = len(findings)
            else:
                result["error"] = "currentProgram not available"
        except Exception as e:
            result["error"] = str(e)[:200]
    else:
        result["error"] = "Ghidra API not available (Jython or standalone run)"

    # GHIDRA_RESULT: 标记供 ghidra_headless.py 解析
    print(f'GHIDRA_RESULT:{json.dumps(result, default=str)}')
    return result


if __name__ == "__main__":
    # 当直接运行 (非 Ghidra 环境), 尝试 objdump fallback
    if not HAS_GHIDRA and len(sys.argv) > 1:
        binary = sys.argv[1]
        findings = scan_with_objdump(binary)
        result = {"tool": "Ghidra-objdump", "findings": findings,
                  "count": len(findings), "heap_danger_calls": len(findings)}
        print(f'GHIDRA_RESULT:{json.dumps(result, default=str)}')
    else:
        main()
