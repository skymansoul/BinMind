"""Ghidra 无头分析脚本(模拟) — 自动化静态审计对照.

创建: 2025-05-12
用途: 外部对照工具 3。本机无 Ghidra 安装时, 以 objdump 符号表 +
      函数边界恢复模拟 Ghidra 无头脚本的典型流程:
        Ghidra importAnalyzeHeadless → symbol recovery → call-site audit
      检测口径与真实 Ghidra 审计脚本一致:
        见危险堆操作调用点即告警 → 高召回高误报。

真实 Ghidra 适配: 若环境含 analyzeHeadless, 可替换为:
  analyzeHeadless project tmp -import <bin> -postScript <script>

CLI:
  python ghidra_headless.py <binary> [--json]
"""

import json
import sys
import time

from modules.vuln.detection.heap_analysis.insn_parser import (
    disassemble, parse_instructions, is_user_function)

_DANGEROUS = {
    'memcpy', 'memmove', 'memset', 'strcpy', 'strncpy', 'strcat',
    'sprintf', 'snprintf', 'gets', 'read', 'fread', 'recv',
    'malloc', 'calloc', 'realloc',
}


def audit(binary: str, timeout_s: int = 30) -> dict:
    t0 = time.time()
    asm = disassemble(binary, timeout_s)
    if not asm:
        return {'tool': 'ghidra', 'binary': binary, 'detected': False,
                'finding_count': 0, 'error': 'disassembly failed',
                'elapsed_sec': round(time.time() - t0, 3)}
    functions = parse_instructions(asm)
    sites = []
    for fn in functions:
        if not is_user_function(fn.name):
            continue
        for insn in fn.insns:
            if insn.mnemonic != 'call':
                continue
            op = insn.operands.lower()
            for d in _DANGEROUS:
                if d in op:
                    sites.append({'func': fn.name, 'addr': insn.addr,
                                  'callee': d})
                    break
    write_sites = [s for s in sites if s['callee'] not in
                   ('malloc', 'calloc', 'realloc')]
    return {
        'tool': 'ghidra', 'binary': binary,
        'detected': len(write_sites) > 0,
        'finding_count': len(write_sites),
        'sites': sites,
        'functions': len(functions),
        'elapsed_sec': round(time.time() - t0, 3),
    }


def main() -> None:
    binary = sys.argv[1] if len(sys.argv) > 1 else 'a.out'
    as_json = '--json' in sys.argv
    result = audit(binary)
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"ghidra: detected={result['detected']} "
              f"sites={result.get('finding_count', 0)} "
              f"elapsed={result['elapsed_sec']}s")


if __name__ == '__main__':
    main()
