"""
分配器感知过滤 CLI — 从二进制或 IR 文本运行堆溢出误报抑制检测。

用法:
    python -m hfp.alloc_aware_scan binary.exe [--json out.json]
    python -m hfp.alloc_aware_scan ir_lines.txt [--json out.json]

二进制路径经 objdump 反汇编后归一化; 文本路径按行读取视为 IR。
输出 JSON 含 findings (三态) 与 stats。
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from .alloc_aware_engine import detect_heap_overflow_hfp, suppress_and_report
from .alloc_aware_verdict import Verdict


def disassemble(binary: str) -> List[str]:
    """objdump -d Intel 语法反汇编 → IR 行列表."""
    proc = subprocess.run(
        ['objdump', '-d', '-M', 'intel', binary],
        capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(f'objdump failed: {proc.stderr[:200]}')
    return _to_ir(proc.stdout)


def _to_ir(asm_text: str) -> List[str]:
    """反汇编文本 → 归一化指令行.

    保留 objdump 的 "地址: 字节\t助记符 操作数" 结构与
    "<函数名>:" 标签行 (供函数块分割), 过滤文件头与注释.
    """
    lines = []
    for line in asm_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(('.', '#', ';', '/')):
            continue
        if 'Disassembly of section' in stripped:
            continue
        if ':     file format' in stripped or ': file format' in stripped:
            continue
        lines.append(stripped)
    return lines


def asm_to_pseudo_ir(asm_text: str, abi: str = 'win64') -> List[str]:
    """反汇编文本 → 伪 IR (经寄存器数据流模拟)."""
    from .asm_translator import AsmTranslator
    lines = _to_ir(asm_text)
    return AsmTranslator(abi).translate(lines)


def run_scan(input_path: str, is_binary: bool) -> dict:
    if is_binary:
        asm_text = _disassemble_text(input_path)
        ir_lines = asm_to_pseudo_ir(asm_text)
    else:
        ir_lines = [l.rstrip() for l in
                    Path(input_path).read_text(encoding='utf-8', errors='replace')
                    .splitlines() if l.strip()]
    findings = detect_heap_overflow_hfp(ir_lines)
    kept, stats = suppress_and_report(findings)
    return {
        'input': input_path,
        'ir_lines': len(ir_lines),
        'stats': stats,
        'findings': [f.to_dict() for f in kept],
    }


def _disassemble_text(binary: str) -> str:
    """objdump -d Intel 语法反汇编 → 原始文本."""
    proc = subprocess.run(
        ['objdump', '-d', '-M', 'intel', binary],
        capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(f'objdump failed: {proc.stderr[:200]}')
    return proc.stdout


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description='分配器感知过滤 heap overflow scan')
    ap.add_argument('input', help='binary or IR text file')
    ap.add_argument('--json', help='output JSON path')
    ap.add_argument('--asm', action='store_true',
                    help='treat input as IR text (default: binary)')
    args = ap.parse_args(argv)

    is_binary = not args.asm
    result = run_scan(args.input, is_binary)
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2),
                                   encoding='utf-8')
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
