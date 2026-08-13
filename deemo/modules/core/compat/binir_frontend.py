# -*- coding: utf-8 -*-
"""真实二进制 IR 前端 - objdump 反汇编 + 寄存器/栈槽级数据流."""

import os
from typing import Dict, List, Optional

from modules.core.compat.binir_disasm import BinIR, disassemble
from modules.core.compat.binir_imports import parse_imports
from modules.core.compat.binir_dataflow import build_ir, RegFlow
from modules.core.compat.binir_candidates import extract_candidates


def analyze_binary(elf_path: str) -> BinIR:
    """对外主入口: 反汇编 -> 导入表解析 -> IR -> 候选."""
    funcs = disassemble(elf_path)
    import_map = parse_imports(elf_path)
    ir = build_ir(funcs, import_map)
    ir.sample_id = _sample_id(elf_path)
    extract_candidates(ir)
    return ir


def _sample_id(elf_path: str) -> str:
    base = os.path.basename(elf_path)
    for ext in ('.exe', '.elf', '.bin'):
        if base.lower().endswith(ext):
            return base[:-len(ext)]
    return base
