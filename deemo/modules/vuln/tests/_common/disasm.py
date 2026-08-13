"""objdump 反汇编文本解析 — 指令流/地址/函数标签.

回归与基准脚本共用. 标签行格式 'addr <name>:' 与指令行
'addr: bytes mnem ops' 并存, 按正则区分.
"""

import re
import subprocess
from typing import List, Optional, Tuple


def disassemble(bin_path: str) -> str:
    for tool in ('objdump', 'llvm-objdump'):
        try:
            proc = subprocess.run([tool, '-d', '-M', 'intel', bin_path],
                                  capture_output=True, text=True, timeout=30)
            if proc.returncode == 0 and len(proc.stdout) > 100:
                return proc.stdout
        except Exception:
            continue
    return ''


def parse_asm(asm: str) -> Tuple[List[str], List[int], List[Tuple[str, int]]]:
    """返回 (指令行, 地址, [(函数名, 行索引)])."""
    lines, addrs, labels = [], [], []
    for raw in asm.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.strip().startswith('.'):
            continue
        lm = re.match(r'^\s*([0-9a-f]+)\s+<([^>]+)>:', line)
        if lm:
            labels.append((lm.group(2).split('+')[0].split('@')[0],
                           len(lines)))
            continue
        m = re.match(r'^\s*([0-9a-f]+):', line)
        addr = int(m.group(1), 16) if m else 0
        body = line[m.end():] if m else line
        if 'file format' in body or 'Disassembly' in body:
            continue
        if '\t' in body:
            segs = [s for s in body.split('\t') if s.strip()]
            if not segs:
                continue
            insn = segs[-1].strip()
        else:
            toks = body.split()
            if not toks:
                continue
            i = 0
            while i < len(toks) and re.fullmatch(r'[0-9a-f]{2}', toks[i]):
                i += 1
            if i >= len(toks):
                continue
            insn = ' '.join(toks[i:])
        if not insn or insn.startswith(';') or insn.startswith('.'):
            continue
        lines.append(insn)
        addrs.append(addr)
    return lines, addrs, labels


def main_range(labels: List[Tuple[str, int]], n_lines: int) -> Optional[Tuple[int, int]]:
    """main 函数区间 (行索引半开区间), 用于过滤 CRT 噪声."""
    for i, (name, idx) in enumerate(labels):
        if name == 'main':
            end = labels[i + 1][1] if i + 1 < len(labels) else n_lines
            return (idx, end)
    return None


def range_from_addr(addrs: List[int], main_addr: int,
                    span: int = 120) -> Optional[Tuple[int, int]]:
    """按 main 起始地址构造用户区间 (stripped 无标签时的回退).

    strip 不重排布局, 编译时记录的 main 地址在去符号后仍有效.
    span 覆盖 main 函数体 (O1 下约 40-70 行), 保守取 120."""
    for i, a in enumerate(addrs):
        if a == main_addr:
            return (i, min(i + span, len(addrs)))
    return None
