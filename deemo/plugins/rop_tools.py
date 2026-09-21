"""
ROP gadget finder and chain builder. Uses radare2 for gadget
discovery and scores chains by reliability and size.
"""

import logging
import os
import re
import subprocess
import time
from typing import Dict, List, Optional

from config import R2_PATH, SUBPROCESS_TIMEOUT

logger = logging.getLogger(__name__)

# gadget 搜索总预算: MSVC 静态 CRT 样本单次 /R 约 8s, 15 个 pattern
# 累计可达 120s; gadget 仅为利用建议的辅助情报, 不参与漏洞检测判定,
# 超预算即跳过剩余 pattern, 避免拖慢主流程.
ROP_SEARCH_BUDGET_S = 60

# Useful ROP gadgets. The "ret" instruction is implicit in all of them.
GADGET_PATTERNS = [
    # name              opcode pattern        description
    ('pop_rdi',         '5fc3',              'pop rdi'),
    ('pop_rsi',         '5ec3',              'pop rsi'),
    ('pop_rdx',         '5ac3',              'pop rdx'),
    ('pop_rcx',         '59c3',              'pop rcx'),
    ('pop_rax',         '58c3',              'pop rax'),
    ('pop_rbx',         '5bc3',              'pop rbx'),
    ('ret',             'c3',                'ret'),
    ('syscall',         '0f05',              'syscall'),
    ('int80',           'cd80',              'int 0x80'),
    ('mov_rax_rdi',     '4889f8',            'mov rax, rdi'),
    ('xchg_rax_rdi',    '4897',              'xchg rax, rdi'),
    ('push_rsp',        '54c3',              'push rsp'),
    ('leave',           'c9c3',              'leave'),
    ('pop_rbp',         '5dc3',              'pop rbp'),
    ('mov_rdi_rax',     '4889c7',            'mov rdi, rax'),
]


def find_gadgets(binary_path: str, arch: str = 'x86-64') -> List[Dict]:
    """
    Search binary for ROP gadgets using r2's /R command.
    """
    if not os.path.isfile(binary_path):
        return []

    cmd = [R2_PATH, '-q', '-e', 'io.color=false',
           '-c', '/R pop rdi;ret', binary_path]

    gadgets = []

    deadline = time.monotonic() + ROP_SEARCH_BUDGET_S

    for name, pattern, description in GADGET_PATTERNS:
        if time.monotonic() > deadline:
            logger.warning("ROP search budget %.0fs exhausted, skip remaining patterns",
                           ROP_SEARCH_BUDGET_S)
            break
        try:
            proc = subprocess.run(
                [R2_PATH, '-q', '-e', 'io.color=false',
                 '-c', f'/R {description}', binary_path],
                capture_output=True, text=True, timeout=30)
            raw = proc.stdout

            for line in raw.splitlines():
                line = line.strip()
                if not line or '0x' not in line:
                    continue
                addr_match = re.search(r'(0x[0-9a-fA-F]+)', line)
                if addr_match:
                    gadgets.append({
                        'type': name,
                        'description': description,
                        'address': addr_match.group(1),
                        'raw_line': line[:120],
                    })
        except Exception as err:
            logger.debug("Gadget search failed for %s: %s", name, err)

    return gadgets


def score_gadget(gadget: Dict) -> float:
    """Score a gadget 0-1 based on how clean/usable it is."""
    desc = gadget.get('description', '').lower()
    raw  = gadget.get('raw_line', '').lower()

    score = 0.5

    # simpler gadgets are better
    if 'pop' in desc:
        score += 0.2
    if 'mov' in raw or 'xchg' in raw:
        score += 0.1

    # penalties for side effects
    bad_ops = ('push', 'call', 'jmp', 'leave', 'xor', 'and', 'or',
               'sub', 'add', 'cmp', 'test')
    for op in bad_ops:
        if op in raw:
            score -= 0.05

    return max(0.0, min(1.0, score))


def build_chain(gadgets: List[Dict], target_type: str = 'execve') -> List[Dict]:
    """
    Build a minimal ROP chain for a common exploit goal (execve / mprotect).
    Returns ordered list of gadget dicts.
    """
    if target_type == 'execve':
        needed = ('pop_rdi', 'pop_rsi', 'pop_rdx', 'pop_rax', 'syscall')
    elif target_type == 'mprotect':
        needed = ('pop_rdi', 'pop_rsi', 'pop_rdx', 'pop_rax', 'syscall')
    else:
        needed = ('pop_rdi', 'syscall')

    by_type = {}
    for g in gadgets:
        t = g.get('type', '')
        by_type.setdefault(t, []).append(g)

    chain = []
    for nt in needed:
        if nt in by_type:
            candidates = sorted(by_type[nt], key=score_gadget, reverse=True)
            chain.append(candidates[0])

    return chain
