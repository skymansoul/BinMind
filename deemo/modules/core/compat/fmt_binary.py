# -*- coding: utf-8 -*-
"""二进制级格式化字符串检测 — 基于 binir 前端的 printf 族调用解析.

误报根源: 把用户可控的格式串误判为常量, 或把常量串中的 %n 写说明符
忽略. 本模块:
  1. 定位 printf/sprintf/snprintf/fprintf 族调用点与格式串参数
  2. 解析格式串指针谱系: rip 相对全局常量 / 函数参数 / 未知
  3. 常量串读取 .rdata 内容, 检查 %n 系写说明符
  4. 分类: 参数来源 → 用户可控格式串 (CWE-134); 常量含 %n → 写漏洞;
     常量无 %n → 安全

判定保守: 参数来源格式串一律报告; %n 写说明符独立于是否可控.
"""

import os, re, subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from modules.core.compat.binir_common import (
    _MEM_TOKEN, is_imm, regs_in, slot_in, split_operands)
from modules.core.compat.binir_disasm import BinIR

# 格式串参数序号 (1-based) 与输出缓冲参数序号 (0=无)
# 函数名经 binir norm_name 归一化 (前导下划线已剥除)
_FMT_FUNCS = {
    'printf': (1, 0), 'vprintf': (1, 0),
    'sprintf': (2, 1), 'fprintf': (2, 0), 'vfprintf': (2, 0),
    'snprintf': (3, 1), 'vsnprintf': (3, 1),
    'mingw_printf': (1, 0), 'mingw_snprintf': (3, 1),
    'mingw_vfprintf': (2, 0),
}

_WRITE_SPEC = re.compile(r'%[-+ #0-9.*]*(\d+\$)?[hlLjzt]*n\b')
_DANGEROUS_SPEC = re.compile(r'%[sS]')

_SECTION = re.compile(
    r'^\s*\d+\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)')

_SECTION_CACHE: Dict[str, List[Tuple[int, int, int]]] = {}


@dataclass
class FmtFinding:
    """单个格式串候选."""
    site: int
    func: str
    fmt_kind: str            # 'external' | 'constant' | 'unknown'
    write_spec: bool         # 含 %n 写说明符
    dangerous: bool
    func_name: str
    detail: str = ''


def analyze_fmt_binary(ir: BinIR, elf_path: str) -> List[FmtFinding]:
    """对单个二进制的 IR 执行格式串检测."""
    findings: List[FmtFinding] = []
    func_insns: Dict[str, List[Dict]] = {}
    for insn in ir.instructions:
        fname = ir.func_of.get(insn['addr'], '')
        if fname:
            func_insns.setdefault(fname, []).append(insn)

    for fname, insns in func_insns.items():
        for site in insns:
            if site['mnemonic'] != 'call':
                continue
            callee = ir.callee_names.get(site['addr'], '')
            fmt_args = _FMT_FUNCS.get(callee)
            if fmt_args is None:
                continue
            fmt_idx, _buf_idx = fmt_args
            fmt_reg = ir.arg_regs[fmt_idx - 1]
            lineage = _fmt_lineage(insns, fmt_reg, site['addr'])
            kind, target = lineage

            write_spec = False
            if kind == 'constant':
                s = _read_string(elf_path, target)
                write_spec = bool(s and _WRITE_SPEC.search(s))
                dangerous = write_spec
            elif kind == 'external':
                dangerous = True
            else:
                dangerous = False

            findings.append(FmtFinding(
                site=site['addr'], func=fname, fmt_kind=kind,
                write_spec=write_spec, dangerous=dangerous,
                func_name=callee,
                detail=_detail(kind, target, write_spec)))
    return findings


def _fmt_lineage(insns: List[Dict], reg: str,
                 boundary: int) -> Tuple[str, int]:
    """解析格式串指针谱系: ('constant', 目标地址) / ('external') / ('unknown').

    沿 mov/lea 链回溯: 命中 rip 相对全局装载或 lea 到常量 → constant;
    链终止于函数参数 (无定义) → external; 其余 → unknown.
    """
    target = reg
    limit = boundary
    for _ in range(8):
        found = None
        for insn in insns:
            if insn['addr'] >= limit:
                break
            ops = split_operands(insn['op_str'])
            if not ops:
                continue
            dst = regs_in(ops[0]) if ops and '[' not in ops[0] else []
            if target in dst:
                found = insn
        if found is None:
            return ('external', 0)
        mn = found['mnemonic']
        ops = split_operands(found['op_str'])
        if mn.startswith('lea') or mn.startswith('mov'):
            m = re.search(r'#\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+)\b',
                          found.get('comment', ''))
            if m and ('rip' in found.get('op_str', '').lower()
                      or '[' in found.get('op_str', '')):
                return ('constant', int(m.group(1), 16))
            if len(ops) >= 2:
                src_op = ops[-1]
                if is_imm(src_op) is not None:
                    return ('unknown', 0)
                src_reg = regs_in(src_op)
                if src_reg:
                    target = src_reg[0]
                    limit = found['addr']
                    continue
                return ('unknown', 0)
        return ('unknown', 0)
    return ('unknown', 0)


def _read_string(elf_path: str, target: int) -> Optional[str]:
    """从二进制初始化数据节读取 NUL 结尾字符串."""
    sections = _get_sections(elf_path)
    if not sections:
        return None
    try:
        with open(elf_path, 'rb') as f:
            raw = f.read()
    except OSError:
        return None
    for vma, size, off in sections:
        if vma <= target < vma + size:
            filepos = off + (target - vma)
            end = raw.find(b'\x00', filepos, filepos + 256)
            if end < 0:
                end = min(filepos + 256, len(raw))
            data = raw[filepos:end]
            try:
                return data.decode('utf-8', errors='replace')
            except Exception:
                return None
    return None


def _get_sections(elf_path: str) -> List[Tuple[int, int, int]]:
    key = os.path.abspath(elf_path)
    if key in _SECTION_CACHE:
        return _SECTION_CACHE[key]
    sections: List[Tuple[int, int, int]] = []
    try:
        r = subprocess.run(['objdump', '-h', elf_path],
                           capture_output=True, text=True, timeout=30)
        out = r.stdout if r.returncode == 0 else ''
    except Exception:
        out = ''
    for line in out.splitlines():
        m = _SECTION.match(line.strip())
        if m:
            name, size_s, vma_s, off_s = m.groups()
            sections.append((int(vma_s, 16), int(size_s, 16),
                             int(off_s, 16)))
    _SECTION_CACHE[key] = sections
    return sections


def _detail(kind: str, target: int, write_spec: bool) -> str:
    if kind == 'constant':
        s = f'常量格式串 @0x{target:x}'
        if write_spec:
            s += ' (含 %n 写说明符)'
        return s
    if kind == 'external':
        return '格式串源自函数参数/外部输入'
    return '格式串来源未知'


def summarize(findings: List[FmtFinding]) -> Dict[str, Any]:
    """汇总统计."""
    by_kind: Dict[str, int] = {}
    n_danger = 0
    for f in findings:
        by_kind[f.fmt_kind] = by_kind.get(f.fmt_kind, 0) + 1
        if f.dangerous:
            n_danger += 1
    return {
        'total': len(findings),
        'by_kind': by_kind,
        'dangerous': n_danger,
        'detail': [
            {'site': hex(f.site), 'func': f.func_name, 'fmt_kind': f.fmt_kind,
             'write_spec': f.write_spec, 'dangerous': f.dangerous,
             'detail': f.detail}
            for f in findings
        ],
    }
