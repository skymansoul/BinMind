"""UAF 基线候选提取器 — 朴素 free→use 扫描 (高 FP 基线).

  - 模拟无代际语义的朴素检测器: free 调用后, 对同一指针载体
    (槽/寄存器/全局) 的任何使用都报为 UAF 候选. 该基线故意不区分
    重赋值/置空, 用于量化 UAF-OG 的误报压缩效果.
  - 使用识别三类: 直接解引用 ([reg+off]), 槽加载传递 (mov reg,
    [slot]), 全局指针 (rip 相对身份).
  - 载体: 栈槽 (spill 稳定) 优先; 全局用 rip 偏移身份.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .gen_flow import GenFlowTracker, slot_name, _strip_ptr
from .uaf_base_helpers import (prev_alloc, src_alloc_origin,
                               slot_alloc_origin, global_alloc_source,
                               call_arg_sources)

_DEREF_RE = re.compile(r'\[([a-z0-9]+)', re.I)
_RIP_RE = re.compile(r'\[rip\+0x([0-9a-fA-F]+)\]', re.I)
_D32_OF = {'rax': 'eax', 'rbx': 'ebx', 'rcx': 'ecx', 'rdx': 'edx',
           'rsi': 'esi', 'rdi': 'edi', 'r8': 'r8d', 'r9': 'r9d'}
_ABS_RE = re.compile(r'#\s+(?:0x)?([0-9a-fA-F]{6,16})\b', re.I)
_REGS = ('rax', 'eax', 'rcx', 'ecx', 'rdx', 'edx', 'r8', 'r8d',
         'r9', 'r9d', 'rbx', 'ebx', 'rsi', 'esi', 'rdi', 'edi')


def _rip_identity(line: str) -> Optional[str]:
    """rip 相对读取的身份: 优先绝对地址注释, 回退 disp.

    disp 随指令位置漂移, 同一全局在 free/use 处的 disp 不同,
    必须用绝对地址归一."""
    am = _ABS_RE.search(line)
    if am:
        return f'ripabs:{am.group(1).lower()}'
    rm = _RIP_RE.search(line)
    if rm:
        return f'rip:{rm.group(1).lower()}'
    return None


@dataclass
class BaseFinding:
    free_line: int
    use_line: int
    free_reg: str = ''
    use_reg: str = ''
    use_slot: str = ''
    confidence: float = 0.5
    description: str = ''


class UafBaseScanner:
    """朴素 free→use 候选提取."""

    def __init__(self, abi: str = 'win64'):
        self._abi = abi

    def scan(self, instructions: List[str],
             addrs: Optional[List[int]] = None,
             user_range: Optional[Tuple[int, int]] = None,
             import_map: Optional[Dict[int, str]] = None) -> List[dict]:
        tracker = GenFlowTracker()
        if import_map:
            tracker.set_import_map(import_map)
        tracker.run(instructions, addrs)
        free_sites = []
        for ev in tracker.free_events():
            params = ev.args.get('params', {})
            free_reg = ev.args.get('free_reg', '')
            free_sites.append({'idx': ev.idx, 'reg': free_reg,
                               'params': params})

        findings = []
        crt_hi = 0x140003000 if user_range is None else None
        for fs in free_sites:
            fidx = fs['idx']
            if crt_hi is not None and \
                    addrs is not None and addrs[fidx] >= crt_hi:
                continue
            if user_range is not None and \
                    not (user_range[0] <= fidx < user_range[1]):
                continue
            freg = fs['reg']
            fslots = self._reg_sources(instructions, fidx, freg,
                                       import_map)
            for i in range(fidx + 1, min(fidx + 60, len(instructions))):
                if user_range is not None and \
                        not (user_range[0] <= i < user_range[1]):
                    break
                line = instructions[i]
                if line.strip().startswith('call'):
                    ca = call_arg_sources(self._reg_sources,
                                           instructions, i,
                                           fslots, import_map)
                    if ca:
                        hits = ca
                    else:
                        continue
                else:
                    if '[' not in line or ']' not in line:
                        continue
                    hits = self._use_identities(line)
                    # 寄存器基址扩展解析到槽身份 (mov eax,[rax] → rax 来源)
                    extra = set()
                    for h in hits:
                        if h.startswith('reg:'):
                            extra |= self._reg_sources(instructions, i,
                                                       h[4:], import_map)
                        elif h.startswith('ripabs:'):
                            alloc = global_alloc_source(
                                self._reg_sources, instructions, i,
                                h[7:], import_map)
                            if alloc:
                                extra.add(f'ret:{alloc[0]}@{alloc[1]}')
                    hits |= extra
                    if not (hits & fslots):
                        # 无解引用命中时尝试 call 参数型 use
                        ca = call_arg_sources(self._reg_sources,
                                               instructions, i,
                                               fslots, import_map)
                        if ca:
                            hits |= ca
                        else:
                            continue
                if hits & fslots:
                    findings.append({
                        'free_line': fidx, 'use_line': i,
                        'free_reg': freg,
                        'use_reg': self._use_reg(line),
                        'use_slot': next(iter(hits & fslots)),
                        'confidence': 0.5,
                        'description': (f'free@{fidx} use@{i} '
                                        f'共享 {hits & fslots}'),
                    })
        return findings

    def _use_identities(self, line: str) -> set:
        """一行的使用身份: 槽 / rip 全局 / 寄存器基址槽来源.

        栈槽赋值行 (mov [rbp-x], reg) 是指针变量自身的 kill, 非 use."""
        parts = line.split(None, 1)
        if len(parts) >= 2 and parts[0].lower() == 'mov' and \
                ',' in parts[1]:
            dst = _strip_ptr(parts[1].split(',', 1)[0].strip())
            if dst.startswith('['):
                sl = slot_name(dst)
                if sl:
                    return set()
        ids = set()
        m = _DEREF_RE.search(line)
        if m:
            base = m.group(1)
            if base in ('rbp', 'rsp'):
                sl = slot_name(line[line.index('['):line.index(']') + 1])
                if sl:
                    ids.add(sl)
                return ids
            if base in _REGS:
                ids.add(f'reg:{base}')
                return ids
        rm = _RIP_RE.search(line)
        if rm:
            rid = _rip_identity(line)
            if rid:
                ids.add(rid)
        return ids

    def _use_reg(self, line: str) -> str:
        parts = line.split(None, 1)
        if len(parts) < 2:
            return ''
        dst = parts[1].split(',', 1)[0].strip().split()[0]
        return dst if dst in _REGS else ''

    def _reg_sources(self, instructions: List[str], at: int,
                     reg: str, import_map=None) -> set:
        """reg 在 at 行前的定义来源身份集合 (沿 mov 直通链回溯).

        -O1 下指针由 callee-saved 寄存器持有, 无栈槽 spill;
        分配返回链 (mov rbx,rax ← call malloc) 以 ret:<func> 身份
        收录, 基于指令窗口位置敏感识别, 不依赖最终态."""
        ids = set()
        cur = reg
        for _hop in range(5):
            found = False
            for i in range(at - 1, max(0, at - 14) - 1, -1):
                line = instructions[i].strip()
                parts = line.split(None, 1)
                if len(parts) < 2:
                    continue
                mnem = parts[0].lower()
                if mnem not in ('mov', 'lea'):
                    continue
                dst = parts[1].split(',', 1)[0].strip()
                dst = _strip_ptr(dst)
                dst_reg = dst.split()[0]
                if dst_reg != cur:
                    # 32 位写零扩展高 32 位, 视为 64 位新定义
                    if _D32_OF.get(cur) == dst_reg:
                        found = True
                        break
                    continue
                if mnem == 'lea':
                    # lea 定义新值, 终止回溯
                    found = True
                    break
                src = _strip_ptr(parts[1].split(',', 1)[1].strip())
                sl = slot_name(src)
                if sl:
                    ids.add(sl)
                    alloc = slot_alloc_origin(self._reg_sources,
                                              instructions, i,
                                              sl, import_map)
                    if alloc:
                        ids.add(f'ret:{alloc[0]}@{alloc[1]}')
                    found = True
                    break
                rm = _RIP_RE.search(src)
                if rm:
                    rid = _rip_identity(line)
                    if rid:
                        ids.add(rid)
                    found = True
                    break
                src_reg = src.split()[0]
                if src_reg in _REGS:
                    if src_reg in ('rax', 'eax'):
                        alloc = prev_alloc(instructions, i,
                                           import_map)
                        if alloc:
                            ids.add(f'ret:{alloc[0]}@{alloc[1]}')
                            found = True
                            break
                    cur = src_reg
                    found = True
                    break
                # 非常量新定义 (imm/mem): 终止链, 不再回溯更早定义
                found = True
                break
            if not found:
                break
        return ids





