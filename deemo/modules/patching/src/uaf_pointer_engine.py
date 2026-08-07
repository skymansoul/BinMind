# UAF指针分析引擎 — 跨寄存器别名追踪 + 栈槽存储/加载链
"""UAF检测的轻量级指针分析引擎。

问题: uaf_analyzer.py 仅追踪简单mov链, 不同寄存器宽度(rax/eax/ax/al)
被当作不同寄存器, 指针存入栈槽后丢失。uaf_demand_driven.py 的
_reg_flows_to也仅做mov链, 无别名归一化。

本模块提供与heap_expr_tracker共享_相同设计模式的_指针值追踪:
  - 寄存器名归一化: rax/eax/ax/al → 同一物理寄存器
  - 栈槽存储/加载链: [rbp-0x8] ← mov [rbp-0x8], rax; mov rdi, [rbp-0x8]
  - 指针来源分类: ALLOC / STACK_SLOT / GLOBAL / PARAM / REALLOC
  - 堆对象身份: 区分malloc(ptr1)和malloc(ptr2) → 避免误匹配

参考: heap_expr_tracker._norm_reg / heap_expr_tracker._trace_stack_slot_store
       Undangle demand-driven pointer provenance
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum, auto


class PtrSourceKind(str, Enum):
    ALLOC = "alloc"         # 来自malloc/calloc/realloc返回
    STACK_SLOT = "stack"    # 来自栈槽加载
    GLOBAL = "global"       # 来自全局变量
    PARAM = "param"         # 来自函数参数
    UNKNOWN = "unknown"


@dataclass
class PtrValue:
    """指针值的追踪状态。"""
    kind: PtrSourceKind = PtrSourceKind.UNKNOWN
    source_line: int = -1       # 来源指令行
    alloc_func: str = ""        # malloc/calloc/realloc
    obj_id: int = -1            # 堆对象身份ID (来自同一malloc=同一对象)
    slot: str = ""              # 栈槽位置 "rbp-0x20"
    reg_name: str = ""          # 规范化寄存器名
    is_aliased: bool = False    # 是否有多个寄存器持有此指针
    alias_regs: Set[str] = field(default_factory=set)
    # 生命周期
    freed_at: int = -1          # free行号 (-1=未释放)
    freed_in_which_func: str = ""


# 寄存器名规范化 (同heap_expr_tracker共享设计模式)

_REG_NORM = {}
for _full, _subs in [
    ('rax', ['eax', 'ax', 'al', 'ah']),
    ('rcx', ['ecx', 'cx', 'cl', 'ch']),
    ('rdx', ['edx', 'dx', 'dl', 'dh']),
    ('rbx', ['ebx', 'bx', 'bl', 'bh']),
    ('rsp', ['esp', 'sp', 'spl']),
    ('rbp', ['ebp', 'bp', 'bpl']),
    ('rsi', ['esi', 'si', 'sil']),
    ('rdi', ['edi', 'di', 'dil']),
]:
    for _r in [_full] + _subs:
        _REG_NORM[_r] = _full
for _i in range(8, 16):
    _base = f'r{_i}'
    for _r in [_base, f'r{_i}d', f'r{_i}w', f'r{_i}b']:
        _REG_NORM[_r] = _base


def _norm(r: str) -> str:
    return _REG_NORM.get(r.lower(), r.lower())


def _same_reg(a: str, b: str) -> bool:
    return _norm(a) == _norm(b)


def _reg_aliases(reg: str) -> List[str]:
    """返回寄存器的所有别名 (不同宽度)。"""
    base = _norm(reg)
    result = [base]
    for k, v in _REG_NORM.items():
        if v == base and k != base:
            result.append(k)
    return result


# 指针值传播器

# alloc函数模式
_ALLOC_FUNCS = re.compile(
    r'\bcall\s+(?:[0-9a-f]+\s+<)?(malloc|calloc|realloc|_Znwm|_Znam|kmalloc)(?:@plt)?>?\b', re.I)
_FREE_FUNCS = re.compile(
    r'\bcall\s+(?:[0-9a-f]+\s+<)?(free|kfree|delete|_ZdlPv|_ZdaPv)(?:@plt)?>?\b', re.I)
# mov [stack], reg — 存储指针到栈
_STACK_STORE = re.compile(
    r'\bmov\s+(?:qword\s+ptr\s+|dword\s+ptr\s+)?'
    r'\[(rbp|rsp)\s*([+\-])\s*(0x[0-9a-f]+|\w+)\]\s*,?\s*(\w+)', re.I)
# mov reg, [stack] — 从栈加载指针
_STACK_LOAD = re.compile(
    r'\bmov\s+(\w+),?\s*(?:qword\s+ptr\s+|dword\s+ptr\s+)?'
    r'\[(rbp|rsp)\s*([+\-])\s*(0x[0-9a-f]+|\w+)\]', re.I)
# 解引用 (use): mov/cmp/... [reg+N]
_DEREF = re.compile(
    r'\b(mov|movzx|movsx|add|sub|cmp|test|and|or|xor)\s+'
    r'(?:\w+,\s*)?(?:qword|dword|word|byte)?\s*(?:ptr\s+)?'
    r'\[(\w+)([+\-]\s*(?:0x[0-9a-f]+|\d+))?\]', re.I)


class UafPointerEngine:
    """指针值跨寄存器/跨栈槽追踪引擎。

    核心能力:
      1. 追踪alloc返回值(rax)在各寄存器间的传播
      2. 追踪指针存入/加载栈槽的完整链
      3. 检测指针被free后仍被解引用的use点
      4. 区分不同堆对象: free(obj_A) + use(obj_B) ≠ UAF

    与heap_expr_tracker共享的设计模式:
      - 寄存器名归一化 (_norm / _same_reg)
      - 栈槽存储回溯 (scan window = 30行)
      - movsxd/movzx语义保留
    """

    def __init__(self, scan_window: int = 30):
        self._window = scan_window
        self._objects: List[PtrValue] = []
        self._obj_counter = 0
        self._func_ranges: List[Tuple[int, int, str]] = []
        self._crt_line_set: set = set()

# CRT过滤 (同uaf_demand_driven共享模式)

    _FUNC_LABEL = re.compile(r'^[0-9a-f]+\s+<([\w.@]+)>:\s*$', re.I)
    _CRT_FUNC = re.compile(
        r'(^_)|(^\.)|([Cc][Rr][Tt][Ss]tart|[Ss]tartup$|check_managed|duplicate_pp|'
        r'^atexit$|^safe_flush$|mark_section|pseudo_reloc|register_frame|'
        r'^wcsnlen$|^strnlen$|^wcrtomb$|^mbrtowc$|^bitstob$|^dtoa_|'
        r'^init_fpreg|^fallback_)', re.I)

    def _build_func_map(self, asm: List[str]) -> None:
        """扫描函数标签, 标记CRT vs 用户函数边界。"""
        labels: List[Tuple[int, str]] = []
        for i, line in enumerate(asm):
            m = self._FUNC_LABEL.match(line.strip())
            if m:
                labels.append((i, m.group(1)))
        self._func_ranges = []
        self._crt_line_set = set()
        for idx, (start, name) in enumerate(labels):
            end = labels[idx + 1][0] if idx + 1 < len(labels) else len(asm)
            self._func_ranges.append((start, end, name))
            if self._CRT_FUNC.search(name):
                for ln in range(start, end):
                    self._crt_line_set.add(ln)

    def _in_user_code(self, line: int) -> bool:
        if not self._func_ranges:
            return True
        return line not in self._crt_line_set

    def trace_forward(self, asm_lines: List[str]) -> List[PtrValue]:
        """前向扫描用户代码, 追踪所有指针对象的生命周期。"""
        # 构建函数边界, 过滤CRT噪音
        self._build_func_map(asm_lines)
        lowered = [l.strip().lower().replace(',', ' ') for l in asm_lines]
        objects: List[PtrValue] = []
        # reg_map: 规范化寄存器名 → 当前持有的PtrValue
        reg_map: Dict[str, PtrValue] = {}
        # slot_map: 栈槽标识 → 当前存储的PtrValue
        slot_map: Dict[str, PtrValue] = {}
        obj_id = 0

        for i, l in enumerate(lowered):
            # 跳过CRT代码行
            if not self._in_user_code(i):
                continue

# malloc/calloc/realloc → 创建新对象
            am = _ALLOC_FUNCS.search(l)
            if am:
                pv = PtrValue(kind=PtrSourceKind.ALLOC, source_line=i,
                              alloc_func=am.group(1).lower(), obj_id=obj_id)
                obj_id += 1
                objects.append(pv)
                reg_map['rax'] = pv
                pv.alias_regs.add('rax')
                continue

# free → 标记已释放
            fm = _FREE_FUNCS.search(l)
            if fm:
                free_reg = self._find_arg_reg(lowered, i, 0)
                if free_reg:
                    n = _norm(free_reg)
                    if n in reg_map:
                        reg_map[n].freed_at = i
                continue

# 指针移动: mov dst, src
            mm = re.search(r'\bmov\s+(\w+),?\s*(\w+)', l)
            if mm and not re.search(r'\[', l):
                dst, src = mm.group(1), mm.group(2)
                nd, ns = _norm(dst), _norm(src)
                if nd in ('rbp', 'rsp', 'rip'):
                    continue
                if ns in reg_map and nd not in ('rbp', 'rsp', 'rip'):
                    reg_map[nd] = reg_map[ns]
                    reg_map[nd].alias_regs.add(_norm(dst))
                continue

# movsxd dst, src (符号扩展, 指针语义保留)
            mm = re.search(r'\bmovsxd\s+(\w+),?\s*(\w+)', l)
            if mm:
                dst, src = mm.group(1), mm.group(2)
                nd, ns = _norm(dst), _norm(src)
                if ns in reg_map:
                    reg_map[nd] = reg_map[ns]
                    reg_map[nd].alias_regs.add(_norm(dst))
                continue

# 栈存储: mov [rbp-N], reg
            sm = _STACK_STORE.search(l)
            if sm:
                base, sign, off, src_reg = sm.group(1), sm.group(2), sm.group(3), sm.group(4)
                slot = f'{base}{sign}{off}'
                ns = _norm(src_reg)
                if ns in reg_map:
                    slot_map[slot] = reg_map[ns]
                continue

# 栈加载: mov reg, [rbp-N]
            lm = _STACK_LOAD.search(l)
            if lm:
                dst_reg = lm.group(1)
                slot = f'{lm.group(2)}{lm.group(3)}{lm.group(4)}'
                nd = _norm(dst_reg)
                if slot in slot_map and nd not in ('rbp', 'rsp', 'rip'):
                    reg_map[nd] = slot_map[slot]
                    reg_map[nd].alias_regs.add(_norm(dst_reg))
                continue

# lea reg, [rbp ± N] → 栈变量地址(非堆指针, 但记录)
            mm = re.search(r'\blea\s+(\w+),?\s*\[(rbp|rsp)\s*([+\-])\s*(0x[0-9a-f]+|\w+)\]', l)
            if mm:
                dst, slot = mm.group(1), f'{mm.group(2)}{mm.group(3)}{mm.group(4)}'
                nd = _norm(dst)
                if nd not in ('rbp', 'rsp', 'rip'):
                    pv = PtrValue(kind=PtrSourceKind.STACK_SLOT, source_line=i,
                                  slot=slot, obj_id=-1)
                    reg_map[nd] = pv
                    pv.alias_regs.add(nd)
                continue

# 全局加载: mov reg, [rip+...]
            mm = re.search(r'\bmov\s+(\w+),?\s*(?:qword\s+ptr\s+)?\[rip[+\-]\s*\w+\]', l)
            if mm:
                dst = mm.group(1)
                nd = _norm(dst)
                if nd not in ('rbp', 'rsp', 'rip'):
                    pv = PtrValue(kind=PtrSourceKind.GLOBAL, source_line=i, obj_id=-1)
                    reg_map[nd] = pv
                    pv.alias_regs.add(nd)
                continue

        self._objects = objects
        return objects

    def find_uaf_in_forward(self, asm_lines: List[str],
                             objects: List[PtrValue]) -> List[Tuple[int, int, str]]:
        """在前向扫描结果中检测 free后的use (UAF)。

        对每个已标记freed_at的对象, 扫描后续指令是否通过其别名寄存器解引用。
        返回: [(free_line, use_line, reason), ...]
        """
        lowered = [l.strip().lower().replace(',', ' ') for l in asm_lines]
        uaf_findings = []

        for obj in objects:
            if obj.freed_at < 0:
                continue
            aliases = obj.alias_regs
            if not aliases:
                aliases = {obj.reg_name}
            for i in range(obj.freed_at + 1, len(lowered)):
                # 跳过CRT代码行
                if not self._in_user_code(i):
                    continue
                dm = _DEREF.search(lowered[i])
                if dm:
                    accessed_reg = dm.group(2)
                    if _norm(accessed_reg) in {_norm(a) for a in aliases}:
                        uaf_findings.append((
                            obj.freed_at, i,
                            f'UAF: obj#{obj.obj_id} ({obj.alloc_func}@line{obj.source_line}) '
                            f'free@line{obj.freed_at} → deref {accessed_reg}@line{i}'
                        ))
        return uaf_findings

    @staticmethod
    def _find_arg_reg(lowered: List[str], call_idx: int, arg_pos: int) -> Optional[str]:
        """找函数调用前设置的参数寄存器。arg_pos=0→第1参数(rdi/rcx)。"""
        param_regs = [['rdi', 'rcx'], ['rsi', 'rdx'], ['rdx', 'r8'], ['rcx', 'r9']]
        regs = param_regs[arg_pos] if arg_pos < len(param_regs) else param_regs[-1]
        for j in range(call_idx - 1, max(call_idx - 6, -1), -1):
            for reg in regs:
                m = re.search(r'\bmov\s+' + reg + r',?\s*(\w+)', lowered[j])
                if m and not re.search(r'\[', lowered[j]):
                    return m.group(1)
        return None
