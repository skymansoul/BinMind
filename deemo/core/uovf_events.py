"""
UOVF 事件提取与别名分组.

从源码行解析 分配/释放/置空/重赋值/别名/调用 事件, 建立别名组,
并沿事件序列生成 free→use 事件链. 只负责提取, 判定由
uovf_verifier 依据值流门控完成.

互操作近似: 函数体内 `free(全局或参数)` 注册到函数名, 调用点
在 pc 处应用其释放效果, 覆盖跨函数全局 UAF (tp_03 类).
"""

import re
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from core.uovf_types import EventKind, PtrEvent, UafChain
from core.hovf_write_extract import _strip_block_comments

_FREE_RE = re.compile(r'\bfree\s*\(\s*([^()]+?)\s*\)')
_ALLOC_RE = re.compile(
    r'(\w+(?:\.\w+)?)\s*=\s*\((?:[^)]*)\)?\s*'
    r'(malloc|calloc|realloc)\s*\(')
_ASGN_RE = re.compile(r'(\w+(?:\.\w+)?)\s*=\s*([^;]+)')
_NULL_RE = re.compile(r'(\w+(?:\.\w+)?)\s*=\s*(NULL|0)\s*;?$')
_CALL_RE = re.compile(r'\b([a-z_]\w*)\s*\(')
_DEREF_USE = re.compile(r'\b(\w+)\s*(?:->|\[)|[*&]\s*(\w+)')
_STRUCT_ACC = re.compile(r'(\w+)\s*->\s*(\w+)')

_DANGER_USE = frozenset((
    'printf', 'fprintf', 'sprintf', 'snprintf', 'memcpy', 'memset',
    'memmove', 'strcpy', 'strncpy', 'strcat', 'strlen', 'strcmp',
    'free', 'realloc', 'puts', 'write', 'read', 'recv', 'send',
))


_KEYWORDS = frozenset((
    'char', 'int', 'long', 'short', 'unsigned', 'signed', 'void',
    'float', 'double', 'struct', 'typedef', 'enum', 'static',
    'const', 'volatile', 'return', 'if', 'else', 'while', 'for',
    'switch', 'case', 'break', 'continue', 'goto', 'sizeof',
    'NULL', 'size_t', 'ssize_t', 'int8_t', 'int16_t', 'int32_t',
    'int64_t', 'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
    'bool', 'true', 'false', 'main', 'stdin', 'stdout', 'stderr',
))


def _operands_in(line: str) -> List[str]:
    """提取行内引用的操作数.

    返回值含 简单变量 与 base.field 伪变量. 剔除关键字与类型名;
    字符串字面量内的标识符用行内去引号预处理规避.
    """
    # 去除字符串与字符字面量, 避免误取字面内容
    cleaned = re.sub(r'"(?:[^"\\]|\\.)*"', '""', line)
    cleaned = re.sub(r"'(?:[^'\\]|\\.)*'", "''", cleaned)
    ops = []
    for m in _STRUCT_ACC.finditer(cleaned):
        ops.append(f'{m.group(1)}.{m.group(2)}')
    for m in re.finditer(r'\b([a-z_]\w*)\b', cleaned):
        w = m.group(1)
        if w in _KEYWORDS or w in _DANGER_USE:
            continue
        if w not in ops:
            ops.append(w)
    return ops


def _direct_operand(arg: str) -> Optional[str]:
    """free 参数的直接操作数.

    `free(obj->data)` 释放的是 obj.data 字段而非 obj 本身, 只取
    结构体访问伪变量或裸标识符, 避免把外层指针误判为悬垂.
    """
    arg = arg.strip()
    m = _STRUCT_ACC.search(arg)
    if m:
        return f'{m.group(1)}.{m.group(2)}'
    if re.fullmatch(r'[a-z_]\w*', arg):
        return arg
    return None


def _free_registry(ir: List[str]) -> Dict[str, Set[str]]:
    """函数名 → 函数体内被 free 的操作数集合.

    跨函数 UAF 的关键近似: 调用 free_buf() 等价于在该调用点对
    其体内 free 的全局/参数执行释放.
    """
    registry: Dict[str, Set[str]] = defaultdict(set)
    current_func = ''
    brace_depth = 0
    sig_re = re.compile(r'^[A-Za-z_][\w \*]*\s*(\w+)\s*\([^)]*\)\s*\{')
    for line in ir:
        m = sig_re.match(line)
        if m:
            current_func = m.group(1)
            brace_depth = line.count('{') - line.count('}')
            continue
        if not current_func:
            continue
        fm = _FREE_RE.search(line)
        if fm:
            op = _direct_operand(fm.group(1))
            if op:
                registry[current_func].add(op)
        brace_depth += line.count('{') - line.count('}')
        if brace_depth <= 0 and '{' in line and '}' in line:
            current_func = ''
    return registry


def _pointer_params(ir: List[str]) -> Set[str]:
    """函数签名中的指针形参名.

    形参在调用处与调用者堆对象别名, 参与别名组, 否则跨函数
    悬垂 (loop_uaf 的 head) 无法关联.
    """
    params: Set[str] = set()
    sig_re = re.compile(
        r'^[A-Za-z_][\w \*]*\b(\w+)\s*\(([^)]*)\)\s*\{')
    for line in ir:
        m = sig_re.match(line.strip())
        if not m:
            continue
        for pm in re.finditer(r'\*\s*(\w+)', m.group(2)):
            params.add(pm.group(1))
    return params


def extract_uovf_events(ir: List[str]) -> Tuple[
        List[PtrEvent], Dict[str, Set[str]], Dict[str, Set[str]]]:
    """提取事件序列与别名组.

    返回 (事件列表按 pc 升序, 别名组 {operand: 组成员}, 释放注册表).
    """
    ir = _strip_block_comments(list(ir))
    registry = _free_registry(ir)
    params = _pointer_params(ir)
    events: List[PtrEvent] = []
    aliases: Dict[str, Set[str]] = {}
    heap_vars: Set[str] = set()

    def group_of(op: str) -> Set[str]:
        return aliases.setdefault(op, {op})

    def join(a: str, b: str) -> None:
        ga, gb = group_of(a), group_of(b)
        merged = ga | gb
        for m in merged:
            aliases[m] = merged

    def is_ptr_like(name: str) -> bool:
        return name in heap_vars or name in aliases or name in params

    for pc, line in enumerate(ir):
        if not line.strip() or line.lstrip().startswith(('#', '//')):
            continue
        fm = _FREE_RE.search(line)
        if fm:
            op = _direct_operand(fm.group(1))
            if op:
                events.append(PtrEvent(EventKind.FREE, op, pc, line))
            continue
        am = _ALLOC_RE.search(line)
        if am:
            lhs = am.group(1)
            kind = am.group(2).lower()
            if kind == 'realloc':
                old = am.group(1)
                events.append(PtrEvent(EventKind.FREE, old, pc, line))
            events.append(PtrEvent(EventKind.REASSIGN, lhs, pc, line))
            heap_vars.add(lhs)
            continue
        nm = _NULL_RE.search(line)
        if nm:
            events.append(PtrEvent(EventKind.NULLIFY, nm.group(1), pc, line))
            continue
        asm = _ASGN_RE.search(line)
        if asm:
            lhs, rhs = asm.group(1), asm.group(2).strip()
            # 字段写入 obj->field = v 是对 obj 的解引用, 不是堆变量重赋值
            f_acc = re.search(r'(\w+)\s*->\s*' + re.escape(lhs), line)
            if f_acc:
                base = f_acc.group(1)
                if is_ptr_like(base):
                    events.append(PtrEvent(EventKind.USE, base, pc, line))
                continue
            if re.fullmatch(r'[a-z_]\w*', rhs):
                if is_ptr_like(rhs):
                    join(lhs, rhs)
                    events.append(PtrEvent(EventKind.ALLOC, lhs, pc, line))
                    heap_vars.add(lhs)
                    continue
            events.append(PtrEvent(EventKind.REASSIGN, lhs, pc, line))
            continue
        cm = _CALL_RE.search(line)
        if cm and cm.group(1) not in ('if', 'while', 'for', 'switch',
                                      'sizeof', 'return'):
            fname = cm.group(1)
            if fname in registry:
                for op in registry[fname]:
                    events.append(PtrEvent(EventKind.FREE, op, pc, line))
        ops = _operands_in(line)
        for op in ops:
            if is_ptr_like(op):
                events.append(PtrEvent(EventKind.USE, op, pc, line))
    # TODO: 线程/回调路径 UAF 未覆盖, 事件序为单线程假设
    return events, aliases, registry


def build_chains(events: List[PtrEvent],
                 aliases: Dict[str, Set[str]]) -> List[UafChain]:
    """沿事件序列生成 free→use 链.

    状态按别名组维护: FREE 使整组悬垂; REASSIGN 只使自身复活;
    NULLIFY 只使自身置空. 悬垂组内任一 USE 生成一条链.
    """
    dangling: Dict[str, int] = {}
    chains: List[UafChain] = []

    def group(op: str) -> Set[str]:
        return aliases.get(op, {op})

    for ev in events:
        op = ev.operand
        if ev.kind == EventKind.FREE:
            for m in group(op):
                dangling[m] = ev.pc
        elif ev.kind in (EventKind.REASSIGN, EventKind.NULLIFY):
            dangling.pop(op, None)
        elif ev.kind == EventKind.USE:
            if op in dangling:
                chains.append(UafChain(
                    operand=op, free_pc=dangling[op], use_pc=ev.pc,
                    free_line='', use_line=ev.detail))
    return chains
