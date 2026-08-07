# coding: utf-8
"""双侧大小可控性分类 — alloc_size 与 write_size 的来源可控性分离判定.

误报根因: 溢出两侧大小均来自内部常量/全局数据时, 溢出不可被攻击者
触发或控制, 现有工具仍将其当作可利用候选. 本模块沿 def-use 链反向
追踪 alloc 与 write 大小的来源, 各自分类为
  CONSTANT  (立即数)
  INTERNAL  (全局数据 / 内部复制产物)
  EXTERNAL  (read/recv/fgets/scanf 等外部输入函数)
  UNKNOWN   (超深或不可达)
随后按四象限严重度矩阵降权或剔除.

设计: 不做完整污点传播, 只对两个 size 变量做定向回溯 (BFS, 有界),
将可控性作为独立维度与 VCT/守卫证明正交组合.
"""

from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

# 与 taint_enhanced_heap 一致的外部输入函数表
_INPUT_FUNCS = {'read', 'fread', 'recv', 'recvfrom', 'recvmsg', 'fgets',
                'gets', 'scanf', 'fscanf', 'getc', 'fgetc', 'readfile',
                'readconsole'}
_INTERNAL_FUNCS = {'memcpy', 'memmove', 'memset', 'strcpy', 'strncpy',
                   'strcat', 'strncat', 'sprintf', 'snprintf'}
_TAINT_PROXY = {'read', 'fread', 'recv', 'recvfrom', 'fgets', 'gets',
                'scanf', 'fscanf', 'getc', 'fgetc'}


class Controllability(Enum):
    CONSTANT = auto()
    INTERNAL = auto()
    EXTERNAL = auto()
    UNKNOWN = auto()


@dataclass
class SizeProvenance:
    """单个 size 变量的来源判定结果."""
    var: str
    level: Controllability
    source: str            # 来源描述
    depth: int = 0
    path: List[int] = field(default_factory=list)


def classify_size(var: str, def_addr: Optional[int],
                  def_use: Dict[int, List[int]],
                  ir_ops: Dict[int, Dict],
                  callee_names: Optional[Dict[int, str]] = None,
                  max_depth: int = 12) -> SizeProvenance:
    # TODO: 跨函数参数溯源需调用图; 当前仅在函数内展开, 参数恒为 UNKNOWN
    """沿 def-use 链反向分类 size 变量的可控性.

    叶子组合语义: 值完全由立即数构成才为 CONSTANT; 任一叶子为函数参数
    (无定义源) 则 UNKNOWN; 命中外部输入函数则 EXTERNAL. 链上出现常量
    上限 (min-cap) 不改变分类, 因为整体值仍依赖变量.
    """
    callee_names = callee_names or {}
    start = def_addr
    leaves: Set[Controllability] = set()
    external = False
    visited: Set[int] = set()
    q = deque([(start, 0)])

    while q:
        addr, depth = q.popleft()
        if addr is None:
            continue
        if depth > max_depth or addr in visited:
            continue
        visited.add(addr)
        op = ir_ops.get(addr, {})
        op_type = op.get('op_type', '')

        callee = (callee_names.get(addr) or op.get('callee', '') or '').lower()
        if any(f in callee for f in _INPUT_FUNCS):
            external = True
            continue
        # 无显式长度写入: 长度取决于源字符串, 静态无法界定
        if any(f in callee for f in ('strcpy', 'strcat', 'sprintf')):
            leaves.add(Controllability.UNKNOWN)
            continue
        if any(f in callee for f in _INTERNAL_FUNCS):
            leaves.add(Controllability.INTERNAL)
            continue
        # RIP 相对全局数据读取 → INTERNAL
        src = op.get('src', '')
        if isinstance(src, str) and src.startswith('rip'):
            leaves.add(Controllability.INTERNAL)
            continue
        # 纯赋值指令的立即数 → CONSTANT 叶子
        if op_type in ('mov', 'li', 'const', 'load_imm', 'assign', 'cast'):
            if op.get('imm') is not None:
                leaves.add(Controllability.CONSTANT)
                continue
            if isinstance(src, str) and src:
                s = src.lstrip('-')
                if s.startswith(('0x', '0X')) or s.isdigit():
                    leaves.add(Controllability.CONSTANT)
                    continue
        srcs = def_use.get(addr, [])
        if not srcs:
            # 无定义源: 函数参数或不可追踪 → 可能受攻击者影响
            leaves.add(Controllability.UNKNOWN)
        for s in srcs:
            q.append((s, depth + 1))

    if external:
        return SizeProvenance(var, Controllability.EXTERNAL,
                              '外部输入', len(visited))
    if Controllability.UNKNOWN in leaves:
        return SizeProvenance(var, Controllability.UNKNOWN,
                              f'含参数/不可溯源节点 ({len(visited)} 节点)',
                              len(visited))
    if Controllability.INTERNAL in leaves:
        return SizeProvenance(var, Controllability.INTERNAL,
                              '内部数据 (全局/复制)', len(visited))
    if leaves and all(l == Controllability.CONSTANT for l in leaves):
        return SizeProvenance(var, Controllability.CONSTANT,
                              '立即数常量', len(visited))
    return SizeProvenance(var, Controllability.UNKNOWN,
                          f'未在 {max_depth} 步内溯源', len(visited))


def classify_candidate(candidate: Dict, def_use: Dict[int, List[int]],
                       ir_ops: Dict[int, Dict],
                       callee_names: Optional[Dict[int, str]] = None,
                       ) -> Dict[str, Any]:
    """对候选的 alloc/write 双侧做可控性分类并计算严重度."""
    a = classify_size(candidate.get('alloc_size_var', 'size'),
                      candidate.get('alloc_def') or candidate.get('alloc_site'),
                      def_use, ir_ops, callee_names)
    w = classify_size(candidate.get('write_size_var', 'size'),
                      candidate.get('write_def') or candidate.get('write_site'),
                      def_use, ir_ops, callee_names)
    sev, conf, downgrade = _severity(a.level, w.level)
    return {
        'alloc_control': a.level.name,
        'write_control': w.level.name,
        'alloc_source': a.source,
        'write_source': w.source,
        'severity': sev,
        'confidence': conf,
        'downgrade': downgrade,
        'alloc_provenance': a,
        'write_provenance': w,
    }


def _severity(a: Controllability, w: Controllability) -> Tuple[str, float, bool]:
    """四象限严重度矩阵.

    downgrade=True 表示两侧均不可控 → 应降权 (误报候选).
    """
    external = Controllability.EXTERNAL
    if a == external and w == external:
        return 'high', 0.90, False
    if a == external or w == external:
        return 'high', 0.80, False
    if a == Controllability.UNKNOWN or w == Controllability.UNKNOWN:
        return 'medium', 0.55, False
    return 'low', 0.30, True


def batch_controllability_filter(
    candidates: List[Dict],
    def_use: Dict[int, List[int]],
    ir_ops: Dict[int, Dict],
    callee_names: Optional[Dict[int, str]] = None,
    drop_internal: bool = True,
) -> Tuple[List[Dict], Dict[str, Any]]:
    """批量可控性过滤. drop_internal=True 时剔除双侧不可控候选."""
    retained: List[Dict] = []
    stats = {'total': len(candidates), 'dropped_internal': 0,
             'high': 0, 'medium': 0, 'low': 0}
    for c in candidates:
        info = classify_candidate(c, def_use, ir_ops, callee_names)
        c['_control'] = info
        if info['downgrade'] and drop_internal:
            c['exploitable'] = False
            c['confidence'] = min(c.get('confidence', 0.5), 0.3)
            c['downgrade_reason'] = (f'双侧大小均不可控 '
                                     f'({info["alloc_control"]}/{info["write_control"]})')
            stats['dropped_internal'] += 1
            continue
        stats[info['severity']] += 1
        retained.append(c)
    stats['retained'] = len(retained)
    return retained, stats
