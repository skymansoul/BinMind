# -*- coding: utf-8 -*-
"""
污点约束的堆溢出检测 — 对 heap_analyzer 报告的候选溢出点做污点反向追踪,
仅当溢出数据来自外部可控输入且路径上无边界检查时标记为 "可利用".
纯内部数据溢出降级为 "潜在缺陷", 降低误报率.

TACE (FSE 2024) 用污点引导符号执行以加速约束求解.
本模块的差异: 在静态检测阶段用污点做误报过滤, 不执行符号执行.
反向追踪沿 def-use 链从溢出点追溯到输入源, 检查每个传播节点是否有边界检查.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class TaintPathNode:
    """污点传播路径上的一个节点."""
    addr: int           # 指令地址
    op_type: str        # 'mov' | 'add' | 'store' | 'load' | 'call' | 'ret'
    reg_or_var: str     # 涉及的数据位置
    has_bounds_check: bool = False  # 此节点前后是否有边界检查
    check_detail: str = ''


@dataclass
class TaintEnhancedResult:
    """污点增强的检测结果."""
    overflow_site: int           # 溢出点地址
    overflow_size: int           # 溢出量 (字节)
    taint_source_type: str       # 'external_input' | 'internal_data' | 'unknown'
    taint_source_desc: str       # 污点源描述
    propagation_path: List[TaintPathNode] = field(default_factory=list)
    bounds_check_found: bool = False
    exploitable: bool = False
    confidence: float = 0.0
    downgrade_reason: str = ''


# 边界检查的指令模式 (x86-64)
_BOUNDS_CHECK_PATTERNS = {
    'cmp_jb':     ('cmp', 'jb', 'jbe'),      # cmp + jb/jbe → 下界检查
    'cmp_ja':     ('cmp', 'ja', 'jae'),      # cmp + ja/jae → 上界检查
    'test_jz':    ('test', 'jz', 'je'),      # test + jz → 空指针检查
    'check_size': ('cmp', 'sub', 'jbe'),     # 大小减法 + 比较
}

# 外部输入的函数调用模式
_EXTERNAL_INPUT_FUNCS = {
    'read', 'fread', 'recv', 'recvfrom', 'recvmsg',
    'fgets', 'gets', 'scanf', 'fscanf', 'getc', 'fgetc',
    'ReadFile', 'ReadConsole', 'URLDownloadToFile',
    'input', 'raw_input',
}

# 内部数据的函数调用模式 (非外部输入)
_INTERNAL_FUNCS = {
    'memcpy', 'memmove', 'memset', 'strcpy', 'strncpy',
    'sprintf', 'snprintf', 'strcat', 'strncat',
}


def _has_bounds_check(instructions: List[Dict], around_addr: int,
                      window: int = 5) -> Tuple[bool, str]:
    """在 around_addr 附近 ±window 条指令中检测边界检查模式."""
    # 简化: 检查 addr 之前的 cmp/test 指令是否后跟条件跳转
    nearby = [i for i in instructions
              if abs(i.get('addr', 0) - around_addr) < window * 4]
    mnemonics = [i.get('mnemonic', '') for i in nearby]
    for pattern_name, ops in _BOUNDS_CHECK_PATTERNS.items():
        found = [op for op in ops if any(op in m for m in mnemonics)]
        if len(found) >= 2:
            return True, f'{pattern_name} at ±{window} insns of 0x{around_addr:x}'
    return False, ''


def trace_taint_source(
    overflow_site: int,
    def_use_chains: Dict[int, List[int]],    # addr → [source_addrs]
    ir_ops: Dict[int, Dict],                 # addr → {op_type, operands, ...}
    instructions: List[Dict],
    max_depth: int = 8,
) -> TaintEnhancedResult:
    """从溢出点反向追踪污点源.

    def_use_chains: def-use 链映射, 从每条指令的地址到其数据来源地址.
    ir_ops: IR 操作映射, 从地址到操作类型.
    instructions: 原始指令列表, 用于边界检查检测.

    返回带污点信息的结果. 沿 def-use 链反向 BFS, 每一步:
    - 记录传播节点
    - 检测边界检查
    - 若命中外部输入函数 → 标记为 external_input, 停止
    - 若超过 max_depth 未命中 → 标记为 unknown
    """
    result = TaintEnhancedResult(
        overflow_site=overflow_site, overflow_size=0,
        taint_source_type='unknown', taint_source_desc='',
    )

    visited: Set[int] = set()
    # BFS: (addr, path_nodes)
    from collections import deque
    queue = deque([(overflow_site, [])])

    while queue and len(result.propagation_path) < max_depth:
        addr, path_nodes = queue.popleft()
        if addr in visited:
            continue
        visited.add(addr)

        op = ir_ops.get(addr, {})
        op_type = op.get('op_type', 'unknown')
        operands = op.get('operands', '')

        has_bc, bc_detail = _has_bounds_check(instructions, addr)
        node = TaintPathNode(
            addr=addr, op_type=op_type, reg_or_var=str(operands),
            has_bounds_check=has_bc, check_detail=bc_detail,
        )
        new_path = path_nodes + [node]

        if has_bc:
            result.bounds_check_found = True

        # 检查是否为外部输入函数调用
        func_name = op.get('callee', '').lower()
        if func_name and any(f in func_name for f in _EXTERNAL_INPUT_FUNCS):
            result.taint_source_type = 'external_input'
            result.taint_source_desc = f'外部输入函数 {func_name} @ 0x{addr:x}'
            result.propagation_path = new_path
            result.exploitable = not result.bounds_check_found
            result.confidence = 0.90 if result.exploitable else 0.30
            if result.bounds_check_found:
                result.downgrade_reason = '溢出点附近存在边界检查'
            result.overflow_size = op.get('write_size', 0)
            return result

        # 检查是否为内部数据操作 (memcpy 等)
        if func_name and any(f in func_name for f in _INTERNAL_FUNCS):
            result.taint_source_type = 'internal_data'
            result.taint_source_desc = f'内部数据操作 {func_name} @ 0x{addr:x}'
            result.propagation_path = new_path
            result.exploitable = False
            result.confidence = 0.40
            result.downgrade_reason = '溢出数据来自内部复制, 非外部可控输入'
            result.overflow_size = op.get('write_size', 0)
            return result

        # 继续反向传播
        sources = def_use_chains.get(addr, [])
        for src in sources:
            if src not in visited:
                queue.append((src, new_path))

    # BFS 耗尽: 无法追溯到明确源
    result.taint_source_type = 'unknown'
    result.taint_source_desc = f'无法在 {max_depth} 步内追溯到外部输入源'
    result.propagation_path = path_nodes if 'path_nodes' in dir() else []
    # 无外部输入证据 → 默认不可利用
    result.exploitable = False
    result.confidence = 0.25
    result.downgrade_reason = '无法证明溢出数据来自外部可控输入'
    return result


def filter_heap_overflow_candidates(
    candidates: List[Dict],             # heap_analyzer 的输出
    def_use_chains: Dict[int, List[int]],
    ir_ops: Dict[int, Dict],
    instructions: List[Dict],
) -> List[TaintEnhancedResult]:
    """批量过滤堆溢出候选: 仅保留污点确认的可利用溢出."""
    results = []
    for c in candidates:
        site = c.get('overflow_site', c.get('alloc_site', 0))
        if isinstance(site, str) and site.startswith('0x'):
            site = int(site, 16)
        if not site:
            continue

        r = trace_taint_source(int(site), def_use_chains, ir_ops, instructions)
        r.overflow_size = c.get('overflow_size', c.get('overflow_bytes', 0))
        results.append(r)

    # 分类统计
    exploitable = [r for r in results if r.exploitable]
    downgraded = [r for r in results if not r.exploitable and r.downgrade_reason]
    return results


def downgrade_summary(results: List[TaintEnhancedResult]) -> Dict[str, Any]:
    """生成降级统计: 展示污点过滤效果."""
    total = len(results)
    exploitable = sum(1 for r in results if r.exploitable)
    downgraded = sum(1 for r in results if r.downgrade_reason)
    by_reason: Dict[str, int] = {}
    for r in results:
        if r.downgrade_reason:
            by_reason[r.downgrade_reason] = by_reason.get(r.downgrade_reason, 0) + 1
    return {
        'total_candidates': total,
        'confirmed_exploitable': exploitable,
        'downgraded': downgraded,
        'false_positive_reduction': f'{(1 - exploitable/max(1,total)):.0%}',
        'downgrade_reasons': by_reason,
    }
