"""
堆/栈/全局内存写区分 —— 基于寄存器特征和地址模式的写目标分类。

核心问题: 从反编译输出中, IR行如 'mov [rax+0x10], rbx' 可能写入:
  - 堆缓冲区 (rax = malloc返回值)
  - 栈帧 (rax = rsp/ebp + offset)
  - 全局数据段 (rax = .bss/.data 地址)
  - 其他堆对象 (rax = 不同malloc的返回值)

现有检测将所有 [base+offset] 写入与最近的malloc关联,
产生大量误报: 实际上base可能指向完全不同的内存区域。

方法: 基于以下特征的三级分类器:
  1. 指令特征: mov [rsp+...] → 栈; mov [rax+...] 且 rax 来自 call malloc → 堆
  2. 寄存器约定: x86_64 上 rsp/rbp → 栈; rip-relative → 全局; rax after malloc → 堆
  3. 变量名推断: 反编译器生成的变量名 (如 var_20 → 栈变量; puVar1 → 可能是堆)

不实现全程序points-to分析 —— 仅做局部(函数内)的轻量区分。
O(n) 一次扫描。

  - "Undangle": 早期UAF检测中的指针分析
  - Ghidra's decompiler: stack vs. heap variable naming conventions
  - x86_64 ABI: calling convention (System V): rax as return register
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Set, Tuple

class MemRegion(str, Enum):
    HEAP = "heap"
    STACK = "stack"
    GLOBAL = "global"
    UNKNOWN = "unknown"

# 栈指示寄存器 (x86_64)
_STACK_REGS = {'rsp', 'rbp', 'esp', 'ebp', 'sp', 'bp', 'fp'}

# 函数调用返回值寄存器 (x86_64 System V ABI: rax; ARM64: x0)
_RETVAL_REGS = {'rax', 'eax', 'ax', 'al', 'x0', 'w0'}

# 全局寻址模式特征
_GLOBAL_INDICATORS = {'rip', 'eip', 'pc', '.data', '.bss', '.rodata'}

# 栈变量命名模式 (反编译器生成)
_STACK_VAR_PATTERNS = [
    r'var_\w+',           # Ghidra: var_20h
    r'local_\w+',         # Hex-Rays
    r'[a-z]Var\d+',       # Ghidra C
    r'iStack\d+',         # Ghidra
    r'auStack\d+',        # Ghidra
    r'pvStack\d+',        # Ghidra
]

# 堆变量命名模式
_HEAP_VAR_PATTERNS = [
    r'puVar\d+',          # Ghidra: puVar1 = pointer undefined
    r'p[vsu]\w*\d+',      # general pointer variables
    r'heap_\w+',          # explicit heap naming
    r'buf\w*',            # buffer naming
    r'ptr\w*',            # pointer naming
]

@dataclass
class MemAccess:
    """一次内存访问的描述。"""
    pc: int = 0
    base_reg: str = ''             # 基址寄存器或变量名
    offset: int = 0                # 偏移量
    access_size: int = 0           # 访问大小 (1/2/4/8)
    region: MemRegion = MemRegion.UNKNOWN
    confidence: float = 0.0
    line: str = ''                 # 原始IR行
    reasoning: str = ''

def _infer_region_from_var_name(var_name: str) -> Tuple[MemRegion, float, str]:
    """从反编译器生成的变量名推断内存区域。"""
    if not var_name:
        return MemRegion.UNKNOWN, 0.0, 'empty variable name'

    for pat in _STACK_VAR_PATTERNS:
        if re.match(pat, var_name):
            return MemRegion.STACK, 0.80, f'variable name matches stack pattern: {pat}'

    for pat in _HEAP_VAR_PATTERNS:
        if re.match(pat, var_name):
            return MemRegion.HEAP, 0.45, f'variable name matches heap pattern: {pat}'

    return MemRegion.UNKNOWN, 0.0, 'name not recognized'

def _infer_region_from_address_expr(addr_expr: str) -> Tuple[MemRegion, float, str]:
    """从地址表达式推断内存区域。

    例如: 'rsp + 0x20' → STACK; 'rip + 0x1234' → GLOBAL.
    """
    expr = addr_expr.strip().lower()
    # 去掉括号
    expr = expr.strip('[]')

    for reg in _STACK_REGS:
        if re.search(rf'\b{re.escape(reg)}\b', expr):
            return MemRegion.STACK, 0.85, f'stack register {reg} in address expression'

    for ind in _GLOBAL_INDICATORS:
        if ind.startswith('.'):
            if ind in expr:
                return MemRegion.GLOBAL, 0.80, f'global indicator {ind} in address expression'
        else:
            if re.search(rf'\b{re.escape(ind)}\b', expr):
                return MemRegion.GLOBAL, 0.80, f'global indicator {ind} in address expression'

    return MemRegion.UNKNOWN, 0.0, 'unrecognized address expression'

def classify_memory_access(
    ir_line: str,
    alloc_vars: Optional[Set[str]] = None,
) -> MemAccess:
    """分类单条 IR 行中的内存访问, 返回带区域分类的 MemAccess。

    alloc_vars 为已知从 malloc 分配返回的变量名集合。
    """
    result = MemAccess(line=ir_line)

    # 提取地址表达式
    addr_m = re.search(r'\[([^\]]+)\]', ir_line)
    if not addr_m:
        result.region = MemRegion.UNKNOWN
        result.confidence = 0.0
        result.reasoning = 'no memory access pattern in line'
        return result

    addr = addr_m.group(1).strip()

    # 第一关: 寄存器/地址表达式模式
    reg_region, reg_conf, reg_reason = _infer_region_from_address_expr(addr)
    if reg_region != MemRegion.UNKNOWN:
        result.region = reg_region
        result.confidence = reg_conf
        result.reasoning = reg_reason
        return result

    # 提取基址变量名 (如 rax+0x10 中的 rax)
    base_m = re.match(r'(\w[\w\d_]*)', addr)
    if base_m:
        base_var = base_m.group(1)
        # 检查是否在已知的堆分配变量集中
        if alloc_vars and base_var in alloc_vars:
            result.region = MemRegion.HEAP
            result.confidence = 0.75
            result.reasoning = f'{base_var} is a known heap allocation variable'
            return result

        # 第二关: 变量命名推断
        name_region, name_conf, name_reason = _infer_region_from_var_name(base_var)
        if name_region != MemRegion.UNKNOWN:
            result.region = name_region
            result.confidence = name_conf
            result.reasoning = name_reason
            return result

    result.region = MemRegion.UNKNOWN
    result.confidence = 0.0
    result.reasoning = 'could not classify memory region'
    return result

def extract_heap_accesses(
    ir_lines: List[str],
    alloc_vars: Optional[Set[str]] = None,
) -> List[MemAccess]:
    """从IR中提取所有堆内存访问, 过滤栈和全局访问。

    这是误报过滤的关键步骤: 确认写入目标确实是堆缓冲区,
    而非误分类的栈/全局访问。
    """
    heap_accesses = []
    for pc, line in enumerate(ir_lines):
        access = classify_memory_access(line, alloc_vars)
        access.pc = pc
        if access.region == MemRegion.HEAP:
            heap_accesses.append(access)
    return heap_accesses

def is_likely_heap_write(
    ir_line: str,
    known_heap_vars: Optional[Set[str]] = None,
    malloc_return_vars: Optional[Set[str]] = None,
) -> Tuple[bool, float, str]:
    """快速判断一条IR行是否'看起来像堆写入'。

    综合三条线索:
      A) 地址表达式中使用的基址变量是已知的malloc返回值
      B) 反编译器将在堆分配的变量命名为puVar*/buf*/ptr*
      C) 不是明显的栈访问 (rsp/rbp-based)

    返回 (is_heap, confidence, reason)。
    用于在告警阶段快速过滤非堆写入, 不等完整分类。
    """
    line_lower = ir_line.lower()

    # 快速排除栈 (word boundary 避免 'esp' 匹配 'despatch')
    for reg in _STACK_REGS:
        if re.search(rf'\b{re.escape(reg)}\b', line_lower):
            return False, 0.90, f'stack register {reg} in line'

    # 快速排除全局 (word boundary matching 避免 'pc' 匹配 'pcm_buf')
    for ind in _GLOBAL_INDICATORS:
        if ind.startswith('.'):
            if ind in line_lower:
                return False, 0.80, f'global indicator {ind} in line'
        else:
            # 寄存器名用 word boundary 匹配
            if re.search(rf'\b{re.escape(ind)}\b', line_lower):
                return False, 0.80, f'global indicator {ind} in line'

    # 检查已知堆变量
    if malloc_return_vars:
        for mv in malloc_return_vars:
            if mv in ir_line:
                return True, 0.85, f'known malloc variable {mv} in line'

    # 检查变量命名
    addr_m = re.search(r'\[([^\]]+)\]', ir_line)
    if addr_m:
        addr = addr_m.group(1)
        base_m = re.match(r'(\w[\w\d_]*)', addr.strip())
        if base_m:
            for pat in _HEAP_VAR_PATTERNS:
                if re.match(pat, base_m.group(1)):
                    return True, 0.50, f'heap variable pattern matched: {base_m.group(1)}'

    if known_heap_vars:
        addr_m2 = re.search(r'\[([^\]]+)\]', ir_line)
        if addr_m2:
            for kv in known_heap_vars:
                if kv in addr_m2.group(1):
                    return True, 0.70, f'known heap var {kv} in address'

    return False, 0.0, 'no heap indicators found'
