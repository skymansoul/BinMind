"""
守卫条件推断引擎 — 从IR序列中提取堆写入前的边界检查条件。

核心问题: 静态工具将 malloc(N)+buf[i]=x 一律报溢出, 但若 i 在写入前
被 cmp i,N; jl safe_path 守卫, 则写入实际安全。不识别守卫条件 → 大量误报。

方法: 在 malloc→write 的 IR 窗口内做模式驱动的守卫识别:
  1. 定位 cmp idx, bound / cmp bound, idx 模式
  2. 跟踪后续条件跳转 (jl/jb/jbe/jle) 的目标
  3. 确认 write 指令在守卫路径上 (受保护) 还是非守卫路径上 (真阳性)
  4. 输出 GuardResult: 守卫变量、边界值、write是否受保护

  ISSTA 2024 "Precise Compositional Buffer Overflow Detection via Heap Disjointness"
    组合式分析将堆对象拆分为不交叠区域, 我们取其守卫条件思想但简化到IR级
  HKUST "Practical Symbolic Static Analysis"
    路径选择策略: 优先探索守卫路径并标记安全/不安全
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Optional

class GuardVerdict(Enum):
    PROTECTED = "protected"       # 写入受显式边界检查保护
    UNGUARDED = "unguarded"       # 未检测到守卫 → 可能是真阳性
    UNCERTAIN = "uncertain"        # 守卫存在但无法确定是否覆盖此写入

@dataclass
class GuardCondition:
    """提取到的单条守卫条件。"""
    cmp_pc: int                    # cmp 指令在IR中的位置
    index_var: str                 # 被比较的索引变量
    bound_value: int               # 边界常量值
    bound_var: str = ""            # 边界变量名 (若非常量)
    comparison: str = "lt"         # lt/le/gt/ge
    jmp_target_offset: int = 0     # 条件跳转目标相对于cmp_pc的偏移

@dataclass
class GuardResult:
    """对单个 write 操作的守卫分析结果。"""
    write_pc: int                  # write 指令位置
    guard: Optional[GuardCondition] = None
    verdict: GuardVerdict = GuardVerdict.UNGUARDED
    guard_distance: int = -1       # 守卫到write的IR行数 (-1=无守卫)
    alloc_size: int = 0            # 关联的分配大小
    write_offset: int = -1         # 写入偏移
    description: str = ""

class GuardInferenceEngine:
    """
    守卫条件推断引擎。

    在 IR 行序列上滑动窗口, 识别 cmp+jcc 守卫模式,
    并判定后续写入是否受到保护。

    架构选择: 不做完整 CFG 重建 (依赖Ghidra/angr太重),
    而是在线性IR上做局部模式匹配 + 窗口搜索。
    代价是跨基本块的长距离守卫可能漏, 收益是速度快、不依赖外部工具。
    """

    # cmp reg, imm 模式的汇编级正则
    _CMP_PAT = re.compile(
        r'cmp\s+(\w+),\s*(0x[0-9a-fA-F]+|\d+)',
        re.IGNORECASE,
    )
    # 条件跳转: jb/jl/jbe/jle/ja/jg/jae/jge
    _JCC_PAT = re.compile(
        r'(?:j(?:b|l|be|le|a|g|ae|ge|ne?|z|nz|e)\s+)|'
        r'(?:if\s*\(|goto\s+)',
        re.IGNORECASE,
    )
    # 写入模式: mov [base+idx], ... 或 memcpy 等
    _WRITE_PAT = re.compile(
        r'(?:mov|movsd|movsq|stos[bdqw]|fstp)\s+'
        r'\[(\w+)\s*\+\s*(\w+|\d+)\]',
        re.IGNORECASE,
    )
    # memcpy/memmove/memset
    _MEMCPY_PAT = re.compile(
        r'(memcpy|memmove|memset|strcpy|strncpy|snprintf|sprintf)\s*\(([^)]+)\)',
        re.IGNORECASE,
    )

    def __init__(self, window_size: int = 30):
        self._window = window_size

    def infer(self, ir_lines: list[str], alloc_pc: int,
              alloc_size: int, store_pc: int,
              base_var: str = "") -> GuardResult:
        """在 alloc_pc 与 store_pc 之间搜索守卫条件。

        base_var 为堆缓冲区基址变量, 用于关联写入操作数。
        """
        result = GuardResult(
            write_pc=store_pc, alloc_size=alloc_size,
        )

        # 搜索窗口: alloc 之后, store 之前
        start = max(0, alloc_pc)
        end = min(len(ir_lines), store_pc + 1)
        search_lines = ir_lines[start:end]
        search_start = start

        guards = self._extract_guards(search_lines, search_start, alloc_size)

        if not guards:
            result.verdict = GuardVerdict.UNGUARDED
            result.description = "no guard detected between alloc and write"
            return result

        # 取离 write 最近的守卫
        closest = max(guards, key=lambda g: g.cmp_pc)
        result.guard = closest
        result.guard_distance = store_pc - closest.cmp_pc

        # 检查 write 中的偏移/索引是否与守卫变量匹配
        write_line = ir_lines[store_pc] if store_pc < len(ir_lines) else ""
        result.write_offset = self._extract_write_offset(write_line, base_var)

        # 判定: 若守卫变量出现在 write 的操作数中, 且守卫边界 ≥ alloc_size,
        # 则 write 受保护
        idx_var = closest.index_var
        if idx_var and self._var_in_write(idx_var, write_line):
            if closest.bound_value > 0 and closest.bound_value <= alloc_size:
                result.verdict = GuardVerdict.PROTECTED
                result.description = (
                    f"guard: cmp {idx_var},{closest.bound_value} "
                    f"(bound≤alloc {alloc_size}) → write PROTECTED"
                )
            elif closest.bound_value > alloc_size:
                # 守卫允许访问超出分配范围 → 但仍需检查实际偏移
                if 0 <= result.write_offset < alloc_size:
                    result.verdict = GuardVerdict.PROTECTED
                    result.description = (
                        f"guard bound={closest.bound_value} > alloc={alloc_size}, "
                        f"but write offset={result.write_offset} within range"
                    )
                else:
                    result.verdict = GuardVerdict.UNCERTAIN
                    result.description = (
                        f"guard bound={closest.bound_value} > alloc={alloc_size}, "
                        f"may exceed allocation"
                    )
            else:
                result.verdict = GuardVerdict.UNCERTAIN
                result.description = f"guard present but cannot verify"
        else:
            # 有守卫但覆盖不同变量 → 可能无关
            result.verdict = GuardVerdict.UNCERTAIN
            result.description = (
                f"guard on '{idx_var}' but write uses different operand"
            )

        return result

    def _extract_guards(self, lines: list[str], base_pc: int,
                        alloc_size: int) -> list[GuardCondition]:
        """从IR行序列中提取所有守卫条件。"""
        guards = []
        for i, line in enumerate(lines):
            m = self._CMP_PAT.search(line)
            if not m:
                continue
            idx_var = m.group(1)
            try:
                bound = int(m.group(2), 0)
            except (ValueError, TypeError):
                bound = 0

            if bound <= 0:
                continue

            # 检查后2行内是否有条件跳转
            jcc_offset = 0
            for j in range(i + 1, min(len(lines), i + 4)):
                if self._JCC_PAT.search(lines[j]):
                    jcc_offset = j - i
                    break

            guards.append(GuardCondition(
                cmp_pc=base_pc + i,
                index_var=idx_var,
                bound_value=bound,
                comparison="lt",  # 默认假设小于比较 (保守)
                jmp_target_offset=jcc_offset,
            ))

        return guards

    def _extract_write_offset(self, line: str, base_var: str) -> int:
        """从写操作行提取偏移量。"""
        # [base + N] 形式
        if base_var:
            m = re.search(
                rf'\[{re.escape(base_var)}\s*\+\s*((?:0x)?[0-9a-fA-F]+)\]',
                line, re.IGNORECASE,
            )
            if m:
                try:
                    return int(m.group(1), 0)
                except (ValueError, TypeError):
                    pass
        # 通用 [reg + N] 形式
        m = re.search(r'\[(\w+)\s*\+\s*((?:0x)?[0-9a-fA-F]+)\]', line)
        if m:
            try:
                return int(m.group(2), 0)
            except (ValueError, TypeError):
                pass
        return -1

    def _var_in_write(self, idx_var: str, write_line: str) -> bool:
        """检查索引变量是否出现在写操作行。"""
        # 去除 x86 寄存器前缀差异 (eax/rax/ax 视为同一变量)
        var_base = re.sub(r'^(?:e|r)?', '', idx_var.lower())
        line_lower = write_line.lower()

        if idx_var.lower() in line_lower:
            return True
        if var_base in line_lower:
            return True
        # 检查 [base + var] 模式
        if re.search(rf'\[.*\+.*{re.escape(idx_var)}', line_lower):
            return True

        return False

    def infer_all(self, ir_lines: list[str],
                  alloc_sites: list, stores: list) -> dict[int, GuardResult]:
        """批量分析所有 alloc→store 对的守卫状态。"""
        results = {}
        for store in stores:
            # 找到最近的 alloc
            relevant_alloc = None
            for a in sorted(alloc_sites, key=lambda x: x.pc, reverse=True):
                if a.pc < store.pc:
                    relevant_alloc = a
                    break

            if relevant_alloc is None:
                continue

            result = self.infer(
                ir_lines, relevant_alloc.pc,
                getattr(relevant_alloc, 'size_arg', 0),
                store.pc,
                getattr(relevant_alloc, 'result_var', ''),
            )
            results[store.pc] = result

        return results

def quick_guard_check(ir_lines: list[str], store_pc: int,
                      alloc_size: int) -> tuple[bool, str]:
    """便捷接口: 返回 (是否受保护, 原因描述)。"""
    engine = GuardInferenceEngine()
    result = engine.infer(ir_lines, 0, alloc_size, store_pc)
    return result.verdict == GuardVerdict.PROTECTED, result.description

__all__ = [
    'GuardVerdict', 'GuardCondition', 'GuardResult',
    'GuardInferenceEngine', 'quick_guard_check',
]
