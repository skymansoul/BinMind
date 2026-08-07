# 内存区域判别器: 区分堆/栈/全局/代码段写入以消除跨区域误报
# 核心创新: 现有分析不区分内存写入的目的区域类型,
#   将"向栈上的指针写入"误判为"向堆块写入".
#   例: mov [rbp-0x8], rax   ; rbp-0x8在栈上,若rax持有heap ptr
#      本应视为"将堆指针保存到栈变量", 而不是"向堆块写入"
#   本模块通过在指令级判定内存操作数的区域类型, 消除此类误报
# 理论来源:
#   Balakrishnan & Reps "Analyzing Memory Accesses in x86 Executables" (CC 2004)
#     — 使用 a-loc (abstract location) 区分内存区域
#   Zhao et al. "TypeMiner: Recovering Types from Binary" (USENIX 2024)
#     — 从二进制的内存访问模式推断区域类型
# 与现有分析的关系: 作为内存写入验证的前置过滤层,
#   只将真正的堆区域写入传递给检测管道
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple
import re


class MemoryRegionType(Enum):
    """内存区域类型枚举."""
    STACK = auto()          # 栈: [rbp±off], [rsp±off]
    HEAP = auto()           # 堆: 通过非栈基址寄存器间接访问
    GLOBAL = auto()         # 全局/静态: rip-relative寻址
    CODE = auto()           # 代码段: 极少被写入
    UNKNOWN = auto()        # 无法判定


@dataclass
class MemoryAccessInfo:
    """内存访问的完整信息."""
    region_type: MemoryRegionType
    base_register: str = ""
    displacement: int = 0
    index_register: str = ""
    scale: int = 1
    access_size: int = 1  # BYTE=1, WORD=2, DWORD=4, QWORD=8
    is_ptr_access: bool = False  # 是否是对指针变量的访问 (不是对指向数据的写入)
    confidence: float = 1.0


class MemoryRegionResolver:
    """内存区域解析器.

    根据指令中的内存操作数格式判定其所属区域.
    核心判定规则:
      1. [rbp±X] 或 [rsp±Y] → STACK (函数栈帧内)
      2. rip-relative [rip+X] → GLOBAL
      3. [非栈基址寄存器] → 需要经过值域/溯源分析确定 → 初始标记UNKNOWN
      4. [rax] 其中rax的值域下界≥堆区域基址 → HEAP

    设计约束: 线性扫描中, 无法回溯指令来确定寄存器来源.
    判定分两阶段:
      Phase A (语法级): 根据操作数格式直接判定
      Phase B (语义级): 结合PointerProvenance和区域特征信息判定
    """

    # 栈帧基址寄存器
    _STACK_BASE_REGS = {'rbp', 'rsp', 'ebp', 'esp', 'rbx'}

    # 典型堆地址范围 (x86-64 Linux)
    _HEAP_BASE = 0x555000000000
    _HEAP_TOP = 0x557000000000

    # Windows堆地址范围 (x86-64)
    _WIN_HEAP_BASE = 0x1C0000000000
    _WIN_HEAP_TOP = 0x1C00FFFFFFFF

    def __init__(self, platform: str = 'linux'):
        self._platform = platform
        self._heap_base = (self._WIN_HEAP_BASE if platform == 'windows'
                           else self._HEAP_BASE)
        self._heap_top = (self._WIN_HEAP_TOP if platform == 'windows'
                          else self._HEAP_TOP)

    def resolve_syntactic(self, dst_operand: str) -> MemoryAccessInfo:
        """Phase A: 纯语法级判定 — 不依赖任何值域或溯源信息."""
        dst = dst_operand.strip()

        # 检查是否是内存操作数
        if not ('[' in dst or 'PTR' in dst.upper()):
            return MemoryAccessInfo(
                region_type=MemoryRegionType.UNKNOWN,
                is_ptr_access=True)  # 不是内存操作→视为寄存器操作

        # 解析基址寄存器
        base, disp, idx, scale = self._parse_memory_operand(dst)

        # Rule 1: rbp/rsp relative → STACK
        if base.lower() in ('rbp', 'rsp', 'ebp', 'esp'):
            return MemoryAccessInfo(
                region_type=MemoryRegionType.STACK,
                base_register=base, displacement=disp,
                index_register=idx, scale=scale,
                is_ptr_access=True, confidence=0.98)

        # Rule 2: rip-relative → GLOBAL
        if base.lower() == 'rip':
            return MemoryAccessInfo(
                region_type=MemoryRegionType.GLOBAL,
                base_register=base, displacement=disp,
                index_register=idx, scale=scale,
                is_ptr_access=False, confidence=0.95)

        # Rule 3: rbx-relative (帧基址有时保存在rbx)
        if base.lower() == 'rbx':
            # 需要进一步判断: rbx可能用作帧基址也可能用作普通指针
            # 保守: 标记为STACK (多数情况rbx是帧基址)
            return MemoryAccessInfo(
                region_type=MemoryRegionType.STACK,
                base_register=base, displacement=disp,
                index_register=idx, scale=scale,
                is_ptr_access=True, confidence=0.70)

        # Rule 4: 非栈基址 → 可能是HEAP, 需要语义级确认
        return MemoryAccessInfo(
            region_type=MemoryRegionType.UNKNOWN,
            base_register=base, displacement=disp,
            index_register=idx, scale=scale,
            is_ptr_access=False, confidence=0.50)

    def resolve_semantic(self, base_reg: str,
                         provenance_is_heap: bool,
                         base_reg_value_lo: int = 0,
                         base_reg_value_hi: int = 0
                         ) -> MemoryRegionType:
        """Phase B: 语义级判定 — 结合溯源和值域信息.

        provenance_is_heap: PointerProvenance是否确认基址寄存器持有堆指针
        base_reg_value_lo/hi: 基址寄存器的值域
        """
        reg_lower = base_reg.lower()

        # 栈帧基址回归确认
        if reg_lower in self._STACK_BASE_REGS:
            return MemoryRegionType.STACK

        # PointerProvenance确认堆指针 → HEAP
        if provenance_is_heap:
            return MemoryRegionType.HEAP

        # 值域在堆地址范围内 → HEAP
        if (base_reg_value_lo >= self._heap_base
                and base_reg_value_hi <= self._heap_top):
            return MemoryRegionType.HEAP

        # 值域在高地址 (典型栈区域) → STACK
        if base_reg_value_hi > 0x7FFFFFFFFFFF:
            return MemoryRegionType.STACK

        return MemoryRegionType.UNKNOWN

    def _parse_memory_operand(self, operand: str
                              ) -> Tuple[str, int, str, int]:
        """解析内存操作数: [base + idx*scale + disp].

        返回 (base, displacement, index, scale).
        """
        # 去除SIZE PTR前缀
        size_clean = re.sub(
            r'(BYTE|WORD|DWORD|QWORD|XMMWORD|YMMWORD|OWORD)\s+PTR\s+',
            '', operand, flags=re.IGNORECASE).strip()

        # 提取[...]中的内容
        if '[' in size_clean and ']' in size_clean:
            start = size_clean.index('[') + 1
            end = size_clean.index(']')
            inner = size_clean[start:end]
        else:
            return '', 0, '', 1

        base, disp, idx, scale = '', 0, '', 1

        # 按 +/- 分割
        parts = re.split(r'([+\-])', inner)
        if not parts:
            return '', 0, '', 1

        # 处理第一个token
        first = parts[0].strip()
        if '*' in first:
            idx_scale = first.split('*')
            idx = idx_scale[0].strip()
            try:
                scale = int(idx_scale[1].strip())
            except (ValueError, IndexError):
                scale = 1
        else:
            m = re.match(r'(\w+)', first)
            if m:
                base = m.group(1)

        # 处理后续的 sign + token 对
        i = 1
        while i + 1 < len(parts):
            sign_str = parts[i].strip()
            token = parts[i + 1].strip()
            sign = 1 if sign_str == '+' else -1

            if '*' in token:
                idx_scale = token.split('*')
                idx = idx_scale[0].strip()
                try:
                    scale = int(idx_scale[1].strip())
                except (ValueError, IndexError):
                    scale = 1
                i += 2
                continue

            try:
                val = int(token, 16) if token.startswith('0x') else int(token)
                disp += sign * val
            except ValueError:
                pass
            i += 2

        return base, disp, idx, scale


class MemoryWriteValidator:
    """内存写入验证器: 只向检测管道传递真正的堆区域写入.

    核心过滤逻辑:
      - 栈上写入 (rbp/rsp相关) → 不是堆写入, 跳过
      - 全局变量写入 (rip-relative) → 不是堆写入, 跳过
      - 寄存器间接写入 + 基址寄存器持有堆溯源 → 是堆写入
      - 寄存器间接写入 + 基址寄存器溯源未知 → 保守通过 (宁可多报不漏报)
    """

    def __init__(self):
        self._resolver = MemoryRegionResolver()

    def is_heap_write(self, dst_operand: str,
                      base_reg_is_heap_ptr: bool = False,
                      base_reg_value_lo: int = 0,
                      base_reg_value_hi: int = 0
                      ) -> Tuple[bool, MemoryAccessInfo]:
        """判定内存写入是否针对堆区域.

        Returns:
          (is_heap_write, access_info) — True表示应继续传递给检测管道
        """
        info = self._resolver.resolve_syntactic(dst_operand)

        # Phase A直接判定的情况
        if info.region_type == MemoryRegionType.STACK:
            # 栈上写入 → 绝对不可能是堆溢出
            return False, info

        if info.region_type == MemoryRegionType.GLOBAL:
            # 全局变量写入 → 不可能是堆溢出
            return False, info

        # Phase B: 需要语义级判定
        if info.region_type == MemoryRegionType.UNKNOWN:
            region = self._resolver.resolve_semantic(
                info.base_register,
                base_reg_is_heap_ptr,
                base_reg_value_lo,
                base_reg_value_hi)
            info.region_type = region

        is_heap = info.region_type == MemoryRegionType.HEAP

        # 关键决策: 只将确认的HEAP写入和基址寄存器持有堆溯源的UNKNOWN写入
        # 传递给检测管道. 纯UNKNOWN写入保守放过 (允许检测管道通过值域验证
        # 自行排除), 确保不因区域判别失误导致漏报.
        if info.region_type == MemoryRegionType.UNKNOWN:
            if base_reg_is_heap_ptr:
                return True, info
            # 保守通过: 没有堆溯源但也不确定是其他区域
            # 让检测管道的值域验证处理
            return True, info

        return is_heap, info

    def filter_inline_writes(self, writes: List[Dict],
                             provenance_map: Dict[str, bool]
                             ) -> List[Dict]:
        """过滤内联写入列表, 只保留堆区域写入."""
        filtered = []
        for w in writes:
            base_reg = w.get('base_reg', '')
            is_heap_ptr = provenance_map.get(base_reg, False)
            is_heap, info = self.is_heap_write(
                f"[{base_reg}]", base_reg_is_heap_ptr=is_heap_ptr)
            if is_heap:
                w['memory_region'] = info.region_type.name
                filtered.append(w)
        return filtered
