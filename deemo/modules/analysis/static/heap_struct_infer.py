# 堆对象结构推断 (Heap Object Structure Inference)
#
# 核心决策:
# 堆溢出误报的第二大来源 - 对堆对象的合法字段访问
#   被误认为是越界写入. 例如: struct { int a; char b[32]; } 的
#   [rax+0x24] 是合法的字段访问, 不是溢出.
#
#   本模块从反汇编中的内存访问模式推断堆对象的结构布局:
#     1. 收集所有对同一堆指针的偏移访问
#     2. 聚类分析: 连续整数偏移 → 数组, 固定步长 → 结构体
#     3. 推断最大合法偏移 (结构体大小下界)
#     4. 将结构信息反馈给溢出检测器
#
#

from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple


class HeapStructField:
    """推断的堆结构字段."""
    __slots__ = ("offset", "size_hint", "access_count", "access_types")
    def __init__(self, offset: int, size_hint: int = 4):
        self.offset = offset
        self.size_hint = size_hint          # 推测的字段大小 (1/2/4/8)
        self.access_count = 0               # 访问次数
        self.access_types: Set[str] = set()  # {"read","write"}


class HeapStructLayout:
    """推断的堆对象结构布局."""
    __slots__ = ("base_reg", "alloc_addr", "fields",
                 "max_observed_offset", "min_stride",
                 "array_element_size", "is_array")
    def __init__(self, base_reg: str, alloc_addr: int = 0):
        self.base_reg = base_reg            # 基址寄存器 (如 "rax")
        self.alloc_addr = alloc_addr        # 分配点地址
        self.fields: Dict[int, HeapStructField] = {}
        self.max_observed_offset = 0
        self.min_stride = 8                 # 默认 8 字节对齐
        self.array_element_size = 0
        self.is_array = False

    def record_access(self, offset: int, size_hint: int,
                      access_type: str, ins_addr: int):
        """记录一次对偏移offset的内存访问."""
        if offset not in self.fields:
            self.fields[offset] = HeapStructField(offset, size_hint)
        field = self.fields[offset]
        field.access_count += 1
        field.access_types.add(access_type)
        if size_hint > field.size_hint:
            field.size_hint = size_hint
        self.max_observed_offset = max(self.max_observed_offset,
                                       offset + size_hint)

    def infer_min_size(self) -> int:
        """推断结构体的最小大小 (字节)."""
        if not self.fields:
            return 0
        # 对齐到 min_stride
        raw = self.max_observed_offset
        return ((raw + self.min_stride - 1) // self.min_stride
                * self.min_stride)

    def is_likely_array(self) -> bool:
        """判断是否为数组访问模式."""
        if len(self.fields) < 3:
            return False
        offsets = sorted(self.fields.keys())
        if not offsets:
            return False
        gaps = [offsets[i+1] - offsets[i] for i in range(len(offsets)-1)]
        if not gaps:
            return False
        # 若所有间距一致 → 数组
        if len(set(gaps)) <= 2:  # 允许 ±1 的浮动
            self.array_element_size = max(set(gaps), key=gaps.count)
            self.is_array = True
            return True
        return False

    def contains_offset(self, offset: int, size: int) -> bool:
        """判断写入 [base+offset, base+offset+size) 是否在结构内."""
        end = offset + size
        if end <= self.infer_min_size():
            return True  # 在已知字段范围内
        # 数组: 若偏移在数组范围内 → 合法
        if self.is_array and self.array_element_size > 0:
            array_end = self.max_observed_offset + self.array_element_size
            if end <= array_end:
                return True
        return False


class HeapStructInference:
    """堆对象结构推断引擎.

    从指令序列中提取对同一堆指针的内存访问模式,
    聚类为字段/数组, 推断结构布局.
    """

    # 指令→访问大小 (bytes) 的启发式规则
    _SIZE_HINTS = {
        "movzx": 1, "movsx": 1,   # byte → word/dword
        "mov": 4,                  # 默认 dword
        "movsxd": 4, "movsx": 2,  # dword→qword, word→dword
        "add": 4, "sub": 4,
    }

    # x86-64 通用寄存器名 (归一化后)
    _GPR64 = {f"r{i}" for i in range(8, 16)} | {
        "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","rip"}

    def __init__(self):
        # key: 基址寄存器 → HeapStructLayout
        self._layouts: Dict[str, HeapStructLayout] = {}
        # 每个分配点产生的指针 → 基址寄存器的映射
        self._alloc_to_reg: Dict[int, str] = {}

    def feed_allocation(self, alloc_addr: int, result_reg: str):
        """记录分配点, 建立 alloc→reg 映射."""
        norm = self._norm_reg(result_reg)
        self._alloc_to_reg[alloc_addr] = norm
        if norm not in self._layouts:
            self._layouts[norm] = HeapStructLayout(norm, alloc_addr)

    def feed_memory_access(self, ins: dict, ptr_reg: str,
                           alloc_addr: int = 0):
        """记录一次对堆指针的内存访问.

        ins: 反汇编指令字典.
        ptr_reg: 被解引用的基址寄存器.
        alloc_addr: 关联的分配点地址 (若已知).
        """
        reg = self._norm_reg(ptr_reg)
        if reg not in self._GPR64:
            return

        ops = ins.get("operands", [])
        mnem = ins.get("mnemonic", "").lower()
        addr = ins.get("address", 0)

        # 解析 [reg+offset] 中的offset
        offset = 0
        for op in ops:
            op_s = op.strip().lower()
            if reg in op_s and "[" in op_s:
                offset = self._parse_offset(op_s, reg)
                break

        # 推断访问大小
        size_hint = self._infer_access_size(mnem, ops)

        # 判断读写类型
        if mnem == "mov" and len(ops) >= 2:
            if "[" in ops[0].strip().lower():
                atype = "write"
            elif "[" in ops[1].strip().lower():
                atype = "read"
            else:
                return  # 不是内存访问
        elif mnem in ("lea",):
            return  # lea 不解引用, 忽略
        else:
            atype = "read"  # 保守

        # 找到或创建对应的布局
        if alloc_addr > 0 and alloc_addr in self._alloc_to_reg:
            reg = self._alloc_to_reg[alloc_addr]
        layout = self._layouts.get(reg)
        if layout is None:
            layout = HeapStructLayout(reg, alloc_addr)
            self._layouts[reg] = layout

        layout.record_access(offset, size_hint, atype, addr)

    def infer_layout(self, ptr_reg: str) -> Optional[HeapStructLayout]:
        """查询某寄存器的推断结构布局."""
        return self._layouts.get(self._norm_reg(ptr_reg))

    def infer_for_alloc(self, alloc_addr: int
                        ) -> Optional[HeapStructLayout]:
        """查询某分配点的推断结构布局."""
        reg = self._alloc_to_reg.get(alloc_addr)
        if reg:
            return self._layouts.get(reg)
        return None

    def is_field_access(self, ptr_reg: str, offset: int,
                        size: int) -> bool:
        """判断对 [ptr_reg+offset] 的 size 字节访问是否是合法字段访问."""
        layout = self._layouts.get(self._norm_reg(ptr_reg))
        if layout is None or not layout.fields:
            return False  # 信息不足, 保守: 不判定为字段
        return layout.contains_offset(offset, size)

    def min_struct_size(self, ptr_reg: str) -> int:
        """返回推断的最小结构体大小 (0 = 未知)."""
        layout = self._layouts.get(self._norm_reg(ptr_reg))
        if layout:
            return layout.infer_min_size()
        return 0

    @staticmethod
    def _parse_offset(operand: str, base_reg: str) -> int:
        """从 [reg+offset] 中提取 offset 值."""
        op = operand.strip().lower()
        op = op.replace("[","").replace("]","")
        # 去除 qword/dword/byte ptr 等前缀
        for prefix in ("qword ptr ", "dword ptr ", "word ptr ",
                       "byte ptr ", "xmmword ptr "):
            op = op.replace(prefix, "")
        # 拆分为各部分
        parts = op.replace("+"," +").replace("-"," -").split()
        total = 0
        for p in parts:
            p = p.strip()
            if p == base_reg or p == "" or p == "*":
                continue
            try:
                if p.startswith("0x"):
                    total += int(p, 16)
                elif p.lstrip("-").isdigit():
                    total += int(p)
                elif p.startswith("-0x"):
                    total -= int(p[1:], 16)
            except ValueError:
                pass
        return total

    @staticmethod
    def _infer_access_size(mnem: str, ops: List[str]) -> int:
        """从助记符和操作数推断内存访问的字节大小."""
        mnem_l = mnem.lower()
        if mnem_l in ("movzx", "movsx"):
            return 2  # 读word扩展到dword
        if mnem_l == "movsxd":
            return 4
        if mnem_l == "mov":
            for op in ops:
                op_s = op.strip().lower()
                if "qword" in op_s:
                    return 8
                if "dword" in op_s:
                    return 4
                if "word" in op_s:
                    return 2
                if "byte" in op_s:
                    return 1
            return 4  # 默认 dword
        return HeapStructInference._SIZE_HINTS.get(mnem_l, 4)

    @staticmethod
    def _norm_reg(reg: str) -> str:
        r = reg.strip().lower().lstrip("%")
        # 32→64 bit
        w32 = {"eax":"rax","ebx":"rbx","ecx":"rcx","edx":"rdx",
               "esi":"rsi","edi":"rdi","r8d":"r8","r9d":"r9",
               "r10d":"r10","r11d":"r11","r12d":"r12","r13d":"r13",
               "r14d":"r14","r15d":"r15"}
        return w32.get(r, r)

    def reset(self):
        self._layouts.clear()
        self._alloc_to_reg.clear()


__all__ = ["HeapStructInference", "HeapStructLayout", "HeapStructField"]
