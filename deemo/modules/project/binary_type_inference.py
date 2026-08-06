# 二进制类型推断器: 内存访问模式→结构体布局 / 虚表检测 / 偏移聚类
# 技术问题: TypeForge (IEEE S&P 2025) 和 BinSub (HotSoS 2025) 实现了
#   通用类型恢复但目标为改善反编译可读性. 漏洞利用场景需要的信息
#   不同: 不需要完整类型名, 需要结构体大小、字段偏移、虚表地址、
#   相邻对象的偏移关系——这些信息直接决定利用策略的可行性
# 解决手段: 从二进制指令trace或反汇编中提取三种利用关键模式:
#   模式1: 偏移聚类 — 对同一基址的常量偏移访问分组→推断struct布局
#   模式2: 虚表检测 — 函数指针数组+构造函数初始化→识别vtable
#   模式3: 步幅分析 — 指针算术的增量模式→区分数组vs链表vs树
# 技术效果: 从二进制指令trace中识别结构体布局和虚表,
#   补充反编译器在复合类型恢复上的不足
# 参考:
#   TypeForge (IEEE S&P 2025) — TFG+LLM类型合成,
#     本项目借鉴其偏移聚类思想但聚焦利用场景而非反编译可读性
#   BinSub (HotSoS 2025) — 代数子类型推断,
#     本项目借鉴其约束传播但简化为启发式偏移分组
#   Ghidra/Hex-Rays benchmarking (SURE 2025) — 反编译器6%复合类型恢复率
from __future__ import annotations
import logging
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)


@dataclass
class InferredStruct:
    """推断的结构体布局."""
    struct_id: str
    base_register: str = ""       # 基址寄存器
    total_size: int = 0           # 推断的总大小
    fields: List[Tuple[int, int, str]] = field(default_factory=list)
    # [(offset, size, access_type)]; access_type: 'r'|'w'|'rw'
    vtable_offset: int = -1       # 虚表指针偏移 (-1=无)
    confidence: float = 0.0


@dataclass
class VTableInfo:
    """虚表信息."""
    vtable_addr: int = 0
    num_entries: int = 0
    function_addrs: List[int] = field(default_factory=list)
    parent_class: str = ""


class BinaryTypeInference:
    """从二进制内存访问模式推断类型信息.

    输入: 指令trace (每行一条内存访问指令) 或 结构化内存访问记录
    输出: 推断的结构体布局和虚表信息
    """

    _MEM_ACCESS = re.compile(
        r'(?:mov|lea|add|sub|cmp|test)\s+.*?'
        r'\[(\w+)\s*(?:([+-])\s*(0x[0-9a-fA-F]+|\d+))?\s*\]')
    _VTABLE_INIT = re.compile(
        r'(?:mov|lea)\s+.*?\[(\w+)\]\s*,.*?(0x[0-9a-fA-F]+)')
    _STRIDE_PATTERN = re.compile(
        r'(?:add|sub|lea)\s+(\w+)\s*,\s*(0x[0-9a-fA-F]+|\d+)')

    def infer_from_trace(self, trace_lines: List[str]
                         ) -> List[InferredStruct]:
        base_offsets: Dict[str, List[Tuple[int, int, str]]] = defaultdict(list)
        for line in trace_lines:
            m = self._MEM_ACCESS.search(line)
            if not m:
                continue
            base = m.group(1)
            sign = m.group(2) or '+'
            off_val = int(m.group(3), 16 if '0x' in (m.group(3) or '') else 10) if m.group(3) else 0
            offset = off_val if sign == '+' else -off_val
            access_size = self._infer_access_size(line)
            access_type = 'w' if 'mov [' in line.lower() or 'mov[' in line.lower() else 'r'
            base_offsets[base].append((offset, access_size, access_type))
        structs = []
        for base, accesses in base_offsets.items():
            if len(accesses) < 2:
                continue
            s = self._cluster_offsets(base, accesses)
            if s.total_size > 0:
                structs.append(s)
        return structs

    def _cluster_offsets(self, base: str,
                         accesses: List[Tuple[int, int, str]]
                         ) -> InferredStruct:
        """将偏移聚类为结构体字段.

        算法: 按偏移排序→合并相邻偏移 (间距≤8→同一字段, 间距>8→新字段).
        字段大小推断: 取该偏移上的最大访问宽度.
        """
        unique = {}
        for off, size, atype in accesses:
            key = off
            if key in unique:
                prev_size, prev_type = unique[key]
                unique[key] = (max(prev_size, size),
                              'rw' if prev_type != atype else atype)
            else:
                unique[key] = (size, atype)
        sorted_offs = sorted(unique.keys())
        if not sorted_offs:
            return InferredStruct(struct_id=f"struct_{base}", base_register=base)
        # 合并近邻偏移
        fields = []
        cluster_start = sorted_offs[0]
        cluster_size, cluster_type = unique[cluster_start]
        for i in range(1, len(sorted_offs)):
            curr = sorted_offs[i]
            gap = curr - (cluster_start + cluster_size)
            if gap <= 8:
                cluster_size = curr + unique[curr][0] - cluster_start
                if unique[curr][1] != cluster_type:
                    cluster_type = 'rw'
            else:
                fields.append((cluster_start, cluster_size, cluster_type))
                cluster_start = curr
                cluster_size, cluster_type = unique[curr]
        fields.append((cluster_start, cluster_size, cluster_type))
        # 结构体总大小: 最后一个字段的结束偏移
        total = fields[-1][0] + fields[-1][1] if fields else 0
        conf = min(1.0, len(accesses) / 20.0)  # 访问越多置信度越高
        return InferredStruct(struct_id=f"struct_{base}",
                             base_register=base, total_size=total,
                             fields=fields, confidence=conf)

    def detect_vtables(self, trace_lines: List[str],
                       known_functions: Optional[Dict[int, str]] = None
                       ) -> List[VTableInfo]:
        """检测虚表: 连续函数指针数组+构造时初始化到对象头部."""
        vtables = []
        func_addrs: List[int] = []
        for line in trace_lines:
            m = self._VTABLE_INIT.search(line)
            if m:
                base = m.group(1)
                addr = int(m.group(2), 16)
                if known_functions and addr in known_functions:
                    func_addrs.append(addr)
            if not func_addrs:
                continue
        if len(func_addrs) >= 2:
            vtables.append(VTableInfo(
                vtable_addr=0, num_entries=len(func_addrs),
                function_addrs=func_addrs))
        return vtables

    def detect_array_stride(self, trace_lines: List[str]
                            ) -> Dict[str, int]:
        """检测数组步幅: 循环中的指针增量模式.

        返回: {base_reg: stride_size}.
        """
        strides = defaultdict(list)
        for line in trace_lines:
            m = self._STRIDE_PATTERN.search(line)
            if m:
                reg = m.group(1)
                val = int(m.group(2), 16 if '0x' in m.group(2) else 10)
                if 1 <= val <= 1024:
                    strides[reg].append(val)
        result = {}
        for reg, vals in strides.items():
            if len(vals) < 2:
                continue
            counter = Counter(vals)
            most_common = counter.most_common(1)[0]
            if most_common[1] >= len(vals) * 0.4:
                result[reg] = most_common[0]
        return result

    def _infer_access_size(self, line: str) -> int:
        """从指令助记符推断内存访问宽度."""
        lowered = line.lower().strip()
        if 'qword' in lowered or 'movq' in lowered:
            return 8
        if 'dword' in lowered or 'movl' in lowered or 'mov dword' in lowered:
            return 4
        if 'word' in lowered or 'movw' in lowered:
            return 2
        if 'byte' in lowered or 'movb' in lowered:
            return 1
        # 寄存器宽度推断
        if re.search(r'(?:rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r\d+)', lowered):
            return 8
        if re.search(r'(?:eax|ebx|ecx|edx|esi|edi|ebp|esp)', lowered):
            return 4
        return 4  # 默认假设32-bit

    def summarize_for_exploitation(self,
                                    structs: List[InferredStruct]
                                    ) -> Dict[str, Dict]:
        """将类型推断结果转换为利用策略相关信息."""
        summary = {}
        for s in structs:
            # 找出可利用的字段: 可写的函数指针 (虚表) / 可写的大小字段 / 相邻缓冲区
            exploitable = []
            for off, size, atype in s.fields:
                if atype == 'rw' and size >= 8:
                    exploitable.append({
                        "offset": off, "size": size,
                        "use": "write_target" if off == s.vtable_offset
                        else "overflow_adjacent"})
            summary[s.struct_id] = {
                "base_reg": s.base_register,
                "total_size": s.total_size,
                "field_count": len(s.fields),
                "has_vtable": s.vtable_offset >= 0,
                "exploitable_fields": exploitable,
                "confidence": round(s.confidence, 3),
            }
        return summary
