"""
堆形状模型 — 对堆中相邻对象的拓扑关系建模, 判定溢出是否真正威胁关键数据.

核心问题: 即使确认了 A.chunk[i] 的写入偏移 > A.alloc_size, 也不一定构成可利用的
漏洞。若溢出的内容只是覆盖了同一分配器的内部 padding 或未使用的对齐间隙,
实际没有安全影响。现有检测器不考虑"溢出物的目标是谁", 一律告警 → 误报.

方法 (基于 heap layout abstraction):
  1. 将函数内所有 malloc 调用建模为一个 AllocationSequence
  2. 根据分配函数、大小、顺序推断对象间的相对位置 (邻接关系)
  3. 对每次写入, 计算溢出字节数, 然后检查:
     a. 溢出是否超出了当前 chunk 的 glibc 有效边界 (含 padding)
     b. 若超出, 会覆盖哪个相邻对象
     c. 该对象中是否包含可利用字段 (函数指针/vtable/长度字段)
  4. 若无相邻对象或相邻对象不含关键字段 → 降置信度 (exploitability < 0.3)

  - Cod/ISSTA 2024: heap disjointness 的组合式分析 — 我们的简化版
  - ptmalloc2 内存布局: chunks 按分配顺序在 fastbin/tcache 中呈 LIFO 排列
  - Shoshitaishvili et al., "Mechanical Phish" — exploit 可达性建模

局限: 不做指针分析, 邻接推断基于概率而非确定. 对自定义分配器不适用.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from core.allocator_model import effective_chunk_size, AllocatorType

class FieldType(Enum):
    """堆对象的字段类型 — 影响溢出后的利用价值."""
    DATA = "data"                   # 普通数据
    POINTER = "pointer"             # 普通指针
    FUNCTION_PTR = "function_ptr"   # 函数指针 — 最高价值目标
    VTABLE_PTR = "vtable_ptr"       # 虚表指针
    SIZE_LEN = "size_len"           # 长度/大小字段 — 次级价值
    METADATA = "metadata"           # chunk metadata (prev_size/size)

@dataclass
class HeapObject:
    """堆中单个对象的抽象."""
    var_name: str                  # 变量名
    alloc_func: str                # malloc/calloc/realloc
    requested_size: int            # 请求大小
    effective_size: int            # 分配器实际提供的可用字节 (含对齐后)
    order: int                     # 在函数内的分配顺序
    line: int                      # 行号
    fields: List[FieldType] = field(default_factory=list)
    is_freed: bool = False         # 是否已被 free

@dataclass
class HeapShape:
    """一个函数内的堆形状快照 — 所有分配对象的拓扑关系."""
    func_name: str
    objects: List[HeapObject] = field(default_factory=list)
    adjacency: List[Tuple[str, str]] = field(default_factory=list)  # (obj_a, obj_b)
    total_heap_usage: int = 0

@dataclass
class OverflowAssessment:
    """对单次溢出操作的影响评估."""
    source_var: str                # 溢出的源对象
    write_offset: int              # 写入偏移
    write_size: int                # 写入字节数
    overflow_bytes: int            # 超出有效边界的字节数
    adjacent_targets: List[str]    # 可能被覆盖的相邻对象
    critical_fields_hit: int       # 覆盖到的关键字段数
    exploitability: float          # 可利用性评分 [0, 1]
    is_false_positive: bool        # 是否建议过滤
    reasoning: str

class HeapShapeModel:
    """堆形状建模器 — 静态推断堆对象拓扑并评估溢出影响.

    输入: 反编译伪代码或一系列 HeapAllocSite
    输出: HeapShape + OverflowAssessment
    """

    _CRITICAL_VAR_PATTERNS = {
        FieldType.FUNCTION_PTR: {'callback', 'handler', 'fn', 'func', 'fp',
                                 'function_ptr', 'on_', 'hook'},
        FieldType.VTABLE_PTR: {'vtable', 'vptr', 'vtbl', 'virtual'},
        FieldType.SIZE_LEN: {'size', 'len', 'length', 'count', 'n', 'num'},
        FieldType.POINTER: {'ptr', 'p_', 'buf', 'data', 'src', 'dst'},
    }

    def __init__(self, allocator: AllocatorType = AllocatorType.GLIBC_PTMALLOC2):
        self._allocator = allocator

    def build_shape(self, func_name: str,
                    alloc_sites: List[Dict]) -> HeapShape:
        """从分配点列表构建堆形状."""
        shape = HeapShape(func_name=func_name)
        objects = []

        for i, site in enumerate(alloc_sites):
            req_size = site.get('size_arg', site.get('requested', 0))
            if req_size <= 0:
                req_size = site.get('estimated', 16)  # 默认估计

            effective = effective_chunk_size(req_size, self._allocator)
            var_name = site.get('result_var', site.get('var_name', ''))

            obj = HeapObject(
                var_name=var_name,
                alloc_func=site.get('alloc_func', 'malloc'),
                requested_size=req_size,
                effective_size=effective,
                order=i,
                line=site.get('line', site.get('pc', 0)),
                fields=self._infer_fields(var_name, req_size),
            )
            objects.append(obj)
            shape.total_heap_usage += effective

        # 推断邻接关系
        shape.objects = objects
        shape.adjacency = self._infer_adjacency(objects)
        return shape

    def assess_overflow(self, shape: HeapShape,
                        source_var: str,
                        write_offset: int,
                        write_size: int) -> OverflowAssessment:
        """评估单次溢出操作的影响."""
        source_obj = None
        for obj in shape.objects:
            if obj.var_name == source_var:
                source_obj = obj
                break

        if source_obj is None:
            return OverflowAssessment(
                source_var=source_var, write_offset=write_offset,
                write_size=write_size, overflow_bytes=0,
                adjacent_targets=[], critical_fields_hit=0,
                exploitability=0.0, is_false_positive=True,
                reasoning="source object not found in heap shape",
            )

        effective_end = source_obj.effective_size
        write_end = write_offset + write_size
        overflow_bytes = max(0, write_end - effective_end)

        if overflow_bytes == 0:
            return OverflowAssessment(
                source_var=source_var, write_offset=write_offset,
                write_size=write_size, overflow_bytes=0,
                adjacent_targets=[], critical_fields_hit=0,
                exploitability=0.0, is_false_positive=True,
                reasoning=(f"write {write_offset}+{write_size}={write_end}B "
                           f"<= effective chunk {effective_end}B"),
            )

        # 确定溢出会影响哪些相邻对象
        adjacent = self._find_adjacent(shape, source_var)
        critical_hits = self._count_critical_fields(shape, adjacent, overflow_bytes)

        # 可利用性评分
        exploit = self._score_exploitability(
            overflow_bytes, critical_hits, source_obj, adjacent)

        is_fp = (exploit < 0.25)

        return OverflowAssessment(
            source_var=source_var, write_offset=write_offset,
            write_size=write_size, overflow_bytes=overflow_bytes,
            adjacent_targets=adjacent,
            critical_fields_hit=critical_hits,
            exploitability=exploit, is_false_positive=is_fp,
            reasoning=(f"{overflow_bytes}B overflow into {len(adjacent)} adjacent "
                       f"objects, {critical_hits} critical fields hit"),
        )

    # helpers

    @classmethod
    def _infer_fields(cls, var_name: str, size: int) -> List[FieldType]:
        """从变量名推断字段类型."""
        if not var_name:
            return [FieldType.DATA]
        name_lower = var_name.lower()
        fields = []
        for ftype, patterns in cls._CRITICAL_VAR_PATTERNS.items():
            if any(p in name_lower for p in patterns):
                fields.append(ftype)
        if not fields:
            fields.append(FieldType.DATA)
        return fields

    @staticmethod
    def _infer_adjacency(objects: List[HeapObject]) -> List[Tuple[str, str]]:
        """推断对象间的邻接关系 — 连续小分配大概率相邻 (LIFO)."""
        adj = []
        for i in range(len(objects)):
            for j in range(i + 1, min(i + 4, len(objects))):
                a, b = objects[i], objects[j]
                if a.var_name and b.var_name:
                    # 同大小偏好: 更可能在同一 bin → 更高邻接概率
                    if abs(a.effective_size - b.effective_size) <= 8:
                        adj.append((a.var_name, b.var_name))
                    elif (a.effective_size <= 128 and b.effective_size <= 128):
                        adj.append((a.var_name, b.var_name))
        return adj

    def _find_adjacent(self, shape: HeapShape, source_var: str) -> List[str]:
        """找到与源对象相邻的所有对象."""
        targets = []
        for (a, b) in shape.adjacency:
            if a == source_var:
                targets.append(b)
            elif b == source_var:
                targets.append(a)
        return targets

    def _count_critical_fields(self, shape: HeapShape,
                               adjacent_vars: List[str],
                               overflow_bytes: int) -> int:
        """计算溢出覆盖的关键字段数."""
        count = 0
        covered_bytes = overflow_bytes
        obj_map = {o.var_name: o for o in shape.objects}

        for var in adjacent_vars:
            if covered_bytes <= 0:
                break
            obj = obj_map.get(var)
            if obj is None:
                continue
            critical = [f for f in obj.fields
                        if f in (FieldType.FUNCTION_PTR, FieldType.VTABLE_PTR,
                                 FieldType.SIZE_LEN)]
            count += len(critical)
            covered_bytes -= obj.effective_size

        return count

    @staticmethod
    def _score_exploitability(overflow_bytes: int,
                               critical_hits: int,
                               source_obj: HeapObject,
                               adjacent: List[str]) -> float:
        """可利用性评分 — 建模 exploit 开发难度."""
        score = 0.0
        # 至少需要一个指针的溢出量
        if overflow_bytes >= 8:
            score += 0.25
        elif overflow_bytes >= 4:
            score += 0.10
        # 有关键字段可覆盖
        score += min(0.40, critical_hits * 0.20)
        # 有相邻对象 (至少要有可覆盖的目标)
        if adjacent:
            score += 0.15
        # 源对象有指针字段 → 可能先 leaked
        if FieldType.POINTER in source_obj.fields:
            score += 0.10
        return min(1.0, score)

def quick_overflow_assess(alloc_sites: List[Dict],
                          source_var: str,
                          write_offset: int,
                          write_size: int,
                          func_name: str = "") -> OverflowAssessment:
    """便捷接口: 一行完成堆形状 → 溢出评估."""
    model = HeapShapeModel()
    shape = model.build_shape(func_name, alloc_sites)
    return model.assess_overflow(shape, source_var, write_offset, write_size)

__all__ = [
    'FieldType', 'HeapObject', 'HeapShape',
    'OverflowAssessment', 'HeapShapeModel', 'quick_overflow_assess',
]
