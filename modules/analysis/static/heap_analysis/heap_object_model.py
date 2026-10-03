# 堆对象结构模型 - 推断和验证堆分配对象的内部结构.
# 访问模式驱动的启发式对象建模: 从已有访问学习对象结构, 非完整类型恢复.

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class AccessType(Enum):
    READ = "read"
    WRITE = "write"
    BOTH = "both"


@dataclass
class ObjectField:
    """堆对象中推断出的字段."""
    offset: int                     # 相对对象基址的偏移
    size: int                       # 字段大小 (字节)
    access_type: AccessType         # 读/写/都
    access_count: int = 0           # 被访问次数
    stride_hint: int = 0            # 若为数组元素, stride=元素大小
    confidence: float = 0.5         # 这是真实字段的置信度


@dataclass
class ArrayRegion:
    """堆对象中推断出的连续数组区域."""
    start_offset: int
    end_offset: int
    elem_size: int
    base_offset_varies: bool = False  # 索引是否变量化 (如 rax*4)


@dataclass
class HeapObjectLayout:
    """一个堆分配对象的推断结构."""
    obj_id: str                     # 对象ID (关联到 Provenance.prov_id)
    alloc_size: int                 # 用户请求的分配大小
    usable_size: int                # 分配器舍入后的可用大小
    fields: List[ObjectField] = field(default_factory=list)
    arrays: List[ArrayRegion] = field(default_factory=list)
    padding_end: int = 0            # 对象尾部的padding字节数
    alignment: int = 16             # 对齐要求

    def offset_in_fields(self, offset: int, size: int) -> bool:
        """检查 offset+size 是否落在任何已知字段或 padding 内."""
        # 精确匹配已知字段
        for f in self.fields:
            if f.offset == offset and f.size >= size:
                return True
        # 在padding区
        if offset >= self.alloc_size and offset + size <= self.usable_size:
            return True
        return False

    def offset_in_array(self, offset: int) -> Optional[ArrayRegion]:
        """检查 offset 是否在已知数组区域内."""
        for arr in self.arrays:
            if arr.start_offset <= offset < arr.end_offset:
                return arr
        return None

    def is_likely_valid_access(self, offset: int, size: int) -> Tuple[bool, str]:
        """判断某偏移的访问是否 likely valid."""
        # 在已知字段上
        if self.offset_in_fields(offset, size):
            return True, "known_field_or_padding"

        # 在数组区域内
        arr = self.offset_in_array(offset)
        if arr:
            if (offset - arr.start_offset) % arr.elem_size == 0:
                if offset + size <= arr.end_offset:
                    return True, "array_element_access"

        # 在分配器padding内
        if offset >= self.alloc_size and offset + size <= self.usable_size:
            return True, "allocator_padding"

        return False, "no_structure_match"


class HeapObjectModel:
    """堆对象结构推断器 - 从访问模式逆向推导对象布局.

    使用方式:
      model = HeapObjectModel()
      model.create_object("alloc@0x401000", alloc_size=256, usable_size=272)
      model.record_access("alloc@0x401000", offset=0, size=8, atype=AccessType.WRITE)
      model.record_access("alloc@0x401000", offset=0, size=8, atype=AccessType.READ)
      model.record_access("alloc@0x401000", offset=64, size=4, atype=AccessType.WRITE)
      model.consolidate()  # 合并访问模式 → 字段推断
      ok, reason = model.validate_access("alloc@0x401000", offset=64, size=4)
      # → (True, "known_field")
    """

    # 字段推断: 同一偏移被访问超过此阈值 → 认为是一个字段
    FIELD_CONFIDENCE_THRESHOLD = 2
    # 数组推断: 等步长访问次数超过此阈值 → 认为是一个数组
    ARRAY_DETECTION_THRESHOLD = 3

    def __init__(self):
        self._objects: Dict[str, HeapObjectLayout] = {}
        # 原始访问记录: obj_id → [(offset, size, type), ...]
        self._raw_accesses: Dict[str, List[Tuple[int, int, AccessType]]] = {}
        # 对齐检查: obj_id → set of offsets → 计算 GCD 得到 stride hint
        self._offset_sets: Dict[str, Set[int]] = {}

    def create_object(self, obj_id: str, alloc_size: int,
                      usable_size: int = 0, alignment: int = 16):
        """创建一个堆对象记录."""
        usable = usable_size if usable_size > 0 else alloc_size
        self._objects[obj_id] = HeapObjectLayout(
            obj_id=obj_id, alloc_size=alloc_size,
            usable_size=usable,
            padding_end=max(0, usable - alloc_size),
            alignment=alignment)
        self._raw_accesses.setdefault(obj_id, [])
        self._offset_sets.setdefault(obj_id, set())

    def record_access(self, obj_id: str, offset: int, size: int,
                      atype: AccessType = AccessType.BOTH):
        """记录一次对该对象的访问."""
        if obj_id in self._raw_accesses:
            self._raw_accesses[obj_id].append((offset, size, atype))
            self._offset_sets[obj_id].add(offset)

    def consolidate(self):
        """合并原始访问记录 → 推断字段和数组."""
        for obj_id, accesses in self._raw_accesses.items():
            if obj_id not in self._objects:
                continue
            obj = self._objects[obj_id]

            # 聚合: offset→(access_count, sizes, types)
            aggr: Dict[int, Tuple[int, Set[int], Set[AccessType]]] = {}
            for off, sz, at in accesses:
                if off not in aggr:
                    aggr[off] = (0, set(), set())
                cnt, sizes, types = aggr[off]
                aggr[off] = (cnt + 1, sizes | {sz}, types | {at})

            # 字段推断
            obj.fields.clear()
            for off, (cnt, sizes, types) in aggr.items():
                if cnt >= self.FIELD_CONFIDENCE_THRESHOLD:
                    max_sz = max(sizes) if sizes else 4
                    combined_at = (AccessType.BOTH
                                   if len(types) >= 2
                                   else (next(iter(types))
                                         if types else AccessType.BOTH))
                    obj.fields.append(ObjectField(
                        offset=off, size=max_sz,
                        access_type=combined_at,
                        access_count=cnt,
                        confidence=min(0.9, cnt * 0.2)))

            # 数组推断: 分析偏移集合中的等步长模式
            offsets = sorted(self._offset_sets.get(obj_id, set()))
            obj.arrays = self._detect_arrays(offsets)

            # 按偏移排序字段
            obj.fields.sort(key=lambda f: f.offset)

    def validate_access(self, obj_id: str, offset: int,
                        size: int) -> Tuple[bool, str]:
        """验证一次访问是否合法."""
        obj = self._objects.get(obj_id)
        if obj is None:
            return False, "unknown_object"

        # 纯数值边界检查
        if offset < 0:
            return False, "negative_offset"
        if offset + size > obj.usable_size:
            return False, "exceeds_usable_size"

        # 若未 consolidate, 执行轻量检查
        if not obj.fields and not obj.arrays:
            return True, "no_structure_data_conservative_pass"

        return obj.is_likely_valid_access(offset, size)

    def get_object(self, obj_id: str) -> Optional[HeapObjectLayout]:
        return self._objects.get(obj_id)

    def _detect_arrays(self, offsets: List[int]) -> List[ArrayRegion]:
        """从偏移集合检测数组区域."""
        arrays = []
        if len(offsets) < self.ARRAY_DETECTION_THRESHOLD:
            return arrays

        # 计算相邻偏移差 → 找常见步长
        diffs = [offsets[i+1] - offsets[i] for i in range(len(offsets)-1)]
        if not diffs:
            return arrays

        from collections import Counter
        stride_counts = Counter(d for d in diffs if d > 0)
        common_strides = [s for s, c in stride_counts.most_common(3)
                         if c >= 2 and s in (1, 2, 4, 8, 16, 32, 64)]

        for stride in common_strides:
            # 找连续区间: 步长=stride 且覆盖 ≥3 个元素
            stride_offsets = sorted(
                [o for o in offsets
                 if any(abs(o - o2) % stride == 0
                       for o2 in offsets if o2 != o)])
            if len(stride_offsets) < self.ARRAY_DETECTION_THRESHOLD:
                continue
            arr = ArrayRegion(
                start_offset=min(stride_offsets),
                end_offset=max(stride_offsets) + stride,
                elem_size=stride)
            arrays.append(arr)

        return arrays

    def stats(self) -> dict:
        return {
            "objects_modeled": len(self._objects),
            "total_fields_inferred": sum(
                len(o.fields) for o in self._objects.values()),
            "total_arrays_detected": sum(
                len(o.arrays) for o in self._objects.values()),
            "mean_fields_per_object": (
                sum(len(o.fields) for o in self._objects.values())
                / max(1, len(self._objects))),
        }

    def reset(self):
        self._objects.clear()
        self._raw_accesses.clear()
        self._offset_sets.clear()


# smoke test
def _check():
    m = HeapObjectModel()
    m.create_object("alloc@0x401000", alloc_size=256, usable_size=272)

    # 模拟结构体字段访问: offset=0 (多次), offset=64, offset=128
    for _ in range(3):
        m.record_access("alloc@0x401000", 0, 8, AccessType.BOTH)
    m.record_access("alloc@0x401000", 64, 4, AccessType.WRITE)
    m.record_access("alloc@0x401000", 128, 8, AccessType.READ)

    m.consolidate()

    ok, reason = m.validate_access("alloc@0x401000", 0, 8)
    assert ok, f"known field at 0 should pass, got: {reason}"

    ok, reason = m.validate_access("alloc@0x401000", 272, 1)
    assert not ok, f"exceeds usable should fail, got: {reason}"

    # padding区的访问
    ok, reason = m.validate_access("alloc@0x401000", 260, 8)
    assert ok, f"padding region should pass, got: {reason}"

    print("[OK] heap_object_model passed")


if __name__ == "__main__":
    _check()
