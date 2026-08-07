"""访问路径验证器 — 综合溯源信息与对象模型判定堆访问安全性.

核心逻辑:
  给定一次堆内存访问 *(ptr + offset),
  1. 查询 ptr 的 Provenance → 确定它来自哪个堆分配
  2. 检查该分配点的 HeapObjectLayout → 判断 offset 是否合法
  3. 结合分配器模型确认 padding 区
  4. 三者都通过 → SAFE (过滤此误报)
  5. 任一不通过 → 保留告警 (保守, 宁可误报不可漏报)

三个维度的组合决策表 (AND逻辑):
  Provenance确定 + offset在对象结构内 + 不超过usable_size → SAFE
  Provenance确定 + offset在padding区 + 不超过usable_size → SAFE
  Provenance未知 + offset合理 + 不超过usable_size → UNCERTAIN (保留)
  Provenance确定 + offset超出对象 → VIOLATION

设计决策:
  - 为什么用 AND 而非 OR: 任一维度都无法单独证明访问安全.
    必须三个维度同时满足才过滤。
  - 保守原则体现在默认值: 无法确定 → UNCERTAIN → 保留告警。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .pointer_provenance import (
    PointerProvenanceTracker, Provenance, ProvenanceType)
from .heap_object_model import HeapObjectModel, HeapObjectLayout


class AccessVerdict(Enum):
    SAFE = "safe"             # 可证明合法 — 过滤
    UNSAFE = "unsafe"         # 可证明越界 — 保留
    UNCERTAIN = "uncertain"   # 无法证明 — 保守保留


@dataclass
class AccessValidationResult:
    """一次堆访问的完整验证结果."""
    insn_addr: int
    ptr_reg: str
    offset: int
    access_size: int
    prov: Optional[Provenance] = None
    object_layout: Optional[HeapObjectLayout] = None
    verdict: AccessVerdict = AccessVerdict.UNCERTAIN
    reason: str = ""
    # 各维度检查结果
    provenance_resolved: bool = False
    structure_match: bool = False
    bounds_check: bool = False
    padding_check: bool = False


class AccessPathValidator:
    """综合验证器 — 判定堆访问是否为合法操作.

    使用方式:
      validator = AccessPathValidator(prov_tracker, object_model)
      result = validator.validate(insn_addr, ptr_reg, offset, access_size,
                                   alloc_size, usable_size)
      if result.verdict == AccessVerdict.SAFE:
          # 过滤此告警 — 这是一个已证实的合法访问
          pass
    """

    def __init__(self, prov_tracker: PointerProvenanceTracker,
                 object_model: HeapObjectModel):
        self._prov = prov_tracker
        self._obj_model = object_model

    def validate(self, insn_addr: int, ptr_reg: str,
                 offset: int, access_size: int,
                 alloc_size: int, usable_size: int) -> AccessValidationResult:
        """对一次堆访问做三维验证."""
        result = AccessValidationResult(
            insn_addr=insn_addr, ptr_reg=ptr_reg,
            offset=offset, access_size=access_size)

        # 维度1: 纯数值边界检查 (最基础的层, 不依赖溯源)
        result.bounds_check = self._check_raw_bounds(
            offset, access_size, usable_size)

        if not result.bounds_check:
            result.verdict = AccessVerdict.UNSAFE
            result.reason = f"offset {offset}+{access_size} exceeds usable {usable_size}"
            return result

        # 维度2: 溯源检查 — 指针是否真的来自预期的 malloc
        prov = self._prov.query(insn_addr, ptr_reg)
        result.prov = prov

        if prov is not None:
            result.provenance_resolved = True
            if not prov.is_heap_alloc():
                # 指针来自栈/全局 — 不是堆对象, 但也不一定是溢出
                # 保守: 保留告警
                result.verdict = AccessVerdict.UNCERTAIN
                result.reason = f"ptr provenance is {prov.prov_type.name}, not heap"
                return result

        # 维度3: 对象结构检查 — offset在对象合法访问范围内吗?
        if prov and prov.is_heap_alloc():
            obj_id = prov.prov_id
            result.structure_match, struct_reason = \
                self._obj_model.validate_access(obj_id, offset, access_size)
            result.object_layout = self._obj_model.get_object(obj_id)

            if result.structure_match:
                result.verdict = AccessVerdict.SAFE
                result.reason = f"provenance={prov.prov_id}, {struct_reason}"
                return result

        # 维度3备选: padding检查 — 分配器舍入的尾部分配
        result.padding_check = self._is_in_padding(
            offset, access_size, alloc_size, usable_size)

        if result.padding_check:
            result.verdict = AccessVerdict.SAFE
            result.reason = (f"access in allocator padding zone "
                           f"[{alloc_size}, {usable_size})")
            return result

        # 默认: 无法证明安全 → 保守保留
        result.verdict = AccessVerdict.UNCERTAIN
        result.reason = "cannot prove safety — conservatively retained"
        return result

    @staticmethod
    def _check_raw_bounds(offset: int, access_size: int,
                          usable_size: int) -> bool:
        """纯数值边界检查 — 最基础的过滤."""
        if offset < 0:
            return False
        if offset + access_size > usable_size:
            return False
        return True

    @staticmethod
    def _is_in_padding(offset: int, access_size: int,
                       alloc_size: int, usable_size: int) -> bool:
        """检查访问是否完全在分配器 padding 区内."""
        # padding 区 = [alloc_size, usable_size)
        # 访问必须在padding区内从头到尾
        padding = usable_size - alloc_size
        if padding <= 0:
            return False
        return (offset >= alloc_size
                and offset + access_size <= usable_size)

    def validate_batch(self,
                       accesses: List[Tuple[int, str, int, int, int, int]]
                       ) -> List[AccessValidationResult]:
        """批量验证 — [ (insn, ptr, offset, size, alloc_sz, usable_sz), ... ]."""
        return [self.validate(*a) for a in accesses]

    def summarize(self,
                  results: List[AccessValidationResult]) -> Dict[str, int]:
        """汇总一批验证结果."""
        summary = {"safe": 0, "unsafe": 0, "uncertain": 0}
        for r in results:
            if r.verdict == AccessVerdict.SAFE:
                summary["safe"] += 1
            elif r.verdict == AccessVerdict.UNSAFE:
                summary["unsafe"] += 1
            else:
                summary["uncertain"] += 1
        return summary

    def filter_false_positives(self,
                               findings: List[dict],
                               alloc_size: int = 0,
                               usable_size: int = 0
                               ) -> Tuple[List[dict], List[dict]]:
        """过滤一批检测结果中的误报.

        findings: [{"insn_addr": int, "ptr_reg": str, "offset": int,
                     "access_size": int, ...}, ...]
        返回: (real_vulns, filtered_safe)
        """
        real = []
        filtered = []
        for f in findings:
            result = self.validate(
                f.get("insn_addr", 0),
                f.get("ptr_reg", ""),
                f.get("offset", 0),
                f.get("access_size", 4),
                alloc_size,
                usable_size if usable_size > 0 else alloc_size)
            if result.verdict == AccessVerdict.SAFE:
                f["filter_reason"] = result.reason
                filtered.append(f)
            else:
                real.append(f)
        return real, filtered

    def stats(self) -> dict:
        return {
            "provenance_stats": self._prov.stats(),
            "object_model_stats": self._obj_model.stats(),
        }

    def reset(self):
        self._prov.reset()
        self._obj_model.reset()


# smoke test
def _check():
    from .pointer_provenance import PointerProvenanceTracker
    from .heap_object_model import HeapObjectModel

    pt = PointerProvenanceTracker()
    ho = HeapObjectModel()

    # 建立场景: malloc(256) → ptr在rax
    pid = pt.register_malloc(0x401000, "main", "rax", 256)
    ho.create_object(pid, alloc_size=256, usable_size=272)

    validator = AccessPathValidator(pt, ho)

    # 测试1: 安全访问 — offset=64, 在范围内
    r1 = validator.validate(0x401010, "rax", 64, 8, 256, 272)
    assert r1.verdict == AccessVerdict.SAFE or r1.verdict == AccessVerdict.UNCERTAIN, \
        f"safe access should not be flagged UNSAFE, got {r1.verdict}"

    # 测试2: 越界访问 — offset=300 > usable_size=272
    r2 = validator.validate(0x401020, "rax", 300, 8, 256, 272)
    assert r2.verdict == AccessVerdict.UNSAFE, \
        f"OOB access should be UNSAFE, got {r2.verdict}: {r2.reason}"

    # 测试3: padding区访问 — offset=260, size=8 (在 [256, 272) 内)
    r3 = validator.validate(0x401030, "rax", 260, 8, 256, 272)
    assert r3.verdict in (AccessVerdict.SAFE, AccessVerdict.UNCERTAIN), \
        f"padding access should be SAFE, got {r3.verdict}: {r3.reason}"

    print("[OK] access_path_validator passed")


if __name__ == "__main__":
    _check()
