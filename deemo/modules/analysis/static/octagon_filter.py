# Octagon 域误报过滤器 (Octagon FP Filter)
#
# 使用关系型约束消除区间域无法判定的堆溢出告警.
# 作为 finalize 管线的 Stage 3.5 运行,
# 在结构推断之后、FP filter 之前.
#
# 判定逻辑:
#   1. 从 finding 中提取 alloc_size_reg 和 write_size_reg
#   2. 查询 Octagon 域: write_size ≤ alloc_size 是否成立
#   3. 若成立 → 过滤 (安全); 若不成立 → 保留 (可能溢出)
#
# 消除的误报类型:
#   - malloc(x); memcpy(p, src, x) → write = alloc → 安全
#   - malloc(n); memcpy(p, src, n-1) → write < alloc → 安全
#   - malloc(n*4); memcpy(p, src, n*4) → write = alloc → 安全
#
# 创建: 2026-06-24

from typing import Dict, List, Optional

from .octagon_domain import OctagonDomain
from .octagon_builder import OctagonConstraintBuilder


class OctagonFPFilter:
    """关系型抽象域驱动的误报过滤器.

    与 HeapFPFilter 互补:
    - HeapFPFilter Stage 3 用非关系型区间比较, write_size 缺失时跳过
    - OctagonFPFilter 用关系型约束, 即使两者都是未知区间,
      只要能证明 write ≤ alloc 即可过滤
    """

    def __init__(self):
        self._filtered = 0
        self._passed = 0
        self._unknown = 0

    def build_domain(self, instructions: List[dict]
                     ) -> OctagonConstraintBuilder:
        """从指令序列构建 Octagon 域约束."""
        builder = OctagonConstraintBuilder()
        builder.build(instructions)
        return builder

    def filter(self, findings: List[dict],
               builder: OctagonConstraintBuilder) -> List[dict]:
        """用 Octagon 域关系约束过滤区间重叠类告警.

        仅处理 heap_overflow_possible 类型 (区间重叠),
        不影响 heap_overflow (确定溢出) 类型.
        """
        survivors = []
        alloc_sites = builder.alloc_sites
        write_sites = builder.write_sites
        domain = builder.domain

        for f in findings:
            ftype = f.get("type", "")
            if ftype != "heap_overflow_possible":
                survivors.append(f)
                continue

            write_addr = f.get("write_addr", 0)
            alloc_addr = f.get("_snapshot_alloc_addr",
                               f.get("alloc_addr", 0))

            alloc_reg = self._find_alloc_reg(
                alloc_addr, alloc_sites, f)
            write_reg = self._find_write_reg(
                write_addr, write_sites, f)

            if alloc_reg is None or write_reg is None:
                self._unknown += 1
                survivors.append(f)
                continue

            result = self._check_relation(domain, alloc_reg, write_reg)
            if result == "safe":
                f["fp_stage"] = "stage3_5_octagon"
                f["fp_reason"] = (
                    f"octagon: {write_reg} ≤ {alloc_reg} "
                    f"(relational constraint)")
                self._filtered += 1
                continue

            self._passed += 1
            survivors.append(f)

        return survivors

    def _find_alloc_reg(self, alloc_addr: int,
                        alloc_sites: Dict[int, str],
                        finding: dict) -> Optional[str]:
        """从分配点查找大小参数寄存器.

        仅从 builder 收集的 alloc_sites 中查找,
        不回退到 size_operand — 否则 alloc_reg 和 write_reg
        会退化为同一寄存器, 导致 _check_relation 误判 safe.
        """
        for site_addr, reg in alloc_sites.items():
            if abs(site_addr - alloc_addr) < 32:
                return reg
        return None

    def _find_write_reg(self, write_addr: int,
                        write_sites: Dict[int, str],
                        finding: dict) -> Optional[str]:
        """从写入点查找大小参数寄存器.

        仅从 builder 收集的 write_sites 中查找,
        不回退到 size_operand — 同 _find_alloc_reg.
        """
        for site_addr, reg in write_sites.items():
            if abs(site_addr - write_addr) < 32:
                return reg
        return None

    def _check_relation(self, domain: OctagonDomain,
                        alloc_reg: str, write_reg: str) -> str:
        """查询 Octagon 域判定 write ≤ alloc 是否成立.

        返回: "safe" (write ≤ alloc), "unknown" (无法判定)

        不对 alloc_reg == write_reg 做 shortcut:
        同一寄存器可能在 alloc 和 write 之间被重新赋值,
        交由域查询根据 DBM 约束判定.
        """
        le = domain.query_le(write_reg, alloc_reg)
        if le is True:
            return "safe"

        diff = domain.query_diff(write_reg, alloc_reg)
        if diff is not None and diff <= 0:
            return "safe"

        return "unknown"

    @property
    def stats(self) -> dict:
        total = self._filtered + self._passed + self._unknown
        return {
            "octagon_filtered": self._filtered,
            "octagon_passed": self._passed,
            "octagon_unknown": self._unknown,
            "total_processed": total,
        }


__all__ = ["OctagonFPFilter"]
