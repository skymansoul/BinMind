# UAF 后处理与统计.
# 职责: 多阶段后过滤(去重/CRT/nulled/路径) + 全局变量延迟free扫描 + 统计输出
# 集成 GlobalFreeScanner 补检跨函数全局变量 UAF

from collections import defaultdict
from typing import Dict, List, Tuple

from .uaf_global_free_scanner import GlobalFreeScanner
from .uaf_local_free_deref import LocalFreeDerefScanner
from .uaf_provenance import UAFProvenanceFilter


class UAFFinalizer:
    """UAF检测结果后处理器."""

    def __init__(self, detector):
        self._det = detector
        self._global_scanner = GlobalFreeScanner(detector)
        self._local_scanner = LocalFreeDerefScanner(detector)
        self._ulp_filter = UAFProvenanceFilter()

    def finalize(self, instructions: List[dict]) -> List[dict]:
        """多阶段后过滤: 全局free补检→去重→CRT过滤→nulled过滤→路径互斥过滤."""
        # 全局变量延迟 free 补检
        global_findings = self._global_scanner.scan(instructions)
        if global_findings:
            for f in global_findings:
                oid = f.get("obj_id")
                if oid is not None and oid in self._det._objects:
                    obj = self._det._objects[oid]
                    if f["address"] not in obj.use_after_free_at:
                        obj.use_after_free_at.append(f["address"])
                    self._det._findings.append(f)

        # 同函数内寄存器级 free→deref 补检
        local_findings = self._local_scanner.scan(instructions)
        if local_findings:
            for f in local_findings:
                oid = f.get("obj_id")
                if oid is not None and oid in self._det._objects:
                    obj = self._det._objects[oid]
                    if f["address"] not in obj.use_after_free_at:
                        obj.use_after_free_at.append(f["address"])
                    self._det._findings.append(f)

        groups: Dict[Tuple[int, int], List[dict]] = defaultdict(list)
        for f in self._det._findings:
            groups[(f.get("obj_id", 0), f.get("freed_at", 0))].append(f)

        deduped = []
        for (oid, freed_at), group in groups.items():
            derefs = [f for f in group if "deref_reg" in f]
            if derefs:
                derefs.sort(key=lambda f: f.get("instr_gap", 999999))
                deduped.append(derefs[0])
            else:
                group.sort(key=lambda f: f.get("instr_gap", 999999))
                deduped.append(group[0])

        filtered = []
        for f in deduped:
            addr = f.get("address", 0)
            obj_id = f.get("obj_id")
            if self._det._is_crt_code(addr):
                continue
            if obj_id is not None:
                obj = self._det._objects.get(obj_id)
                # nulled_after_free 仅过滤 NULL 赋值之后的 finding,
                # NULL 之前的使用仍在生命周期内应保留
                if obj and obj.nulled_after_free:
                    if obj.nulled_at is not None and addr < obj.nulled_at:
                        pass
                    elif obj.nulled_at is not None and \
                         self._det._path_analyzer.are_mutually_exclusive(
                             obj.nulled_at, addr):
                        pass
                    else:
                        continue
                if obj and not self._det._is_user_code(obj.alloc_addr):
                    continue
            if not self._det._is_user_code(addr):
                continue
            filtered.append(f)

        if getattr(self._det, "_ulp_enabled", True):
            confirmed, suspected, benign = self._ulp_filter.filter(
                filtered, instructions)
            self._det._suspected_findings = suspected
            self._det._benign_findings = benign
            # 只抑制可证明安全(BENIGN); SUSPECTED未证安全, 保留在检出中.
            return confirmed + suspected
        self._det._suspected_findings = []
        self._det._benign_findings = []
        return filtered

    def stats(self) -> dict:
        """生成检测统计摘要."""
        n_freed = sum(1 for o in self._det._objects.values() if o.freed_at)
        n_realloc = sum(1 for o in self._det._objects.values()
                        if o.realloc_count > 0)
        return {
            "objects_allocated": self._det._next_obj_id - 1,
            "objects_freed": n_freed,
            "uaf_detected": len([f for f in self._det._findings
                                 if f["type"] == "use_after_free"]),
            "double_free_detected": len([f for f in self._det._findings
                                         if f["type"] == "double_free"]),
            "realloc_objects": n_realloc,
        }


__all__ = ["UAFFinalizer"]
