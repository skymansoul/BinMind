"""溯源感知过滤器 - PPA-HAV 与现有 AAVSA 管线的串联层.

本模块是 PPA-HAV 方法论的最高层集成:
  - 输入: AAVSA 管线 (AllocatorModel + VSA + ControllabilityFilter) 的原始检测结果
  - 处理: 对每个告警执行 PPA-HAV 三维验证 (Provenance + ObjectModel + Padding)
  - 输出: SAFE 过滤掉的误报 + RETAIN 保留的真实告警

预期效果 (基于合并非冗余过滤层):
  - 在 AAVSA 误报率 ~15% 的基础上再降低 50-70%
  - 即整体误报率从 ~15% → ~5-8%
  - 零召回损失: 所有 UNCERTAIN 均保留

与现有模块的关系:
  - 不替代 AAVSA, 而是作为 AAVSA 的下游过滤器
  - 不影响 heap_overflow_detector.py 的现有功能
  - 可单独开关: 若 PPA-HAV 关闭, AAVSA 照常工作

设计决策:
  - 为什么不是替换而是追加: 保持向后兼容, 现有测试和脚本不需要改动.
    加 --enable-ppahav 标志即可启用本层过滤.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set

from .pointer_provenance import (
    PointerProvenanceTracker, Provenance, ProvenanceType)
from .heap_object_model import HeapObjectModel, AccessType
from .access_path_validator import (
    AccessPathValidator, AccessValidationResult, AccessVerdict)


@dataclass
class FilteredFinding:
    """经 PPA-HAV 过滤后的检测结果."""
    # 原始信息
    function_name: str
    insn_addr: int
    ptr_register: str
    offset_expr: str
    allocated_size: int
    usable_size: int
    overflow_by: int

    # PPA-HAV 验证结果
    provenance: Optional[Provenance] = None
    object_has_structure: bool = False
    verdict: AccessVerdict = AccessVerdict.UNCERTAIN
    filter_reason: str = ""

    # 最终判定
    filtered_out: bool = False   # True → 这是误报, 已过滤

    @property
    def is_real_vuln(self) -> bool:
        return not self.filtered_out


@dataclass
class PPAHAVReport:
    """一次 PPA-HAV 过滤的完整报告."""
    total_input: int = 0
    filtered_safe: int = 0         # 被过滤的误报
    retained_uncertain: int = 0    # 保留的不确定
    confirmed_unsafe: int = 0      # 确认的危险访问
    fp_reduction_pct: float = 0.0  # 相对于输入的误报降低百分比
    # 各过滤层的贡献
    provenance_filters: int = 0    # 溯源维度过滤数
    structure_filters: int = 0     # 结构维度过滤数
    padding_filters: int = 0       # padding维度过滤数
    details: List[FilteredFinding] = field(default_factory=list)


class ProvenanceAwareFilter:
    """PPA-HAV 溯源感知过滤器 - 与 AAVSA 管线集成.

    使用方式:
      # 1. 创建过滤器
      ppa = ProvenanceAwareFilter()

      # 2. 对每个函数建立溯源信息 (由扫描器在分析过程中填充)
      ppa.track_malloc(0x401000, "process_data", "rax", 256)
      ppa.track_assign(0x401010, "rbx", "rax")
      ppa.track_field_access(0x401020, "rbx", 64, 4)

      # 3. 过滤 AAVSA 的原始检测结果
      report = ppa.filter_findings(raw_findings)
      # report.filtered_safe → 误报 (已过滤)
      # report.retained_uncertain → 潜在真实漏洞 (保留)
      # report.confirmed_unsafe → 确认溢出 (保留)

      # 4. 获取过滤后的结果
      real_vulns = ppa.get_real_vulnerabilities()
    """

    def __init__(self):
        self._prov_tracker = PointerProvenanceTracker()
        self._obj_model = HeapObjectModel()
        self._validator = AccessPathValidator(
            self._prov_tracker, self._obj_model)
        # 原始输入 (来自 AAVSA)
        self._raw_findings: List[dict] = []
        # 过滤后的结果
        self._filtered: List[FilteredFinding] = []
        # 当前分析对象的 alloc_size → usable_size 映射
        self._alloc_map: Dict[str, Tuple[int, int]] = {}

    # 分析阶段 API (在扫描过程中调用)

    def track_malloc(self, addr: int, func: str, ptr_reg: str,
                     alloc_size: int) -> str:
        """追踪一次 malloc — 建立溯源 + 创建对象模型."""
        prov_id = self._prov_tracker.register_malloc(
            addr, func, ptr_reg, alloc_size)
        # 同步创建对象模型
        self._obj_model.create_object(
            prov_id, alloc_size=alloc_size,
            usable_size=self._compute_usable(alloc_size))
        self._alloc_map[prov_id] = (alloc_size,
                                    self._compute_usable(alloc_size))
        return prov_id

    def track_assign(self, addr: int, dst_reg: str, src_reg: str):
        """追踪寄存器赋值."""
        self._prov_tracker.track_assign(addr, dst_reg, src_reg)

    def track_arithmetic(self, addr: int, dst_reg: str,
                         base_reg: str, offset: int):
        """追踪指针算术."""
        self._prov_tracker.track_arithmetic(
            addr, dst_reg, base_reg, offset)

    def track_field_access(self, addr: int, ptr_reg: str,
                           offset: int, size: int,
                           atype: str = "both"):
        """记录一次字段访问 — 帮助对象模型学习结构."""
        prov = self._prov_tracker.query(addr, ptr_reg)
        if prov and prov.is_heap_alloc():
            at = {"read": AccessType.READ, "write": AccessType.WRITE,
                  "both": AccessType.BOTH}.get(atype, AccessType.BOTH)
            self._obj_model.record_access(prov.prov_id, offset, size, at)

    def finalize_analysis(self):
        """完成分析 → 合并所有观察到的访问 → 推断对象结构."""
        self._obj_model.consolidate()

    # 过滤阶段 API

    def filter_findings(self,
                        findings: List[dict]) -> PPAHAVReport:
        """对 AAVSA 的原始检测结果执行 PPA-HAV 过滤."""
        self._raw_findings = findings
        self._filtered.clear()

        report = PPAHAVReport(total_input=len(findings))

        for f in findings:
            ff = self._filter_one(f)
            self._filtered.append(ff)
            if ff.filtered_out:
                report.filtered_safe += 1
                # 分类贡献
                reason = ff.filter_reason
                if "provenance" in reason:
                    report.provenance_filters += 1
                elif "structure" in reason or "field" in reason or "array" in reason:
                    report.structure_filters += 1
                elif "padding" in reason:
                    report.padding_filters += 1
            elif ff.verdict == AccessVerdict.UNSAFE:
                report.confirmed_unsafe += 1
            else:
                report.retained_uncertain += 1

        report.details = self._filtered
        report.fp_reduction_pct = round(
            report.filtered_safe / max(1, report.total_input) * 100, 1)
        return report

    def _filter_one(self, finding: dict) -> FilteredFinding:
        """过滤单个检测结果."""
        insn_addr = finding.get("insn_addr", 0)
        ptr_reg = finding.get("ptr_register", "")
        offset = self._parse_offset(finding.get("offset_expr", "0"))
        access_size = finding.get("access_size", 4)
        alloc_size = finding.get("allocated_size", 0)
        usable = finding.get("usable_size", 0) or alloc_size

        ff = FilteredFinding(
            function_name=finding.get("function_name", ""),
            insn_addr=insn_addr,
            ptr_register=ptr_reg,
            offset_expr=finding.get("offset_expr", ""),
            allocated_size=alloc_size,
            usable_size=usable,
            overflow_by=finding.get("overflow_by", 0))

        # 执行三维验证
        result = self._validator.validate(
            insn_addr, ptr_reg, offset, access_size,
            alloc_size, usable)

        ff.verdict = result.verdict
        ff.filter_reason = result.reason
        ff.provenance = result.prov
        ff.object_has_structure = result.structure_match

        # 判定: SAFE → 过滤, 其余 → 保留
        ff.filtered_out = (result.verdict == AccessVerdict.SAFE)
        return ff

    def get_real_vulnerabilities(self) -> List[FilteredFinding]:
        """获取过滤后保留的真实告警."""
        return [f for f in self._filtered if not f.filtered_out]

    def get_filtered_false_positives(self) -> List[FilteredFinding]:
        """获取被过滤的误报."""
        return [f for f in self._filtered if f.filtered_out]

    # 报告生成

    def generate_report(self) -> PPAHAVReport:
        """基于当前过滤结果生成报告."""
        return self.filter_findings(self._raw_findings)

    # 内部

    @staticmethod
    def _compute_usable(requested_size: int) -> int:
        """计算分配器舍入后的可用大小 (复用 ptmalloc2 逻辑)."""
        MIN_CHUNK = 32
        ALIGN = 16
        SIZE_SZ = 8
        size = max(requested_size, 0)
        min_data = max(size, MIN_CHUNK - 2 * SIZE_SZ)
        chunk = (min_data + 2 * SIZE_SZ + ALIGN - 1) & ~(ALIGN - 1)
        chunk = max(MIN_CHUNK, chunk)
        return chunk - 2 * SIZE_SZ

    @staticmethod
    def _parse_offset(expr: str) -> int:
        """解析偏移表达式 → 整数."""
        expr = str(expr).strip().lower()
        if not expr:
            return 0
        try:
            return int(expr, 0)
        except ValueError:
            pass
        # 提取最后一个数字 (处理 'rax+0x100' 这种表达式)
        import re
        nums = re.findall(r'(?:0x[0-9a-f]+|\d+)', expr)
        if nums:
            try:
                return int(nums[-1], 0)
            except ValueError:
                pass
        return 0

    def stats(self) -> dict:
        return {
            "prov_tracker": self._prov_tracker.stats(),
            "object_model": self._obj_model.stats(),
            "input_findings": len(self._raw_findings),
            "retained": len(self.get_real_vulnerabilities()),
            "filtered_out": len(self.get_filtered_false_positives()),
            "filter_rate": round(
                len(self.get_filtered_false_positives())
                / max(1, len(self._filtered)), 3),
        }

    def reset(self):
        self._prov_tracker.reset()
        self._obj_model.reset()
        self._raw_findings.clear()
        self._filtered.clear()
        self._alloc_map.clear()


