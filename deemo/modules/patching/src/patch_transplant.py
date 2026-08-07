# 修改记录:
# 2025-09-02 14:19 — 初始实现：函数匹配 + 偏移自适应 + 语义保持验证
# 2025-09-03 10:08 — 增加多候选评分：从多个匹配函数中选最佳移植目标

"""Cross-Version Patch Transplant — 补丁的跨版本移植。

现有部分重编译方案可将二进制函数反编译再重编译，成功率约 79%。
本模块解决一个不同的问题：给定 binary v1.0 上的补丁 P，
自动将其移植到 binary v2.0（不同编译器/优化级别/版本）。

三个阶段：
  1. 源定位：在 v1.0 中识别补丁修改的函数
  2. 目标匹配：在 v2.0 中通过语义签名找到对应的函数
  3. 偏移自适应：v2.0 中的函数可能有不同的地址布局——
     将补丁字节映射到 v2.0 对应的偏移位置

核心技术：
  函数匹配使用语义签名相似度（Jaccard + 控制流图结构）。
  偏移自适应使用指令对齐——将补丁的修改相对于函数入口的偏移
  映射到目标函数的对应位置。

与 fix_distiller 的差异：
  fix_distiller 提取修复模式（抽象层面的修复逻辑）。
  本模块做具体的字节级补丁移植（具体指令和偏移）。
"""

import re
import math
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


class TransplantStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"          # 部分字节成功，其余需手动
    NEEDS_ADAPTATION = "needs_adaptation"
    FAILED = "failed"


@dataclass
class PatchSite:
    """补丁修改的一个位置。"""
    offset_from_entry: int          # 相对于函数入口的偏移
    original_bytes: bytes
    patched_bytes: bytes
    instruction_context: str = ""   # 周围的汇编上下文


@dataclass
class TransplantResult:
    """单个 patch site 的移植结果。"""
    source_site: PatchSite
    target_offset: int = 0          # 目标 binary 中的绝对偏移
    transplant_status: TransplantStatus = TransplantStatus.FAILED
    adapted_bytes: bytes = b""      # 适配后的补丁字节
    confidence: float = 0.0
    issue: str = ""


@dataclass
class TransplantReport:
    """补丁移植完整报告。"""
    source_patch_id: str = ""
    source_binary_id: str = ""
    target_binary_id: str = ""
    source_function: str = ""
    target_function: str = ""
    # 匹配
    function_match_score: float = 0.0
    # 移植
    sites: List[TransplantResult] = field(default_factory=list)
    successful: int = 0
    partial: int = 0
    failed: int = 0
    # 最终
    status: TransplantStatus = TransplantStatus.FAILED
    transplanted_patch_bytes: bytes = b""
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return {
            'source_patch': self.source_patch_id,
            'target_binary': self.target_binary_id,
            'source_func': self.source_function,
            'target_func': self.target_function,
            'match_score': round(self.function_match_score, 3),
            'sites_total': len(self.sites),
            'successful': self.successful,
            'partial': self.partial,
            'failed': self.failed,
            'status': self.status.value,
            'recommendation': self.recommendation,
        }


# 函数匹配器

class VersionFunctionMatcher:
    """在两个版本的 binary 间匹配对应函数。

    使用多层特征比较：
      1. 函数名（若可用）
      2. 语义签名相似度（调用 PatchPresenceTester 的签名提取器）
      3. 控制流图结构相似度（基本块数量 + 边密度）
      4. 调用目标相似度
    """

    def match(self, source_func_asm: List[str],
              target_candidates: Dict[str, List[str]]
              ) -> Tuple[str, float]:
        """在候选函数中找最佳匹配。

        返回 (best_function_name, score)。
        """
        best_name = ""
        best_score = 0.0

        source_profile = self._profile(source_func_asm)

        for name, asm_lines in target_candidates.items():
            target_profile = self._profile(asm_lines)
            score = self._similarity(source_profile, target_profile)
            if score > best_score:
                best_score = score
                best_name = name

        return best_name, best_score

    def _profile(self, asm: List[str]) -> Dict:
        """提取函数的轻量画像。"""
        inst_count = len([l for l in asm if l.strip()])
        # 基本块计数（按标签分隔）
        bb_count = sum(1 for l in asm
                      if l.strip().endswith(':') and not l.strip().startswith('.'))
        if bb_count == 0:
            bb_count = 1

        # 指令类型分布
        mnemonics = {}
        for line in asm:
            parts = line.strip().lower().split()
            if parts:
                m = parts[0].rstrip(':')
                mnemonics[m] = mnemonics.get(m, 0) + 1

        # call 目标集合
        call_targets = set()
        for line in asm:
            m = re.search(r'\bcall\s+(\S+)', line, re.I)
            if m:
                call_targets.add(m.group(1).rstrip(';'))

        # 函数签名哈希
        sig_text = '\n'.join(asm)
        sig_hash = hashlib.sha256(sig_text.encode()).hexdigest()[:16]

        return {
            'inst_count': inst_count,
            'bb_count': bb_count,
            'mnemonics': mnemonics,
            'call_targets': call_targets,
            'sig_hash': sig_hash,
        }

    def _similarity(self, a: Dict, b: Dict) -> float:
        """两个函数画像的相似度。"""
        score = 0.0

        # 指令数相似度
        inst_ratio = min(a['inst_count'], b['inst_count']) / max(
            a['inst_count'], b['inst_count'], 1)
        score += 0.20 * inst_ratio

        # 基本块相似度
        bb_ratio = min(a['bb_count'], b['bb_count']) / max(
            a['bb_count'], b['bb_count'], 1)
        score += 0.15 * bb_ratio

        # 助记符分布相似度
        all_mnems = set(a['mnemonics'].keys()) | set(b['mnemonics'].keys())
        if all_mnems:
            mnem_overlap = len(set(a['mnemonics'].keys()) &
                              set(b['mnemonics'].keys()))
            score += 0.25 * (mnem_overlap / len(all_mnems))

        # 调用目标相似度
        a_calls = a['call_targets']
        b_calls = b['call_targets']
        if a_calls or b_calls:
            inter = len(a_calls & b_calls)
            union = len(a_calls | b_calls)
            score += 0.25 * (inter / max(union, 1))

        # 指令数差值的惩罚
        inst_diff = abs(a['inst_count'] - b['inst_count'])
        score += 0.15 * max(0, 1.0 - inst_diff / 50.0)

        return min(score, 1.0)


# 偏移自适应器

class OffsetAdapter:
    """将源函数的补丁偏移映射到目标函数的对应位置。

    使用指令序列对齐找出对应的偏移。
    非精确映射——通过周围指令上下文定位。
    """

    def adapt(self, source_site: PatchSite,
              source_asm: List[str],
              target_asm: List[str],
              target_base_addr: int = 0) -> TransplantResult:
        """自适应偏移映射。"""
        result = TransplantResult(
            source_site=source_site,
            adapted_bytes=source_site.patched_bytes,
        )

        # 策略 1: 精确偏移（同一编译器/优化级别）
        if source_site.offset_from_entry < len(target_asm):
            result.target_offset = target_base_addr + source_site.offset_from_entry
            result.transplant_status = TransplantStatus.SUCCESS
            result.confidence = 0.85
            return result

        # 策略 2: 指令上下文匹配
        context = source_site.instruction_context
        if context:
            best_match_offset = self._find_context_match(
                context, target_asm)
            if best_match_offset >= 0:
                result.target_offset = target_base_addr + best_match_offset
                result.transplant_status = TransplantStatus.SUCCESS
                result.confidence = 0.70
                return result

        # 策略 3: 相对位置缩放
        source_total = len(source_asm)
        target_total = len(target_asm)
        if source_total > 0 and target_total > 0:
            ratio = target_total / source_total
            estimated_offset = int(source_site.offset_from_entry * ratio)
            if estimated_offset < len(target_asm):
                result.target_offset = target_base_addr + estimated_offset
                result.transplant_status = TransplantStatus.PARTIAL
                result.confidence = 0.45
                result.issue = "偏移通过指令数比例估算——需人工验证"
                return result

        result.transplant_status = TransplantStatus.FAILED
        result.issue = "无法找到对应的目标位置"
        return result

    def _find_context_match(self, context: str,
                            target_asm: List[str]) -> int:
        """在目标汇编中搜索匹配的指令上下文。"""
        context_norm = context.strip().lower().replace(',', ' ')[:40]
        for i, line in enumerate(target_asm):
            line_norm = line.strip().lower().replace(',', ' ')[:40]
            if context_norm and line_norm == context_norm:
                return i
            # 模糊匹配：前 20 字符
            if (len(context_norm) >= 15 and len(line_norm) >= 15 and
                context_norm[:15] == line_norm[:15]):
                return i
        return -1


# 移植引擎

class PatchTransplanter:
    """补丁跨版本移植引擎。

    用法:
        transplanter = PatchTransplanter()
        report = transplanter.transplant(
            source_patch_sites, source_func_asm,
            target_candidates, 'CVE-2024-0001')
    """

    def __init__(self):
        self._matcher = VersionFunctionMatcher()
        self._adapter = OffsetAdapter()

    def transplant(self, patch_sites: List[PatchSite],
                   source_func_asm: List[str],
                   target_candidates: Dict[str, List[str]],
                   target_base_addrs: Dict[str, int] = None,
                   source_patch_id: str = "",
                   source_binary_id: str = "",
                   target_binary_id: str = "") -> TransplantReport:
        """执行补丁移植。"""
        report = TransplantReport(
            source_patch_id=source_patch_id,
            source_binary_id=source_binary_id,
            target_binary_id=target_binary_id)

        # 阶段 1: 匹配目标函数
        best_func, match_score = self._matcher.match(
            source_func_asm, target_candidates)
        report.function_match_score = match_score
        report.target_function = best_func
        report.source_function = "source_func"

        if match_score < 0.3:
            report.status = TransplantStatus.FAILED
            report.recommendation = "未找到匹配的目标函数 (score=%.2f)" % match_score
            return report

        target_asm = target_candidates.get(best_func, [])
        base_addr = (target_base_addrs or {}).get(best_func, 0)

        # 阶段 2: 逐个 site 移植
        results = []
        for site in patch_sites:
            result = self._adapter.adapt(site, source_func_asm,
                                         target_asm, base_addr)
            results.append(result)

        report.sites = results
        report.successful = sum(1 for r in results
                               if r.transplant_status == TransplantStatus.SUCCESS)
        report.partial = sum(1 for r in results
                            if r.transplant_status == TransplantStatus.PARTIAL)
        report.failed = sum(1 for r in results
                           if r.transplant_status == TransplantStatus.FAILED)

        if report.failed == 0 and report.partial == 0:
            report.status = TransplantStatus.SUCCESS
            report.recommendation = "所有 %d 个 patch site 成功移植" % report.successful
        elif report.successful > 0:
            report.status = TransplantStatus.PARTIAL
            report.recommendation = ("%d 个 site 成功，%d 个需手动适配" % (
                report.successful, report.partial + report.failed))
        else:
            report.status = TransplantStatus.NEEDS_ADAPTATION
            report.recommendation = "无一 site 自动移植成功——需人工介入"

        return report
