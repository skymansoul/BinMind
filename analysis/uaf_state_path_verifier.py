"""
UAF 时序-别名-可达-路径验证五阶段误报削减验证管线.

时序-别名-可达-路径验证 = Type-state + Alias + Reachability + Path + Sanitization.

五阶段方法 → 已提取至 analysis.uaf_state_path_stages.
本文件保留 UafTarpsVerifier 主类 + verify() 管线编排.

保守性原则: 只在所有层都确认"安全"时才过滤. 任一阶段不确定即保留.

v2: Stage R/P 集成 CFG 级支配关系分析 (UAFDominatorVerifier).
  不再仅用正则扫描, 而是构建基本块CFG → 计算支配树 → 判定free/use关系.
  引入 lengauer-tarjan 支配树 + post-dominator 分析.
  回退策略: CFG构建失败时退回正则匹配, 保证功能不退化.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple

from analysis.uaf_state_path_types import HeapObject, TarpsResult, TarpsVerdict
# 五阶段检查方法 → 已提取至 analysis.uaf_state_path_stages
from analysis.uaf_state_path_stages import (
    check_type_state, check_alias,
    check_reachability, check_path_guard, check_sanitization,
    addr_to_line, extract_freed_ptr,
)

_log = logging.getLogger(__name__)


class UafTarpsVerifier:
    """时序-别名-可达-路径验证五阶段 UAF 误报验证器.

    使用方式:
      verifier = UafTarpsVerifier()
      for candidate in raw_uaf_findings:
          result = verifier.verify(candidate, insns)
          if result.verdict in (TarpsVerdict.DEF_FP, TarpsVerdict.LIKELY_FP):
              pass  # 过滤

    v2: 新增跨函数CFG支持 + Realloc别名悬空检测.
      通过 InterProcCFGBuilder 构建调用图, 在时序-别名-可达-路径验证五阶段之前做跨函数可达性预筛选.
      若 alloc/free/use 分别在不同函数且CG路径不可达 → 直接判定 SAFE.
      Stage A 增强: _check_realloc_dangle 检测 realloc() 导致的对齐别名悬空.

    v3: Stage R/P 集成 CFG级支配关系分析.
      优先使用 UAFDominatorVerifier (iterative fixpoint dominator tree).
      CFG构建失败时退回正则匹配, 保证兼容性.
    """

    def __init__(self, use_interproc: bool = True):
        self._objects: Dict[int, HeapObject] = {}
        self._ptr_aliases: Dict[int, Set[int]] = {}
        self._use_interproc = use_interproc
        # v3: dominator verifier cache — lazy-init per verify() call
        self._dom_verifier = None
        self._dom_result = None

    def clear(self):
        self._objects.clear()
        self._ptr_aliases.clear()

    def verify(self, alloc_site: int, free_site: int, use_site: int,
               insns: List[Tuple[int, str]],
               ir_text: str = "") -> TarpsResult:
        """对单个 UAF 候选执行五阶段验证 (含跨函数预筛选 + CFG支配关系).

        v2: 在五阶段之前, 首先检查跨函数可达性.
          若 alloc/free/use 分属不同函数且 CG 路径不可达 → 直接 SAFE.
        v3: 构建 UAFDominatorVerifier 的CFG → 增强 R/P 阶段.
        """
        result = TarpsResult(alloc_site=alloc_site,
                             free_site=free_site,
                             use_site=use_site)

        # v2: 跨函数可达性预筛选
        if self._use_interproc and ir_text:
            try:
                from analysis.uaf_interproc_utils import enhance_tarps_with_interproc
                should_skip, reason = enhance_tarps_with_interproc(
                    ir_text, alloc_site, free_site, use_site)
                if should_skip:
                    for k in result.stages:
                        result.stages[k] = False
                    result.verdict = TarpsVerdict.DEF_FP
                    result.confidence = 0.02
                    result.reason = reason
                    return result
            except ImportError:
                pass

        # v3: 构建 CFG 级支配关系 (用于 R/P 阶段)
        self._dom_verifier = None
        self._dom_result = None
        if ir_text:
            try:
                from analysis.uaf_dominator_verifier import (
                    UAFDominatorVerifier, DominatorVerdict)
                self._dom_verifier = UAFDominatorVerifier()
                free_line = addr_to_line(free_site, insns)
                use_line = addr_to_line(use_site, insns)
                ptr_var = extract_freed_ptr(free_site, insns)
                if free_line > 0 and use_line > 0:
                    self._dom_result = self._dom_verifier.verify(
                        ir_text, free_line, use_line, ptr_var)
            except ImportError:
                pass

        # T: Type-state — 委托给 uaf_state_path_sta
        result.stages['T'] = check_type_state(free_site, use_site, insns)

        # A: Alias — 委托给 uaf_state_path_sta
        result.stages['A'] = check_alias(free_site, use_site, insns)

        # A+: Realloc 别名悬空增强 (双向校正)
        realloc_danger = self._check_realloc_dangle(use_site, insns, ir_text)
        if not result.stages['A'] and realloc_danger:
            result.stages['A'] = True  # realloc 揭示别名危险
        elif result.stages['A'] and self._check_realloc_safe(
                use_site, insns, ir_text):
            result.stages['A'] = False  # realloc 证明变量已更新, 安全

        # R: Reachability — 委托给 uaf_state_path_sta
        result.stages['R'] = check_reachability(
            free_site, use_site, insns, self._dom_result)

        # P: Path condition — 委托给 uaf_state_path_sta
        result.stages['P'] = check_path_guard(use_site, insns, self._dom_result)

        # S: Sanitization — 委托给 uaf_state_path_sta
        result.stages['S'] = check_sanitization(ir_text)

        # 汇总判定
        danger_count = sum(1 for v in result.stages.values() if v)
        safe_count = len(result.stages) - danger_count

        if safe_count == 5:
            result.verdict = TarpsVerdict.DEF_FP
            result.confidence = 0.05
            result.reason = "五阶段全部确认安全"
        elif safe_count >= 3:
            result.verdict = TarpsVerdict.LIKELY_FP
            result.confidence = 0.25
            result.reason = f"{safe_count}/{len(result.stages)} 阶段确认安全"
        elif danger_count >= 3:
            result.verdict = TarpsVerdict.LIKELY_TP
            result.confidence = 0.75
            result.reason = f"{danger_count}/{len(result.stages)} 阶段确认危险"
        elif danger_count == 5:
            result.verdict = TarpsVerdict.DEF_TP
            result.confidence = 0.95
            result.reason = "五阶段全部确认危险"

        return result

    # A+ Realloc helpers (delegated to uaf_realloc_helpers)

    @staticmethod
    def _check_realloc_dangle(use_site: int,
                              insns: List[Tuple[int, str]],
                              ir_text: str = "") -> bool:
        """A+阶段: Realloc 别名悬空检测."""
        from analysis.uaf_realloc_helpers import check_realloc_dangle
        return check_realloc_dangle(use_site, insns, ir_text)

    @staticmethod
    def _check_realloc_safe(use_site: int,
                            insns: List[Tuple[int, str]],
                            ir_text: str = "") -> bool:
        """A+阶段逆向: Realloc 安全更新检测."""
        from analysis.uaf_realloc_helpers import check_realloc_safe
        return check_realloc_safe(use_site, insns, ir_text)


# 向后兼容: 将旧入口函数重定向到新模块
# (这些函数保留在此处供历史导入)
def _check_type_state(alloc_site, free_site, use_site, insns):
    return check_type_state(free_site, use_site, insns)

def _check_alias(alloc_site, free_site, use_site, insns):
    return check_alias(free_site, use_site, insns)

def _check_reachability(free_site, use_site, insns):
    return check_reachability(free_site, use_site, insns)

def _check_path_guard(use_site, insns):
    return check_path_guard(use_site, insns)

def _check_sanitization(alloc_site, free_site, use_site, insns, ir_text):
    return check_sanitization(ir_text)

def _addr_to_line(addr, insns):
    return addr_to_line(addr, insns)

def _extract_freed_ptr(addr, insns):
    return extract_freed_ptr(addr, insns)


__all__ = ['UafTarpsVerifier']
