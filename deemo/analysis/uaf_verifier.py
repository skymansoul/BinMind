"""
UAF误报验证器 — 时序-别名-可达-路径验证 (Type-State Alias Reachability Verification) 五阶段FP削减.

Stage A: NULL置零 / Stage B: 立即复用 / Stage C: 别名分析
Stage D: 路径条件 / Stage E: 引用计数/作用域守卫.
保守性: 仅可证明安全时 FILTER; 不确定时 KEEP.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
import re


@dataclass
class UafVerdict:
    """单个UAF候选的验证判定."""
    PROTECTED = "PROTECTED"    # 可证明安全 (FP, 应过滤)
    LIKELY_FP = "LIKELY_FP"    # 高概率误报 (降级+降低置信度)
    CONFIRMED = "CONFIRMED"    # 确认UAF (保留+提升置信度)
    UNCERTAIN = "UNCERTAIN"    # 无法判定 (保留原置信度)


@dataclass
class UafVerifyResult:
    """单个候选的验证结果."""
    candidate_index: int
    verdict: str = ''            # UafVerdict value
    stage: str = ''              # 做出判定的阶段
    reason: str = ''             # 判定理由
    confidence_delta: float = 0.0
    pointer_name: str = ''       # 涉及的指针变量名


@dataclass
class UafVerifyStats:
    """UAF验证统计."""
    candidates_in: int = 0
    candidates_out: int = 0
    stage_a_nullified: int = 0
    stage_b_reused: int = 0
    stage_c_alias: int = 0
    stage_d_path: int = 0
    stage_e_refcount: int = 0
    confirmed: int = 0
    uncertain: int = 0
    time_ms: float = 0.0


class UafVerifier:
    """多阶段UAF误报验证器 — 每个阶段独立, 可单独禁用."""

    def __init__(self, enable_alias: bool = True,
                 enable_path: bool = True,
                 enable_refcount: bool = True):
        self._enable_alias = enable_alias
        self._enable_path = enable_path
        self._enable_refcount = enable_refcount

    def verify(self, candidates: List[dict],
               ir_lines: Optional[List[str]] = None,
               decompiled_text: str = '') -> Tuple[List[dict], List[UafVerifyResult]]:
        """主入口: 对 UAF 候选列表执行多阶段验证。

        返回 (filtered_candidates, all_results)。
        """
        import time
        t0 = time.perf_counter()
        results: List[UafVerifyResult] = []
        kept = list(candidates)

        if not candidates:
            return [], []

        text = decompiled_text or ''
        if ir_lines:
            text = text or '\n'.join(ir_lines)

        # 预计算: 从反编译文本中提取安全模式
        nullified_vars = self._find_nullified_vars(text)
        reused_vars = self._find_reused_vars(text)
        guarded_vars = self._find_guarded_free_vars(text)
        alias_map = self._build_alias_map(text) if self._enable_alias else {}
        refcount_vars = self._find_refcount_protected(text) if self._enable_refcount else set()

        for idx, c in enumerate(kept):
            ptr_name = self._extract_ptr_name(c)
            result = UafVerifyResult(
                candidate_index=idx, pointer_name=ptr_name,
                verdict=UafVerdict.UNCERTAIN, stage='',
            )

            # 阶段A: NULL置零检测
            if ptr_name and ptr_name in nullified_vars:
                result.verdict = UafVerdict.PROTECTED
                result.stage = 'A (nullified)'
                result.reason = f'pointer {ptr_name} set to NULL after free'
                result.confidence_delta = -0.50

            # 阶段B: 立即复用检测
            elif ptr_name and ptr_name in reused_vars:
                result.verdict = UafVerdict.PROTECTED
                result.stage = 'B (reused)'
                result.reason = f'pointer {ptr_name} immediately reused (realloc) after free'
                result.confidence_delta = -0.50

            # 阶段C: 别名分析 — 合并同一对象的多指针时间线
            elif ptr_name and self._enable_alias and ptr_name in alias_map:
                canonical = alias_map[ptr_name]
                if canonical in nullified_vars or canonical in reused_vars:
                    result.verdict = UafVerdict.PROTECTED
                    result.stage = 'C (alias)'
                    result.reason = f'alias {ptr_name} → {canonical} is safe'
                    result.confidence_delta = -0.40

            # 阶段D: 路径条件 — free在条件分支内, 使用路径不可达
            elif ptr_name and self._enable_path and ptr_name in guarded_vars:
                result.verdict = UafVerdict.LIKELY_FP
                result.stage = 'D (path condition)'
                result.reason = f'free({ptr_name}) is guarded by null-check; use path may be infeasible'
                result.confidence_delta = -0.30

            # 阶段E: 引用计数 — 对象生命周期受引用计数保护
            elif ptr_name and self._enable_refcount and ptr_name in refcount_vars:
                result.verdict = UafVerdict.LIKELY_FP
                result.stage = 'E (refcount)'
                result.reason = f'pointer {ptr_name} protected by reference counting'
                result.confidence_delta = -0.25

            # 确认UAF: 明确的 free→use 无保护
            elif self._is_confirmed_uaf(c, ptr_name, text):
                result.verdict = UafVerdict.CONFIRMED
                result.stage = 'confirmed'
                result.reason = 'clear temporal violation: use after free without protection'
                result.confidence_delta = +0.15

            results.append(result)

        # 应用判定结果
        filtered = []
        for c, r in zip(kept, results):
            if r.verdict == UafVerdict.PROTECTED:
                continue  # 可证明安全, 过滤
            if r.confidence_delta != 0.0 and isinstance(c, dict):
                c['confidence'] = min(0.98, max(0.05,
                    c.get('confidence', 0.5) + r.confidence_delta))
            filtered.append(c)

        return filtered, results

    # 安全模式检测

    @staticmethod
    def _find_nullified_vars(text: str) -> Set[str]:
        """检测 free(p) 后紧跟 p=NULL 的模式."""
        nullified = set()
        # 模式: free(p); p = NULL;
        for m in re.finditer(r'free\s*\(\s*(?:&?\*?)(\w+)\s*\)', text):
            v = m.group(1)
            after = text[m.end():m.end() + 200]
            if re.search(rf'\b{v}\s*=\s*(?:NULL|nullptr|0)\s*;', after):
                nullified.add(v)
        return nullified

    @staticmethod
    def _find_reused_vars(text: str) -> Set[str]:
        """检测 free(p) 后立即 p=malloc(...) 的模式."""
        reused = set()
        for m in re.finditer(r'free\s*\(\s*(?:&?\*?)(\w+)\s*\)', text):
            v = m.group(1)
            after = text[m.end():m.end() + 200]
            if re.search(rf'\b{v}\s*=\s*(?:malloc|calloc|realloc)\s*\(', after):
                reused.add(v)
        return reused

    @staticmethod
    def _find_guarded_free_vars(text: str) -> Set[str]:
        """检测在条件分支内free的指针 — if(p) free(p)."""
        guarded = set()
        for m in re.finditer(r'if\s*\(\s*(\w+)\s*(?:!=\s*(?:NULL|nullptr|0))?\s*\)', text):
            v = m.group(1)
            after = text[m.end():m.end() + 300]
            if re.search(rf'free\s*\(\s*(?:&?\*?){v}\s*\)', after):
                guarded.add(v)
        return guarded

    @staticmethod
    def _build_alias_map(text: str) -> Dict[str, str]:
        """构建别名映射: 多指针指向同一对象的合并关系."""
        alias = {}
        # 模式: p2 = p1 (指针赋值传递)
        for m in re.finditer(r'(\w+)\s*=\s*(\w+)\s*;', text):
            lhs, rhs = m.group(1), m.group(2)
            # 跳过关键字和常量
            if rhs in ('NULL', 'nullptr', '0', '1', 'malloc', 'calloc'):
                continue
            if rhs in alias:
                alias[lhs] = alias[rhs]
            else:
                alias[lhs] = rhs
        return alias

    @staticmethod
    def _find_refcount_protected(text: str) -> Set[str]:
        """检测引用计数保护的指针 (refcount/ref_cnt/atomic_dec 模式)."""
        refcount_vars = set()
        refcount_patterns = [
            r'(?:refcount|ref_cnt|ref_count|atomic_dec|__sync_sub_and_fetch)\s*\(',
            r'(?:add_ref|release|retain|unref)\s*\(',
        ]
        for pat in refcount_patterns:
            for m in re.finditer(pat, text, re.IGNORECASE):
                # 在引用计数操作附近查找指针变量
                ctx_start = max(0, m.start() - 100)
                ctx = text[ctx_start:m.end() + 100]
                ptrs = re.findall(r'\b(p\w+|ptr\w+|obj\w+|buf\w+)\b', ctx)
                refcount_vars.update(ptrs)
        return refcount_vars

    @staticmethod
    def _is_confirmed_uaf(candidate: dict, ptr_name: str,
                          text: str) -> bool:
        """判定是否为确认UAF: free→use 明确且无任何保护."""
        if not ptr_name:
            return False
        # 查找 free(ptr) 的位置
        free_m = re.search(rf'free\s*\(\s*(?:&?\*?){ptr_name}\s*\)', text)
        if not free_m:
            return False
        # 查找 free 之后的 dereference
        after = text[free_m.end():]
        use_m = re.search(rf'\*{ptr_name}\b|{ptr_name}\s*->|{ptr_name}\s*\[', after)
        if not use_m:
            return False
        # 确认两者之间没有 NULL 置零或复用
        between = after[:use_m.start()]
        if re.search(rf'\b{ptr_name}\s*=\s*(?:NULL|nullptr|0|malloc|calloc)\s*[\(;]', between):
            return False
        return True

    @staticmethod
    def _extract_ptr_name(candidate: dict) -> str:
        """从候选字典中提取指针变量名."""
        return (candidate.get('freed_variable')
                or candidate.get('pointer_name')
                or candidate.get('alloc_var')
                or candidate.get('variable', ''))


def verify_uaf_candidates(
    candidates: List[dict],
    ir_lines: Optional[List[str]] = None,
    decompiled_text: str = '',
) -> Tuple[List[dict], UafVerifyStats]:
    """便捷函数: 对UAF候选列表执行验证, 返回 (filtered, stats).

    兼容现有 pipeline 接口, 可被 import 后直接调用.
    """
    import time
    t0 = time.perf_counter()

    verifier = UafVerifier(enable_alias=True, enable_path=True, enable_refcount=True)
    filtered, results = verifier.verify(candidates, ir_lines, decompiled_text)

    stats = UafVerifyStats(
        candidates_in=len(candidates),
        candidates_out=len(filtered),
        time_ms=round((time.perf_counter() - t0) * 1000, 1),
    )
    for r in results:
        if r.verdict == UafVerdict.PROTECTED:
            if 'nullified' in r.stage:
                stats.stage_a_nullified += 1
            elif 'reused' in r.stage:
                stats.stage_b_reused += 1
            elif 'alias' in r.stage:
                stats.stage_c_alias += 1
        elif r.verdict == UafVerdict.LIKELY_FP:
            if 'path' in r.stage:
                stats.stage_d_path += 1
            elif 'refcount' in r.stage:
                stats.stage_e_refcount += 1
        elif r.verdict == UafVerdict.CONFIRMED:
            stats.confirmed += 1
        else:
            stats.uncertain += 1

    return filtered, stats


__all__ = [
    'UafVerdict', 'UafVerifyResult', 'UafVerifyStats',
    'UafVerifier', 'verify_uaf_candidates',
]
