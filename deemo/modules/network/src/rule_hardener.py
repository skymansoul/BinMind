# 规则硬化器 —— 基于约束间隙分析生成最小修改硬化建议。
#
# 硬化策略:
#   - offset_unbounded → 追加 offset:0;
#   - depth_unbounded → 追加 depth:<content_len+64>;
#   - case_sensitive → 追加 nocase;
#   - pcre_no_anchor → 在pcre前后追加 ^ 和 $
#   - dsize_boundary → 微调dsize阈值包含边界
#
# 每个策略附安全性评估: 过度硬化(如offset过严)可能增加假阴性。

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .adversarial_ids_hardener import (
    Constraint, ConstraintType, EvasionGap, HardeningProposal,
)


class EvasionGapAnalyzer:
    """规避间隙分析器 —— 对每条约束识别攻击者可利用的语义间隙。

    分析维度:
      1. offset/depth缺失: content无位置约束→前置/后置注入
      2. within/distance缺失: 多content间无距离约束→中间注入
      3. nocase缺失: 大小写变换空间
      4. dsize边界: 边界值±1灰色地带
      5. pcre锚点缺失: 无^/$→前缀/后缀绕过
      6. 贪婪量词: .*/.*可能过度吸收中间字符

    规避面大小 = 2^gap_count(各间隙可构造唯一边界绕过载荷的几何均值)。
    """

    def analyze(self, constraints: List[Constraint],
                rule_text: str = "") -> List[EvasionGap]:
        gaps: List[EvasionGap] = []

        for i, c in enumerate(constraints):
            if c.ctype == ConstraintType.CONTENT:
                gaps.extend(self._analyze_content(i, c))
            elif c.ctype == ConstraintType.PCRE:
                gaps.extend(self._analyze_pcre(i, c))
            elif c.ctype in (ConstraintType.DSIZE_MIN, ConstraintType.DSIZE_MAX):
                gaps.extend(self._analyze_dsize(i, c))

        return gaps

    def _analyze_content(self, idx: int, c: Constraint) -> List[EvasionGap]:
        gaps: List[EvasionGap] = []
        mods = c.modifiers

        if 'offset' not in mods:
            pad = b'\x90' * 64
            gap_bytes = pad + (c.value if isinstance(c.value, bytes) else b'')
            gaps.append(EvasionGap(
                constraint_idx=idx,
                gap_type="offset_unbounded",
                description="content缺少offset约束: 可在匹配位置前插入任意字节",
                bypass_payload_preview=gap_bytes[:80],
                severity=0.9,
            ))

        if 'depth' not in mods and 'within' not in mods:
            gaps.append(EvasionGap(
                constraint_idx=idx,
                gap_type="depth_unbounded",
                description="content缺少depth/within约束: 匹配可能在很深的偏移处",
                severity=0.6,
            ))

        if 'nocase' not in mods:
            val = c.value if isinstance(c.value, bytes) else b''
            if any(0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A for b in val):
                gaps.append(EvasionGap(
                    constraint_idx=idx,
                    gap_type="case_sensitive",
                    description="content区分大小写: 大小写变换可绕过",
                    bypass_payload_preview=bytes(
                        b ^ 0x20 if 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A else b
                        for b in val)[:80],
                    severity=0.7,
                ))

        if 'within' not in mods and 'distance' not in mods:
            gaps.append(EvasionGap(
                constraint_idx=idx,
                gap_type="distance_unbounded",
                description="多content间缺少within/distance约束: 可插入任意分隔字节",
                severity=0.5,
            ))

        return gaps

    def _analyze_pcre(self, idx: int, c: Constraint) -> List[EvasionGap]:
        gaps: List[EvasionGap] = []
        pat = str(c.value)

        if not pat.startswith('^') and not pat.startswith('\\A'):
            gaps.append(EvasionGap(
                constraint_idx=idx, gap_type="pcre_no_anchor_start",
                description="pcre缺少起始锚定(^): 前缀注入可绕过",
                severity=0.8,
            ))

        if not pat.endswith('$') and not pat.endswith('\\Z') and not pat.endswith('\\z'):
            gaps.append(EvasionGap(
                constraint_idx=idx, gap_type="pcre_no_anchor_end",
                description="pcre缺少结束锚定($): 后缀注入可绕过",
                severity=0.6,
            ))

        if re.search(r'\.\*|\.\+', pat):
            gaps.append(EvasionGap(
                constraint_idx=idx, gap_type="pcre_greedy_quantifier",
                description="pcre含贪婪量词(.*/.+): 匹配边界不可预测",
                severity=0.4,
            ))

        return gaps

    def _analyze_dsize(self, idx: int, c: Constraint) -> List[EvasionGap]:
        gaps: List[EvasionGap] = []
        thresh = c.value if isinstance(c.value, int) else 0
        if c.ctype == ConstraintType.DSIZE_MIN and thresh > 0:
            gaps.append(EvasionGap(
                constraint_idx=idx, gap_type="dsize_boundary",
                description=f"dsize边界: {thresh-1}字节载荷可绕过{'>' if c.ctype == ConstraintType.DSIZE_MIN else '<'}{thresh}",
                severity=0.3,
            ))
        return gaps


class RuleHardener:
    """规则硬化器 —— 基于间隙分析生成最小修改硬化建议。

    硬化策略有安全性排序: offset>nocase>depth>pcre锚定>dsize。
    过度硬化(如对所有content加offset:0)可能导致假阴性增加。

    规避面估计: 每个未填补间隙 ≈ 2^gap_count种唯一边界绕过。
    实际绕过数可能更多(如并发多间隙组合)，此估计为下界。
    """

    def harden(self, rule_text: str,
               constraints: List[Constraint],
               gaps: List[EvasionGap]) -> HardeningProposal:
        modifications: List[str] = []
        gap_types_covered: Set[str] = set()

        for gap in gaps:
            if gap.gap_type in gap_types_covered:
                continue
            mod = self._gap_to_modification(gap, constraints)
            if mod:
                modifications.append(mod)
                gap_types_covered.add(gap.gap_type)

        hardened = self._build_hardened_preview(rule_text, modifications)

        before = 2 ** len(gaps) if gaps else 1
        remaining_gaps = len(gaps) - len(modifications)
        after = 2 ** max(remaining_gaps, 0)

        sid_match = re.search(r'sid:\s*(\d+)', rule_text)
        sid = int(sid_match.group(1)) if sid_match else 0

        return HardeningProposal(
            rule_sid=sid, original_rule=rule_text.strip(),
            proposed_modifications=modifications,
            hardened_rule_preview=hardened,
            evasion_surface_before=before,
            evasion_surface_after=after,
        )

    def _gap_to_modification(self, gap: EvasionGap,
                              constraints: List[Constraint]) -> Optional[str]:
        if gap.gap_type == "offset_unbounded":
            return "追加 offset:0; —— 强制content从载荷起始处匹配"
        elif gap.gap_type == "depth_unbounded":
            c = constraints[gap.constraint_idx] if gap.constraint_idx < len(constraints) else None
            content_len = len(c.value) if c and isinstance(c.value, bytes) else 16
            return f"追加 depth:{content_len + 64}; —— 限制匹配搜索深度"
        elif gap.gap_type == "case_sensitive":
            return "追加 nocase; —— 启用大小写不敏感匹配"
        elif gap.gap_type == "pcre_no_anchor_start":
            return "pcre模式追加起始锚定 ^ —— 防止前缀注入绕过"
        elif gap.gap_type == "pcre_no_anchor_end":
            return "pcre模式追加结束锚定 $ —— 防止后缀注入绕过"
        elif gap.gap_type == "pcre_greedy_quantifier":
            return "pcre: 考虑将 .* 替换为精确字符类(如 [a-zA-Z0-9]*)"
        elif gap.gap_type == "dsize_boundary":
            return "微调dsize边界值以消除边界规避"
        return None

    def _build_hardened_preview(self, rule_text: str,
                                 modifications: List[str]) -> str:
        modified = rule_text.strip()
        if modified.endswith(';)'):
            insert_pos = modified.rfind(';)')
            comment_mods = '; '.join(
                m.split(' —— ')[0] if ' —— ' in m else m
                for m in modifications
            )
            modified = (modified[:insert_pos] +
                       ' # HARDENED: ' + comment_mods +
                       modified[insert_pos:])
        return modified


def analyze_rule_evasion_surface(rule_text: str) -> Tuple[
    List[Constraint], List[EvasionGap], HardeningProposal
]:
    """便捷入口: 单条规则→约束提取→间隙分析→硬化建议。"""
    from .adversarial_ids_hardener import ConstraintExtractor
    constraints = ConstraintExtractor.extract(rule_text)
    analyzer = EvasionGapAnalyzer()
    gaps = analyzer.analyze(constraints, rule_text)
    hardener = RuleHardener()
    proposal = hardener.harden(rule_text, constraints, gaps)
    return constraints, gaps, proposal


def batch_harden_rules(rule_texts: List[str]) -> Dict[int, HardeningProposal]:
    """批量硬化: 仅返回至少有一个规避间隙的规则。"""
    results: Dict[int, HardeningProposal] = {}
    for rt in rule_texts:
        if not rt.strip() or rt.strip().startswith('#'):
            continue
        _, gaps, proposal = analyze_rule_evasion_surface(rt)
        if gaps and proposal.rule_sid > 0:
            results[proposal.rule_sid] = proposal
    return results


__all__ = [
    "EvasionGapAnalyzer", "RuleHardener",
    "analyze_rule_evasion_surface", "batch_harden_rules",
]
