"""PCFV 判定引擎 — 综合守卫/值流/证明规则输出每个访问的最终判定.

创建: 2023-08-05
设计决策:
  - 判定顺序: 先安全证明(有充分证据才过滤), 再溢出证明(有充分证据才确认),
    两者都无 → LIKELY/UNPROVEN (保守保留, 保召回).
  - 溢出证明中的"用户可控"判定基于 ValueInfo.tainted: 只有 True 才
    构成可控性证据; None(未知)不构成, 但也不构成"不可控"过滤依据.
  - 与基线关键差异: 基线在"未注册数据流边"时按 UNTAINTED 过滤,
    本引擎要求过滤必须携带常量/守卫/分配器padding 证据.
"""
from typing import Dict, List, Optional, Tuple

from .types import (Verdict, ProofRule, Evidence, ValueInfo,
                    FindingVerdict, GuardConstraint, Provenance)
from .proof import SafetyProver, OverflowProver
from .guard_dominance import GuardExtractor
from .alloc import AllocSizeResolver


class PCFVEngine:
    """一次扫描的判定引擎."""

    def __init__(self, rule_enabled: dict = None):
        self.safety = SafetyProver(rule_enabled)
        self.overflow = OverflowProver(rule_enabled)
        self.alloc_resolver = AllocSizeResolver()
        self._stats = {'total': 0, 'safe': 0, 'confirmed': 0,
                       'likely': 0, 'unproven': 0}

    def evaluate_access(self, access: dict, mallocs: List[dict],
                        insns: list,
                        guard_extractor=None,
                        insn_index: dict = None) -> FindingVerdict:
        """对单个访问做完整判定.

        guard_extractor/insn_index: 函数级复用对象 — 每访问点重建
        CFG 是大函数超线性耗时的主源 (scal_4000 245s)."""
        self._stats['total'] += 1
        fv = FindingVerdict(
            sample_id=access.get('sample_id', ''),
            function=access.get('function', ''),
            insn_addr=access.get('addr', 0),
            access_kind=access.get('kind', 'store'),
        )
        base_ptr = access.get('base_ptr') or access.get('dst_info') or ''
        alloc_site = _parse_alloc_site(base_ptr)
        if alloc_site is None and not str(base_ptr).startswith('arg-ptr'):
            # 指针未关联到已知分配 → 无法判定
            fv.verdict = Verdict.UNPROVEN
            fv.fp_probability = 0.5
            return fv
        fv.alloc_site = alloc_site
        alloc = self.alloc_resolver.resolve(
            alloc_site, access.get('addr', 0), mallocs, insns)
        fv.alloc_size = alloc
        if alloc is not None:
            from .alloc import ptmalloc2_usable
            fv.usable_size = ptmalloc2_usable(alloc)

        fv.offset_info = access.get('offset_info')
        fv.copy_size_info = access.get('size_info')
        fv.loop_iters = access.get('loop_iters')
        fv.loop_stride = access.get('loop_stride')
        if fv.copy_size_info is None:
            fv.copy_size_info = ValueInfo(
                interval_lo=access.get('access_size', 4),
                interval_hi=access.get('access_size', 4),
                is_constant=True,
                constant_value=access.get('access_size', 4),
                tainted=False, taint_confidence=0.9,
                provenance=Provenance.CONSTANT,
                summary='store-size')

# 守卫收集: 与偏移/大小寄存器相关的支配守卫
        related = self._related_regs(access, insns, insn_index)
        guards = []
        if related:
            if guard_extractor is None:
                guard_extractor = GuardExtractor(insns)
            guards = guard_extractor.collect_for_access(
                access.get('addr', 0), related)
        if guards:
            fv.evidences.append(Evidence(
                rule=ProofRule.GUARD_DOMINANCE,
                detail=f'{len(guards)} dominating guards',
                confidence=0.7,
                extra={'n_guards': len(guards)}))

# 阶段1: 安全证明 (alloc 未知时仍可借最小块规则证明)
        safe_evs = self.safety.prove(fv, guards, related)
        if safe_evs:
            fv.evidences.extend(safe_evs)
            fv.verdict = Verdict.SAFE_FILTERED
            fv.fp_probability = min(0.98,
                                    max(e.confidence for e in safe_evs))
            self._stats['safe'] += 1
            return fv

# 阶段2: 溢出证明
        ovf_evs = self.overflow.prove(fv)
        if ovf_evs:
            fv.evidences.extend(ovf_evs)
            # 可控性核验: 常量偏移或污点链
            off = fv.offset_info
            ctrl = (off is not None and off.is_constant) or (
                off is not None and off.tainted is True)
            if ctrl and alloc is not None:
                fv.verdict = Verdict.CONFIRMED
                fv.fp_probability = 0.05
                self._stats['confirmed'] += 1
            else:
                fv.verdict = Verdict.LIKELY
                fv.fp_probability = 0.30
                self._stats['likely'] += 1
            return fv

# 阶段3: alloc 未知且无溢出证据 → 保守保留
        if alloc is None:
            fv.evidences.append(Evidence(
                rule=ProofRule.ALLOC_SIZE_UNKNOWN,
                detail=('alloc site %s unresolved'
                        % (hex(alloc_site) if alloc_site else 'arg-ptr')),
                extra={'alloc_site': alloc_site}))
            fv.verdict = Verdict.UNPROVEN
            fv.fp_probability = 0.5
            self._stats['unproven'] += 1
            return fv

# 阶段4: 无溢出证据 → 保守保留
        off = fv.offset_info
        if off is not None and off.tainted is True:
            fv.verdict = Verdict.LIKELY
            fv.fp_probability = 0.35
            self._stats['likely'] += 1
        else:
            fv.verdict = Verdict.UNPROVEN
            fv.fp_probability = 0.45
            self._stats['unproven'] += 1
        return fv

    @staticmethod
    def _related_regs(access: dict, insns: list,
                      insn_index: dict = None) -> Tuple[str, ...]:
        """收集与访问偏移相关的寄存器/槽 (供守卫匹配)."""
        import re
        regs = set()
        off = access.get('offset_info')
        if off is not None and off.summary:
            # 槽来源: 'mem-load[rbp-4]' → slot:[rbp-4]
            sm = re.search(r'mem-load(\[[^\]]+\])', off.summary)
            if sm:
                regs.add('slot:' + sm.group(1))
            for m in re.finditer(
                    r'\b(r[0-9a-d]+[bwd]?|[er]?[abcd]x)\b', off.summary):
                regs.add(m.group(1).lower())
        # 从访问指令文本中直接找索引寄存器 (索引表避免线性扫描)
        target = None
        if insn_index is not None:
            target = insn_index.get(access.get('addr', 0))
        if target is None:
            target = next((i for i in insns if i.addr == access.get('addr', 0)),
                          None)
        if target is not None:
            for m in re.finditer(
                    r'\b(r[0-9a-d]+[bwd]?|[er]?[abcd]x)\b',
                    target.operands, re.IGNORECASE):
                regs.add(m.group(1).lower())
        return tuple(regs)

    def stats(self) -> dict:
        s = dict(self._stats)
        s['safety_rules'] = self.safety.stats()
        s['overflow_rules'] = self.overflow.stats()
        return s


def _parse_alloc_site(base_ptr: str) -> Optional[int]:
    """从 'malloc@0x140001772+96+256' 提取分配点地址."""
    if not base_ptr:
        return None
    m = __import__('re').search(r'malloc@([0-9a-fA-F]+)', str(base_ptr))
    if m:
        return int(m.group(1), 16)
    m = __import__('re').search(r'@([0-9a-fA-F]+)', str(base_ptr))
    if m:
        return int(m.group(1), 16)
    return None
