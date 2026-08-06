"""
跨模态幻觉检测器 (Cross-Modal Hallucination Detector, CMHD)
-------------------------------------------------------------
检测多模态融合中的证据冲突, 防止某模态的 LLM 幻觉污染融合结果.

设计依据:
  多模态二进制分析 (反汇编 + 反编译 + 动态 trace + 符号执行) 中,
  LLM 可能在某一模态产生幻觉 (如误读反编译代码的控制流),
  该幻觉通过注意力融合传播到最终输出.
  现有融合方法 (Transformer cross-attention, late fusion) 无幻觉检测机制.

  CMHD 检测跨模态证据冲突:
    1. 语义等价性: 两模态对同一地址的描述是否语义一致
    2. 结构一致性: CFG 边在反汇编和动态 trace 中是否匹配
    3. 时序合理性: 动态 trace 的事件顺序是否与静态 CFG 可达性一致
  当冲突超过阈值时标记该模态片段为"可疑", 降低其在融合中的权重.
"""
import math
import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class ModalityEvidence:
    """单模态的证据片段."""
    modality: str        # 'disasm' | 'decompile' | 'dynamic' | 'symexec'
    address: str         # 如 '0x401050'
    description: str     # 语义描述
    confidence: float    # 该模态自身的置信度
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConflictReport:
    """跨模态冲突报告."""
    address: str
    modality_a: str
    modality_b: str
    conflict_type: str   # 'semantic' | 'structural' | 'temporal'
    description_a: str
    description_b: str
    severity: float      # 0-1
    resolution: str = ""


class CrossModalHallucinationDetector:
    """跨模态幻觉检测器.

    用法:
      cmhd = CrossModalHallucinationDetector()
      evidence = {
          'disasm': [ModalityEvidence(...), ...],
          'decompile': [ModalityEvidence(...), ...],
          'dynamic': [ModalityEvidence(...), ...],
      }
      conflicts = cmhd.detect(evidence)
      clean_weights = cmhd.compute_trust_weights(evidence, conflicts)
    """

    def __init__(self, semantic_threshold: float = 0.3,
                 structural_threshold: float = 0.5):
        self._sem_threshold = semantic_threshold
        self._struct_threshold = structural_threshold

    def detect(self, evidence: Dict[str, List[ModalityEvidence]]
              ) -> List[ConflictReport]:
        """检测所有模态对间的证据冲突."""
        conflicts = []
        modalities = list(evidence.keys())

        for i in range(len(modalities)):
            for j in range(i + 1, len(modalities)):
                ma, mb = modalities[i], modalities[j]
                # 按地址对齐
                ev_a = {e.address: e for e in evidence.get(ma, [])}
                ev_b = {e.address: e for e in evidence.get(mb, [])}
                common_addrs = set(ev_a) & set(ev_b)

                for addr in common_addrs:
                    ea, eb = ev_a[addr], ev_b[addr]
                    # 语义冲突检测
                    sem_conflict = self._check_semantic(ea, eb)
                    if sem_conflict:
                        conflicts.append(sem_conflict)
                    # 结构冲突检测 (仅 control_flow 类型)
                    struct_conflict = self._check_structural(ea, eb)
                    if struct_conflict:
                        conflicts.append(struct_conflict)

        # 时序冲突: dynamic trace vs static CFG 的可达性
        conflicts.extend(self._check_temporal(evidence))

        conflicts.sort(key=lambda c: c.severity, reverse=True)
        return conflicts

    def _check_semantic(self, a: ModalityEvidence, b: ModalityEvidence
                        ) -> Optional[ConflictReport]:
        """检测语义冲突 — 用 n-gram 相似度作为代理."""
        sim = _text_similarity(a.description, b.description)
        if sim >= self._sem_threshold:
            return None  # 一致, 无冲突
        return ConflictReport(
            address=a.address, modality_a=a.modality, modality_b=b.modality,
            conflict_type='semantic',
            description_a=a.description[:100],
            description_b=b.description[:100],
            severity=round(1.0 - sim, 3),
        )

    def _check_structural(self, a: ModalityEvidence, b: ModalityEvidence
                          ) -> Optional[ConflictReport]:
        """检测结构冲突 — 比较 CFG 后继地址."""
        succ_a = set(a.metadata.get('cfg_successors', []))
        succ_b = set(b.metadata.get('cfg_successors', []))
        if not succ_a or not succ_b:
            return None
        jaccard = len(succ_a & succ_b) / len(succ_a | succ_b) if (succ_a | succ_b) else 1.0
        if jaccard >= self._struct_threshold:
            return None
        return ConflictReport(
            address=a.address, modality_a=a.modality, modality_b=b.modality,
            conflict_type='structural',
            description_a=f'successors: {sorted(succ_a)[:5]}',
            description_b=f'successors: {sorted(succ_b)[:5]}',
            severity=round(1.0 - jaccard, 3),
        )

    def _check_temporal(self, evidence: Dict[str, List[ModalityEvidence]]
                        ) -> List[ConflictReport]:
        """时序冲突: dynamic trace 中的边是否在静态 CFG 中可达."""
        dyn = evidence.get('dynamic', [])
        static = evidence.get('disasm', evidence.get('decompile', []))
        if not dyn or not static:
            return []
        static_addrs = {e.address for e in static}
        conflicts = []
        for e in dyn:
            trace_seq = e.metadata.get('trace_sequence', [])
            for k in range(len(trace_seq) - 1):
                src, dst = trace_seq[k], trace_seq[k+1]
                if src not in static_addrs and dst in static_addrs:
                    conflicts.append(ConflictReport(
                        address=str(src),
                        modality_a='dynamic', modality_b='static',
                        conflict_type='temporal',
                        description_a=f'动态执行从 {src} 跳转至 {dst}',
                        description_b=f'静态分析中 {src} 不可达, 可能为动态生成代码',
                        severity=0.7,
                    ))
        return conflicts

    def compute_trust_weights(
        self, evidence: Dict[str, List[ModalityEvidence]],
        conflicts: List[ConflictReport],
    ) -> Dict[str, float]:
        """根据冲突报告计算各模态的可信权重.
        冲突越多的模态权重越低.
        """
        conflict_count: Dict[str, int] = defaultdict(int)
        for c in conflicts:
            conflict_count[c.modality_a] += 1
            conflict_count[c.modality_b] += 1

        total_evidence = sum(len(v) for v in evidence.values())
        weights = {}
        for mod in evidence:
            n_ev = len(evidence[mod])
            n_conf = conflict_count.get(mod, 0)
            # 冲突密度 = 冲突数 / 证据数
            density = n_conf / max(1, n_ev)
            # 权重 = e^(-density) — 冲突密度越高, 可信度越低
            weights[mod] = round(math.exp(-density * 3.0), 4)
        # 归一化
        total_w = sum(weights.values()) or 1.0
        return {k: round(v / total_w, 4) for k, v in weights.items()}

    def hallucination_score(self, modality: str,
                            conflicts: List[ConflictReport]) -> float:
        """计算单模态的幻觉风险得分 (0=无风险, 1=高风险)."""
        mod_conflicts = [c for c in conflicts
                        if c.modality_a == modality or c.modality_b == modality]
        if not mod_conflicts:
            return 0.0
        avg_severity = sum(c.severity for c in mod_conflicts) / len(mod_conflicts)
        # 严重冲突 (>0.7) 加权更重
        severe = sum(1 for c in mod_conflicts if c.severity > 0.7)
        bonus = min(0.5, severe * 0.1)
        return round(min(1.0, avg_severity + bonus), 4)


def _text_similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0

    def ngrams(s: str, n: int = 4) -> Set[str]:
        s = s.lower().strip()
        return {s[i:i+n] for i in range(max(0, len(s) - n + 1))}

    ga, gb = ngrams(a), ngrams(b)
    if not ga or not gb:
        return 0.0
    return len(ga & gb) / len(ga | gb)


class SemanticConflictDetector:
    """基于技术术语提取的语义冲突检测.

    相比纯 n-gram Jaccard (表层字符串匹配):
      - 从证据描述中提取技术实体 (函数名/寄存器/操作类型/地址)
      - 比较两模态的证据在实体级别的一致性
      - 例如: 'memcpy at 0x401000' 和 'copy operation at 0x401000' →
        地址匹配 + 操作类型匹配 → 高语义一致性
      - 而: 'buffer overflow' 和 'integer underflow' →
        操作类型不同 → 语义冲突

    这比纯文本相似度更准确——两段描述可能用不同措辞表达相同语义.
    """

    # 技术术语模式
    _FUNC_PAT = r'\b(memcpy|strcpy|malloc|free|sprintf|read|write|recv|send|mmap|mprotect|exec|system)\b'
    _REG_PAT = r'\b(e?[ra]x|[er]bx|[er]cx|[er]dx|[er]si|[er]di|[er]sp|[er]bp|r[0-9]+[d]?|xmm[0-9]+)\b'
    _ADDR_PAT = r'\b(0x[0-9a-fA-F]{4,})\b'
    _OPTYPE_PAT = r'\b(overflow|underflow|injection|corruption|leak|null|dereference|bypass|escalation|confusion|forgery)\b'

    def __init__(self):
        import re
        self._func_re = re.compile(self._FUNC_PAT, re.IGNORECASE)
        self._reg_re = re.compile(self._REG_PAT, re.IGNORECASE)
        self._addr_re = re.compile(self._ADDR_PAT)
        self._optype_re = re.compile(self._OPTYPE_PAT, re.IGNORECASE)

    def extract_entities(self, text: str) -> Dict[str, set]:
        """从描述文本中提取技术实体."""
        return {
            'functions': set(self._func_re.findall(text)),
            'registers': set(self._reg_re.findall(text)),
            'addresses': set(self._addr_re.findall(text)),
            'optypes': set(self._optype_re.findall(text)),
        }

    def semantic_similarity(self, text_a: str, text_b: str) -> float:
        """计算两段描述的技术语义相似度 [0, 1]."""
        ea = self.extract_entities(text_a)
        eb = self.extract_entities(text_b)
        scores = []
        for key in ('functions', 'registers', 'addresses', 'optypes'):
            sa, sb = ea[key], eb[key]
            union = len(sa | sb)
            if union > 0:
                scores.append(len(sa & sb) / union)
        if not scores:
            return 0.0
        # 地址匹配权重最高 (同一地址 = 同一代码位置)
        addr_score = scores[2] if len(scores) > 2 else 0.0
        avg_score = sum(scores) / len(scores)
        return 0.6 * addr_score + 0.4 * avg_score

    def detect_conflict(self, desc_a: str, desc_b: str,
                        threshold: float = 0.3) -> Tuple[bool, float, str]:
        """检测两段描述是否语义冲突.
        返回 (is_conflict, similarity, reason).
        """
        sim = self.semantic_similarity(desc_a, desc_b)
        if sim >= threshold:
            return False, sim, ''
        ea = self.extract_entities(desc_a)
        eb = self.extract_entities(desc_b)
        # 分析冲突原因
        reasons = []
        if ea['addresses'] and eb['addresses'] and not (ea['addresses'] & eb['addresses']):
            reasons.append('描述不同地址的代码')
        if ea['optypes'] and eb['optypes'] and not (ea['optypes'] & eb['optypes']):
            reasons.append('操作类型不匹配: ' + str(ea['optypes']) + ' vs ' + str(eb['optypes']))
        if ea['functions'] and eb['functions'] and not (ea['functions'] & eb['functions']):
            reasons.append('涉及不同函数: ' + str(ea['functions']) + ' vs ' + str(eb['functions']))
        reason = '; '.join(reasons) if reasons else '表层语义不一致'
        return True, sim, reason
