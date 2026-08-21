# 初始实现：证据锚定的多Agent对抗辩论 + 事实基底约束

"""对抗辩论编排器 — 多 Agent 对抗辩论 + 证据锚定 + 共识合成。

现有的 llm_agent_binary.py 使用流水线式 Agent 协作（反汇编→漏洞发现→利用→报告），
各 Agent 顺序执行，无对抗性审查。VulTrial 引入了法庭式辩论但发现关键缺陷：
无证据锚定的辩论在第一轮后即退化-Agent 通过"相互让步"而非"事实推理"收敛。

本模块的核心机制-证据锚定的对抗辩论 (Evidence-Anchored Adversarial Debate, EAAD)：
1. 辩论启动前，FactExtractor Agent 从二进制中提取"证据基底"-
   CFG 片段、数据流路径、危险函数调用链等不可辩驳的结构化事实。
2. Prosecutor Agent（主张漏洞存在）和 Defender Agent（反驳）的所有论点
   必须引用证据基底中的具体条目-无法引用的论点自动降权。
3. Judge Agent 不参与辩论，仅在辩论结束后基于证据基底+双方论点
   给出结构化裁决（漏洞存在/不存在/不确定+证据支撑度）。
4. 裁决附带"不确定性来源"列表-哪些事实缺失导致无法确定-
   供上层系统决定是否需要动态分析补充证据。

与 VulTrial/Aegis 的区别：
- VulTrial: 源码级、无证据约束、多轮退化。
- Aegis: CPG 切片证据但用于事后审计而非辩论约束。
- 本方案: 证据基底在辩论前锁定、辩论中强制引用、违规论点自动降权。
  与 Aegis 的 CPG 切片证据基底思路相近-
  本方案将证据引用作为论点权重的显式因子，而非仅用于事后审计。

- VulTrial — 法庭式多 Agent 辩论的框架设计。
- Aegis — 证据锚定审计的"closed factual substrate"概念。
"""

import hashlib
import math
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

_EPS: float = 1e-9

class Verdict(Enum):
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    UNCERTAIN = "uncertain"

@dataclass
class EvidenceItem:
    """证据基底中的一条结构化事实。

    例：CFG 边(0x401000→0x401050), 数据流(def at 0x401020, use at 0x401080),
    危险函数调用(strcpy@0x401200, arg来自用户输入)。
    """
    evidence_id: str
    evidence_type: str       # cfg_edge / data_flow / dangerous_call / memory_access / taint_path
    source: str              # 来源地址/变量
    target: str              # 目标地址/变量
    description: str
    confidence: float = 1.0  # 证据自身的置信度（反汇编不确定性等）

@dataclass
class Argument:
    """辩论中一条论点-必须引用证据。"""
    agent_role: str          # prosecutor / defender
    claim: str
    cited_evidence: List[str]  # 引用的 evidence_id 列表
    evidence_support: float = 0.0  # 自动计算：引用证据的平均 confidence
    weight: float = 1.0       # 裁判调整后的权重（未引用证据→0.2）

@dataclass
class DebateRound:
    """一轮辩论的记录。"""
    round_number: int
    prosecutor_args: List[Argument]
    defender_args: List[Argument]
    new_evidence_cited: Set[str]  # 本轮首次引用的证据

@dataclass
class VerdictResult:
    """Judge Agent 的最终裁决。"""
    verdict: Verdict
    confidence: float
    supporting_evidence: List[str]
    counter_evidence: List[str]
    uncertainty_sources: List[str]  # 缺失的、可能导致不确定的证据类型
    debate_rounds: int
    prosecutor_score: float  # 主张方论证质量
    defender_score: float    # 反驳方论证质量

class EvidenceAnchoredDebate:
    """证据锚定的对抗辩论编排器。

    使用范式：
      debate = EvidenceAnchoredDebate()
      evidence_base = FactExtractor.extract(binary_path, target_function)
      verdict = debate.run_debate(evidence_base, target_function, max_rounds=2)
    """

    def __init__(
        self,
        max_debate_rounds: int = 2,
        evidence_weight_penalty: float = 0.2,
        uncertainty_threshold: float = 0.4,
    ):
        """
        max_debate_rounds: 最大辩论轮数（VulTrial 发现 >1 轮可能退化）。
        evidence_weight_penalty: 未引用证据的论点权重系数。
        uncertainty_threshold: 低于此 confidence 的裁决标记为 uncertain。
        """
        self.max_rounds = max_debate_rounds
        self.evidence_weight_penalty = evidence_weight_penalty
        self.uncertainty_threshold = uncertainty_threshold

    def run_debate(
        self,
        evidence_base: List[EvidenceItem],
        target_function: str,
        prosecutor_args: Optional[List[Argument]] = None,
        defender_args: Optional[List[Argument]] = None,
    ) -> VerdictResult:
        """执行一次完整的证据锚定辩论。

        若无预生成的论点（prosecutor_args=None），
        返回基于证据基底的启发式初步评估。
        """
        _evidence_by_id = {e.evidence_id: e for e in evidence_base}

        _all_evidence_ids = set(_evidence_by_id.keys())
        _cited_evidence: Set[str] = set()

        _debate_log: List[DebateRound] = []

        for _round_num in range(self.max_rounds):
            _p_args = self._generate_prosecutor_args(
                evidence_base, _cited_evidence, _round_num,
            ) if prosecutor_args is None and _round_num == 0 else (
                prosecutor_args or []
            )
            _d_args = self._generate_defender_args(
                evidence_base, _cited_evidence, _round_num, _p_args,
            ) if defender_args is None and _round_num == 0 else (
                defender_args or []
            )

            # 锚定：调整论点权重-引用证据不足的论点降权
            _p_args = self._anchor_arguments(_p_args, _evidence_by_id)
            _d_args = self._anchor_arguments(_d_args, _evidence_by_id)

            _new_cited: Set[str] = set()
            for _arg in _p_args + _d_args:
                _new_cited.update(_arg.cited_evidence)

            _debate_log.append(DebateRound(
                round_number=_round_num + 1,
                prosecutor_args=_p_args,
                defender_args=_d_args,
                new_evidence_cited=_new_cited - _cited_evidence,
            ))
            _cited_evidence.update(_new_cited)

        # Judge 合成裁决
        return self._synthesize_verdict(
            evidence_base, _debate_log, target_function,
        )

    # 论点锚定

    def _anchor_arguments(
        self,
        args: List[Argument],
        evidence_by_id: Dict[str, EvidenceItem],
    ) -> List[Argument]:
        """将论点锚定到证据基底-计算证据支撑度并调整权重。"""
        _anchored: List[Argument] = []
        for _arg in args:
            if not _arg.cited_evidence:
                # 无引用 → 纯推测，权重设为基准的 penalty 倍
                _arg.evidence_support = 0.0
                _arg.weight = self.evidence_weight_penalty
                _anchored.append(_arg)
                continue

            _supports: List[float] = []
            for _eid in _arg.cited_evidence:
                _ev = evidence_by_id.get(_eid)
                if _ev is not None:
                    _supports.append(_ev.confidence)

            _arg.evidence_support = (
                sum(_supports) / len(_supports) if _supports else 0.0
            )
            # 权重 = 证据支撑度，但至少保留基础权重
            _arg.weight = max(self.evidence_weight_penalty, _arg.evidence_support)
            _anchored.append(_arg)

        return _anchored

    # 论点生成（启发式-生产环境替换为 LLM 生成）

    def _generate_prosecutor_args(
        self, evidence: List[EvidenceItem],
        cited: Set[str], round_num: int,
    ) -> List[Argument]:
        """生成主张方论点-基于危险函数调用和污点路径。"""
        _args = []
        for _ev in evidence:
            if _ev.evidence_type == "dangerous_call" and _ev.evidence_id not in cited:
                _args.append(Argument(
                    agent_role="prosecutor",
                    claim=f"危险函数 {_ev.target} 被调用，source={_ev.source}",
                    cited_evidence=[_ev.evidence_id],
                ))
            elif _ev.evidence_type == "taint_path" and _ev.evidence_id not in cited:
                _args.append(Argument(
                    agent_role="prosecutor",
                    claim=f"污点数据从 {_ev.source} 流向 {_ev.target}",
                    cited_evidence=[_ev.evidence_id],
                ))
        return _args

    def _generate_defender_args(
        self, evidence: List[EvidenceItem],
        cited: Set[str], round_num: int,
        prosecutor_args: List[Argument],
    ) -> List[Argument]:
        """生成反驳方论点-基于保护机制和数据流截断证据。"""
        _args = []
        _protection_types = {"stack_canary", "safe_copy", "bounds_check",
                            "null_check", "input_validation"}
        for _ev in evidence:
            if _ev.evidence_type in _protection_types and _ev.evidence_id not in cited:
                _args.append(Argument(
                    agent_role="defender",
                    claim=f"保护机制 {_ev.evidence_type} 在 {_ev.source} 处生效",
                    cited_evidence=[_ev.evidence_id],
                ))

        # 若主张方引用危险函数，检查是否有输入验证截断
        for _p_arg in prosecutor_args:
            _has_validation = any(
                e.evidence_type == "input_validation" and e.evidence_id not in cited
                for e in evidence
            )
            if _has_validation:
                _args.append(Argument(
                    agent_role="defender",
                    claim="输入验证截断了污点传播路径",
                    cited_evidence=[
                        e.evidence_id for e in evidence
                        if e.evidence_type == "input_validation"
                    ][:3],
                ))
                break

        return _args

    # 裁决合成

    def _synthesize_verdict(
        self,
        evidence_base: List[EvidenceItem],
        debate_log: List[DebateRound],
        target_function: str,
    ) -> VerdictResult:
        """Judge Agent-基于证据基底和辩论记录合成最终裁决。"""
        _ev_by_type = defaultdict(list)
        for _ev in evidence_base:
            _ev_by_type[_ev.evidence_type].append(_ev)

        _all_p_args: List[Argument] = []
        _all_d_args: List[Argument] = []
        for _round in debate_log:
            _all_p_args.extend(_round.prosecutor_args)
            _all_d_args.extend(_round.defender_args)

        # 计算双方论证质量（加权分数）
        _p_score = sum(a.weight * a.evidence_support for a in _all_p_args)
        _p_score /= max(len(_all_p_args), 1)

        _d_score = sum(a.weight * a.evidence_support for a in _all_d_args)
        _d_score /= max(len(_all_d_args), 1)

        # 证据基底中的风险信号
        _danger_count = len(_ev_by_type.get("dangerous_call", []))
        _taint_count = len(_ev_by_type.get("taint_path", []))
        _protection_count = len(_ev_by_type.get("stack_canary", [])) + \
            len(_ev_by_type.get("safe_copy", [])) + \
            len(_ev_by_type.get("bounds_check", []))

        _risk_score = 0.0
        if _danger_count + _taint_count > 0:
            _risk_score = (_danger_count * 0.6 + _taint_count * 0.4) / \
                (_danger_count + _taint_count + _protection_count * 0.5 + _EPS)

        # 综合裁决
        _net_score = _risk_score * 0.3 + (_p_score - _d_score) * 0.5 + 0.2

        # 零证据 → 强制 UNCERTAIN
        _total_evidence = len(evidence_base)
        if _total_evidence == 0:
            _verdict = Verdict.UNCERTAIN
        elif _net_score > 0.7:
            _verdict = Verdict.VULNERABLE
        elif _net_score < 0.3:
            _verdict = Verdict.NOT_VULNERABLE
        else:
            _verdict = Verdict.UNCERTAIN

        # 不确定性的来源
        _uncertainty = []
        if _taint_count == 0:
            _uncertainty.append("no taint path evidence available")
        if _danger_count == 0 and _taint_count == 0:
            _uncertainty.append("insufficient evidence: no danger signals detected")
        if _protection_count == 0 and _danger_count > 0:
            _uncertainty.append("no protection mechanism evidence to assess exploitability")

        return VerdictResult(
            verdict=_verdict,
            confidence=round(abs(_net_score - 0.5) * 2.0, 4),
            supporting_evidence=[
                a.claim for a in _all_p_args if a.evidence_support > 0.5
            ],
            counter_evidence=[
                a.claim for a in _all_d_args if a.evidence_support > 0.5
            ],
            uncertainty_sources=_uncertainty,
            debate_rounds=len(debate_log),
            prosecutor_score=round(_p_score, 4),
            defender_score=round(_d_score, 4),
        )

# 冒烟测试
def _smoke_test():
    _evidence = [
        EvidenceItem("e1", "dangerous_call", "user_input", "strcpy@0x401200",
                     "strcpy with user-controlled src"),
        EvidenceItem("e2", "taint_path", "recv@0x401000", "strcpy@0x401200",
                     "data flows from recv to strcpy without sanitization"),
        EvidenceItem("e3", "stack_canary", "func_entry@0x401100", "func_exit@0x401300",
                     "stack canary present at function boundaries"),
        EvidenceItem("e4", "memory_access", "strcpy@0x401200", "stack_buf@rbp-64",
                     "strcpy writes to stack buffer of 64 bytes"),
    ]

    _debate = EvidenceAnchoredDebate(max_debate_rounds=1)
    _verdict = _debate.run_debate(_evidence, "vuln_func")

    print(f"[debate] verdict: {_verdict.verdict.value}")
    print(f"[debate] confidence: {_verdict.confidence:.4f}")
    print(f"[debate] prosecutor_score: {_verdict.prosecutor_score:.4f}")
    print(f"[debate] defender_score: {_verdict.defender_score:.4f}")
    print(f"[debate] supporting: {len(_verdict.supporting_evidence)} claims")
    print(f"[debate] counter: {len(_verdict.counter_evidence)} claims")
    print(f"[debate] uncertainty: {_verdict.uncertainty_sources}")
    print(f"[debate] rounds: {_verdict.debate_rounds}")

    # 验证危险函数+污点路径的证据应推高主张方评分
    assert _verdict.prosecutor_score > 0, (
        "prosecutor should have some evidence support"
    )
    # 有栈保护 → 反驳方应有得分
    assert _verdict.defender_score > 0, (
        "defender should have some evidence support from canary"
    )
    # 验证裁决合理性
    assert _verdict.verdict in {Verdict.VULNERABLE, Verdict.NOT_VULNERABLE,
                                 Verdict.UNCERTAIN}

    # 无证据场景
    _empty_verdict = _debate.run_debate([], "empty_func")
    print(f"[debate] empty func verdict: {_empty_verdict.verdict.value}")
    assert _empty_verdict.verdict == Verdict.UNCERTAIN

    print("[OK] EvidenceAnchoredDebate smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
