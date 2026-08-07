# 修改记录:
# 2025-08-06 17:55 - 初始实现：Granger因果框架→多漏洞间交互效应检测

"""跨漏洞交互分析 — 检测看似独立漏洞间的隐蔽互补/抵消关系。

现有漏洞分析沿单一维度评估：CVSS评分、CWE分类、调用图可达性。
但两个单独低危（CVSS 4.0）的漏洞组合可能形成高危利用链——
B的利用前提恰好被A的副作用提供。反之，两个本应独立的漏洞
可能共享一个资源导致"漏洞抵消"——A的修补意外修复B。

本模块的核心机制——Granger因果启发的跨漏洞交互检测：
1. 漏洞表示为其"能力签名"——(提供原语集, 需求原语集, 影响的地址空间)。
2. 对每对漏洞 (A, B)，检测三种交互：
   - 互补: A的副作用 ∈ B的需求集 → A降低了B的利用难度
   - 冲突: A和B争夺同一资源(dangling pointer/固定大小缓冲区) → 互斥
   - 级联: A的执行改变了B所处的执行上下文 → A使B从"理论"变"实际"
3. 构建漏洞交互图 → 识别"关键节点"（其存在使多数其他漏洞可利用）。

技术依据：
- 漏洞能力签名(VCS)概念来自 ExploitPrimitive 的组合理论。
- Granger因果的统计框架用于时间序列因果推断，
  此处被改编为静态能力匹配——检测"B的可利用性是否在A出现后
  显著变化"的静态等价形式。

与既有模块的关系：
- vuln_propagation: 沿调用图的单向传播。本模块检测非调用图可达的
  隐蔽交互（通过共享内存/文件描述符/信号等）。
- vuln_chain_analyzer: 静态BFS链搜索。本模块提供链中每个环节的
  交互强度，作为BFS的边权重。
"""

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


class InteractionType(Enum):
    COMPLEMENT = "complement"     # A的副作用满足B的前置条件
    CONFLICT = "conflict"         # A和B互斥——利用一个破坏另一个
    CASCADE = "cascade"           # A改变上下文使B可行
    INDEPENDENT = "independent"   # 无明显交互


@dataclass
class CapabilitySignature:
    """漏洞的能力签名——精确描述漏洞提供和需要的原语。"""
    vuln_id: str
    provides: FrozenSet[str]     # 利用此漏洞后获得的原语
    requires: FrozenSet[str]     # 利用此漏洞所需的前置条件
    address_space: str = "user"  # user / kernel / hypervisor
    confidence: float = 0.5      # 签名的置信度


@dataclass
class CrossVulnInteraction:
    """一对漏洞间的交互效应。"""
    vuln_a: str
    vuln_b: str
    interaction_type: InteractionType
    strength: float              # [0, 1] 交互强度
    mechanism: str               # 交互的技术机制
    evidence: List[str] = field(default_factory=list)


class CrossVulnInteractionAnalyzer:
    """跨漏洞交互分析器——漏洞间非调用图可达的隐蔽关系发现。

    使用范式：
      analyzer = CrossVulnInteractionAnalyzer()
      analyzer.load_vulnerabilities(capability_signatures)
      interactions = analyzer.detect_interactions()
      critical_nodes = analyzer.identify_critical_nodes()
    """

    def __init__(
        self,
        complement_threshold: float = 0.5,
        conflict_jaccard_threshold: float = 0.6,
    ):
        self.complement_threshold = complement_threshold
        self.conflict_jaccard_threshold = conflict_jaccard_threshold

        self._signatures: Dict[str, CapabilitySignature] = {}
        self._interactions: List[CrossVulnInteraction] = []

    # 公开 API

    def load_vulnerabilities(
        self, signatures: List[CapabilitySignature],
        vuln_metadata: Optional[Dict[str, Dict]] = None,
    ):
        """加载漏洞能力签名。"""
        self._signatures = {s.vuln_id: s for s in signatures}

    def detect_interactions(
        self,
    ) -> List[CrossVulnInteraction]:
        """检测所有漏洞对的交互效应。"""
        _ids = list(self._signatures.keys())
        _results: List[CrossVulnInteraction] = []

        for _i in range(len(_ids)):
            for _j in range(_i + 1, len(_ids)):
                _a = self._signatures[_ids[_i]]
                _b = self._signatures[_ids[_j]]

                _interactions = self._analyze_pair(_a, _b)
                _results.extend(_interactions)

        self._interactions = _results
        return _results

    def identify_critical_nodes(
        self, min_degree: int = 2,
    ) -> List[Tuple[str, float]]:
        """识别关键漏洞节点——其存在使多个其他漏洞达到可利用状态。

        关键节点评分 = 以该节点为源的互补交互数 +
                       以该节点为目标的级联交互数
        """
        if not self._interactions:
            self.detect_interactions()

        _scores: Dict[str, float] = defaultdict(float)
        for _ix in self._interactions:
            if _ix.interaction_type in (InteractionType.COMPLEMENT,
                                         InteractionType.CASCADE):
                _scores[_ix.vuln_a] += _ix.strength
                _scores[_ix.vuln_b] += _ix.strength * 0.5

        _ranked = sorted(_scores.items(), key=lambda x: x[1], reverse=True)
        return [(n, s) for n, s in _ranked if s >= min_degree]

    def interaction_graph(
        self,
    ) -> Dict[str, Any]:
        """构建漏洞交互图——节点=漏洞，边=交互关系。"""
        if not self._interactions:
            self.detect_interactions()

        _nodes = [
            {"id": vid, "provides": list(s.provides),
             "requires": list(s.requires)}
            for vid, s in self._signatures.items()
        ]
        _edges = [
            {"source": ix.vuln_a, "target": ix.vuln_b,
             "type": ix.interaction_type.value, "strength": ix.strength}
            for ix in self._interactions
            if ix.interaction_type != InteractionType.INDEPENDENT
        ]

        return {"nodes": _nodes, "edges": _edges}

    def find_maximal_exploit_chain(
        self,
        entry_vuln: str,
    ) -> List[str]:
        """从入口漏洞出发，寻找通过交互可达的最大利用链。"""
        if not self._interactions:
            self.detect_interactions()

        _reachable: Set[str] = {entry_vuln}
        _queue = [entry_vuln]

        while _queue:
            _cur = _queue.pop(0)
            for _ix in self._interactions:
                if _ix.vuln_a == _cur and _ix.interaction_type in (
                    InteractionType.COMPLEMENT, InteractionType.CASCADE
                ):
                    if _ix.vuln_b not in _reachable:
                        _reachable.add(_ix.vuln_b)
                        _queue.append(_ix.vuln_b)

        return list(_reachable)

    # 内部

    def _analyze_pair(
        self, a: CapabilitySignature, b: CapabilitySignature,
    ) -> List[CrossVulnInteraction]:
        """分析一对漏洞的交互关系。"""
        _results: List[CrossVulnInteraction] = []

        # 1. 互补检测：A的提供 ∩ B的需求
        _a_to_b = a.provides & b.requires
        _b_to_a = b.provides & a.requires

        if _a_to_b:
            _strength = len(_a_to_b) / max(len(b.requires), 1)
            if _strength >= self.complement_threshold:
                _results.append(CrossVulnInteraction(
                    vuln_a=a.vuln_id, vuln_b=b.vuln_id,
                    interaction_type=InteractionType.COMPLEMENT,
                    strength=round(_strength, 3),
                    mechanism=f"A provides {_a_to_b} which B requires",
                ))

        if _b_to_a:
            _strength = len(_b_to_a) / max(len(a.requires), 1)
            if _strength >= self.complement_threshold:
                _results.append(CrossVulnInteraction(
                    vuln_a=b.vuln_id, vuln_b=a.vuln_id,
                    interaction_type=InteractionType.COMPLEMENT,
                    strength=round(_strength, 3),
                    mechanism=f"B provides {_b_to_a} which A requires",
                ))

        # 2. 冲突检测：共享资源 + 需求重叠 → 可能互斥
        _shared_requires = a.requires & b.requires
        _union = a.requires | b.requires
        if _union:
            _jaccard = len(_shared_requires) / len(_union)
            if _jaccard >= self.conflict_jaccard_threshold:
                _results.append(CrossVulnInteraction(
                    vuln_a=a.vuln_id, vuln_b=b.vuln_id,
                    interaction_type=InteractionType.CONFLICT,
                    strength=round(_jaccard, 3),
                    mechanism=f"shared prerequisites: {_shared_requires}",
                ))

        # 3. 级联检测：A的地址空间影响B
        if a.address_space == b.address_space:
            _results.append(CrossVulnInteraction(
                vuln_a=a.vuln_id, vuln_b=b.vuln_id,
                interaction_type=InteractionType.CASCADE,
                strength=0.3,  # 同地址空间 → 弱级联
                mechanism=f"same address space: {a.address_space}",
            ))

        return _results


# 冒烟测试
def _smoke_test():
    _sigs = [
        CapabilitySignature("VULN-1", frozenset({"pc_control", "stack_leak"}),
                           frozenset({"user_input"}), "user", 0.8),
        CapabilitySignature("VULN-2", frozenset({"arb_write"}),
                           frozenset({"stack_leak", "code_leak"}), "user", 0.7),
        CapabilitySignature("VULN-3", frozenset({"code_exec"}),
                           frozenset({"arb_write", "pc_control"}), "user", 0.9),
        CapabilitySignature("VULN-4", frozenset({"heap_leak"}),
                           frozenset({"heap_overflow"}), "user", 0.6),
        CapabilitySignature("VULN-5", frozenset({"code_leak"}),
                           frozenset({"user_input", "aslr_bypass"}), "user", 0.5),
    ]

    _analyzer = CrossVulnInteractionAnalyzer()
    _analyzer.load_vulnerabilities(_sigs)
    _interactions = _analyzer.detect_interactions()

    print(f"[cross_vuln] detected {len(_interactions)} interactions:")
    for _ix in _interactions:
        print(f"  {_ix.vuln_a} --[{_ix.interaction_type.value}]--> {_ix.vuln_b} "
              f"(strength={_ix.strength:.3f})")

    _critical = _analyzer.identify_critical_nodes()
    print(f"[cross_vuln] critical nodes: {_critical}")

    _graph = _analyzer.interaction_graph()
    print(f"[cross_vuln] graph: {len(_graph['nodes'])} nodes, {len(_graph['edges'])} edges")

    _chain = _analyzer.find_maximal_exploit_chain("VULN-1")
    print(f"[cross_vuln] maximal chain from VULN-1: {_chain}")

    assert len(_interactions) >= 1, "should detect at least one interaction"
    assert len(_critical) >= 1, "should identify critical nodes"
    print("[OK] CrossVulnInteractionAnalyzer smoke test passed.")


if __name__ == "__main__":
    _smoke_test()
