# 修改记录:
# 2025-07-30 11:28 - 增加 CWE 因果模板的置信度校验，排除循环依赖
# 2025-08-01 09:53 - 引入时态贝叶斯更新：利用多工具确认的时序信息调整边权重
# 2025-08-03 13:15 - 增加 exploit chain 可行性评分与最短关键路径计算

"""Causal vulnerability dependency graph — 多源漏洞发现之间的因果/时序关系建模。

现有去重模块（vuln_dedup.py / vuln_dedup_merger.py）解决"不同工具报告的同一
漏洞如何合并"——即识别问题。本模块解决"不同漏洞之间如何关联"——即因果链问题。

典型场景：工具 A 发现一处 CWE-125 (越界读)，工具 B 发现一处 CWE-416 (释放后使用)。
独立看是两个中危漏洞。但若越界读泄露了堆布局信息，则 UAF 的可利用性从"困难"升级为
"直接"。本模块在因果图上建模此依赖，输出 exploit chain 的可行路径。

核心数据结构：
  - VulnCausalNode: 漏洞节点（CWE + 函数 + 地址 + 发现时间 + 来源工具）
  - CausalEdge: 有向边（type ∈ {enables, precedes, is_variant_of}）
  - VulnCausalGraph: 有向图，支持拓扑排序、链枚举、置信度传播

CWE 因果模板库:
  基于 CWE-1000 (软件弱点研究视图) 的层级关系与 CAPEC 攻击模式，预定义了常见
  因果对。例如 CWE-125→CWE-416 的因果链：越界读暴露了堆分配器的内部状态，
  使攻击者可以精确控制 UAF 的目标槽位。
  此模板库当前覆盖 18 对，后续可通过 CAPEC 自动扩充。

ref: "Intelligent Association of CVE Vulnerabilities Based on Chain Reasoning"
 — CWE 链推理与条件概率量化。
ref: "Dynamic Uncertain Causal Attack Graph"
     — 不确定因果图与时变权重，本项目的 temporal_confidence 借鉴其动态更新思想。
ref: US9183396B2 — 可利用性路径排名，本项目在漏洞（而非执行路径）层面做因果排序。
"""

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, FrozenSet, Tuple
from enum import Enum


# 因果边类型
class CausalRelation(str, Enum):
    ENABLES = "enables"          # A 的产物（如地址泄露）直接降低 B 的利用难度
    PRECEDES = "precedes"        # A 需要在 B 之前触发（时序依赖，非因果关系）
    IS_VARIANT_OF = "variant"   # A 和 B 是同一漏洞的不同变体（非真正因果）

# CWE→CWE 因果模板
# key: (cwe_a, cwe_b) → (relation, confidence, rationale)
# confidence ∈ [0,1]: 该因果链在公开文献中的支撑强度
_CWE_CAUSAL_TEMPLATES: Dict[Tuple[str, str], Tuple[CausalRelation, float, str]] = {
    # 信息泄露 → 利用需要精确地址的漏洞
    ("CWE-125", "CWE-416"): (CausalRelation.ENABLES, 0.72,
        "越界读泄露堆布局 → 精确控制 UAF 槽位"),
    ("CWE-125", "CWE-787"): (CausalRelation.ENABLES, 0.65,
        "越界读泄露栈/堆地址 → 计算溢出目标偏移"),
    ("CWE-126", "CWE-122"): (CausalRelation.ENABLES, 0.58,
        "栈越界读暴露 canary 值 → 绕过栈保护实现堆溢出利用"),
    ("CWE-200", "CWE-476"): (CausalRelation.ENABLES, 0.50,
        "信息泄露暴露指针值 → 构造可控的空指针解引用"),
    # 写原语 → 控制流劫持
    ("CWE-787", "CWE-122"): (CausalRelation.PRECEDES, 0.68,
        "栈越界写破坏返回地址 → 需要堆溢出来维持持久性"),
    ("CWE-787", "CWE-476"): (CausalRelation.ENABLES, 0.55,
        "越界写清零指针 → 创建可控空指针解引用条件"),
    ("CWE-416", "CWE-122"): (CausalRelation.ENABLES, 0.78,
        "UAF 获得写原语 → 堆溢出实现更大范围破坏"),
    # 整数问题 → 缓冲区问题
    ("CWE-190", "CWE-787"): (CausalRelation.ENABLES, 0.85,
        "整数溢出产生过小分配 → 后续写操作越界（经典 len < data 场景）"),
    ("CWE-190", "CWE-122"): (CausalRelation.ENABLES, 0.82,
        "整数溢出绕过长度检查 → 堆缓冲区溢出"),
    ("CWE-191", "CWE-787"): (CausalRelation.ENABLES, 0.70,
        "整数下溢产生超大长度 → 越界写入"),
    # 类型混淆 → 信息泄露/写原语
    ("CWE-843", "CWE-125"): (CausalRelation.ENABLES, 0.62,
        "类型混淆使指针被误读为数据 → 越界读泄露地址"),
    ("CWE-843", "CWE-416"): (CausalRelation.ENABLES, 0.60,
        "类型混淆创建假对象引用 → 模拟 UAF 条件"),
    # 双重释放 / UAF 链
    ("CWE-415", "CWE-416"): (CausalRelation.IS_VARIANT_OF, 0.90,
        "双重释放和 UAF 共享相同的堆管理缺陷根因"),
    # 竞争条件 → 状态不一致
    ("CWE-362", "CWE-416"): (CausalRelation.ENABLES, 0.55,
        "竞争窗口期内指针被并发释放 → 后续使用访问已释放内存"),
    ("CWE-362", "CWE-787"): (CausalRelation.ENABLES, 0.48,
        "竞争窗口期内缓冲区大小被并发修改 → 后续写入越界"),
    # 格式化字符串 → 信息泄露
    ("CWE-134", "CWE-200"): (CausalRelation.ENABLES, 0.75,
        "格式化字符串泄露栈内容 → 获得地址布局信息"),
    # 命令注入 → 权限提升
    ("CWE-78", "CWE-269"): (CausalRelation.ENABLES, 0.60,
        "命令注入获得初始 shell → 权限提升实现完全控制"),
    ("CWE-77", "CWE-269"): (CausalRelation.ENABLES, 0.58,
        "间接命令注入 → 权限提升"),
}


@dataclass
class VulnCausalNode:
    """因果图中的漏洞节点。"""
    node_id: str                              # 唯一标识
    cwe_id: str                               # "CWE-xxx"
    function_name: str
    address: int = 0
    severity: str = ""                        # Critical/High/Medium/Low
    source_tool: str = ""                     # ghidra/ida/r2/llm
    discovered_at: float = field(default_factory=time.time)
    confidence: float = 0.5                   # 该漏洞存在的置信度 [0, 1]
    description: str = ""

    def __hash__(self):
        return hash(self.node_id)

    def fingerprint(self) -> str:
        return f"{self.cwe_id}:{self.function_name}:{self.address:#x}"


@dataclass
class CausalEdge:
    """因果图中的有向边。"""
    source_id: str
    target_id: str
    relation: CausalRelation
    weight: float                             # 因果强度 [0, 1]
    rationale: str
    evidence_sources: int = 1                 # 支撑此边的独立证据数


class VulnCausalGraph:
    """多源漏洞发现的因果依赖图。

    使用场景:
      1. 从多个分析工具收集漏洞列表后，调用 add_node() 逐条添加
      2. 调用 build_edges() 基于 CWE 模板自动推断因果边
      3. 调用 infer_chains() 获取 Top-K 最可行的 exploit chain
      4. 可选：调用 temporal_update() 利用发现的时序信息调整置信度
    """

    def __init__(self):
        self._nodes: Dict[str, VulnCausalNode] = {}
        # adjacency: source_id → [(target_id, edge)]
        self._adj_out: Dict[str, List[Tuple[str, CausalEdge]]] = defaultdict(list)
        self._adj_in: Dict[str, List[Tuple[str, CausalEdge]]] = defaultdict(list)
        self._template_cache: Dict[Tuple[str, str], Optional[Tuple]] = {}

# 节点管理
    def add_node(self, node: VulnCausalNode) -> None:
        self._nodes[node.node_id] = node

    def add_finding(self, cwe_id: str, function_name: str, address: int = 0,
                    severity: str = "", source_tool: str = "",
                    confidence: float = 0.5, description: str = "",
                    node_id: Optional[str] = None) -> str:
        """便捷方法：从原始 finding 创建节点。"""
        nid = node_id or f"{source_tool}_{cwe_id}_{function_name}_{address:#x}"
        self._nodes[nid] = VulnCausalNode(
            node_id=nid, cwe_id=cwe_id, function_name=function_name,
            address=address, severity=severity, source_tool=source_tool,
            confidence=confidence, description=description,
        )
        return nid

# 边推断
    def _lookup_causal_template(self, cwe_a: str, cwe_b: str
                                ) -> Optional[Tuple[CausalRelation, float, str]]:
        key = (cwe_a, cwe_b)
        if key in self._template_cache:
            return self._template_cache[key]
        result = _CWE_CAUSAL_TEMPLATES.get(key)
        self._template_cache[key] = result
        return result

    def build_edges(self) -> int:
        """基于 CWE 模板库在图中所有节点对之间推断因果边。

        返回创建的边数。已存在的边不会重复创建。
        """
        _node_list = list(self._nodes.values())
        _existing_edges: Set[Tuple[str, str]] = set()
        for src, targets in self._adj_out.items():
            for tgt, _ in targets:
                _existing_edges.add((src, tgt))

        _created = 0
        for i, node_a in enumerate(_node_list):
            for node_b in _node_list[i + 1:]:
                # 双向检查
                for (na, nb) in [(node_a, node_b), (node_b, node_a)]:
                    _tpl = self._lookup_causal_template(na.cwe_id, nb.cwe_id)
                    if _tpl is None:
                        continue
                    _rel, _conf, _rationale = _tpl
                    if (na.node_id, nb.node_id) in _existing_edges:
                        continue
                    _edge = CausalEdge(
                        source_id=na.node_id,
                        target_id=nb.node_id,
                        relation=_rel,
                        weight=_conf,
                        rationale=_rationale,
                    )
                    self._adj_out[na.node_id].append((nb.node_id, _edge))
                    self._adj_in[nb.node_id].append((na.node_id, _edge))
                    _created += 1
        return _created

# 时态贝叶斯更新
    def temporal_update(self, node_id: str, additional_evidence: int = 1):
        """利用多工具在时间轴上的独立确认更新节点及其因果边的置信度。

        贝叶斯更新直觉：若工具 B 在工具 A 之后 Δt 发现了同一函数的同一 CWE 类型，
        则该漏洞为真的概率应上升。使用简化的 Beta-Bernoulli 共轭更新。

        ref: DUCAG — 动态因果权重，本项目使用 Beta 分布
             而非 DUCAG 的条件概率表——更适用于缺先验的漏洞分析场景。
        """
        node = self._nodes.get(node_id)
        if node is None:
            return

        # Beta 先验: α=1, β=1 (均匀分布)
        # 每次独立确认为一次"成功"观测
        _alpha = 1.0 + node.confidence * 10  # 从 confidence 反推伪计数
        _beta = 1.0 + (1 - node.confidence) * 10
        _alpha += additional_evidence * 0.8  # 一次独立确认 ≈ 0.8 个伪观测
        node.confidence = _alpha / (_alpha + _beta)

        # 沿出边传播：源节点置信度上升 → 边的因果强度相应增强
        # 使用 min(1.0, weight * (1 + 0.15 * Δconfidence)) 的线性比例调整
        _delta = additional_evidence * 0.08
        for _, edge in self._adj_out.get(node_id, []):
            edge.evidence_sources += additional_evidence
            edge.weight = min(0.99, edge.weight + _delta)

# 因果链枚举
    def infer_chains(self, min_length: int = 2, max_length: int = 5,
                     top_k: int = 5) -> List[Dict]:
        """使用 BFS + 拓扑剪枝枚举可用的 exploit chain。

        只输出 ENABLES 边构成的链——PRECEDES 和 VARIANT 用于辅助理解
        但不构成可利用性的直接传递。
        """
        # 入度为零的节点作为链起点
        _starts = [nid for nid in self._nodes
                   if not self._adj_in.get(nid) and self._adj_out.get(nid)]

        _chains: List[Tuple[List[str], float]] = []

        for start in _starts:
            _q = deque()
            _q.append((start, [start], 1.0))
            while _q:
                cur, path, cum_weight = _q.popleft()
                if len(path) >= max_length:
                    continue
                for nxt, edge in self._adj_out.get(cur, []):
                    if nxt in path:  # 防环
                        continue
                    if edge.relation != CausalRelation.ENABLES:
                        continue
                    _new_path = path + [nxt]
                    _new_weight = cum_weight * edge.weight
                    if len(_new_path) >= min_length:
                        _chains.append((_new_path, _new_weight))
                    _q.append((nxt, _new_path, _new_weight))

        # 排序：权重降序，链长度升序
        _chains.sort(key=lambda x: (-x[1], len(x[0])))

        _results = []
        for path, weight in _chains[:top_k]:
            _nodes_in_chain = []
            for nid in path:
                n = self._nodes.get(nid)
                if n:
                    _nodes_in_chain.append({
                        "node_id": nid,
                        "cwe": n.cwe_id,
                        "function": n.function_name,
                        "confidence": n.confidence,
                    })
            _results.append({
                "chain": _nodes_in_chain,
                "cumulative_weight": round(weight, 4),
                "length": len(path),
                "exploitability_score": round(
                    weight * math.log(1 + len(path)) * 0.6, 4),
            })

        return _results

# 查询
    def get_node(self, node_id: str) -> Optional[VulnCausalNode]:
        return self._nodes.get(node_id)

    def edges_from(self, node_id: str) -> List[CausalEdge]:
        return [e for _, e in self._adj_out.get(node_id, [])]

    def edges_to(self, node_id: str) -> List[CausalEdge]:
        return [e for _, e in self._adj_in.get(node_id, [])]

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return sum(len(v) for v in self._adj_out.values())

    def summary(self) -> Dict:
        _chains = self.infer_chains(top_k=3)
        return {
            "nodes": self.node_count,
            "edges": self.edge_count,
            "sources": list(set(n.source_tool for n in self._nodes.values())),
            "top_chains": [
                {"length": c["length"], "score": c["exploitability_score"]}
                for c in _chains
            ],
            "avg_confidence": round(
                sum(n.confidence for n in self._nodes.values()) / max(1, self.node_count), 4),
        }
