# CrossInspector: 跨合约漏洞检测 — 状态依赖图 (SDG) 分析
#
#   "CrossInspector: A Static Analysis Approach for Cross-Contract
#    Vulnerability Detection"
#    核心: 通过构建 State Dependency Graph (SDG) 实现跨合约数据流追踪,
#    97% 精度识别 timestamp/block 依赖漏洞
#    方法: (1) 合约内 CFG + 调用图 → (2) 跨合约调用边 →
#          (3) SDG 构建 → (4) 依赖模式匹配
#   "Decompiling Smart Contracts with a Large Language Model"
# — LLM 辅助反编译提高 SDG 精度

import re
import logging
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

logger = logging.getLogger(__name__)

# CrossInspector 的 State Dependency Graph 节点类型
_SDG_NODE_TYPES = {
    "CALL": "外部合约调用点",
    "SLOAD": "storage 读取",
    "SSTORE": "storage 写入",
    "CALLDATA": "外部输入 (calldata)",
    "TIMESTAMP": "区块时间戳",
    "NUMBER": "区块高度",
    "BALANCE": "余额查询",
    "ORIGIN": "tx.origin",
    "GASPRICE": "gas 价格",
    "SELFDESTRUCT": "合约销毁",
    "DELEGATECALL": "代理调用",
}


@dataclass
class SDGNode:
    node_id: int
    node_type: str          # 来自 _SDG_NODE_TYPES
    contract_addr: str = "" # 所属合约地址 (hex)
    function_name: str = ""
    position: int = 0       # 字节码偏移
    opcode: str = ""
    data: dict = field(default_factory=dict)
    # 跨合约追踪
    is_cross_contract: bool = False
    target_contract: str = ""  # CALL/DELEGATECALL 的目标地址


@dataclass
class SDGEdge:
    from_node: int
    to_node: int
    edge_type: str  # "data_flow", "control_flow", "call", "delegate_call"
    label: str = ""


@dataclass
class StateDependencyGraph:
    nodes: list[SDGNode] = field(default_factory=list)
    edges: list[SDGEdge] = field(default_factory=list)
    entry_contract: str = ""
    cross_contract_edges: int = 0


@dataclass
class CrossContractVuln:
    vuln_id: str
    vuln_type: str
    severity: str
    description: str = ""
    source_contract: str = ""
    target_contract: str = ""
    sdg_path: list[int] = field(default_factory=list)  # node_id 路径
    confidence: float = 0.0
    recommendation: str = ""


class CrossInspector:
    """跨合约漏洞检测器 (arXiv 2408.15292)。

    构建 State Dependency Graph 以追踪跨合约的变量依赖。
    检测三类跨合约漏洞：
    1. 跨合约重入 (Cross-contract reentrancy):
       A→CALL→B→CALL→A: B 的回调重新进入 A 时状态未更新
    2. 跨合约时间戳操控 (Cross-contract timestamp manipulation):
       合约 A 的 TIMESTAMP 依赖通过 CALL 传播到合约 B 的关键判断
    3. 跨合约存储碰撞 (Cross-contract storage collision):
       DELEGATECALL 链中两个代理的 storage slot 冲突
    """

    # 区块环境变量 — 链上所有合约读取同一值，
    # 跨合约追踪的关键是这些值是否被用于条件分支或资产转移
    _BLOCK_STATE_SOURCES: frozenset[str] = frozenset({
        "TIMESTAMP", "NUMBER", "GASLIMIT", "DIFFICULTY",
        "COINBASE", "GASPRICE", "CHAINID", "BASEFEE"
    })

    # 敏感目标操作 — 当 block env 变量流向这些操作时发出警告
    _SENSITIVE_TARGETS: frozenset[str] = frozenset({
        "CALL", "DELEGATECALL", "SSTORE", "SELFDESTRUCT",
        "CREATE", "CREATE2", "JUMPI",
    })

    def __init__(self, contracts: dict[str, list[dict]] | None = None):
        """初始化跨合约分析器。"""
        self._contracts = contracts or {}
        self._sdg: StateDependencyGraph = StateDependencyGraph()
        self._vulns: list[CrossContractVuln] = []

    def add_contract(self, addr: str, instructions: list[dict]):
        self._contracts[addr] = instructions

    def build_sdg(self) -> StateDependencyGraph:
        """构建 State Dependency Graph。

        阶段 1: 为每个合约独立构建节点 (SLOAD/SSTORE/CALL/DELEGATECALL/BLOCK ENV)
        阶段 2: 添加合约内数据流边 (同合约中 data source → data sink)
        阶段 3: 添加跨合约边 (CALL/DELEGATECALL 连接两个合约的 SDG)
        """
        g = StateDependencyGraph()
        node_id = 0
        addr_to_nodes: dict[str, list[int]] = defaultdict(list)
        # 阶段 1: 节点构建
        for addr, instrs in self._contracts.items():
            for instr in instrs:
                op = instr.get("opcode", "")
                nt = self._classify_node_type(op)
                if nt:
                    node = SDGNode(
                        node_id=node_id, node_type=nt,
                        contract_addr=addr,
                        position=instr.get("position", 0),
                        opcode=op,
                        data={"operand": instr.get("operand")},
                    )
                    # 跨合约标记
                    if op in ("CALL", "DELEGATECALL", "CALLCODE", "STATICCALL"):
                        node.is_cross_contract = True
                        # 从 CALL 的目标地址参数尝试提取目标合约
                        if "target" in instr:
                            node.target_contract = instr["target"]
                    g.nodes.append(node)
                    addr_to_nodes[addr].append(node_id)
                    node_id += 1
        # 阶段 2: 合约内数据流边
        for addr, nids in addr_to_nodes.items():
            nodes_in_contract = [n for n in g.nodes if n.node_id in nids]
            nodes_in_contract.sort(key=lambda n: n.position)
            for i in range(len(nodes_in_contract) - 1):
                src = nodes_in_contract[i]
                for j in range(i + 1, min(i + 20, len(nodes_in_contract))):
                    dst = nodes_in_contract[j]
                    if self._has_data_flow(src, dst):
                        g.edges.append(SDGEdge(
                            from_node=src.node_id, to_node=dst.node_id,
                            edge_type="data_flow",
                            label=f"{src.node_type}→{dst.node_type}"))
        # 阶段 3: 跨合约边
        for node in g.nodes:
            if node.is_cross_contract and node.target_contract:
                target_nids = addr_to_nodes.get(node.target_contract, [])
                for tnid in target_nids:
                    g.edges.append(SDGEdge(
                        from_node=node.node_id, to_node=tnid,
                        edge_type="call",
                        label=f"CALL {node.contract_addr}→{node.target_contract}"))
                    g.cross_contract_edges += 1
        self._sdg = g
        return g

    def _classify_node_type(self, opcode: str) -> str | None:
        mapped = {
            "CALL": "CALL", "DELEGATECALL": "DELEGATECALL",
            "CALLCODE": "CALL", "STATICCALL": "CALL",
            "SLOAD": "SLOAD", "SSTORE": "SSTORE",
            "CALLDATALOAD": "CALLDATA", "CALLDATASIZE": "CALLDATA",
            "TIMESTAMP": "TIMESTAMP", "NUMBER": "NUMBER",
            "BALANCE": "BALANCE", "ORIGIN": "ORIGIN",
            "GASPRICE": "GASPRICE", "GASLIMIT": "GASLIMIT",
            "SELFDESTRUCT": "SELFDESTRUCT",
        }
        result = mapped.get(opcode)
        return result

    def _has_data_flow(self, src: SDGNode, dst: SDGNode) -> bool:
        """判断两个 SDG 节点间是否存在数据流。

        规则:
        - SLOAD → SSTORE: storage 读取流向写入 (状态依赖)
        - CALLDATA → SSTORE: 外部输入流向存储
        - CALLDATA → CALL: 外部输入流向外部调用参数
        - TIMESTAMP/NUMBER → JUMPI: 区块变量流向条件分支
        - BALANCE → CALL: 余额查询流向 .transfer/.send
        """
        flow_rules = [
            ({"SLOAD"}, {"SSTORE"}),
            ({"CALLDATA"}, {"SSTORE", "CALL"}),
            ({"TIMESTAMP", "NUMBER"}, {"JUMPI"}),
            ({"BALANCE"}, {"CALL"}),
            ({"ORIGIN"}, {"JUMPI"}),
            ({"GASPRICE"}, {"CALL"}),
        ]
        for src_types, dst_types in flow_rules:
            if src.node_type in src_types and dst.node_type in dst_types:
                return True
        return False

    def detect_cross_contract_vulns(self) -> list[CrossContractVuln]:
        """基于 SDG 的跨合约漏洞模式匹配。"""
        if not self._sdg.nodes:
            self.build_sdg()
        vulns = []
        # 1. 跨合约重入: CALL 边回到已访问合约
        call_edges = [e for e in self._sdg.edges if e.edge_type == "call"]
        for e1 in call_edges:
            src_node = self._find_node(e1.from_node)
            dst_node = self._find_node(e1.to_node)
            if src_node is None or dst_node is None:
                continue
            # 检查是否有反向 CALL 边
            for e2 in call_edges:
                if e2.from_node in [n.node_id for n in self._sdg.nodes
                                     if n.contract_addr == dst_node.contract_addr]:
                    back_node = self._find_node(e2.to_node)
                    if back_node and back_node.contract_addr == src_node.contract_addr:
                        vulns.append(CrossContractVuln(
                            vuln_id="CC-REENTRY-001", vuln_type="cross_contract_reentrancy",
                            severity="Critical",
                            description=f"Cross-contract reentrancy: {src_node.contract_addr} ↔ {dst_node.contract_addr}",
                            source_contract=src_node.contract_addr,
                            target_contract=dst_node.contract_addr,
                            sdg_path=[e1.from_node, e1.to_node, e2.to_node],
                            confidence=0.85,
                            recommendation="Use reentrancy guard and follow Checks-Effects-Interactions pattern",
                        ))
        # 2. 跨合约 timestamp 操控
        block_nodes = [n for n in self._sdg.nodes
                       if n.node_type in self._BLOCK_STATE_SOURCES]
        for bn in block_nodes:
            # 跟随数据流边找到 CALL/SSTORE
            for edge in self._sdg.edges:
                if edge.from_node == bn.node_id:
                    target = self._find_node(edge.to_node)
                    if target and target.opcode in self._SENSITIVE_TARGETS:
                        vulns.append(CrossContractVuln(
                            vuln_id="CC-TIMESTAMP-001", vuln_type="cross_contract_timestamp_manipulation",
                            severity="High",
                            description=f"{bn.node_type} → {target.opcode} via cross-contract flow",
                            source_contract=bn.contract_addr,
                            target_contract=target.contract_addr,
                            sdg_path=[bn.node_id, target.node_id],
                            confidence=0.70,
                            recommendation="Avoid using block.timestamp for critical logic; use block.number for coarse timing",
                        ))
        # 3. 跨合约存储碰撞
        delegate_nodes = [n for n in self._sdg.nodes if n.opcode == "DELEGATECALL"]
        for dn in delegate_nodes:
            # DELEGATECALL 链中两个代理的 storage slot 冲突
            if dn.target_contract:
                related_sstores = [n for n in self._sdg.nodes
                                   if n.opcode == "SSTORE" and
                                   (n.contract_addr == dn.contract_addr or
                                    n.contract_addr == dn.target_contract)]
                if len(related_sstores) >= 2:
                    vulns.append(CrossContractVuln(
                        vuln_id="CC-STORAGE-001", vuln_type="cross_contract_storage_collision",
                        severity="High",
                        description=f"Potential storage collision via DELEGATECALL: {dn.contract_addr}→{dn.target_contract}",
                        source_contract=dn.contract_addr,
                        target_contract=dn.target_contract,
                        sdg_path=[dn.node_id],
                        confidence=0.65,
                        recommendation="Follow EIP-1967 storage slot standard; use unstructured storage proxy",
                    ))
        self._vulns = vulns
        return vulns

    def _find_node(self, node_id: int) -> SDGNode | None:
        for n in self._sdg.nodes:
            if n.node_id == node_id:
                return n
        return None

    def export_sdg_summary(self) -> dict:
        return {
            "total_nodes": len(self._sdg.nodes),
            "total_edges": len(self._sdg.edges),
            "cross_contract_edges": self._sdg.cross_contract_edges,
            "contracts_analyzed": len(set(n.contract_addr for n in self._sdg.nodes)),
            "node_types": dict(Counter(n.node_type for n in self._sdg.nodes)),
            "vulnerabilities_found": len(self._vulns),
        }


def analyze_cross_contract(contracts: dict[str, list[dict]]) -> dict:
    insp = CrossInspector(contracts)
    vulns = insp.detect_cross_contract_vulns()
    summary = insp.export_sdg_summary()
    summary["vulnerabilities"] = [
        {"id": v.vuln_id, "type": v.vuln_type, "severity": v.severity,
         "confidence": v.confidence, "source": v.source_contract,
         "target": v.target_contract, "recommendation": v.recommendation}
        for v in vulns
    ]
    return summary
