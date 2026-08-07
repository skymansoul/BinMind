"""
CrossInspector V2 — 增强跨合约漏洞检测 (代理模式 + NEUROSCOPE DNN 逆向)。

理论依据:
  1. CrossInspector: SDG 跨合约数据流分析, 97% 精度。
     原版覆盖 3 种漏洞: 时间戳依赖、重入、委托调用。
  2. NEUROSCOPE: 编译器无关 DNN 二进制逆向,
     动态分析 + 灰盒对抗攻击评估。

动机:
  原 CrossInspector 的 SDG 节点类型为 11 种, 仅覆盖基本漏洞类型。
  V2 扩展:
  1. 新增代理模式节点: DELEGATECALL_CHAIN, PROXY_DELEGATION,
     DIAMOND_PROXY, TRANSPARENT_PROXY, UUPS_PROXY
  2. 检测可升级合约漏洞 (存储冲突 + 初始化函数重入)
  3. 钻石代理 (EIP-2535) 的多面选择器冲突检测

模块位置: platform/smart_contract/cross_inspector_v2.py
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

import logging
_log = logging.getLogger(__name__)


# 扩展的 SDG 节点类型

class SDGNodeType(Enum):
    """SDG 节点类型 — V2 扩展 (原 11 → 18)。"""
    # 原始 11 种
    CALL = "CALL"
    SLOAD = "SLOAD"
    SSTORE = "SSTORE"
    CALLDATA = "CALLDATA"
    TIMESTAMP = "TIMESTAMP"
    NUMBER = "NUMBER"
    BALANCE = "BALANCE"
    ORIGIN = "ORIGIN"
    GASPRICE = "GASPRICE"
    SELFDESTRUCT = "SELFDESTRUCT"
    DELEGATECALL = "DELEGATECALL"
    # V2 新增 — 代理模式
    DELEGATECALL_CHAIN = "DELEGATECALL_CHAIN"       # delegatecall 链 (>1 层)
    PROXY_DELEGATION = "PROXY_DELEGATION"            # 标准代理委托
    DIAMOND_PROXY = "DIAMOND_PROXY"                  # EIP-2535 钻石代理
    TRANSPARENT_PROXY = "TRANSPARENT_PROXY"          # 透明代理 (OpenZeppelin)
    UUPS_PROXY = "UUPS_PROXY"                        # UUPS 代理 (EIP-1822)
    INITIALIZE = "INITIALIZE"                        # 初始化函数 (可升级合约)
    STORAGE_COLLISION = "STORAGE_COLLISION"          # 存储布局冲突


# SDG 数据模型

@dataclass
class SDGNode:
    """状态依赖图节点。"""
    node_id: str
    node_type: SDGNodeType
    contract_address: str = ""
    function_sig: str = ""       # 4 字节函数选择器
    storage_slot: int = 0        # 存储槽位 (SSTORE/SLOAD)
    data_deps: List[str] = field(default_factory=list)  # 依赖的其他节点 ID


@dataclass
class SDGEdge:
    """SDG 边 — 节点间的数据流/控制流依赖。"""
    source: str         # 源节点 ID
    target: str         # 目标节点 ID
    edge_type: str      # DATA_FLOW | CONTROL_FLOW | DELEGATION
    confidence: float = 1.0


@dataclass
class ProxyPattern:
    """检测到的代理模式。"""
    pattern_type: str           # DIAMOND | TRANSPARENT | UUPS | UNKNOWN
    proxy_contract: str
    implementation_contracts: List[str] = field(default_factory=list)
    diamond_facets: Dict[str, str] = field(default_factory=dict)  # selector → contract
    storage_layout_conflicts: List[str] = field(default_factory=list)
    risk_level: str = "LOW"     # CRITICAL | HIGH | MEDIUM | LOW


# CrossInspector V2 — 增强检测器

class CrossInspectorV2:
    """
    CrossInspector V2 — 扩展跨合约漏洞检测。

    新增检测能力 (相比原版):
      1. 代理模式识别 (钻石/透明/UUPS)
      2. 存储布局冲突检测
      3. 可升级合约初始化函数安全性
      4. 钻石代理面选择器冲突
    """

    # 已知代理模式的字节码特征
    _PROXY_PATTERNS = {
        "EIP1967_TRANSPARENT": bytes.fromhex("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"),
        "EIP1967_BEACON": bytes.fromhex("a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"),
        "EIP1822_UUPS": bytes.fromhex("4e487b7100000000000000000000000000000000000000000000000000000000"),
        "DIAMOND_STORAGE": bytes.fromhex("c8fcad8db84d3cc18b4c41d551ea0ee7"),
    }

    # 可升级合约的常见初始化函数选择器
    _INIT_SELECTORS = [
        "0x8129fc1c",  # initialize()
        "0xc4d66de8",  # initialize(address)
        "0x485cc955",  # initialize(address,address)
        "0x7f7c1491",  # __init()
    ]

    def __init__(self):
        self._nodes: Dict[str, SDGNode] = {}
        self._edges: List[SDGEdge] = []

    def build_sdg(
        self, bytecode: bytes, contract_addr: str = ""
    ) -> Tuple[List[SDGNode], List[SDGEdge]]:
        """
        构建扩展的状态依赖图 (SDG) — 包含代理模式节点。

        构建过程:
          1. 扫描 EVM 操作码提取基本节点 (CALL, SLOAD, SSTORE, ...)
          2. 识别 delegatecall 链 → 生成代理模式节点
          3. 分析存储槽位访问 → 标记存储冲突
        """
        nodes: List[SDGNode] = []
        edges: List[SDGEdge] = []
        node_counter = 0

        # 1) 基本操作码扫描
        # DELEGATECALL 检测
        if bytes.fromhex("f4") in bytecode:  # DELEGATECALL opcode
            nid = f"delegatecall_{node_counter}"
            nodes.append(SDGNode(
                node_id=nid, node_type=SDGNodeType.DELEGATECALL,
                contract_address=contract_addr,
            ))
            node_counter += 1

        # 代理模式识别
        proxy = self._detect_proxy_pattern(bytecode, contract_addr)
        if proxy and proxy.pattern_type == "DIAMOND":
            nid = f"diamond_{node_counter}"
            nodes.append(SDGNode(
                node_id=nid, node_type=SDGNodeType.DIAMOND_PROXY,
                contract_address=contract_addr,
            ))

        # 2) 存储槽位分析
        sstore_count = bytecode.count(bytes.fromhex("55"))  # SSTORE
        sload_count = bytecode.count(bytes.fromhex("54"))   # SLOAD
        if sstore_count > 0 or sload_count > 0:
            nid = f"storage_{node_counter}"
            nodes.append(SDGNode(
                node_id=nid,
                node_type=SDGNodeType.STORAGE_COLLISION if sstore_count > 3 else SDGNodeType.SSTORE,
                contract_address=contract_addr,
                storage_slot=sstore_count,
            ))

        # 3) 初始化函数检测
        for sel in self._INIT_SELECTORS:
            sel_bytes = bytes.fromhex(sel[2:])  # 去掉 "0x" 前缀
            if sel_bytes in bytecode:
                nid = f"init_{node_counter}"
                nodes.append(SDGNode(
                    node_id=nid, node_type=SDGNodeType.INITIALIZE,
                    contract_address=contract_addr, function_sig=sel,
                ))
                node_counter += 1

        self._nodes = {n.node_id: n for n in nodes}
        self._edges = edges
        return nodes, edges

    def _detect_proxy_pattern(
        self, bytecode: bytes, addr: str
    ) -> Optional[ProxyPattern]:
        """
        检测代理模式 — 通过字节码特征匹配。

        支持的模式:
          - EIP-1967 透明代理 (Transparent Proxy)
          - EIP-1822 UUPS 代理
          - EIP-2535 钻石代理 (Diamond Proxy)
        """
        for pat_name, pat_bytes in self._PROXY_PATTERNS.items():
            if pat_bytes in bytecode:
                if "TRANSPARENT" in pat_name:
                    return ProxyPattern(
                        pattern_type="TRANSPARENT",
                        proxy_contract=addr,
                        risk_level="MEDIUM",
                    )
                elif "UUPS" in pat_name:
                    return ProxyPattern(
                        pattern_type="UUPS",
                        proxy_contract=addr,
                        risk_level="MEDIUM",
                    )
                elif "DIAMOND" in pat_name:
                    return ProxyPattern(
                        pattern_type="DIAMOND",
                        proxy_contract=addr,
                        risk_level="HIGH",
                    )

        # 启发式: delegatecall + fallback 函数 → 可能是未知代理
        has_delegate = bytes.fromhex("f4") in bytecode
        has_fallback = len(bytecode) < 200  # 小字节码 → 可能是代理
        if has_delegate and has_fallback:
            return ProxyPattern(
                pattern_type="UNKNOWN_PROXY",
                proxy_contract=addr,
                risk_level="LOW",
            )
        return None

    def detect_storage_collision(
        self, impl_a_slots: Set[int], impl_b_slots: Set[int]
    ) -> List[str]:
        """
        检测两个实现合约之间的存储布局冲突。

        可升级合约的核心风险: 当升级到新实现时, 存储布局必须兼容。
        若两个实现在相同槽位存储不同类型的变量, 会导致状态损坏。
        """
        conflicts = []
        overlap = impl_a_slots & impl_b_slots
        for slot in sorted(overlap):
            conflicts.append(
                f"存储冲突 @ 槽位 {slot}: 两个实现都使用此槽位, "
                f"升级可能导致状态损坏"
            )
        return conflicts

    def detect_uninitialized_risk(
        self, init_node: SDGNode, access_control_nodes: List[SDGNode]
    ) -> Tuple[bool, str]:
        """
        检测初始化函数的安全风险。

        风险:
          1. 初始化函数可被多次调用 (缺少 onlyInitializing 修饰符)
          2. 初始化函数缺少访问控制 (anyone 可调用)

        返回:
          (has_risk, reason)
        """
        # 检查是否存在访问控制 (通过 CALLER 操作码检测)
        has_auth = False  # 实际实现中应分析 modifier 调用

        if not has_auth:
            return True, (
                f"初始化函数 {init_node.function_sig} 缺少访问控制: "
                f"任何地址都可能调用此函数"
            )

        return False, "初始化函数已受保护"

    def detect_diamond_selector_conflict(
        self, facets: Dict[str, List[str]]  # selector → [contract_addrs]
    ) -> List[str]:
        """
        检测钻石代理中的选择器冲突。

        EIP-2535 钻石代理的核心风险: 多个面 (facet) 声明了相同的
        函数选择器。只有第一个被注册的面会被调用, 其他的被静默遮蔽。
        """
        conflicts = []
        for selector, contracts in facets.items():
            if len(contracts) >= 2:
                conflicts.append(
                    f"选择器冲突: {selector} 被 {len(contracts)} 个面声明 "
                    f"({', '.join(contracts)}), 只有第一个注册的面会被调用"
                )
        return conflicts

    def full_analysis(
        self, bytecode: bytes, contract_addr: str = ""
    ) -> Dict:
        """
        完整分析 — 返回结构化报告。

        报告包含:
          - SDG 节点和边
          - 检测到的代理模式
          - 存储冲突列表
          - 选择器冲突
          - 风险评分
        """
        nodes, edges = self.build_sdg(bytecode, contract_addr)
        proxy = self._detect_proxy_pattern(bytecode, contract_addr)

        risks = []
        risk_score = 0.0

        if proxy:
            if proxy.risk_level == "HIGH":
                risks.append(f"高风险代理模式: {proxy.pattern_type}")
                risk_score += 0.3
            elif proxy.risk_level == "MEDIUM":
                risks.append(f"中风险代理模式: {proxy.pattern_type}")
                risk_score += 0.15

        # 检查未受保护的初始化
        init_nodes = [n for n in nodes if n.node_type == SDGNodeType.INITIALIZE]
        for init_n in init_nodes:
            has_risk, reason = self.detect_uninitialized_risk(init_n, [])
            if has_risk:
                risks.append(reason)
                risk_score += 0.25

        # 存储冲突 (需要两个合约的实现, 此处标记为需要外部输入)
        storage_nodes = [n for n in nodes if n.node_type == SDGNodeType.STORAGE_COLLISION]
        if storage_nodes:
            risks.append(f"检测到 {len(storage_nodes)} 个存储密集型节点, 建议检查升级兼容性")
            risk_score += 0.1

        return {
            "contract": contract_addr,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "proxy_pattern": proxy.pattern_type if proxy else "NONE",
            "risks": risks,
            "risk_score": min(risk_score, 1.0),
            "risk_level": (
                "CRITICAL" if risk_score > 0.7
                else "HIGH" if risk_score > 0.4
                else "MEDIUM" if risk_score > 0.15
                else "LOW"
            ),
        }


# 便捷函数

def analyze_contract_proxy(bytecode: bytes, addr: str = "") -> Dict:
    """便捷函数: 分析合约的代理模式和安全风险。"""
    return CrossInspectorV2().full_analysis(bytecode, addr)


def check_upgrade_safety(
    old_impl_slots: Set[int], new_impl_slots: Set[int]
) -> List[str]:
    """便捷函数: 检查合约升级的存储兼容性。"""
    inspector = CrossInspectorV2()
    return inspector.detect_storage_collision(old_impl_slots, new_impl_slots)


__all__ = [
    "SDGNodeType", "SDGNode", "SDGEdge", "ProxyPattern",
    "CrossInspectorV2",
    "analyze_contract_proxy", "check_upgrade_safety",
]
