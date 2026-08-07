"""
密码学攻击树构建 — 从检测到的弱点自动构建攻击树并计算复合攻击成本。

创建: 2026-05-08 08:31
修改:
  2025-09-27 08:31 — 初始实现: AND/OR门/叶节点/成本传播/最优攻击路径

设计意图:
  crypto_attack_feasibility对单个弱点做可行性估计(如\"MD5碰撞≈2^18操作\"),
  但现实攻击常组合多个弱点: 暴力破解密钥 + 碰撞伪造证书 + 降级协议版本。
  攻击树(Attack Tree)是安全工程的标准工具, 用AND/OR门组合攻击步骤,
  自底向上传播成本, 找到全局最优攻击路径。

  本模块构建和评估攻击树:
    N1 (叶节点): 单个可攻击的弱点 — 附带成本估计(log2操作数)。
    N2 (OR门): 任一子节点成功即成功 — 成本 = min(子节点成本)。
    N3 (AND门): 所有子节点成功才成功 — 成本 = Σ(子节点成本) (独立假设)。
    N4 (序贯AND): 子节点必须顺序执行 — 成本 = Σ(子节点成本), 但对N-1个做折扣。
    N5 (根节点): 攻击者的最终目标 — 成本 = 门传播结果。

  输出: 最优攻击路径 + 攻击总成本 + 可行性等级。

  - Schneier: 攻击树方法论 — AND/OR门形式化。
  - Buldas et al.: 多参数攻击树 — 序贯AND门和成本折扣。
  - NIST SP 800-30 Rev.1: 风险评估指南 — 攻击树用于威胁建模。

边界条件:
  - 攻击树中的成本假设各步骤独立 — 实际中步骤间可能有依赖(降低或增加总成本)。
  - 成本估计为log2数量级近似 — 不精确到常数因子。
  - 攻击树为静态模型 — 不建模自适应攻击者(根据中间结果改变策略)。
"""

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

class GateType(Enum):
    LEAF = 0
    OR = 1
    AND = 2
    SEQ_AND = 3   # 序贯AND: 子节点必须按顺序执行

@dataclass
class AttackNode:
    node_id: str = ""
    label: str = ""
    gate: GateType = GateType.LEAF
    cost_bits: float = 0.0       # log2(操作数/时间/资源)
    children: List['AttackNode'] = field(default_factory=list)
    is_exploitable: bool = False  # 叶节点: 此弱点是否实际可攻击
    evidence: str = ""            # 叶节点: 二进制中的检测证据
    mitigation: str = ""          # 叶节点: 如何消除此弱点

@dataclass
class AttackTreeResult:
    root: AttackNode
    total_cost_bits: float = 0.0
    optimal_path: List[str] = field(default_factory=list)
    feasibility: str = ""         # TRIVIAL / PRACTICAL / ACADEMIC / THEORETICAL
    estimated_cost_usd: str = ""
    estimated_time: str = ""

# 成本传播

def _propagate_cost(node: AttackNode) -> float:
    """
    自底向上传播攻击成本。
    LEAF: 直接返回cost_bits
    OR: min(child costs) — 攻击者选择最便宜的路径
    AND: sum(child costs) — 攻击者需完成全部子步骤
    SEQ_AND: sum + 对N-1步骤做log2(N)折扣(步骤越多→越难并行)
    """
    if node.gate == GateType.LEAF:
        return node.cost_bits if node.is_exploitable else float('inf')

    child_costs = [_propagate_cost(c) for c in node.children]
    if not child_costs:
        return float('inf')

    if node.gate == GateType.OR:
        cost = min(child_costs)
    elif node.gate == GateType.AND:
        cost = sum(c for c in child_costs if c != float('inf'))
        if any(c == float('inf') for c in child_costs):
            cost = float('inf')  # AND: 一个不可行→全部不可行
    elif node.gate == GateType.SEQ_AND:
        finite = [c for c in child_costs if c != float('inf')]
        if len(finite) < len(child_costs):
            cost = float('inf')
        else:
            cost = sum(finite)
            n = len(finite)
            if n >= 2:
                cost -= math.log2(n) * (n - 1)  # 序贯折扣
    else:
        cost = float('inf')

    node.cost_bits = max(0.0, cost)
    return node.cost_bits

def _extract_optimal_path(node: AttackNode, path: List[str]) -> None:
    """从根节点回溯最优攻击路径。"""
    path.append(f'{node.label} [{node.gate.name}]')

    if node.gate == GateType.LEAF:
        return

    if node.gate == GateType.OR:
        # 选成本最小的子节点
        best = min(node.children, key=lambda c: c.cost_bits)
        _extract_optimal_path(best, path)
    elif node.gate in (GateType.AND, GateType.SEQ_AND):
        # 全取(但跳过不可行的)
        feasible = [c for c in node.children if c.cost_bits != float('inf')]
        for c in sorted(feasible, key=lambda x: -x.cost_bits):
            _extract_optimal_path(c, path)

# 预定义攻击树模板

def build_tls_interception_tree() -> AttackNode:
    """
    构建TLS拦截攻击树: 攻击者希望解密或伪造TLS会话。
    根=OR(中间人解密, 证书伪造, 降级攻击, 私钥窃取)
    """
    return AttackNode(
        node_id='ROOT', label='TLS会话攻破', gate=GateType.OR,
        children=[
            AttackNode(node_id='MITM', label='中间人解密', gate=GateType.SEQ_AND,
                children=[
                    AttackNode('C1', 'ARP/DNS欺骗', GateType.LEAF, 5.0,
                               is_exploitable=True, evidence='网络位置'),
                    AttackNode('C2', 'TLS降级到弱密码套件', GateType.LEAF, 3.0,
                               is_exploitable=True, evidence='协议支持DES/3DES'),
                    AttackNode('C3', '暴力破解会话密钥', GateType.LEAF, 56.0,
                               is_exploitable=True, evidence='DES-56bit密钥'),
                ]),
            AttackNode(node_id='CERT_FORGERY', label='证书伪造', gate=GateType.AND,
                children=[
                    AttackNode('C4', 'MD5碰撞生成 rogue CA', GateType.LEAF, 18.0,
                               is_exploitable=True, evidence='MD5签名检测'),
                    AttackNode('C5', '部署伪造证书', GateType.LEAF, 8.0,
                               is_exploitable=True, evidence='网络访问'),
                ]),
            AttackNode(node_id='DOWNGRADE', label='协议降级攻击', gate=GateType.SEQ_AND,
                children=[
                    AttackNode('C6', '剥离TLS→明文', GateType.LEAF, 10.0,
                               is_exploitable=True, evidence='无HSTS'),
                    AttackNode('C7', '中间人转发明文流量', GateType.LEAF, 5.0,
                               is_exploitable=True, evidence='网络位置'),
                ]),
            AttackNode(node_id='KEY_THEFT', label='私钥窃取', gate=GateType.OR,
                children=[
                    AttackNode('C8', '内存转储提取密钥', GateType.LEAF, 15.0,
                               is_exploitable=True, evidence='密钥未清零'),
                    AttackNode('C9', '侧信道(DIRECT信道)', GateType.LEAF, 20.0,
                               is_exploitable=True, evidence='memcpy近密钥'),
                ]),
        ])

def build_aes_key_recovery_tree(entropy_bits: int = 128,
                                 has_side_channel: bool = False,
                                 has_weak_entropy: bool = False) -> AttackNode:
    """
    构建AES密钥恢复攻击树, 根据检测结果定制。
    """
    # 叶节点根据检测结果动态设置
    brute_force_cost = entropy_bits if has_weak_entropy else 128
    children = [
        AttackNode('BF', '暴力破解密钥', GateType.LEAF, brute_force_cost,
                   is_exploitable=brute_force_cost < 90,
                   evidence=f'密钥熵≈{entropy_bits}bit'
                   + ('(弱熵源)' if has_weak_entropy else ''),
                   mitigation='使用硬件TRNG + 256-bit密钥'),
        AttackNode('CRYPT', '密码分析攻击', GateType.LEAF, 80.0,
                   is_exploitable=False,
                   evidence='AES无已知密码分析攻击',
                   mitigation='N/A — AES已充分分析'),
    ]
    if has_side_channel:
        children.append(
            AttackNode('SC', '侧信道密钥提取', GateType.LEAF, 10.0,
                       is_exploitable=True,
                       evidence='侧信道泄漏路径存在',
                       mitigation='实现常量时间AES + 掩码对策'))

    return AttackNode(
        node_id='AES_ROOT', label='AES密钥恢复', gate=GateType.OR,
        children=children)

# 主评估函数

def evaluate_attack_tree(root: AttackNode) -> AttackTreeResult:
    """评估攻击树: 传播成本 → 提取最优路径 → 判定可行性。"""
    total = _propagate_cost(root)

    path: List[str] = []
    if total != float('inf'):
        _extract_optimal_path(root, path)

    # 可行性判定
    if total <= 20:
        feas = 'TRIVIAL'
        cost_str = '<$100'
        time_str = '<1 hour'
    elif total <= 40:
        feas = 'PRACTICAL'
        cost_str = '$100–$10K'
        time_str = '<1 week'
    elif total <= 70:
        feas = 'ACADEMIC'
        cost_str = '$10K–$1M'
        time_str = '<1 year'
    elif total <= 100:
        feas = 'THEORETICAL'
        cost_str = '>$1M'
        time_str = '>10 years'
    else:
        feas = 'NOT_FEASIBLE'
        cost_str = '>$1B'
        time_str = '>100 years'

    return AttackTreeResult(
        root=root,
        total_cost_bits=round(total, 2) if total != float('inf') else float('inf'),
        optimal_path=path,
        feasibility=feas,
        estimated_cost_usd=cost_str,
        estimated_time=time_str)
