# -*- coding: utf-8 -*-
# 创建: 2026-07-30  |  攻击图构建器
# 修改: 2026-08-04  |  审计后补充文件头与错误处理
#
"""
漏洞驱动攻击图合成——从二进制漏洞分析自动构建系统级攻击图。

节点: VULN(漏洞)/STATE(系统状态)/ACTION(攻击动作)/DEFENSE(防护)
边: EXPLOIT(利用)/ESCALATE(提权)/PIVOT(横向移动)/MITIGATE(阻断)
自动推断: 漏洞类型→前提条件→后置条件→图边

与ChainReactor(PDDL需手工)和Raiju(RL需Metasploit)不同:
本模块从二进制漏洞分析输出自动推断攻击图——消除手工建模。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


# ============================================================================
# 攻击图类型
# ============================================================================


class NodeType(str, Enum):
    VULN = "vulnerability"
    STATE = "system_state"
    ACTION = "attack_action"
    DEFENSE = "defense_mechanism"


class EdgeType(str, Enum):
    EXPLOIT = "exploit"
    ESCALATE = "escalate"
    PIVOT = "pivot"
    MITIGATE = "mitigate"


@dataclass
class AttackNode:
    """攻击图节点"""
    node_id: str
    node_type: str           # NodeType值
    # 漏洞节点
    cve_id: str = ""
    vuln_type: str = ""
    cvss_score: float = 0.0
    # 状态节点
    privilege_level: str = ""  # none|user|root|kernel
    network_access: str = ""   # local|lan|wan
    # 防护节点
    mitigation_type: str = ""  # ASLR|NX|CFI|CANARY|SECCOMP
    is_bypassed: bool = False
    # 图结构
    data: Dict = field(default_factory=dict)


@dataclass
class AttackEdge:
    """攻击图边——有向攻击步骤"""
    from_node: str
    to_node: str
    edge_type: str           # EdgeType值
    # 利用条件
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    # 攻击难度
    difficulty: float = 0.5   # [0, 1]
    estimated_time_hours: float = 0.0
    # 所需能力
    required_capabilities: List[str] = field(default_factory=list)


@dataclass
class AttackGraph:
    """完整攻击图——节点+边+攻击路径"""
    nodes: Dict[str, AttackNode] = field(default_factory=dict)
    edges: List[AttackEdge] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)
    high_value_targets: List[str] = field(default_factory=list)
    # 图属性
    total_nodes: int = 0
    total_edges: int = 0
    max_attack_depth: int = 0


# ============================================================================
# 攻击图构建器
# ============================================================================


class AttackGraphBuilder:
    """从漏洞分析结果自动构建攻击图。

    推断规则——漏洞类型→攻击前提+后置:
      基于MITRE ATT&CK和CWE数据库的先验知识。
      每条规则定义: 此漏洞类型需要什么前提条件，成功后获得什么能力。

    构建流程:
      1. 创建VULN节点(每漏洞一个)
      2. 为每个VULN推断前提条件→创建STATE节点
      3. 连接VULN→STATE边(EXPLOIT类型)
      4. 创建DEFENSE节点(CANARY/CFI/ASLR等)
      5. 连接DEFENSE→VULN边(MITIGATE类型——若防护有效)
      6. 识别入口点(外部可达)和高价值目标(root/shell)
    """

    _VULN_RULES = {
        'stack_buffer_overflow': {
            'pre': ['可控输入', '无栈canary或canary已知', 'NX可绕过或关闭'],
            'post': ['RIP控制', '任意代码执行', 'user级shell'],
            'capabilities': ['ROP链构造', 'shellcode或ret2libc'],
            'difficulty_base': 0.3,
        },
        'heap_overflow': {
            'pre': ['堆分配可控', '堆布局可操纵'],
            'post': ['任意写', '控制流劫持(间接调用)'],
            'capabilities': ['堆风水', 'malloc/free模式理解'],
            'difficulty_base': 0.6,
        },
        'use_after_free': {
            'pre': ['悬垂指针可触发', '堆喷射可行'],
            'post': ['对象类型混淆', '虚表劫持', '任意代码执行'],
            'capabilities': ['堆风水', '类型混淆利用'],
            'difficulty_base': 0.7,
        },
        'format_string': {
            'pre': ['格式化字符串可控', '栈地址已知或可泄露'],
            'post': ['任意读', '任意写', '信息泄露'],
            'capabilities': ['格式化字符串利用', '%n写原语'],
            'difficulty_base': 0.4,
        },
        'integer_overflow': {
            'pre': ['整数运算无检查', '溢出导致缓冲区缩小'],
            'post': ['缓冲区溢出(间接)', '堆/栈破坏'],
            'capabilities': ['整数溢出触发', '后续利用链'],
            'difficulty_base': 0.5,
        },
    }

    def __init__(self):
        self._graph = AttackGraph()
        self._node_counter = 0

    def build(self, vulnerabilities: List[Dict],
               protections: Dict[str, str] = None,
               system_info: Dict = None) -> AttackGraph:
        """从漏洞列表构建攻击图。

        参数:
          vulnerabilities: [{type, cve_id, function, cvss, address}, ...]
          protections: {NX, ASLR, PIE, CANARY, CFI, SECCOMP}
          system_info: {os, arch, network_exposure, ...}

        返回AttackGraph。
        """
        self._graph = AttackGraph()
        prot = protections or {}

        # 创建初始状态节点
        entry = self._add_state_node("初始访问", "none", "wan")
        self._graph.entry_points.append(entry.node_id)

        root_target = self._add_state_node("root权限", "root", "local")
        self._graph.high_value_targets.append(root_target.node_id)

        shell_target = self._add_state_node("shell访问", "user", "local")
        self._graph.high_value_targets.append(shell_target.node_id)

        # 为每个漏洞创建VULN节点+边
        for vuln in vulnerabilities:
            vtype = vuln.get('type', '')
            rule = self._VULN_RULES.get(vtype, {})
            pre = rule.get('pre', ['未知前提条件'])
            post = rule.get('post', ['未知后置条件'])
            caps = rule.get('capabilities', [])
            diff = rule.get('difficulty_base', 0.5)

            # VULN节点
            vnode = self._add_vuln_node(vuln, diff)

            # 连接入口点到VULN——攻击者从初始访问出发
            self._graph.edges.append(AttackEdge(
                from_node=entry.node_id, to_node=vnode.node_id,
                edge_type=EdgeType.EXPLOIT,
                preconditions=['网络可达', '输入可控'],
                difficulty=0.1))

            # 检查防护是否阻断
            mitigated = self._check_mitigations(vtype, prot)
            if mitigated:
                for m in mitigated:
                    mnode = self._add_defense_node(m)
                    self._graph.edges.append(AttackEdge(
                        from_node=mnode.node_id, to_node=vnode.node_id,
                        edge_type=EdgeType.MITIGATE,
                        preconditions=[f"{m}启用"], difficulty=0.0))

            # 前提条件→VULN边
            for pcond in pre:
                pnode = self._add_state_node(pcond, "none", "local")
                self._graph.edges.append(AttackEdge(
                    from_node=pnode.node_id, to_node=vnode.node_id,
                    edge_type=EdgeType.EXPLOIT,
                    preconditions=[pcond], difficulty=0.2))

            # VULN→后置条件边
            for pcond in post:
                snode = self._add_state_node(pcond, "varies", "local")
                edge = AttackEdge(
                    from_node=vnode.node_id, to_node=snode.node_id,
                    edge_type=EdgeType.EXPLOIT,
                    preconditions=pre,
                    postconditions=post,
                    difficulty=diff,
                    estimated_time_hours=diff * 48.0,
                    required_capabilities=caps)
                self._graph.edges.append(edge)

            # 若后置条件含"shell"或"代码执行"→连接至shell_target
            if any('shell' in p.lower() or '代码执行' in p for p in post):
                self._graph.edges.append(AttackEdge(
                    from_node=vnode.node_id, to_node=shell_target.node_id,
                    edge_type=EdgeType.ESCALATE,
                    preconditions=post, difficulty=diff))

        # 从shell→root的提权边(若存在setuid/sudo路径)
        self._graph.edges.append(AttackEdge(
            from_node=shell_target.node_id, to_node=root_target.node_id,
            edge_type=EdgeType.ESCALATE,
            preconditions=['user级shell', '可提权漏洞或配置错误'],
            difficulty=0.5, estimated_time_hours=4.0))

        self._graph.total_nodes = len(self._graph.nodes)
        self._graph.total_edges = len(self._graph.edges)

        return self._graph

    def _add_vuln_node(self, vuln: Dict, diff: float) -> AttackNode:
        node = AttackNode(
            node_id=f"VULN_{self._node_counter}",
            node_type=NodeType.VULN,
            cve_id=vuln.get('cve_id', ''),
            vuln_type=vuln.get('type', ''),
            cvss_score=vuln.get('cvss', 5.0),
            data={'difficulty': diff})
        self._graph.nodes[node.node_id] = node
        self._node_counter += 1
        return node

    def _add_state_node(self, label: str, priv: str,
                          net: str) -> AttackNode:
        sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', label)[:40]
        nid = f"STATE_{sanitized}_{self._node_counter}"
        if nid not in self._graph.nodes:
            node = AttackNode(node_id=nid, node_type=NodeType.STATE,
                               privilege_level=priv, network_access=net,
                               data={'label': label})
            self._graph.nodes[nid] = node
            self._node_counter += 1
            return node
        return self._graph.nodes[nid]

    def _add_defense_node(self, mtype: str) -> AttackNode:
        nid = f"DEF_{mtype}"
        if nid not in self._graph.nodes:
            node = AttackNode(node_id=nid, node_type=NodeType.DEFENSE,
                               mitigation_type=mtype)
            self._graph.nodes[nid] = node
            self._node_counter += 1
            return node
        return self._graph.nodes[nid]

    def _check_mitigations(self, vtype: str,
                            prot: Dict[str, str]) -> List[str]:
        """检查哪些防护机制可阻断此漏洞类型的利用"""
        blocked = []
        if 'stack' in vtype:
            if prot.get('CANARY', '') == 'yes':
                blocked.append('CANARY')
            if prot.get('NX', 'yes') == 'yes':
                blocked.append('NX')
        if 'heap' in vtype or 'use_after_free' in vtype:
            if prot.get('CFI', '') == 'yes':
                blocked.append('CFI')
        if prot.get('ASLR', 'yes') == 'yes':
            blocked.append('ASLR')
        return blocked


__all__ = [
    "NodeType", "EdgeType",
    "AttackNode", "AttackEdge", "AttackGraph",
    "AttackGraphBuilder",
]
