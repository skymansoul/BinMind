# coding: utf-8
#
"""
传递式供应链漏洞传播-函数级依赖图构建。

技术问题:
  现有SBOM漏洞分析(supply_chain.py)仅报告直接依赖的已知CVE。
  现实中漏洞通过传递式依赖链传播:   libA-libB-app,
  libA的漏洞通过libB的调用路径间接影响app。

  现有方法(Grype/Syft/VPSS)在包级分析，无法区分:
   - app依赖libB, libB使用了libA的易受攻击函数 - 真实风险
   - app依赖libB, libB未调用libA的易受攻击函数 - 误报

解决方案:
  在每个包的SBOM依赖关系之上叠加
  函数调用图的细粒度可达性分析:
    节点: (包, 函数) 二元组
      边: (包A.f - 包B.g) 若f直接或间接调用g
     漏洞标记: 已知CVE影响的函数节点
     传播: 从漏洞标记沿反向调用边BFS,受影响的调用者即传播目标

  函数级修剪的实证依据:
    调用图分析显示项目通常仅使用导入库功能的一小部分，
    基于清单的依赖网络系统性高估传递式关系。

与supply_chain.py的关系:
   supply_chain.py - 直接依赖的包级CVE匹配
   本模块 - 传递式依赖的函数级可达性分析与风险传播
"""

import re
import math
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict, deque

_log = logging.getLogger(__name__)


# 依赖图类型


@dataclass
class DepNode:
    """依赖图节点: (包, 函数)二元组"""
    package: str = ""          # 包名/组件名(空字符串仅用于回退DepNode())
    version: str = ""
    function_name: str = ""    # 空字符串-包级节点(非函数级)
    # 漏洞元数据
    cve_ids: List[str] = field(default_factory=list)
    cvss_scores: Dict[str, float] = field(default_factory=dict)
    # 图结构
    callers: Set[str] = field(default_factory=set)    # 调用者节点ID
    callees: Set[str] = field(default_factory=set)    # 被调用者节点ID
    # 统计
    is_vulnerable: bool = False
    is_entry_point: bool = False  # 外部可访问入口


@dataclass
class TransitivePath:
    """传递式传播路径: 从漏洞源到受影响目标的完整调用链"""
    source_node: str           # 漏洞节点ID
    target_node: str           # 受影响目标节点ID
    path_nodes: List[str] = field(default_factory=list)  # 中间节点ID序列
    path_length: int = 0
    # 传播风险
    propagation_probability: float = 0.0  # 漏洞沿此路径传播的概率
    call_depth: int = 0
    # 时间维度
    vuln_disclosure_days: float = 0.0     # 漏洞公开至今的天数


@dataclass
class DepGraphAnalysis:
    """依赖图分析完整输出"""
    nodes: Dict[str, DepNode] = field(default_factory=dict)
    paths: List[TransitivePath] = field(default_factory=list)
    # 统计
    total_packages: int = 0
    total_functions: int = 0
    vulnerable_nodes: int = 0
    affected_targets: int = 0
    max_propagation_depth: int = 0


# 函数级依赖图构建器


class FunctionLevelDepGraph:
    """函数级依赖图: 在包依赖关系之上叠加函数调用可达性。

    构建流程:
      1. 加载包级依赖关系(SBOM/清单)
      2. 对每对依赖包，提取跨包函数调用
      3. 构建(包, 函数)-(包, 函数)的有向调用图
      4. 标注已知CVE影响的函数节点
      5. 反向BFS计算所有受影响节点与传播路径

    复杂度: O(|V| + |E|) 用于BFS可达性，O(|P|×|F|)用于图构建
    其中|P|=包数, |F|=每包函数数。
    """

    def __init__(self):
        self._nodes: Dict[str, DepNode] = {}
        # 节点ID格式: "package::function" 或 "package::"(包级)

    def add_package(self, name: str, version: str = "",
                     functions: List[str] = None):
        """添加包及可选函数列表"""
        pkg_id = f"{name}::"
        if pkg_id not in self._nodes:
            self._nodes[pkg_id] = DepNode(package=name, version=version)

        for func in (functions or []):
            node_id = f"{name}::{func}"
            if node_id not in self._nodes:
                self._nodes[node_id] = DepNode(
                    package=name, version=version, function_name=func)
            # 建立包-函数包含关系
            self._nodes[pkg_id].callees.add(node_id)

    def add_dependency(self, from_pkg: str, to_pkg: str):
        """添加包级依赖关系: from依赖to"""
        from_id = f"{from_pkg}::"
        to_id = f"{to_pkg}::"
        if from_id in self._nodes and to_id in self._nodes:
            self._nodes[from_id].callees.add(to_id)
            self._nodes[to_id].callers.add(from_id)

    def add_call_edge(self, caller_pkg: str, caller_func: str,
                       callee_pkg: str, callee_func: str):
        """添加跨包函数调用边"""
        caller_id = f"{caller_pkg}::{caller_func}"
        callee_id = f"{callee_pkg}::{callee_func}"
        for nid in (caller_id, callee_id):
            if nid not in self._nodes:
                parts = nid.split('::')
                self._nodes[nid] = DepNode(
                    package=parts[0], function_name=parts[1])
        self._nodes[caller_id].callees.add(callee_id)
        self._nodes[callee_id].callers.add(caller_id)

    def mark_vulnerable(self, package: str, function: str,
                          cve_id: str, cvss: float = 7.0):
        """标记漏洞函数"""
        node_id = f"{package}::{function}"
        if node_id in self._nodes:
            self._nodes[node_id].is_vulnerable = True
            self._nodes[node_id].cve_ids.append(cve_id)
            self._nodes[node_id].cvss_scores[cve_id] = cvss
        else:
            # 创建仅有漏洞标记的节点
            self._nodes[node_id] = DepNode(
                package=package, function_name=function,
                is_vulnerable=True, cve_ids=[cve_id],
                cvss_scores={cve_id: cvss})

    def analyze_propagation(self, max_depth: int = 5
                             ) -> DepGraphAnalysis:
        """执行传递式传播分析: 从漏洞节点反向BFS。

        找出所有可通过调用链到达漏洞节点的上游函数。
        这些函数即潜在的受漏洞影响的调用者。
        """
        # 识别所有漏洞节点
        vuln_nodes = [nid for nid, node in self._nodes.items()
                      if node.is_vulnerable and node.function_name]

        if not vuln_nodes:
            return DepGraphAnalysis(
                nodes=self._nodes,
                total_packages=len(set(n.package for n in self._nodes.values())),
                total_functions=len([n for n in self._nodes.values()
                                      if n.function_name]))

        # 对每个漏洞节点执行反向BFS
        all_paths = []
        affected = set()

        for vuln_id in vuln_nodes:
            # 反向BFS-沿callers追溯
            visited = {vuln_id}
            q = deque([(vuln_id, [vuln_id], 0)])
            while q:
                current, path, depth = q.popleft()
                if depth >= max_depth:
                    continue
                for caller in self._nodes.get(current, DepNode()).callers:
                    if caller in visited:
                        continue
                    visited.add(caller)
                    new_path = [caller] + path
                    # 仅记录函数级节点作为传播目标
                    if self._nodes[caller].function_name:
                        affected.add(caller)
                        all_paths.append(TransitivePath(
                            source_node=vuln_id,
                            target_node=caller,
                            path_nodes=new_path,
                            path_length=len(new_path),
                            propagation_probability=0.8 ** (len(new_path) - 1),
                            call_depth=len(new_path) - 1))
                    q.append((caller, new_path, depth + 1))

        # 去重,保留最短路径
        unique_paths = {}
        for p in all_paths:
            key = (p.source_node, p.target_node)
            if key not in unique_paths or p.path_length < unique_paths[key].path_length:
                unique_paths[key] = p

        return DepGraphAnalysis(
            nodes=self._nodes,
            paths=list(unique_paths.values()),
            total_packages=len(set(n.package for n in self._nodes.values())),
            total_functions=len([n for n in self._nodes.values()
                                  if n.function_name]),
            vulnerable_nodes=len(vuln_nodes),
            affected_targets=len(affected),
            max_propagation_depth=max(
                (p.path_length for p in unique_paths.values()), default=0))


__all__ = [
    "DepNode",
    "TransitivePath",
    "DepGraphAnalysis",
    "FunctionLevelDepGraph",
]
