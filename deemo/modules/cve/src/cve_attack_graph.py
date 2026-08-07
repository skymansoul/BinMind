# ~ 2026-09-21
# CVE攻击图生成器——基于CVE匹配数据构建利用链DAG。
# 思路源于Aksu et al. 2018 "Automated Generation of Attack Graphs Using NVD"，
# 但实现更简约：用CWE前置/后置条件对加产品重叠推导潜在利用链，
# 以CVSS可利用性指标加权边概率。
#
# 输出为有向图：节点为CVE，边表示"利用A使利用B更容易或成为可能"。
# 边权重为0-1概率，由CWE关系强度与EPSS评分推导。
#
# 图导出格式：JSON（程序化使用）和GraphML（Gephi/Cytoscape可视化）。

import json
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any

from .cve_models import CVEEntry, Severity

# CWE前置→后置条件链
# 格式: (source_cwe, target_cwe, relationship, confidence)
# confidence: 0.0–1.0，源使能目标的可信度
# 人工整理自CWE研究文献及真实利用链案例。
# 非全覆盖——涵盖APT报告中最常见的链接模式。

_CWE_CHAINS: List[Tuple[str, str, str, float]] = [
    # 信息泄露 → 定向攻击
    ("CWE-200", "CWE-79",  "info_disclosure_enables_targeting", 0.4),
    ("CWE-200", "CWE-89",  "info_disclosure_enables_targeting", 0.3),
    ("CWE-200", "CWE-78",  "info_disclosure_enables_targeting", 0.3),

    # XSS → CSRF（XSS可读取CSRF令牌）
    ("CWE-79",  "CWE-352", "xss_bypasses_csrf", 0.7),

    # SSRF → RCE/注入
    ("CWE-918", "CWE-78",  "ssrf_to_rce", 0.6),
    ("CWE-918", "CWE-94",  "ssrf_to_code_injection", 0.5),
    ("CWE-918", "CWE-89",  "ssrf_to_sqli", 0.3),

    # 认证绕过 → 一切
    ("CWE-287", "CWE-79",  "auth_bypass_enables", 0.5),
    ("CWE-287", "CWE-89",  "auth_bypass_enables", 0.6),
    ("CWE-287", "CWE-78",  "auth_bypass_enables", 0.6),
    ("CWE-287", "CWE-94",  "auth_bypass_enables", 0.5),
    ("CWE-287", "CWE-22",  "auth_bypass_enables", 0.7),
    ("CWE-287", "CWE-434", "auth_bypass_enables", 0.6),

    # 缺失认证 → 类似认证绕过
    ("CWE-306", "CWE-79",  "missing_auth_enables", 0.5),
    ("CWE-306", "CWE-89",  "missing_auth_enables", 0.6),
    ("CWE-306", "CWE-78",  "missing_auth_enables", 0.6),

    # 权限提升 → 高影响
    ("CWE-269", "CWE-78",  "privesc_to_rce", 0.7),
    ("CWE-269", "CWE-94",  "privesc_to_code_injection", 0.6),
    ("CWE-269", "CWE-787", "privesc_to_memory_corruption", 0.5),

    # 路径遍历 → 信息泄露 / RCE
    ("CWE-22",  "CWE-200", "traversal_to_disclosure", 0.8),
    ("CWE-22",  "CWE-94",  "traversal_to_code_exec", 0.4),

    # 反序列化 → RCE
    ("CWE-502", "CWE-94",  "deserialize_to_rce", 0.8),
    ("CWE-502", "CWE-78",  "deserialize_to_rce", 0.6),

    # SQL注入 → 认证绕过 / 数据暴露
    ("CWE-89",  "CWE-287", "sqli_to_auth_bypass", 0.7),
    ("CWE-89",  "CWE-200", "sqli_to_disclosure", 0.8),

    # 文件上传 → RCE / XSS
    ("CWE-434", "CWE-94",  "upload_to_rce", 0.7),
    ("CWE-434", "CWE-79",  "upload_to_xss", 0.5),

    # 缓冲区溢出 → 代码执行
    ("CWE-119", "CWE-94",  "buffer_overflow_to_rce", 0.8),
    ("CWE-787", "CWE-94",  "oob_write_to_rce", 0.7),
    ("CWE-125", "CWE-200", "oob_read_to_disclosure", 0.6),

    # UAF → 代码执行
    ("CWE-416", "CWE-94",  "uaf_to_rce", 0.7),
]


def _cwe_chain_lookup(source_cwe: str, target_cwe: str) -> Optional[Tuple[str, float]]:
    """查找CWE链关系。返回 (relation_type, confidence) 或 None。"""
    for s, t, rel, conf in _CWE_CHAINS:
        if s == source_cwe and t == target_cwe:
            return (rel, conf)
    return None


# 主图构建器

def build_attack_graph(
    cve_matches: List[Dict],
    kb=None,
    include_epss: bool = True,
    min_edge_confidence: float = 0.3,
) -> Dict[str, Any]:
    """从CVE匹配字典列表构建攻击图。

    每个匹配字典至少需含: cve_id, severity, cwes (列表)。
    可选: cvss_score, epss_score, products, description。

    kb: 可选CVEKnowledgeBase用于富化查询（CWE、EPSS）。
    include_epss: 用EPSS评分加权边（若可用）。
    min_edge_confidence: 滤除低置信度边。

    返回图字典:
      {nodes: [...], edges: [...], metadata: {node_count, edge_count, ...}}
    """
    # 按CVE ID索引匹配项
    cve_index: Dict[str, Dict] = {}
    for m in cve_matches:
        cid = m.get("cve_id", "")
        if cid:
            cve_index[cid] = m

    # 构建节点
    nodes: List[Dict] = []
    node_ids: Set[str] = set()
    for cid, m in cve_index.items():
        severity = m.get("severity", "UNKNOWN")
        cwes = m.get("cwes", m.get("cwe", []))
        if isinstance(cwes, str):
            cwes = [cwes]

        # 从知识库富化（若可用）
        if kb and hasattr(kb, 'get'):
            full = kb.get(cid)
            if full is not None:
                if hasattr(full, 'cwes') and full.cwes:
                    cwes = list(full.cwes)
                if hasattr(full, 'epss_score') and full.epss_score is not None:
                    m["epss_score"] = full.epss_score

        node = {
            "id": cid,
            "label": cid,
            "severity": severity,
            "cwes": cwes,
            "cvss_score": m.get("cvss_score"),
            "epss_score": m.get("epss_score"),
            "description": (m.get("description", "") or "")[:200],
            "products": m.get("products", m.get("product", [])),
        }
        nodes.append(node)
        node_ids.add(cid)

    # 构建边：检查每对CVE是否存在CWE链
    edges: List[Dict] = []
    cve_list = list(cve_index.keys())

    for i in range(len(cve_list)):
        for j in range(len(cve_list)):
            if i == j:
                continue
            cid_a = cve_list[i]
            cid_b = cve_list[j]

            m_a = cve_index[cid_a]
            m_b = cve_index[cid_b]

            cwes_a = m_a.get("cwes", m_a.get("cwe", []))
            cwes_b = m_b.get("cwes", m_b.get("cwe", []))
            if isinstance(cwes_a, str):
                cwes_a = [cwes_a]
            if isinstance(cwes_b, str):
                cwes_b = [cwes_b]

            # 检查每对源→目标CWE
            for cwe_src in cwes_a:
                for cwe_tgt in cwes_b:
                    chain = _cwe_chain_lookup(cwe_src, cwe_tgt)
                    if chain is None:
                        continue
                    rel_type, base_conf = chain

                    # 用EPSS调整置信度（若启用）
                    edge_conf = base_conf
                    epss_a = m_a.get("epss_score")
                    epss_b = m_b.get("epss_score")
                    if include_epss and epss_a is not None and epss_b is not None:
                        # 目标EPSS越高 → 链的可利用性越高
                        edge_conf = base_conf * (0.5 + 0.5 * max(epss_a, epss_b))

                    # 同产品加成（共享攻击面）
                    prods_a = set(m_a.get("products", m_a.get("product", [])))
                    prods_b = set(m_b.get("products", m_b.get("product", [])))
                    if isinstance(prods_a, str):
                        prods_a = {prods_a}
                    if isinstance(prods_b, str):
                        prods_b = {prods_b}
                    if prods_a and prods_b and (prods_a & prods_b or _product_overlap(prods_a, prods_b)):
                        edge_conf = min(edge_conf * 1.3, 1.0)

                    if edge_conf >= min_edge_confidence:
                        edges.append({
                            "source": cid_a,
                            "target": cid_b,
                            "relationship": rel_type,
                            "confidence": round(edge_conf, 3),
                            "source_cwe": cwe_src,
                            "target_cwe": cwe_tgt,
                        })
                        break  # 每对(A,B)一条边
                else:
                    continue
                break  # 外层同样跳出

    # 产品重叠边（同产品、不同CWE → 潜在链）
    for i in range(len(cve_list)):
        for j in range(i + 1, len(cve_list)):
            cid_a = cve_list[i]
            cid_b = cve_list[j]
            prods_a = set(cve_index[cid_a].get("products", cve_index[cid_a].get("product", [])))
            prods_b = set(cve_index[cid_b].get("products", cve_index[cid_b].get("product", [])))
            if isinstance(prods_a, str):
                prods_a = {prods_a}
            if isinstance(prods_b, str):
                prods_b = {prods_b}

            if prods_a and prods_b and prods_a & prods_b:
                # 检查是否已存在边
                already = any(
                    (e["source"] == cid_a and e["target"] == cid_b) or
                    (e["source"] == cid_b and e["target"] == cid_a)
                    for e in edges
                )
                if not already:
                    edges.append({
                        "source": cid_a,
                        "target": cid_b,
                        "relationship": "shared_product",
                        "confidence": 0.35,
                        "shared_products": list(prods_a & prods_b),
                    })

    # 计算图指标
    in_degree: Dict[str, int] = defaultdict(int)
    out_degree: Dict[str, int] = defaultdict(int)
    for e in edges:
        out_degree[e["source"]] += 1
        in_degree[e["target"]] += 1

    # 根节点（无入边）与叶节点（无出边）
    roots = [cid for cid in node_ids if in_degree.get(cid, 0) == 0]
    leaves = [cid for cid in node_ids if out_degree.get(cid, 0) == 0]

    # PageRank风格中心性（简化：入度+出度）
    centrality = {
        cid: in_degree.get(cid, 0) + out_degree.get(cid, 0)
        for cid in node_ids
    }

    return {
        "nodes": nodes,
        "edges": edges,
        "metadata": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "root_nodes": roots,
            "leaf_nodes": leaves,
            "centrality": centrality,
            "builder": "cve_attack_graph v1.0",
        },
    }


# 导出

def export_graph_json(graph: Dict, output_path: Optional[str] = None) -> str:
    """攻击图导出为JSON。给定output_path则写入文件。
    始终返回JSON字符串。"""
    json_str = json.dumps(graph, indent=2, default=str, ensure_ascii=False)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)
    return json_str


def export_graph_graphml(graph: Dict, output_path: str) -> str:
    """攻击图导出为GraphML XML（Gephi/Cytoscape用）。"""
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
        '  <key id="severity" for="node" attr.name="severity" attr.type="string"/>',
        '  <key id="cvss_score" for="node" attr.name="cvss_score" attr.type="double"/>',
        '  <key id="epss_score" for="node" attr.name="epss_score" attr.type="double"/>',
        '  <key id="confidence" for="edge" attr.name="confidence" attr.type="double"/>',
        '  <key id="relationship" for="edge" attr.name="relationship" attr.type="string"/>',
        '  <graph id="G" edgedefault="directed">',
    ]

    for node in graph["nodes"]:
        lines.append(
            f'    <node id="{_xml_escape(node["id"])}">'
            f'<data key="severity">{node.get("severity", "")}</data>'
            f'<data key="cvss_score">{node.get("cvss_score") or 0}</data>'
            f'<data key="epss_score">{node.get("epss_score") or 0}</data>'
            f'</node>'
        )

    for edge in graph["edges"]:
        lines.append(
            f'    <edge source="{_xml_escape(edge["source"])}" '
            f'target="{_xml_escape(edge["target"])}">'
            f'<data key="confidence">{edge.get("confidence", 0)}</data>'
            f'<data key="relationship">{_xml_escape(edge.get("relationship", ""))}</data>'
            f'</edge>'
        )

    lines.append('  </graph>')
    lines.append('</graphml>')

    xml_str = '\n'.join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(xml_str)
    return output_path


# 路径分析

def find_attack_paths(
    graph: Dict,
    source_cve: str,
    target_cve: str,
    max_depth: int = 5,
) -> List[List[str]]:
    """在攻击图中查找从source_cve到target_cve的所有简单路径。
    使用DFS加max_depth限制以避免路径爆炸。"""
    # 构建邻接表
    adj: Dict[str, List[str]] = defaultdict(list)
    for edge in graph["edges"]:
        adj[edge["source"]].append(edge["target"])

    paths: List[List[str]] = []

    def dfs(current: str, target: str, visited: Set[str], path: List[str]):
        if len(path) > max_depth:
            return
        if current == target:
            paths.append(list(path))
            return
        for neighbor in adj.get(current, []):
            if neighbor not in visited:
                visited.add(neighbor)
                path.append(neighbor)
                dfs(neighbor, target, visited, path)
                path.pop()
                visited.discard(neighbor)

    if source_cve in adj:
        dfs(source_cve, target_cve, {source_cve}, [source_cve])

    return paths


def highest_risk_paths(graph: Dict, top_n: int = 5) -> List[Dict]:
    """查找图中风险最高的攻击路径。
    风险 = 沿路径的 confidence × severity_weight 之和。
    返回按风险降序排列的top_n条路径。"""
    severity_weight = {
        "CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "NONE": 0, "UNKNOWN": 1,
    }

    # 构建节点查找表
    nodes_by_id = {n["id"]: n for n in graph["nodes"]}

    scored_paths: List[Dict] = []
    roots = graph["metadata"].get("root_nodes", [])
    leaves = graph["metadata"].get("leaf_nodes", [])

    for root in roots[:5]:  # 根节点探索上限
        for leaf in leaves[:5]:
            paths = find_attack_paths(graph, root, leaf, max_depth=4)
            for path in paths:
                risk = 0.0
                for i, cid in enumerate(path):
                    node = nodes_by_id.get(cid, {})
                    sw = severity_weight.get(node.get("severity", "UNKNOWN"), 1)
                    risk += sw
                scored_paths.append({
                    "path": path,
                    "length": len(path),
                    "risk_score": risk,
                    "severities": [nodes_by_id.get(cid, {}).get("severity", "?") for cid in path],
                })

    scored_paths.sort(key=lambda x: x["risk_score"], reverse=True)
    return scored_paths[:top_n]


# 辅助函数

def _product_overlap(prods_a: Set[str], prods_b: Set[str]) -> bool:
    """按子串模糊匹配检查产品名重叠。"""
    for a in prods_a:
        al = a.lower()
        for b in prods_b:
            bl = b.lower()
            if al in bl or bl in al:
                return True
    return False


def _xml_escape(s: str) -> str:
    """XML/GraphML特殊字符转义。"""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
