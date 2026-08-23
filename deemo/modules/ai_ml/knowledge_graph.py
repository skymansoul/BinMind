#!/usr/bin/env python3
# 漏洞知识图: 高层分析（中心性/差异对比/可视化/合并）
# 底层图DB操作抽取到 src/graph/graph_ops.py
# VulnKnowledgeGraph继承BaseGraphOps保持向后兼容

import logging as _logging
import json as _json
import os as _os
from collections import defaultdict as _defaultdict
from typing import Dict, List, Optional, Any, Tuple, Set, Union

# 底层图DB操作——向后兼容重导出
from .src.graph.graph_ops import (
    ENTITY_TYPES,
    RELATION_TYPES,
    KnowledgeGraphEntity,
    KnowledgeGraphRelation,
    CypherQuery,
    BaseGraphOps,
)

_dbg = _logging.getLogger(__name__)


class VulnKnowledgeGraph(BaseGraphOps):
    """漏洞知识图——分析/可视化/导出。

    继承BaseGraphOps的CRUD/遍历/查询/子图/统计/序列化，
    新增中心性分析、差异对比、D3/Graphviz/GEXF导出、图合并。
    """

    __slots__ = ()

    def __init__(self, name="vuln_kg"):
        super().__init__(name)

    # 中心性分析——识别知识图中关键枢纽节点
    # 度中心性: C_D(v) = deg(v)/(N-1)，度量局部影响力
    # 介数中心性: 经过节点的最短路径比例(Brandes算法无权)
    # CVE图中介数高者通常是核心漏洞或广泛依赖的库

    def find_central_nodes(self, top_n: int = 10, centrality: str = "degree") -> List[Dict[str, Any]]:
        """计算中心性分数，返回前N个核心节点。

        centrality模式:
          - "degree": 度中心性（归一化）
          - "betweenness": 介数中心性（Brandes算法无权）
          - "all": 同时返回度和介数
        """
        n = max(len(self.m_entities), 1)
        entities = list(self.m_entities.values())

        # ---- 度中心性: C_D(v) = deg(v) / (n-1) ----
        if centrality in ("degree", "all"):
            degree_scores: Dict[str, float] = {}
            ei = 0
            while ei < len(entities):
                eid = entities[ei].m_id
                out_d = len(self.m_adj_out.get(eid, []))
                in_d = len(self.m_adj_in.get(eid, []))
                degree_scores[eid] = (out_d + in_d) / (n - 1) if n > 1 else 0.0
                ei += 1

# 介数中心性: Brandes算法每节点BFS
        if centrality in ("betweenness", "all"):
            # O(V*(V+E))——大图警告
            betweenness: Dict[str, float] = {e.m_id: 0.0 for e in entities}
            if n > 5000:
                _dbg.warning("Betweenness centrality may be slow for graphs with >5000 nodes (%d nodes)", n)

            # 构建前向邻接表
            fwd_adj: Dict[str, List[str]] = _defaultdict(list)
            rels = list(self.m_relations.values())
            ri = 0
            while ri < len(rels):
                r = rels[ri]
                fwd_adj[r.m_src].append(r.m_dst)
                ri += 1

            eids_list = list(self.m_entities.keys())
            si = 0
            while si < len(eids_list):
                s = eids_list[si]
                # BFS从s出发
                stack: List[str] = []
                pred: Dict[str, List[str]] = {v: [] for v in eids_list}
                sigma: Dict[str, float] = {v: 0.0 for v in eids_list}
                dist: Dict[str, int] = {v: -1 for v in eids_list}

                sigma[s] = 1.0
                dist[s] = 0
                q: List[str] = [s]
                qi = 0
                while qi < len(q):
                    v = q[qi]
                    qi += 1
                    stack.append(v)
                    nbrs = fwd_adj.get(v, [])
                    wj = 0
                    while wj < len(nbrs):
                        w = nbrs[wj]
                        if dist[w] < 0:
                            dist[w] = dist[v] + 1
                            q.append(w)
                        if dist[w] == dist[v] + 1:
                            sigma[w] += sigma[v]
                            pred[w].append(v)
                        wj += 1

                delta: Dict[str, float] = {v: 0.0 for v in eids_list}
                # 逆序处理栈（叶到根）
                sk = len(stack) - 1
                while sk >= 0:
                    w = stack[sk]
                    sk -= 1
                    pj = 0
                    pw_list = pred[w]
                    while pj < len(pw_list):
                        v = pw_list[pj]
                        frac = (sigma[v] / sigma[w]) if sigma[w] > 0 else 0.0
                        delta[v] += frac * (1.0 + delta[w])
                        pj += 1
                    if w != s:
                        betweenness[w] += delta[w]
                si += 1

            # 有向图归一化: 除以(n-1)*(n-2)
            norm_factor = (n - 1) * (n - 2) if n > 2 else 1.0
            if norm_factor > 0:
                bi = 0
                bkeys = list(betweenness.keys())
                while bi < len(bkeys):
                    betweenness[bkeys[bi]] /= norm_factor
                    bi += 1

# 汇总结果
        result: List[Dict[str, Any]] = []
        ei = 0
        while ei < len(entities):
            ent = entities[ei]
            entry: Dict[str, Any] = {
                "id": ent.m_id,
                "type": ent.m_type,
                "label": ent.get_property("name", ent.m_id),
            }
            if centrality in ("degree", "all"):
                entry["degree_centrality"] = round(degree_scores[ent.m_id], 6)
            if centrality in ("betweenness", "all"):
                entry["betweenness_centrality"] = round(betweenness[ent.m_id], 6)
            result.append(entry)
            ei += 1

        # 按主中心性指标排序
        if centrality == "betweenness":
            result.sort(key=lambda x: x.get("betweenness_centrality", 0), reverse=True)
        elif centrality == "all":
            result.sort(key=lambda x: x.get("degree_centrality", 0), reverse=True)
        else:
            result.sort(key=lambda x: x.get("degree_centrality", 0), reverse=True)

        return result[:top_n]

    # 图差异对比——用于漏洞数据版本追踪
    # 返回新增/删除/修改的实体和关系，支持审计和回归检测

    def diff(self, other: 'VulnKnowledgeGraph') -> Dict[str, Any]:
        """对比本图(基线)与另一图(新版本)。

        返回含 added/removed/modified 实体和关系的字典。
        实体类型/属性/标签变化即为modified；关系类型/权重/源/目标/属性变化同理。
        """
        changes: Dict[str, Any] = {
            "added_entities": [],
            "removed_entities": [],
            "modified_entities": [],
            "added_relations": [],
            "removed_relations": [],
            "modified_relations": [],
        }

# 实体对比
        my_eids = set(self.m_entities.keys())
        other_eids = set(other.m_entities.keys())

        # 新增(在other中，不在self中)
        add_eids = other_eids - my_eids
        aid = 0
        add_list = sorted(add_eids)
        while aid < len(add_list):
            changes["added_entities"].append(other.m_entities[add_list[aid]].to_dict())
            aid += 1

        # 删除(在self中，不在other中)
        del_eids = my_eids - other_eids
        didx = 0
        del_list = sorted(del_eids)
        while didx < len(del_list):
            changes["removed_entities"].append(self.m_entities[del_list[didx]].to_dict())
            didx += 1

        # 修改(双方都有但内容不同)
        common_eids = my_eids & other_eids
        eids_sorted = sorted(common_eids)
        ei = 0
        while ei < len(eids_sorted):
            eid = eids_sorted[ei]
            my_ent = self.m_entities[eid]
            other_ent = other.m_entities[eid]
            mod_entry: Dict[str, Any] = {"id": eid, "changes": []}
            if my_ent.m_type != other_ent.m_type:
                mod_entry["changes"].append({
                    "field": "type",
                    "old": my_ent.m_type,
                    "new": other_ent.m_type,
                })
            if my_ent.m_props != other_ent.m_props:
                all_prop_keys = set(my_ent.m_props.keys()) | set(other_ent.m_props.keys())
                pk = 0
                pk_list = sorted(all_prop_keys)
                while pk < len(pk_list):
                    key = pk_list[pk]
                    ov = my_ent.m_props.get(key)
                    nv = other_ent.m_props.get(key)
                    if ov != nv:
                        mod_entry["changes"].append({
                            "field": f"property.{key}",
                            "old": ov,
                            "new": nv,
                        })
                    pk += 1
            if sorted(my_ent.m_labels) != sorted(other_ent.m_labels):
                mod_entry["changes"].append({
                    "field": "labels",
                    "old": list(my_ent.m_labels),
                    "new": list(other_ent.m_labels),
                })
            if mod_entry["changes"]:
                changes["modified_entities"].append(mod_entry)
            ei += 1

# 关系对比
        my_rids = set(self.m_relations.keys())
        other_rids = set(other.m_relations.keys())

        add_rids = other_rids - my_rids
        ai = 0
        add_rids_sorted = sorted(add_rids)
        while ai < len(add_rids_sorted):
            changes["added_relations"].append(other.m_relations[add_rids_sorted[ai]].to_dict())
            ai += 1

        del_rids = my_rids - other_rids
        di = 0
        del_rids_sorted = sorted(del_rids)
        while di < len(del_rids_sorted):
            changes["removed_relations"].append(self.m_relations[del_rids_sorted[di]].to_dict())
            di += 1

        common_rids = my_rids & other_rids
        rids_sorted = sorted(common_rids)
        ri = 0
        while ri < len(rids_sorted):
            rid = rids_sorted[ri]
            my_rel = self.m_relations[rid]
            other_rel = other.m_relations[rid]
            mod_rel: Dict[str, Any] = {"id": rid, "changes": []}
            if my_rel.m_type != other_rel.m_type:
                mod_rel["changes"].append({
                    "field": "type",
                    "old": my_rel.m_type,
                    "new": other_rel.m_type,
                })
            if my_rel.m_src != other_rel.m_src:
                mod_rel["changes"].append({
                    "field": "source",
                    "old": my_rel.m_src,
                    "new": other_rel.m_src,
                })
            if my_rel.m_dst != other_rel.m_dst:
                mod_rel["changes"].append({
                    "field": "target",
                    "old": my_rel.m_dst,
                    "new": other_rel.m_dst,
                })
            if abs(my_rel.m_weight - other_rel.m_weight) > 1e-9:
                mod_rel["changes"].append({
                    "field": "weight",
                    "old": my_rel.m_weight,
                    "new": other_rel.m_weight,
                })
            if my_rel.m_props != other_rel.m_props:
                all_rpk = set(my_rel.m_props.keys()) | set(other_rel.m_props.keys())
                rpk = 0
                rpk_list = sorted(all_rpk)
                while rpk < len(rpk_list):
                    key = rpk_list[rpk]
                    ov = my_rel.m_props.get(key)
                    nv = other_rel.m_props.get(key)
                    if ov != nv:
                        mod_rel["changes"].append({
                            "field": f"property.{key}",
                            "old": ov,
                            "new": nv,
                        })
                    rpk += 1
            if mod_rel["changes"]:
                changes["modified_relations"].append(mod_rel)
            ri += 1

        _dbg.info(
            "Diff complete: +%d/-%d/~%d entities, +%d/-%d/~%d relations",
            len(changes["added_entities"]), len(changes["removed_entities"]),
            len(changes["modified_entities"]),
            len(changes["added_relations"]), len(changes["removed_relations"]),
            len(changes["modified_relations"]),
        )
        return changes

# 可视化辅助

    def _type_color_map(self):
        """实体类型→颜色映射(D3友好调色板)。"""
        cmap = {
            "VULNERABILITY": "#e74c3c",
            "CVE": "#c0392b",
            "EXPLOIT": "#e67e22",
            "FUNCTION": "#3498db",
            "BASIC_BLOCK": "#2980b9",
            "BINARY": "#2ecc71",
            "LIBRARY": "#27ae60",
            "STRING": "#9b59b6",
            "IMPORT": "#8e44ad",
            "PASSWORD": "#f1c40f",
            "KEY": "#f39c12",
            "CERTIFICATE": "#1abc9c",
            "PATCH": "#16a085",
            "COMMIT": "#7f8c8d",
            "AUTHOR": "#95a5a6",
            "SYSCALL": "#d35400",
            "NETWORK_ENDPOINT": "#e91e63",
        }
        return cmap

    def _type_size_map(self):
        """实体类型→大小映射(D3可视化用)。"""
        smap = {
            "VULNERABILITY": 12,
            "CVE": 14,
            "EXPLOIT": 13,
            "FUNCTION": 8,
            "BASIC_BLOCK": 6,
            "BINARY": 16,
            "LIBRARY": 10,
            "PASSWORD": 7,
            "KEY": 7,
            "PATCH": 9,
            "DEFAULT": 7,
        }
        return smap

# D3.js导出

    def to_d3_json(self, output_path=None) -> str:
        """导出D3.js力导向布局JSON。"""
        cmap = self._type_color_map()
        smap = self._type_size_map()

        nodes: List[Dict] = []
        edges: List[Dict] = []

        ent_list = list(self.m_entities.values())
        ei = 0
        while ei < len(ent_list):
            ent = ent_list[ei]
            node = {
                "id": ent.m_id,
                "type": ent.m_type,
                "label": ent.get_property("name", ent.m_id),
                "color": cmap.get(ent.m_type, "#bdc3c7"),
                "size": smap.get(ent.m_type, smap["DEFAULT"]),
                "properties": dict(ent.m_props),
                "labels": list(ent.m_labels),
            }
            nodes.append(node)
            ei += 1

        rel_list = list(self.m_relations.values())
        ri = 0
        while ri < len(rel_list):
            rel = rel_list[ri]
            edge = {
                "id": rel.m_id,
                "source": rel.m_src,
                "target": rel.m_dst,
                "type": rel.m_type,
                "weight": rel.m_weight,
                "properties": dict(rel.m_props),
            }
            edges.append(edge)
            ri += 1

        d3_data = {
            "graph": {
                "name": self.m_name,
                "nodes": nodes,
                "edges": edges,
                "stats": self.statistics(),
            }
        }

        result = _json.dumps(d3_data, indent=2, ensure_ascii=False, default=str)
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as fh:
                fh.write(result)
            _dbg.info("D3 JSON exported to %s (%d nodes, %d edges)", output_path, len(nodes), len(edges))

        return result

    def to_d3_html(self, output_path=None) -> str:
        """生成自包含的D3.js可视化HTML页面。"""
        d3_json = self.to_d3_json()

        html = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Knowledge Graph — """ + self.m_name + r"""</title>
<style>
body { margin: 0; overflow: hidden; background: #1a1a2e; font-family: 'Segoe UI', sans-serif; }
.links line { stroke: #555; stroke-opacity: 0.6; stroke-width: 1px; }
.nodes circle { stroke: #fff; stroke-width: 1.5px; cursor: pointer; }
.nodes text { fill: #ccc; font-size: 10px; pointer-events: none; }
.tooltip { position: absolute; background: #2c3e50; color: #ecf0f1; padding: 8px 12px;
    border-radius: 4px; font-size: 12px; pointer-events: none; opacity: 0;
    transition: opacity 0.2s; max-width: 300px; word-wrap: break-word; }
.legend { position: absolute; top: 10px; right: 10px; background: rgba(44,62,80,0.9);
    padding: 10px; border-radius: 4px; color: #ecf0f1; font-size: 11px; }
</style>
</head>
<body>
<div class="tooltip" id="tooltip"></div>
<div class="legend" id="legend"></div>
<svg width="100%" height="100%"></svg>
<script src="https://d3js.org/d3.v7.min.js"></script>
<script>
const graphData = """ + d3_json + r""";
const width = window.innerWidth;
const height = window.innerHeight;

const svg = d3.select("svg"),
    g = svg.append("g");

const zoom = d3.zoom().scaleExtent([0.1, 4]).on("zoom", (event) => {
    g.attr("transform", event.transform);
});
svg.call(zoom);

const simulation = d3.forceSimulation(graphData.graph.nodes)
    .force("link", d3.forceLink(graphData.graph.edges).id(d => d.id).distance(100))
    .force("charge", d3.forceManyBody().strength(-300))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("collide", d3.forceCollide(30));

const link = g.append("g").attr("class", "links").selectAll("line")
    .data(graphData.graph.edges).enter().append("line")
    .attr("stroke-width", d => Math.max(1, Math.min(d.weight * 3, 6)));

const node = g.append("g").attr("class", "nodes").selectAll("g")
    .data(graphData.graph.nodes).enter().append("g")
    .call(d3.drag().on("start", dragstarted).on("drag", dragged).on("end", dragended));

node.append("circle").attr("r", d => d.size).attr("fill", d => d.color);

node.append("text").text(d => d.label.substring(0, 20))
    .attr("dx", d => d.size + 4).attr("dy", 3);

node.on("mouseover", (event, d) => {
    d3.select("#tooltip").style("opacity", 1)
        .html("<b>" + d.label + "</b><br>Type: " + d.type + "<br>" +
              JSON.stringify(d.properties).substring(0, 200));
}).on("mousemove", (event) => {
    d3.select("#tooltip").style("left", (event.pageX + 10) + "px")
        .style("top", (event.pageY - 10) + "px");
}).on("mouseout", () => {
    d3.select("#tooltip").style("opacity", 0);
});

simulation.on("tick", () => {
    link.attr("x1", d => d.source.x).attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x).attr("y2", d => d.target.y);
    node.attr("transform", d => "translate(" + d.x + "," + d.y + ")");
});

function dragstarted(event, d) { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }
function dragged(event, d) { d.fx = event.x; d.fy = event.y; }
function dragended(event, d) { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }

// Legend
const types = [...new Set(graphData.graph.nodes.map(n => n.type))];
const legendHtml = types.map(t => {
    const node = graphData.graph.nodes.find(n => n.type === t);
    const color = node ? node.color : "#bdc3c7";
    return `<div><span style="display:inline-block;width:12px;height:12px;
        background:${color};border-radius:50%;margin-right:6px;"></span>${t}</div>`;
}).join("");
d3.select("#legend").html("<b>Legend</b><br>" + legendHtml);
</script>
</body>
</html>"""

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as fh:
                fh.write(html)
            _dbg.info("D3 HTML exported to %s", output_path)

        return html

# Graphviz导出

    def to_dot(self, output_path=None) -> str:
        """导出Graphviz DOT格式。"""
        lines: List[str] = []
        lines.append(f"digraph {self.m_name} {{")
        lines.append('    rankdir=LR;')
        lines.append('    node [fontname="Courier New", fontsize=10];')
        lines.append('    edge [fontname="Courier New", fontsize=8];')
        lines.append('')

        cmap = self._type_color_map()

        # 节点
        ent_list = list(self.m_entities.values())
        ei = 0
        while ei < len(ent_list):
            ent = ent_list[ei]
            eid_safe = ent.m_id.replace('"', '\\"').replace('\n', '\\n')
            color = cmap.get(ent.m_type, "#bdc3c7")
            label = ent.get_property("name", ent.m_id)[:40]
            lines.append(f'    "{eid_safe}" [label="{label}", fillcolor="{color}", style=filled, shape=box];')
            ei += 1

        lines.append('')

        # 边
        rel_list = list(self.m_relations.values())
        ri = 0
        while ri < len(rel_list):
            rel = rel_list[ri]
            src_safe = rel.m_src.replace('"', '\\"').replace('\n', '\\n')
            dst_safe = rel.m_dst.replace('"', '\\"').replace('\n', '\\n')
            lines.append(f'    "{src_safe}" -> "{dst_safe}" [label="{rel.m_type}" weight={rel.m_weight}];')
            ri += 1

        lines.append('}')

        dot_content = '\n'.join(lines)

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as fh:
                fh.write(dot_content)
            _dbg.info("DOT exported to %s", output_path)

        return dot_content

# GEXF导出

    def save_gexf(self, filepath: str):
        """导出GEXF格式(Gephi兼容)。"""
        import xml.etree.ElementTree as _ET
        root = _ET.Element("gexf", xmlns="http://gexf.net/1.3", version="1.3")
        graph_elem = _ET.SubElement(root, "graph", mode="static", defaultedgetype="directed")

        # 属性
        attrs_node = _ET.SubElement(graph_elem, "attributes", {"class": "node", "mode": "static"})
        _ET.SubElement(attrs_node, "attribute", {"id": "type", "title": "Type", "type": "string"})
        _ET.SubElement(attrs_node, "attribute", {"id": "labels", "title": "Labels", "type": "string"})

        attrs_edge = _ET.SubElement(graph_elem, "attributes", {"class": "edge", "mode": "static"})
        _ET.SubElement(attrs_edge, "attribute", {"id": "reltype", "title": "RelationType", "type": "string"})
        _ET.SubElement(attrs_edge, "attribute", {"id": "weight", "title": "Weight", "type": "float"})

        # 节点
        nodes_elem = _ET.SubElement(graph_elem, "nodes")
        ent_list = list(self.m_entities.values())
        ei = 0
        while ei < len(ent_list):
            ent = ent_list[ei]
            node_elem = _ET.SubElement(nodes_elem, "node", {"id": str(ent.m_id), "label": ent.get_property("name", ent.m_id)})
            attvals = _ET.SubElement(node_elem, "attvalues")
            _ET.SubElement(attvals, "attvalue", {"for": "type", "value": ent.m_type})
            _ET.SubElement(attvals, "attvalue", {"for": "labels", "value": ",".join(ent.m_labels)})
            ei += 1

        # 边
        edges_elem = _ET.SubElement(graph_elem, "edges")
        rel_list = list(self.m_relations.values())
        ri = 0
        ridx = 0
        while ri < len(rel_list):
            rel = rel_list[ri]
            edge_elem = _ET.SubElement(edges_elem, "edge", {
                "id": str(ridx),
                "source": str(rel.m_src),
                "target": str(rel.m_dst),
                "type": "directed",
            })
            attvals_e = _ET.SubElement(edge_elem, "attvalues")
            _ET.SubElement(attvals_e, "attvalue", {"for": "reltype", "value": rel.m_type})
            _ET.SubElement(attvals_e, "attvalue", {"for": "weight", "value": str(rel.m_weight)})
            ri += 1
            ridx += 1

        tree = _ET.ElementTree(root)
        tree.write(filepath, encoding="utf-8", xml_declaration=True)
        _dbg.info("GEXF exported to %s", filepath)

# 合并

    def merge(self, other: 'VulnKnowledgeGraph', conflict_strategy="keep_first"):
        """合并另一知识图到当前图。

        conflict_strategy:
          - "keep_first": 已存在的实体/关系跳过(默认)
          - "update": 用新数据覆盖已有数据
        """
        other_ents = other.get_all_entities()
        oi = 0
        while oi < len(other_ents):
            ent = other_ents[oi]
            if ent.m_id not in self.m_entities:
                self.add_entity(KnowledgeGraphEntity(
                    ent.m_id, ent.m_type,
                    dict(ent.m_props), list(ent.m_labels),
                ))
            elif conflict_strategy == "update":
                self.update_entity(ent.m_id, dict(ent.m_props), list(ent.m_labels))
            oi += 1

        other_rels = other.get_all_relations()
        oj = 0
        while oj < len(other_rels):
            rel = other_rels[oj]
            if rel.m_id not in self.m_relations:
                self.add_relation(KnowledgeGraphRelation(
                    rel.m_id, rel.m_src, rel.m_dst, rel.m_type,
                    dict(rel.m_props), rel.m_weight,
                ))
            elif conflict_strategy == "update":
                self.update_relation(rel.m_id, dict(rel.m_props), rel.m_weight)
            oj += 1

        _dbg.info("Merged %d entities and %d relations", len(other_ents), len(other_rels))


# 便捷工厂函数

def create_knowledge_graph(name="vuln_kg") -> VulnKnowledgeGraph:
    return VulnKnowledgeGraph(name)


def load_knowledge_graph(filepath: str) -> Optional[VulnKnowledgeGraph]:
    ext = _os.path.splitext(filepath)[1].lower()
    if ext == ".json":
        return VulnKnowledgeGraph.load_json(filepath)
    elif ext in (".pkl", ".pickle"):
        return VulnKnowledgeGraph.load_pickle(filepath)
    else:
        _dbg.error("Unsupported file format: %s", ext)
        return None
