# 2026-09-18 ~ 2026-09-21
# CVE Attack Graph Generator — builds exploit chain DAGs from CVE match data.
# Inspired by Aksu et al. 2018 "Automated Generation of Attack Graphs Using NVD"
# but the approach here is simpler: we use CWE pre/post-condition pairs and
# product overlap to derive potential exploit chains, plus CVSS exploitability
# metrics to weight edge probabilities.
#
# The output is a directed graph: nodes are CVEs, edges mean "exploiting A
# makes exploiting B easier or possible." Edge weights are 0-1 probabilities
# derived from the CWE relationship strength and EPSS scores.
#
# Graph export formats: JSON (default, for programmatic use) and GraphML
# (for visualization in Gephi/Cytoscape).

import json
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any

from .cve_models import CVEEntry, Severity

# ---- CWE pre→post condition chains ----
# Format: (source_cwe, target_cwe, relationship, confidence)
# confidence: 0.0–1.0, how reliably source enables target
# Hand-curated from CWE research literature + real-world exploit chains.
# NOT exhaustive — covers the most common chaining patterns seen in APT reports.

_CWE_CHAINS: List[Tuple[str, str, str, float]] = [
    # info disclosure → targeted attacks
    ("CWE-200", "CWE-79",  "info_disclosure_enables_targeting", 0.4),
    ("CWE-200", "CWE-89",  "info_disclosure_enables_targeting", 0.3),
    ("CWE-200", "CWE-78",  "info_disclosure_enables_targeting", 0.3),

    # XSS → CSRF (XSS can read CSRF tokens)
    ("CWE-79",  "CWE-352", "xss_bypasses_csrf", 0.7),

    # SSRF → RCE/Injection
    ("CWE-918", "CWE-78",  "ssrf_to_rce", 0.6),
    ("CWE-918", "CWE-94",  "ssrf_to_code_injection", 0.5),
    ("CWE-918", "CWE-89",  "ssrf_to_sqli", 0.3),

    # auth bypass → everything
    ("CWE-287", "CWE-79",  "auth_bypass_enables", 0.5),
    ("CWE-287", "CWE-89",  "auth_bypass_enables", 0.6),
    ("CWE-287", "CWE-78",  "auth_bypass_enables", 0.6),
    ("CWE-287", "CWE-94",  "auth_bypass_enables", 0.5),
    ("CWE-287", "CWE-22",  "auth_bypass_enables", 0.7),
    ("CWE-287", "CWE-434", "auth_bypass_enables", 0.6),

    # missing auth → similar to auth bypass
    ("CWE-306", "CWE-79",  "missing_auth_enables", 0.5),
    ("CWE-306", "CWE-89",  "missing_auth_enables", 0.6),
    ("CWE-306", "CWE-78",  "missing_auth_enables", 0.6),

    # privilege escalation → high impact
    ("CWE-269", "CWE-78",  "privesc_to_rce", 0.7),
    ("CWE-269", "CWE-94",  "privesc_to_code_injection", 0.6),
    ("CWE-269", "CWE-787", "privesc_to_memory_corruption", 0.5),

    # path traversal → info disclosure / RCE
    ("CWE-22",  "CWE-200", "traversal_to_disclosure", 0.8),
    ("CWE-22",  "CWE-94",  "traversal_to_code_exec", 0.4),

    # deserialization → RCE
    ("CWE-502", "CWE-94",  "deserialize_to_rce", 0.8),
    ("CWE-502", "CWE-78",  "deserialize_to_rce", 0.6),

    # SQL injection → auth bypass / data exposure
    ("CWE-89",  "CWE-287", "sqli_to_auth_bypass", 0.7),
    ("CWE-89",  "CWE-200", "sqli_to_disclosure", 0.8),

    # file upload → RCE / XSS
    ("CWE-434", "CWE-94",  "upload_to_rce", 0.7),
    ("CWE-434", "CWE-79",  "upload_to_xss", 0.5),

    # buffer overflow → code execution
    ("CWE-119", "CWE-94",  "buffer_overflow_to_rce", 0.8),
    ("CWE-787", "CWE-94",  "oob_write_to_rce", 0.7),
    ("CWE-125", "CWE-200", "oob_read_to_disclosure", 0.6),

    # UAF → code execution
    ("CWE-416", "CWE-94",  "uaf_to_rce", 0.7),
]


def _cwe_chain_lookup(source_cwe: str, target_cwe: str) -> Optional[Tuple[str, float]]:
    """Look up a CWE chain relationship. Returns (relation_type, confidence) or None."""
    for s, t, rel, conf in _CWE_CHAINS:
        if s == source_cwe and t == target_cwe:
            return (rel, conf)
    return None


# ---- main graph builder ----

def build_attack_graph(
    cve_matches: List[Dict],
    kb=None,
    include_epss: bool = True,
    min_edge_confidence: float = 0.3,
) -> Dict[str, Any]:
    """Build an attack graph from a list of CVE match dicts.

    Each match dict should have at minimum: cve_id, severity, cwes (list).
    Optionally: cvss_score, epss_score, products, description.

    kb: optional CVEKnowledgeBase for enriched lookups (CWEs, EPSS).
    include_epss: weight edges by EPSS scores if available.
    min_edge_confidence: filter out low-confidence edges.

    Returns graph dict:
      {nodes: [...], edges: [...], metadata: {node_count, edge_count, ...}}
    """
    # index matches by CVE ID
    cve_index: Dict[str, Dict] = {}
    for m in cve_matches:
        cid = m.get("cve_id", "")
        if cid:
            cve_index[cid] = m

    # build nodes
    nodes: List[Dict] = []
    node_ids: Set[str] = set()
    for cid, m in cve_index.items():
        severity = m.get("severity", "UNKNOWN")
        cwes = m.get("cwes", m.get("cwe", []))
        if isinstance(cwes, str):
            cwes = [cwes]

        # enrich from KB if available
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

    # build edges: for each pair of CVEs, check if there's a CWE chain
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

            # check CWE chain for every source→target pair
            for cwe_src in cwes_a:
                for cwe_tgt in cwes_b:
                    chain = _cwe_chain_lookup(cwe_src, cwe_tgt)
                    if chain is None:
                        continue
                    rel_type, base_conf = chain

                    # adjust confidence with EPSS if enabled
                    edge_conf = base_conf
                    epss_a = m_a.get("epss_score")
                    epss_b = m_b.get("epss_score")
                    if include_epss and epss_a is not None and epss_b is not None:
                        # higher EPSS on target → more likely chain is exploitable
                        edge_conf = base_conf * (0.5 + 0.5 * max(epss_a, epss_b))

                    # boost if same product affected (same attack surface)
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
                        break  # one edge per (A,B) pair
                else:
                    continue
                break  # outer break too

    # also add product-overlap edges (same product, different CWEs → potential chain)
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
                # check if edge already exists
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

    # compute graph metrics
    in_degree: Dict[str, int] = defaultdict(int)
    out_degree: Dict[str, int] = defaultdict(int)
    for e in edges:
        out_degree[e["source"]] += 1
        in_degree[e["target"]] += 1

    # find root nodes (no incoming edges) and leaf nodes (no outgoing)
    roots = [cid for cid in node_ids if in_degree.get(cid, 0) == 0]
    leaves = [cid for cid in node_ids if out_degree.get(cid, 0) == 0]

    # rank nodes by PageRank-ish centrality (simplified: in_degree + out_degree)
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


# ---- export ----

def export_graph_json(graph: Dict, output_path: Optional[str] = None) -> str:
    """Export attack graph as JSON. If output_path given, writes to file.
    Always returns the JSON string."""
    json_str = json.dumps(graph, indent=2, default=str, ensure_ascii=False)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)
    return json_str


def export_graph_graphml(graph: Dict, output_path: str) -> str:
    """Export attack graph as GraphML XML for Gephi/Cytoscape."""
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


# ---- path analysis ----

def find_attack_paths(
    graph: Dict,
    source_cve: str,
    target_cve: str,
    max_depth: int = 5,
) -> List[List[str]]:
    """Find all simple paths from source_cve to target_cve in the attack graph.
    Uses DFS with max_depth to avoid path explosion."""
    # build adjacency list
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
    """Find the highest-risk attack paths in the graph.
    Risk = sum of (confidence * severity_weight) along the path.
    Returns top_n paths sorted by risk descending."""
    severity_weight = {
        "CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "NONE": 0, "UNKNOWN": 1,
    }

    # build node lookup
    nodes_by_id = {n["id"]: n for n in graph["nodes"]}

    scored_paths: List[Dict] = []
    roots = graph["metadata"].get("root_nodes", [])
    leaves = graph["metadata"].get("leaf_nodes", [])

    for root in roots[:5]:  # limit root exploration
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


# ---- helpers ----

def _product_overlap(prods_a: Set[str], prods_b: Set[str]) -> bool:
    """Check if product names overlap by substring (fuzzy match)."""
    for a in prods_a:
        al = a.lower()
        for b in prods_b:
            bl = b.lower()
            if al in bl or bl in al:
                return True
    return False


def _xml_escape(s: str) -> str:
    """Escape special chars for XML/GraphML output."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
