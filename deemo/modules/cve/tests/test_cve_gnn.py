# GNN 可利用性传播测试 — 2026-11-03
# 测试异构图构建、消息传递、分数区分性和归因路径

import pytest
from modules.cve.src.cve_kb import CVEKnowledgeBase


@pytest.fixture
def gn_kb():
    """构建包含 6 个 CVE 的种子 KB, 覆盖 KEV/非KEV, 多 CWE 共现."""
    db = CVEKnowledgeBase(":memory:")
    items = [
        ("CVE-2024-KEV-A", "RCE in Log4j via JNDI", "CRITICAL", 9.8, 0.85, 0.96, True, "weaponized",
         ["log4j-core"], ["apache"], ["CWE-502", "CWE-94"]),
        ("CVE-2024-KEV-B", "Buffer overflow in OpenSSL TLS", "HIGH", 7.8, 0.62, 0.88, True, "functional",
         ["openssl"], ["openssl"], ["CWE-787", "CWE-119"]),
        ("CVE-2024-NORM-C", "XSS in React DOM", "MEDIUM", 5.4, 0.12, 0.35, False, "unknown",
         ["react-dom"], ["facebook"], ["CWE-79"]),
        ("CVE-2024-NORM-D", "SQL injection in Django ORM", "HIGH", 8.2, 0.28, 0.55, False, "poc",
         ["django"], ["djangoproject"], ["CWE-89"]),
        ("CVE-2024-NORM-E", "Path traversal in Flask", "MEDIUM", 6.1, 0.15, 0.40, False, "unknown",
         ["flask"], ["pallets"], ["CWE-22"]),
        ("CVE-2024-NORM-F", "DoS via HTTP/2 in nginx", "LOW", 3.5, 0.03, 0.10, False, "unknown",
         ["nginx"], ["nginx"], ["CWE-400"]),
    ]
    for cid, desc, sev, cvss, epss, pct, kev, mat, prods, vends, cwes in items:
        db.insert({
            "cve_id": cid, "description": desc, "severity": sev,
            "cvss_score": cvss, "epss_score": epss, "epss_percentile": pct,
            "cisa_kev": kev, "exploit_maturity": mat,
            "products": prods, "vendors": vends, "cwes": cwes,
            "cpe_matches": [f"cpe:2.3:a:{vends[0]}:{prods[0]}:1.0:*:*:*:*:*:*:*" for _ in prods],
            "published_date": "2024-06-15T00:00:00.000",
        })
    yield db
    db.close()


class TestGraphConstruction:
    """图构建测试 — 验证节点类型计数和边结构."""

    def test_build_empty(self):
        from modules.cve.src.cve_graph_gnn import CVEExploitGraph
        g = CVEExploitGraph(CVEKnowledgeBase(":memory:"))
        g.build()
        assert g.stats()["total_nodes"] == 0

    def test_build_nodes(self, gn_kb):
        from modules.cve.src.cve_graph_gnn import CVEExploitGraph
        g = CVEExploitGraph(gn_kb)
        g.build()
        s = g.stats()
        assert s["total_nodes"] >= 6  # at least 6 CVE nodes
        assert s["node_types"]["CVE"] == 6

    def test_node_types_present(self, gn_kb):
        from modules.cve.src.cve_graph_gnn import CVEExploitGraph, _NTYPE_NAMES
        g = CVEExploitGraph(gn_kb)
        g.build()
        types = g.stats()["node_types"]
        assert "CVE" in types
        assert "CWE" in types

    def test_edges_exist(self, gn_kb):
        from modules.cve.src.cve_graph_gnn import CVEExploitGraph
        g = CVEExploitGraph(gn_kb)
        g.build()
        s = g.stats()
        assert s["total_edges"] > 0
        assert "hasWeakness" in s["edges_by_relation"]

    def test_edge_types(self, gn_kb):
        from modules.cve.src.cve_graph_gnn import CVEExploitGraph
        g = CVEExploitGraph(gn_kb)
        g.build()
        edge_types = g.stats()["edges_by_relation"]
        for rel in ("hasWeakness", "affectsProduct"):
            assert rel in edge_types, f"missing relation: {rel}"


class TestPropagation:
    """消息传播测试 — 验证分数计算和排序."""

    def test_propagate_returns_all_cves(self, gn_kb):
        from modules.cve.src.cve_graph_gnn import CVEExploitGraph
        g = CVEExploitGraph(gn_kb)
        g.build()
        scores = g.propagate()
        assert len(scores) == 6

    def test_kev_ranks_higher(self, gn_kb):
        """KEV 条目应获得比非 KEV 条目更高的 GNN 分数."""
        from modules.cve.src.cve_graph_gnn import CVEExploitGraph
        g = CVEExploitGraph(gn_kb)
        g.build()
        scores = g.propagate()
        kev_scores = [scores[c]["score"] for c in scores if "KEV" in c]
        norm_scores = [scores[c]["score"] for c in scores if "NORM" in c]
        assert min(kev_scores) > max(norm_scores), \
            f"KEV min={min(kev_scores):.4f} should exceed NORM max={max(norm_scores):.4f}"

    def test_scores_in_range(self, gn_kb):
        from modules.cve.src.cve_graph_gnn import CVEExploitGraph
        g = CVEExploitGraph(gn_kb)
        g.build()
        scores = g.propagate()
        for info in scores.values():
            assert 0.0 <= info["score"] <= 1.0

    def test_confidence_in_range(self, gn_kb):
        from modules.cve.src.cve_graph_gnn import CVEExploitGraph
        g = CVEExploitGraph(gn_kb)
        g.build()
        scores = g.propagate()
        for info in scores.values():
            assert 0.0 < info["confidence"] <= 1.0

    def test_path_contributions(self, gn_kb):
        from modules.cve.src.cve_graph_gnn import CVEExploitGraph
        g = CVEExploitGraph(gn_kb)
        g.build()
        scores = g.propagate()
        cve_a = scores.get("CVE-2024-KEV-A", {})
        paths = cve_a.get("path_contributions", {})
        assert len(paths) >= 1, "should have at least one contributing path"

    def test_label_assignment(self, gn_kb):
        from modules.cve.src.cve_graph_gnn import CVEExploitGraph
        g = CVEExploitGraph(gn_kb)
        g.build()
        scores = g.propagate()
        for info in scores.values():
            assert info["label"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_node_degree(self, gn_kb):
        from modules.cve.src.cve_graph_gnn import CVEExploitGraph
        g = CVEExploitGraph(gn_kb)
        g.build()
        scores = g.propagate()
        for info in scores.values():
            assert info["node_degree"] >= 0


class TestConvenienceAPI:
    """便捷函数测试."""

    def test_score_cves_with_gnn(self, gn_kb):
        from modules.cve.src.cve_graph_gnn import score_cves_with_gnn
        result = score_cves_with_gnn(gn_kb)
        assert len(result) == 6

    def test_top_exploitable(self, gn_kb):
        from modules.cve.src.cve_graph_gnn import top_exploitable_cves
        top = top_exploitable_cves(gn_kb, top_n=3)
        assert len(top) == 3
        assert top[0][1] >= top[1][1] >= top[2][1]  # descending scores


class TestFeatureBuilders:
    """特征构建函数测试."""

    def test_cve_features(self):
        from modules.cve.src.cve_graph_gnn import _build_cve_features
        meta = {"epss_score": 0.5, "epss_percentile": 0.8, "cvss_score": 7.5,
                "kev": 1.0, "days_since_pub": 100, "exploit_maturity": 0.5,
                "has_fix": 1.0, "entry": type('obj', (object,), {'cwes': ['CWE-79']})()}
        cwe_freq = {"CWE-79": 10, "CWE-89": 5}
        feats = _build_cve_features(meta, cwe_freq)
        assert len(feats) == 8
        assert feats[0] == 0.5  # epss_score
        assert feats[3] == 1.0  # kev flag

    def test_maturity_encoding(self):
        from modules.cve.src.cve_graph_gnn import _maturity_encoding
        assert _maturity_encoding("weaponized") == 1.0
        assert _maturity_encoding("poc") == 0.25
        assert _maturity_encoding("unknown") == 0.0

    def test_temporal_weight(self):
        from modules.cve.src.cve_graph_gnn import _temporal_weight
        w_now = _temporal_weight(0)
        w_year = _temporal_weight(365)
        w_decade = _temporal_weight(3650)
        assert w_now == 1.0
        assert w_year < 1.0
        assert w_decade < w_year
