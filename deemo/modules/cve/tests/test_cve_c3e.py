# C3E 流水线测试 : 因果发现, 对比学习, 因果传播

import pytest
from modules.cve.src.cve_kb import CVEKnowledgeBase


@pytest.fixture
def c3e_kb():
    """8 个 CVE 的种子 KB, 覆盖 KEV/非KEV, 多产品/厂商."""
    db = CVEKnowledgeBase(":memory:")
    data = [
        ("CVE-2024-KEV-1", 9.8, 0.88, 0.97, True, "weaponized", ["log4j"], ["apache"], ["CWE-502"]),
        ("CVE-2024-KEV-2", 7.8, 0.65, 0.89, True, "functional", ["openssl"], ["openssl"], ["CWE-787"]),
        ("CVE-2024-KEV-3", 8.0, 0.55, 0.82, True, "metasploit", ["curl"], ["curl"], ["CWE-918"]),
        ("CVE-2024-NORM-1", 5.4, 0.10, 0.30, False, "unknown", ["react"], ["facebook"], ["CWE-79"]),
        ("CVE-2024-NORM-2", 8.2, 0.28, 0.55, False, "poc", ["django"], ["django"], ["CWE-89"]),
        ("CVE-2024-NORM-3", 5.0, 0.05, 0.15, False, "unknown", ["nginx"], ["nginx"], ["CWE-400"]),
        ("CVE-2024-NORM-4", 6.1, 0.15, 0.40, False, "unknown", ["flask"], ["pallets"], ["CWE-22"]),
        ("CVE-2024-NORM-5", 4.5, 0.08, 0.20, False, "unknown", ["rails"], ["rails"], ["CWE-352"]),
    ]
    for cid, cvss, epss, pct, kev, mat, prods, vends, cwes in data:
        db.insert({
            "cve_id": cid, "description": f"Vuln {cid}", "cvss_score": cvss,
            "epss_score": epss, "epss_percentile": pct, "cisa_kev": kev,
            "exploit_maturity": mat, "products": prods, "vendors": vends,
            "cwes": cwes, "published_date": "2024-06-15T00:00:00.000",
        })
    yield db
    db.close()


class TestCausalFeatureSelector:
    """因果特征选择测试."""

    def test_fit_basic(self, c3e_kb):
        from modules.cve.src.cve_causal_contrastive import CausalFeatureSelector
        feats = [[0.9, 0.8, 0.9, 1.0, 1.0, 0.1, 0.5, 0.0, 0.3, 0.2],
                 [0.5, 0.1, 0.3, 0.0, 0.0, 0.1, 0.2, 0.0, 0.1, 0.1],
                 [0.8, 0.5, 0.8, 1.0, 0.7, 0.1, 0.4, 0.0, 0.2, 0.3],
                 [0.5, 0.1, 0.2, 0.0, 0.0, 0.1, 0.3, 1.0, 0.1, 0.1],
                 [0.6, 0.1, 0.4, 0.0, 0.2, 0.1, 0.1, 0.0, 0.1, 0.1]]
        labels = [1, 0, 1, 0, 0]
        sel = CausalFeatureSelector()
        sel.fit(feats, labels)
        weights = sel.causal_weights
        assert len(weights) >= 1  # at least one feature has non-zero weight

    def test_weights_in_range(self, c3e_kb):
        from modules.cve.src.cve_causal_contrastive import CausalFeatureSelector
        feats = [[0.9, 0.8, 0.9, 1.0, 1.0, 0.1, 0.5, 0.0, 0.3, 0.2],
                 [0.5, 0.1, 0.3, 0.0, 0.0, 0.1, 0.2, 0.0, 0.1, 0.1],
                 [0.8, 0.5, 0.8, 1.0, 0.7, 0.1, 0.4, 0.0, 0.2, 0.3]]
        labels = [1, 0, 1]
        sel = CausalFeatureSelector()
        sel.fit(feats, labels)
        for w in sel.causal_weights.values():
            assert 0.0 <= w <= 1.0

    def test_small_sample(self):
        from modules.cve.src.cve_causal_contrastive import CausalFeatureSelector
        sel = CausalFeatureSelector()
        sel.fit([[0.5, 0.3]], [0])  # N < 5, should return early without error
        assert isinstance(sel.causal_weights, dict)


class TestC3EPipeline:
    """C3E 完整流水线测试."""

    def test_fit_and_scores(self, c3e_kb):
        from modules.cve.src.cve_causal_contrastive import C3EPipeline
        pipeline = C3EPipeline(c3e_kb)
        stats = pipeline.fit()
        assert stats["n_cves"] == 8
        scores = pipeline.get_scores()
        assert len(scores) == 8

    def test_kev_ranks_higher(self, c3e_kb):
        from modules.cve.src.cve_causal_contrastive import C3EPipeline
        pipeline = C3EPipeline(c3e_kb)
        pipeline.fit()
        scores = pipeline.get_scores()
        kev_avg = sum(scores[c]["c3e_score"] for c in scores if "KEV" in c) / 3
        norm_avg = sum(scores[c]["c3e_score"] for c in scores if "NORM" in c) / 5
        assert kev_avg > norm_avg

    def test_scores_in_range(self, c3e_kb):
        from modules.cve.src.cve_causal_contrastive import C3EPipeline
        pipeline = C3EPipeline(c3e_kb)
        pipeline.fit()
        for info in pipeline.get_scores().values():
            assert 0.0 <= info["c3e_score"] <= 1.0

    def test_labels_valid(self, c3e_kb):
        from modules.cve.src.cve_causal_contrastive import C3EPipeline
        pipeline = C3EPipeline(c3e_kb)
        pipeline.fit()
        for info in pipeline.get_scores().values():
            assert info["label"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_convenience_api(self, c3e_kb):
        from modules.cve.src.cve_causal_contrastive import run_c3e_pipeline
        result = run_c3e_pipeline(c3e_kb)
        assert "stats" in result
        assert "top_10" in result
        assert len(result["top_10"]) <= 10

    def test_empty_kb(self):
        from modules.cve.src.cve_causal_contrastive import C3EPipeline
        pipeline = C3EPipeline(CVEKnowledgeBase(":memory:"))
        stats = pipeline.fit()
        assert "error" in stats

    def test_find_similar(self, c3e_kb):
        from modules.cve.src.cve_causal_contrastive import C3EPipeline
        pipeline = C3EPipeline(c3e_kb)
        pipeline.fit()
        similar = pipeline.find_similar_cves("CVE-2024-KEV-1", top_n=3)
        assert len(similar) <= 3
        # KEV-1 should find other KEVs as similar
        if similar:
            assert all(isinstance(s, tuple) and len(s) == 2 for s in similar)

    def test_embeddings_dimension(self, c3e_kb):
        from modules.cve.src.cve_causal_contrastive import C3EPipeline, _EMBEDDING_DIM
        pipeline = C3EPipeline(c3e_kb)
        pipeline.fit()
        # embeddings should have the configured dimension
        assert pipeline._encoder is not None
        for cid, emb in pipeline._encoder.embeddings.items():
            assert len(emb) == _EMBEDDING_DIM
