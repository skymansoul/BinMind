# Round 8 测试——嵌入、VEX、变更日志
# ~25项测试，覆盖新增特性

import json
import pytest
import time
from modules.cve.src.cve_kb import CVEKnowledgeBase
from modules.cve.src.cve_models import CVEEntry, _make_test_entry

@pytest.fixture
def kb():
    db = CVEKnowledgeBase(":memory:")
    yield db
    db.close()

@pytest.fixture
def seeded_kb():
    """KB with entries having richer descriptions for embedding search."""
    db = CVEKnowledgeBase(":memory:")
    entries = [
        ("CVE-2024-0001", "Remote code execution in Apache Log4j via JNDI injection allows attackers to execute arbitrary code on the target server", "CRITICAL", 9.8),
        ("CVE-2024-0002", "Cross-site scripting vulnerability in React DOM allows attackers to inject malicious scripts into web pages viewed by other users", "MEDIUM", 5.4),
        ("CVE-2024-0003", "SQL injection vulnerability in Django ORM allows remote attackers to execute arbitrary SQL commands and take over the database", "HIGH", 8.2),
        ("CVE-2024-0004", "Buffer overflow in OpenSSL TLS handshake leads to remote code execution on vulnerable servers when processing crafted packets", "HIGH", 7.8),
        ("CVE-2024-0005", "Denial of service vulnerability in nginx HTTP/2 implementation allows attackers to crash the server by sending specially crafted requests", "MEDIUM", 5.0),
    ]
    for cid, desc, sev, score in entries:
        db.insert({"cve_id": cid, "description": desc, "severity": sev, "cvss_score": score})
    yield db
    db.close()

# Embedding index (8 tests)

class TestEmbeddingIndex:
    def test_build_empty(self, kb):
        from modules.cve.src.cve_embeddings import CVEEmbeddingIndex
        idx = CVEEmbeddingIndex(kb)
        idx.build()
        assert idx.doc_count == 0

    def test_build_with_data(self, seeded_kb):
        from modules.cve.src.cve_embeddings import CVEEmbeddingIndex
        idx = CVEEmbeddingIndex(seeded_kb)
        idx.build()
        assert idx.doc_count == 5
        assert idx.vocab_size > 0

    def test_search_finds_similar(self, seeded_kb):
        from modules.cve.src.cve_embeddings import CVEEmbeddingIndex
        idx = CVEEmbeddingIndex(seeded_kb)
        idx.build()
        # use min_score=0 to see all matches in a tiny corpus
        results = idx.search("remote code execution", min_score=0.0)
        assert len(results) > 0
        # top result should be one of the RCE entries
        top_cve = results[0][0].cve_id
        assert top_cve in ("CVE-2024-0001", "CVE-2024-0004")

    def test_search_empty_query(self, seeded_kb):
        from modules.cve.src.cve_embeddings import CVEEmbeddingIndex
        idx = CVEEmbeddingIndex(seeded_kb)
        idx.build()
        results = idx.search("")
        assert results == []

    def test_find_similar_cves(self, seeded_kb):
        from modules.cve.src.cve_embeddings import CVEEmbeddingIndex
        idx = CVEEmbeddingIndex(seeded_kb)
        idx.build()
        results = idx.find_similar("CVE-2024-0001")
        assert len(results) > 0
        # should find itself as top match or very close
        cve_ids = [r[0].cve_id for r in results]
        assert "CVE-2024-0001" in cve_ids

    def test_hybrid_search(self, seeded_kb):
        from modules.cve.src.cve_embeddings import CVEEmbeddingIndex
        idx = CVEEmbeddingIndex(seeded_kb)
        idx.build()
        results = idx.search_hybrid("remote code execution vulnerability", top_n=3, bm25_weight=0.5)
        assert len(results) <= 3
        assert len(results) >= 1

    def test_search_scores_positive(self, seeded_kb):
        from modules.cve.src.cve_embeddings import CVEEmbeddingIndex
        idx = CVEEmbeddingIndex(seeded_kb)
        idx.build()
        results = idx.search("log4j JNDI", min_score=0.01)
        for _, score in results:
            assert score >= 0.0

    def test_rebuild(self, seeded_kb):
        from modules.cve.src.cve_embeddings import CVEEmbeddingIndex
        idx = CVEEmbeddingIndex(seeded_kb)
        idx.build()
        first_vocab = idx.vocab_size
        idx.build()  # rebuild
        assert idx.vocab_size == first_vocab  # same data, same vocab

# VEX generation (7 tests)

class TestVEXGeneration:
    def test_make_basic_vex(self):
        from modules.cve.src.cve_vex import make_vex_document
        matches = [
            {"cve_id": "CVE-2024-0001", "component": "log4j", "component_version": "2.14.1",
             "severity": "CRITICAL", "description": "RCE in Log4j", "cvss_score": 9.8},
        ]
        doc = make_vex_document(matches, "test-product", "1.0")
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.5"
        assert "serialNumber" in doc
        assert len(doc["vulnerabilities"]) == 1
        assert doc["vulnerabilities"][0]["id"] == "CVE-2024-0001"

    def test_vex_statuses(self):
        from modules.cve.src.cve_vex import make_vex_document
        matches = [
            {"cve_id": "CVE-2024-0001", "component": "pkg1", "component_version": "1.0",
             "severity": "CRITICAL", "description": "Test",
             "vex_status": "not_affected", "vex_justification": "component_not_present"},
            {"cve_id": "CVE-2024-0002", "component": "pkg2", "component_version": "1.0",
             "severity": "HIGH", "description": "Test 2",
             "vex_status": "under_investigation"},
            {"cve_id": "CVE-2024-0003", "component": "pkg3", "component_version": "1.0",
             "severity": "MEDIUM", "description": "Test 3",
             "vex_status": "fixed", "vex_action": "Patched in v2.0"},
        ]
        doc = make_vex_document(matches, "test")
        assert len(doc["vulnerabilities"]) == 3

    def test_vex_deduplicates_cves(self):
        from modules.cve.src.cve_vex import make_vex_document
        matches = [
            {"cve_id": "CVE-2024-0001", "component": "pkg-a", "component_version": "1.0",
             "severity": "HIGH", "description": "Test"},
            {"cve_id": "CVE-2024-0001", "component": "pkg-b", "component_version": "2.0",
             "severity": "HIGH", "description": "Test"},
        ]
        doc = make_vex_document(matches)
        assert len(doc["vulnerabilities"]) == 1  # deduped

    def test_annotate_vex_status(self):
        from modules.cve.src.cve_vex import annotate_vex_status
        matches = [
            {"cve_id": "CVE-2024-0001", "severity": "CRITICAL"},
            {"cve_id": "CVE-2024-0002", "severity": "LOW"},
        ]
        decisions = {"CVE-2024-0001": "affected", "CVE-2024-0002": "not_affected"}
        result = annotate_vex_status(matches, decisions, justification="component_not_present")
        assert result[0]["vex_status"] == "affected"
        assert result[1]["vex_status"] == "not_affected"

    def test_auto_vex_status(self):
        from modules.cve.src.cve_vex import auto_vex_status
        matches = [
            {"cve_id": "CVE-2024-CRIT", "severity": "CRITICAL", "epss_score": 0.5, "match_confidence": 0.9},
            {"cve_id": "CVE-2024-LOWCONF", "severity": "MEDIUM", "epss_score": 0.01, "match_confidence": 0.4},
        ]
        result = auto_vex_status(matches)
        assert result[0]["vex_status"] == "affected"
        assert result[1]["vex_status"] == "under_investigation"

    def test_vex_without_product_name(self):
        from modules.cve.src.cve_vex import make_vex_document
        doc = make_vex_document([])
        assert doc["vulnerabilities"] == []
        assert "component" not in doc.get("metadata", {})

    def test_export_vex_json(self, tmp_path):
        from modules.cve.src.cve_vex import export_vex_json
        out = str(tmp_path / "test.vex.json")
        result = export_vex_json([], out)
        assert result == out
        with open(out) as f:
            doc = json.load(f)
        assert doc["bomFormat"] == "CycloneDX"

# Changelog (8 tests)

class TestChangelog:
    def test_diff_entries_no_change(self):
        from modules.cve.src.cve_changelog import diff_entries
        e = _make_test_entry("CVE-2024-0001", severity="HIGH")
        changes = diff_entries(e, e)
        assert changes == []

    def test_diff_entries_severity_change(self):
        from modules.cve.src.cve_changelog import diff_entries
        old = _make_test_entry("CVE-2024-0001", severity="MEDIUM")
        new = _make_test_entry("CVE-2024-0001", severity="HIGH")
        changes = diff_entries(old, new)
        assert len(changes) == 1
        assert changes[0]["field"] == "severity"
        assert changes[0]["old_value"] == "MEDIUM"
        assert changes[0]["new_value"] == "HIGH"

    def test_diff_entries_list_fields(self):
        from modules.cve.src.cve_changelog import diff_entries
        old = _make_test_entry("CVE-2024-0001", products=["a", "b"])
        new = _make_test_entry("CVE-2024-0001", products=["a", "b", "c"])
        changes = diff_entries(old, new)
        # at least one change for products
        assert any(c["field"] == "products" for c in changes)

    def test_diff_entries_dict_input(self):
        from modules.cve.src.cve_changelog import diff_entries
        old = {"cve_id": "CVE-2024-0001", "severity": "LOW"}
        new = {"cve_id": "CVE-2024-0001", "severity": "CRITICAL"}
        changes = diff_entries(old, new)
        assert len(changes) >= 1
        assert changes[0]["field"] == "severity"

    def test_changelog_record_update(self, kb):
        from modules.cve.src.cve_changelog import CVEChangelog
        kb.insert({"cve_id": "CVE-2024-0001", "severity": "MEDIUM", "description": "old desc"})
        old = kb.get("CVE-2024-0001")
        cl = CVEChangelog(kb)
        new = _make_test_entry("CVE-2024-0001", severity="HIGH", description="new desc")
        count = cl.record_update(old, new)
        assert count >= 1

    def test_changelog_get_history(self, kb):
        from modules.cve.src.cve_changelog import CVEChangelog
        kb.insert({"cve_id": "CVE-2024-HIST", "severity": "LOW", "description": "desc"})
        old = kb.get("CVE-2024-HIST")
        cl = CVEChangelog(kb)
        new = _make_test_entry("CVE-2024-HIST", severity="CRITICAL", description="desc")
        cl.record_update(old, new)
        history = cl.get_changelog("CVE-2024-HIST")
        assert len(history) >= 1

    def test_changelog_recent_changes(self, kb):
        from modules.cve.src.cve_changelog import CVEChangelog
        kb.insert({"cve_id": "CVE-2024-RECENT", "severity": "MEDIUM"})
        old = kb.get("CVE-2024-RECENT")
        cl = CVEChangelog(kb)
        new = _make_test_entry("CVE-2024-RECENT", severity="HIGH")
        cl.record_update(old, new)
        recent = cl.get_recent_changes(since=0, limit=10)
        assert len(recent) >= 1

    def test_changelog_stats(self, kb):
        from modules.cve.src.cve_changelog import CVEChangelog
        kb.insert({"cve_id": "CVE-2024-STATS", "severity": "LOW"})
        old = kb.get("CVE-2024-STATS")
        cl = CVEChangelog(kb)
        new = _make_test_entry("CVE-2024-STATS", severity="HIGH")
        cl.record_update(old, new)
        stats = cl.stats()
        assert stats["total_field_changes"] >= 1
