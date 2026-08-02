# Extended CVE tests — CJK support, edge cases, compat
# Tests from the original test_cve_extended.py

import pytest
from modules.cve.src.cve_kb import CVEKnowledgeBase
from modules.cve.src.cve_models import _make_test_entry


@pytest.fixture
def kb():
    db = CVEKnowledgeBase(":memory:")
    yield db
    db.close()


class TestCJKSearch:
    """CJK (Chinese/Japanese/Korean) search support."""

    def test_cjk_cve_search(self, kb):
        """Search with CJK characters in description."""
        kb.insert({
            "cve_id": "CVE-2024-0001",
            "description": "Apache Log4j 远程代码执行漏洞",
            "severity": "CRITICAL",
        })
        kb.insert({
            "cve_id": "CVE-2024-0002",
            "description": "Regular English vulnerability description",
            "severity": "LOW",
        })
        # search by CJK query
        entries, total = kb.search(query="远程代码执行")
        # unpack search tuple
        assert total >= 1

    def test_mixed_cjk_latin_search(self, kb):
        """Search with mixed CJK and Latin query."""
        kb.insert({
            "cve_id": "CVE-2024-0001",
            "description": "Apache Log4j RCE 漏洞",
            "severity": "HIGH",
        })
        entries, total = kb.search(query="log4j")
        assert total >= 1


class TestDictCompat:
    """Dict-based entries that test backward compatibility."""

    def test_dict_with_alternate_keys(self, kb):
        """Entries with alternate key names should work."""
        kb.insert({
            "id": "CVE-2024-0001",
            "desc": "Test description",
            "severity": "HIGH",
        })
        e = kb.get("CVE-2024-0001")
        assert e is not None

    def test_dict_with_no_severity(self, kb):
        """Entry without severity defaults to UNKNOWN."""
        kb.insert({"cve_id": "CVE-2024-0001"})
        e = kb.get("CVE-2024-0001")
        assert e.severity == "UNKNOWN"

    def test_dict_edge_case_keys(self, kb):
        """Test with edge-case dict keys to match older test style."""
        kb.insert({
            "cve_id": "CVE-2024-0001",
            "product": "single-product",  # singular, not list
            "cpe": "cpe:2.3:a:v:p:*:*:*:*:*:*:*",  # singular
        })
        e = kb.get("CVE-2024-0001")
        assert e is not None


class TestVersionEdgeCases:
    """Version-related edge cases from extended tests."""

    def test_version_with_build_metadata(self):
        """Versions with build metadata should be handled."""
        from modules.cve.src.cve_matcher import _parse_cpe
        result = _parse_cpe("cpe:2.3:a:vendor:product:1.0.0+20130313144700:*:*:*:*:*:*:*")
        assert result is not None

    def test_version_with_tilde(self):
        """Versions with tilde prefix."""
        from modules.cve.src.cve_matcher import _parse_cpe
        result = _parse_cpe("cpe:2.3:a:vendor:product:~1.0.0:*:*:*:*:*:*:*")
        assert result is not None


class TestGHSACompat:
    """GHSA module compatibility tests."""

    def test_ghsa_import(self):
        """GHSA module should import correctly."""
        from modules.cve.src.cve_ghsa import GHSAEntry, search_ghsa
        assert GHSAEntry is not None
        assert search_ghsa is not None

    def test_source_confidence_field(self):
        """Merged entries should have source_confidence field."""
        from modules.cve.src.cve_ghsa import merge_with_confidence
        result = merge_with_confidence([
            {"entries": [{"cve_id": "CVE-2024-0001", "source": "nvd", "source_confidence": 1.0}]}
        ])
        assert result is not None


class TestImportPaths:
    """Verify all public API imports work from expected locations."""

    def test_top_level_imports(self):
        """Main imports from cve module work."""
        from modules.cve import CVEKnowledgeBase, CVEEntry, Severity
        assert CVEKnowledgeBase is not None
        assert CVEEntry is not None
        assert Severity is not None

    def test_submodule_imports(self):
        """Individual submodule imports work."""
        from modules.cve.src.cve_models import CVEEntry, CPEPart
        from modules.cve.src.cve_kb import CVEKnowledgeBase
        from modules.cve.src.cve_ssvc import evaluate_cve
        from modules.cve.src.cve_exploitdb import ExploitMaturity
        from modules.cve.src.cve_search import CVESearchEngine
        from modules.cve.src.cve_kev import KEVClient
        from modules.cve.src.cve_analyzer import CVEAnalyzer
        from modules.cve.src.cve_matcher import _parse_cpe
        from modules.cve.src.cve_purl_cpe import purl_to_cpe
        from modules.cve.src.cve_ghsa import search_ghsa
        from modules.cve.src.cve_epss import EPSSClient
        # all should import without error
        assert True
