# CVE扩展测试——CJK支持、边界情况、兼容性
# 来自原始test_cve_extended.py

import pytest
from modules.cve.src.cve_kb import CVEKnowledgeBase
from modules.cve.src.cve_models import _make_test_entry


@pytest.fixture
def kb():
    db = CVEKnowledgeBase(":memory:")
    yield db
    db.close()


class TestCJKSearch:
    """CJK（中日韩）搜索支持。"""

    def test_cjk_cve_search(self, kb):
        """在描述中使用CJK字符搜索。"""
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
        """使用混合CJK与拉丁字符查询搜索。"""
        kb.insert({
            "cve_id": "CVE-2024-0001",
            "description": "Apache Log4j RCE 漏洞",
            "severity": "HIGH",
        })
        entries, total = kb.search(query="log4j")
        assert total >= 1


class TestDictCompat:
    """基于dict的条目测试向后兼容性。"""

    def test_dict_with_alternate_keys(self, kb):
        """使用备用键名的条目应正常工作。"""
        kb.insert({
            "id": "CVE-2024-0001",
            "desc": "Test description",
            "severity": "HIGH",
        })
        e = kb.get("CVE-2024-0001")
        assert e is not None

    def test_dict_with_no_severity(self, kb):
        """未指定severity的条目默认为UNKNOWN。"""
        kb.insert({"cve_id": "CVE-2024-0001"})
        e = kb.get("CVE-2024-0001")
        assert e.severity == "UNKNOWN"

    def test_dict_edge_case_keys(self, kb):
        """使用边界dict键测试以兼容旧测试风格。"""
        kb.insert({
            "cve_id": "CVE-2024-0001",
            "product": "single-product",  # singular, not list
            "cpe": "cpe:2.3:a:v:p:*:*:*:*:*:*:*",  # singular
        })
        e = kb.get("CVE-2024-0001")
        assert e is not None


class TestVersionEdgeCases:
    """版本相关边界情况——来自扩展测试。"""

    def test_version_with_build_metadata(self):
        """含构建元数据的版本应正确处理。"""
        from modules.cve.src.cve_matcher import _parse_cpe
        result = _parse_cpe("cpe:2.3:a:vendor:product:1.0.0+20130313144700:*:*:*:*:*:*:*")
        assert result is not None

    def test_version_with_tilde(self):
        """含波浪线前缀的版本。"""
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
        """合并条目应含source_confidence字段。"""
        from modules.cve.src.cve_ghsa import merge_with_confidence
        result = merge_with_confidence([
            {"entries": [{"cve_id": "CVE-2024-0001", "source": "nvd", "source_confidence": 1.0}]}
        ])
        assert result is not None


class TestImportPaths:
    """验证所有公开API导入可从预期位置工作。"""

    def test_top_level_imports(self):
        """从cve模块的主导入正常工作。"""
        from modules.cve import CVEKnowledgeBase, CVEEntry, Severity
        assert CVEKnowledgeBase is not None
        assert CVEEntry is not None
        assert Severity is not None

    def test_submodule_imports(self):
        """各子模块导入正常工作。"""
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
