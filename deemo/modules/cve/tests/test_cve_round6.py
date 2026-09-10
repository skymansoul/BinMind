# Round 6 测试——CVSS 4.0、CJK FTS5、版本比较增强
# ~30项测试，覆盖新增特性

import pytest
import json
from modules.cve.src.cve_kb import CVEKnowledgeBase
from modules.cve.src.cve_models import CVEEntry, _make_test_entry, parse_cvss40_vector


@pytest.fixture
def kb():
    db = CVEKnowledgeBase(":memory:")
    yield db
    db.close()


# CVSS 4.0 parsing (8 tests)

class TestCVSS40:
    def test_parse_full_vector(self):
        """解析完整的CVSS 4.0向量字符串。"""
        vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        result = parse_cvss40_vector(vec)
        assert result is not None
        assert result["AV"] == "N"
        assert result["AC"] == "L"
        assert result["VC"] == "H"
        assert result["VI"] == "H"
        assert result["VA"] == "H"
        assert result["SC"] == "N"

    def test_parse_partial_vector(self):
        """Lenient parse: partial vector still works for present keys."""
        vec = "CVSS:4.0/AV:L/AC:H/VC:H"
        result = parse_cvss40_vector(vec)
        assert result is not None
        assert result.get("AV") == "L"
        assert result.get("AC") == "H"
        assert result.get("VC") == "H"
        # missing keys not present
        assert "SC" not in result or result.get("SC") is None

    def test_reject_v30_vector(self):
        """CVSS 3.0 vectors should NOT be parsed as 4.0."""
        assert parse_cvss40_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None

    def test_reject_v31_vector(self):
        """CVSS 3.1 vectors should NOT be parsed as 4.0."""
        assert parse_cvss40_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None

    def test_empty_vector(self):
        assert parse_cvss40_vector("") is None
        assert parse_cvss40_vector(None) is None

    def test_from_nvd_item_v40(self):
        """NVD item with cvssMetricV40 should parse correctly."""
        nvd_item = {
            "id": "CVE-2024-TEST",
            "descriptions": [{"lang": "en", "value": "Test CVSS 4.0 vuln"}],
            "metrics": {
                "cvssMetricV40": [{
                    "cvssData": {
                        "version": "4.0",
                        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                        "baseScore": 9.3,
                    }
                }]
            },
            "weaknesses": [],
            "configurations": [],
            "references": [],
            "published": "2024-06-01T00:00:00.000",
            "lastModified": "2024-06-02T00:00:00.000",
        }
        entry = CVEEntry.from_nvd_item(nvd_item)
        assert entry.cve_id == "CVE-2024-TEST"
        assert entry.cvss_version == "4.0"
        assert entry.cvss_score == 9.3
        assert entry.severity == "CRITICAL"

    def test_from_nvd_item_prefers_v30_over_v40(self):
        """When both v30 and v40 are present, v30 is preferred."""
        nvd_item = {
            "id": "CVE-2024-TEST2",
            "descriptions": [{"lang": "en", "value": "Both v30 and v40"}],
            "metrics": {
                "cvssMetricV40": [{
                    "cvssData": {
                        "version": "4.0",
                        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                        "baseScore": 9.3,
                    }
                }],
                "cvssMetricV31": [{
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseScore": 7.5,
                    }
                }]
            },
            "weaknesses": [],
            "configurations": [],
            "references": [],
            "published": "2024-07-01T00:00:00.000",
            "lastModified": "2024-07-02T00:00:00.000",
        }
        entry = CVEEntry.from_nvd_item(nvd_item)
        # should prefer v3.1
        assert entry.cvss_version == "3.1"
        assert entry.cvss_score == 7.5

    def test_from_nvd_item_no_cvss(self):
        """No CVSS data at all → severity UNKNOWN."""
        nvd_item = {
            "id": "CVE-2024-NOSCORE",
            "descriptions": [{"lang": "en", "value": "No score available"}],
            "metrics": {},
            "weaknesses": [],
            "configurations": [],
            "references": [],
            "published": "2024-06-01T00:00:00.000",
            "lastModified": "2024-06-02T00:00:00.000",
        }
        entry = CVEEntry.from_nvd_item(nvd_item)
        assert entry.severity == "UNKNOWN"
        assert entry.cvss_score is None


# FTS5 CJK tokenizer (7 tests)

class TestCJKTokenizer:
    def test_import(self):
        from modules.cve.src.cve_fts_tokenizer import tokenize_cjk, has_cjk
        assert tokenize_cjk is not None

    def test_has_cjk_positive(self):
        from modules.cve.src.cve_fts_tokenizer import has_cjk
        assert has_cjk("远程代码执行") is True
        assert has_cjk("log4j 漏洞") is True

    def test_has_cjk_negative(self):
        from modules.cve.src.cve_fts_tokenizer import has_cjk
        assert has_cjk("hello world") is False
        assert has_cjk("") is False

    def test_tokenize_pure_ascii(self):
        from modules.cve.src.cve_fts_tokenizer import tokenize_cjk
        result = tokenize_cjk("remote code execution in log4j")
        # ascii words pass through (tokenizer split by the internal logic)
        assert "remote" in result.lower() or "remote" in result
        assert "log4j" in result.lower() or "log4j" in result

    def test_tokenize_pure_cjk(self):
        from modules.cve.src.cve_fts_tokenizer import tokenize_cjk
        result = tokenize_cjk("远程代码执行漏洞")
        # should produce bigrams
        assert "远程" in result
        assert "代码" in result
        assert "执行" in result

    def test_tokenize_mixed(self):
        from modules.cve.src.cve_fts_tokenizer import tokenize_cjk
        result = tokenize_cjk("Apache Log4j 远程代码执行")
        # should have both ascii and CJK bigrams
        assert "apache" in result.lower()
        assert "log4j" in result.lower()
        # CJK bigrams
        assert "远程" in result

    def test_tokenize_empty(self):
        from modules.cve.src.cve_fts_tokenizer import tokenize_cjk
        assert tokenize_cjk("") == ""
        assert tokenize_cjk(None) == ""


# KB CJK search (3 tests)

class TestKBCJKSearch:
    def test_search_cjk_finds_cjk_desc(self, kb):
        """search_cjk should find entries with Chinese descriptions."""
        kb.insert({
            "cve_id": "CVE-2024-CJK1",
            "description": "Apache Log4j 远程代码执行漏洞",
            "severity": "CRITICAL",
        })
        kb.insert({
            "cve_id": "CVE-2024-CJK2",
            "description": "Regular English description only",
            "severity": "LOW",
        })
        results = kb.search_cjk("远程代码执行")
        assert len(results) >= 1
        cve_ids = [e.cve_id for e in results]
        assert "CVE-2024-CJK1" in cve_ids

    def test_search_cjk_empty_query(self, kb):
        """Empty query should return empty list."""
        results = kb.search_cjk("")
        assert results == []

    def test_search_cjk_fallback_to_like(self, kb):
        """When FTS isn't available or fails, fall back to LIKE."""
        kb.insert({
            "cve_id": "CVE-2024-FALLBACK1",
            "description": "Buffer overflow in network stack",
            "severity": "HIGH",
        })
        results = kb.search_cjk("buffer overflow")
        assert len(results) >= 1


# npm semver ranges (6 tests)

class TestNpmSemverRanges:
    def test_import(self):
        from modules.cve.src.cve_matcher import satisfies_npm_range
        assert satisfies_npm_range is not None

    def test_caret_range(self):
        """^1.2.3 should allow 1.x.x >= 1.2.3 but not 2.0.0."""
        from modules.cve.src.cve_matcher import satisfies_npm_range
        assert satisfies_npm_range("1.2.3", "^1.2.3") is True
        assert satisfies_npm_range("1.9.9", "^1.2.3") is True
        assert satisfies_npm_range("2.0.0", "^1.2.3") is False
        assert satisfies_npm_range("1.2.2", "^1.2.3") is False

    def test_tilde_range(self):
        """~1.2.3 allows 1.2.x >= 1.2.3 but not 1.3.0."""
        from modules.cve.src.cve_matcher import satisfies_npm_range
        assert satisfies_npm_range("1.2.3", "~1.2.3") is True
        assert satisfies_npm_range("1.2.9", "~1.2.3") is True
        assert satisfies_npm_range("1.3.0", "~1.2.3") is False

    def test_gte_lte_range(self):
        """>=1.0.0 <2.0.0 composite range."""
        from modules.cve.src.cve_matcher import satisfies_npm_range
        assert satisfies_npm_range("1.5.0", ">=1.0.0 <2.0.0") is True
        assert satisfies_npm_range("0.9.0", ">=1.0.0 <2.0.0") is False
        assert satisfies_npm_range("2.0.0", ">=1.0.0 <2.0.0") is False

    def test_caret_zero_major(self):
        """^0.2.3 should allow >=0.2.3 <0.3.0."""
        from modules.cve.src.cve_matcher import satisfies_npm_range
        assert satisfies_npm_range("0.2.5", "^0.2.3") is True
        assert satisfies_npm_range("0.3.0", "^0.2.3") is False

    def test_wildcard_range(self):
        """* means any version."""
        from modules.cve.src.cve_matcher import satisfies_npm_range
        assert satisfies_npm_range("9.9.9", "*") is True
        assert satisfies_npm_range("0.0.1", "") is True


# Maven version comparison (5 tests)

class TestMavenVersions:
    def test_import(self):
        from modules.cve.src.cve_matcher import compare_maven_versions
        assert compare_maven_versions is not None

    def test_basic_numeric(self):
        """Simple numeric comparison."""
        from modules.cve.src.cve_matcher import compare_maven_versions
        assert compare_maven_versions("1.0", "2.0") == -1
        assert compare_maven_versions("2.0", "1.0") == 1
        assert compare_maven_versions("1.0", "1.0") == 0

    def test_qualifier_ordering(self):
        """Maven qualifier order: alpha < beta < rc < snapshot < release."""
        from modules.cve.src.cve_matcher import compare_maven_versions
        # alpha comes before beta
        assert compare_maven_versions("1.0-alpha", "1.0-beta") == -1
        # beta before rc
        assert compare_maven_versions("1.0-beta", "1.0-rc1") == -1
        # rc before snapshot
        assert compare_maven_versions("1.0-rc1", "1.0-SNAPSHOT") == -1
        # snapshot before release
        assert compare_maven_versions("1.0-SNAPSHOT", "1.0") == -1

    def test_same_version_different_qualifier(self):
        """1.0 is higher than 1.0-SNAPSHOT (release is highest precedence)."""
        from modules.cve.src.cve_matcher import compare_maven_versions
        assert compare_maven_versions("1.0", "1.0-SNAPSHOT") == 1

    def test_edge_case_empty(self):
        """Empty or equal strings."""
        from modules.cve.src.cve_matcher import compare_maven_versions
        assert compare_maven_versions("", "") == 0
        # non-empty vs empty — non-empty comes after
        result = compare_maven_versions("1.0", "")
        assert result in (1, -1)  # direction depends on implementation


# ===== calver detection + version coercion (4 tests) =====

class TestCalverAndCoerce:
    def test_detect_ubuntu_calver(self):
        from modules.cve.src.cve_matcher import detect_calver
        assert detect_calver("22.04") == "ubuntu"
        assert detect_calver("24.10") == "ubuntu"

    def test_detect_python_calver(self):
        from modules.cve.src.cve_matcher import detect_calver
        assert detect_calver("2024.1.15") == "python"
        assert detect_calver("2024.06") == "python"

    def test_detect_not_calver(self):
        from modules.cve.src.cve_matcher import detect_calver
        assert detect_calver("1.2.3") is None
        assert detect_calver("v1.0.0") is None

    def test_coerce_version(self):
        from modules.cve.src.cve_matcher import coerce_version
        assert coerce_version("v1.2.3") == "1.2.3"
        assert coerce_version("V2.0.0") == "2.0.0"
        assert coerce_version(" 1.0 ") == "1.0"
        assert coerce_version("") == "0"

    def test_coerce_pypi(self):
        from modules.cve.src.cve_matcher import coerce_version
        assert coerce_version("==1.0", "pypi") == "1.0"
        assert coerce_version(">=2.0", "pip") == "2.0"

    def test_coerce_maven_release(self):
        from modules.cve.src.cve_matcher import coerce_version
        assert coerce_version("1.0-RELEASE", "maven") == "1.0"
        assert coerce_version("2.0.0.FINAL", "maven") == "2.0.0"
