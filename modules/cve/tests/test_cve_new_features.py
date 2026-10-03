"""26项测试: SSVC (11), purl/CPE (6), 传递风险 (3), GHSA覆盖 (3), 版本边界 (3)"""

import pytest
from modules.cve.src.cve_kb import CVEKnowledgeBase
from modules.cve.src.cve_models import CVEEntry, _make_test_entry


@pytest.fixture
def kb():
    db = CVEKnowledgeBase(":memory:")
    yield db
    db.close()


# SSVC测试 (11项)

class TestSSVC:
    def test_import(self):
        from modules.cve.src.cve_ssvc import evaluate_cve, Decision
        assert evaluate_cve is not None
        assert Decision is not None

    def test_evaluate_critical_active(self):
        """含活跃exploit的Critical CVE → Act。"""
        from modules.cve.src.cve_ssvc import evaluate_cve
        entry = _make_test_entry("CVE-2024-0001", cvss_score=9.8)
        entry._exploit_maturity = "metasploit"
        result = evaluate_cve(entry)
        assert result["decision"] in ("act", "Act", "ACT")

    def test_evaluate_low_not_automatable(self):
        """Low severity, not automatable → Track."""
        from modules.cve.src.cve_ssvc import evaluate_cve
        entry = _make_test_entry("CVE-2024-0001", cvss_score=3.0)
        entry._exploit_maturity = "unknown"
        result = evaluate_cve(entry)
        # low + not automatable + no active exploit → lower priority
        assert result["decision"] in ("track", "Track", "TRACK", "track_star", "Track*")

    def test_evaluate_with_epss_high(self):
        """High EPSS score → likely active exploitation."""
        from modules.cve.src.cve_ssvc import evaluate_cve
        entry = _make_test_entry("CVE-2024-0001", cvss_score=7.5)
        entry.epss_score = 0.95
        entry.epss_percentile = 0.98
        result = evaluate_cve(entry)
        assert result["exploit_status"] == "active"

    def test_evaluate_reasoning_includes_maturity(self):
        """Reasoning should mention maturity when available."""
        from modules.cve.src.cve_ssvc import evaluate_cve
        entry = _make_test_entry("CVE-2024-0001")
        entry._exploit_maturity = "functional"
        result = evaluate_cve(entry)
        reasoning_str = " ".join(result["reasoning"])
        assert "functional" in reasoning_str.lower()

    def test_evaluate_reasoning_includes_epss(self):
        """Reasoning should mention EPSS when that's the source."""
        from modules.cve.src.cve_ssvc import evaluate_cve
        entry = _make_test_entry("CVE-2024-0001")
        entry.epss_score = 0.8
        entry.epss_percentile = 0.9
        entry._exploit_maturity = "unknown"
        result = evaluate_cve(entry)
        reasoning_str = " ".join(result["reasoning"])
        assert "epss" in reasoning_str.lower() or "statistical" in reasoning_str.lower()

    def test_evaluate_dict_input(self):
        """SSVC should handle dict input (not just CVEEntry)."""
        from modules.cve.src.cve_ssvc import evaluate_cve
        entry = {"cve_id": "CVE-2024-0001", "severity": "HIGH", "cvss_score": 8.0}
        result = evaluate_cve(entry)
        assert "decision" in result

    def test_extract_maturity(self):
        from modules.cve.src.cve_ssvc import _extract_maturity
        entry = _make_test_entry("CVE-2024-0001")
        entry._exploit_maturity = "poc"
        assert _extract_maturity(entry) == "poc"

        d = {"exploit_maturity": "functional"}
        assert _extract_maturity(d) == "functional"

    def test_maturity_to_exploit(self):
        from modules.cve.src.cve_ssvc import _maturity_to_exploit
        assert _maturity_to_exploit("poc") == "poc"
        assert _maturity_to_exploit("functional") == "active"
        assert _maturity_to_exploit("metasploit") == "active"
        assert _maturity_to_exploit("weaponized") == "active"
        assert _maturity_to_exploit("unknown") == "unknown"

    def test_infer_automatable(self):
        from modules.cve.src.cve_ssvc import _infer_automatable
        # AV:N → likely automatable
        assert _infer_automatable("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is True
        # AV:L → likely not automatable
        assert _infer_automatable("AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N") is False

    def test_check_kev_flag(self):
        from modules.cve.src.cve_ssvc import _check_kev_flag
        entry = _make_test_entry("CVE-2024-0001")
        entry.cisa_kev = True
        assert _check_kev_flag(entry) is True

        d = {"cisa_kev": False}
        assert _check_kev_flag(d) is False


# PURL/CPE tests (6 tests)

class TestPurlCPE:
    def test_purl_to_cpe_pypi(self):
        from modules.cve.src.cve_purl_cpe import purl_to_cpe
        cpe = purl_to_cpe("pkg:pypi/django@3.2.0")
        assert cpe is not None
        assert "django" in cpe

    def test_purl_to_cpe_maven(self):
        from modules.cve.src.cve_purl_cpe import purl_to_cpe
        cpe = purl_to_cpe("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
        assert cpe is not None
        assert "log4j" in cpe

    def test_purl_to_cpe_npm(self):
        from modules.cve.src.cve_purl_cpe import purl_to_cpe
        cpe = purl_to_cpe("pkg:npm/lodash@4.17.21")
        assert cpe is not None
        assert "lodash" in cpe

    def test_cpe_to_purl(self):
        from modules.cve.src.cve_purl_cpe import cpe_to_purl
        purl = cpe_to_purl("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
        assert purl is not None
        assert "log4j" in purl

    def test_eco_vendor_mapping(self):
        from modules.cve.src.cve_purl_cpe import _ECO_VENDOR
        assert "pypi" in _ECO_VENDOR
        assert "maven" in _ECO_VENDOR
        assert "npm" in _ECO_VENDOR

    def test_npm_scoped_package(self):
        from modules.cve.src.cve_purl_cpe import purl_to_cpe
        cpe = purl_to_cpe("pkg:npm/%40angular/core@14.0.0")
        assert cpe is not None
        assert "angular" in cpe


# Transitive risk (3 tests)

class TestTransitiveRisk:
    def test_propagate_risk_import(self):
        from modules.cve.src.cve_purl_cpe import propagate_risk, transitive_risk_report
        assert propagate_risk is not None
        assert transitive_risk_report is not None

    def test_simple_dependency_tree(self):
        from modules.cve.src.cve_purl_cpe import propagate_risk
        # A depends on B depends on C (C has critical vuln)
        graph = {
            "A": {"depends_on": ["B"], "risk_score": 0},
            "B": {"depends_on": ["C"], "risk_score": 0},
            "C": {"depends_on": [], "risk_score": 9.5},
        }
        result = propagate_risk(graph)
        assert result is not None

    def test_transitive_report_with_depth(self):
        from modules.cve.src.cve_purl_cpe import transitive_risk_report
        components = [
            {"name": "A", "risk_score": 5.0, "depth": 0},
            {"name": "B", "risk_score": 8.0, "depth": 2},
        ]
        report = transitive_risk_report(components)
        assert report is not None


# GHSA coverage (3 tests)

class TestGHSACoverage:
    def test_cross_source_coverage_import(self):
        from modules.cve.src.cve_ghsa import cross_source_coverage, merge_with_confidence
        assert cross_source_coverage is not None
        assert merge_with_confidence is not None

    def test_coverage_empty(self):
        from modules.cve.src.cve_ghsa import cross_source_coverage
        result = cross_source_coverage([], [])
        assert "only_nvd" in result
        assert "only_ghsa" in result
        assert "both" in result
        assert result["total"] == 0

    def test_merge_with_confidence(self):
        from modules.cve.src.cve_ghsa import merge_with_confidence
        nvd = [{"cve_id": "CVE-2024-0001", "source": "nvd"}]
        ghsa = [{"cve_id": "CVE-2024-0001", "source": "ghsa"}]
        result = merge_with_confidence([{"entries": nvd}, {"entries": ghsa}])
        assert result is not None


# Version edge cases (3 tests)

class TestVersionEdgeCases:
    def test_prerelease_detection(self):
        from modules.cve.src.cve_matcher import _parse_cpe
        # should handle milestone/nightly/canary prerelease tags
        cpe_str = "cpe:2.3:a:vendor:product:1.0.0-milestone:*:*:*:*:*:*:*"
        result = _parse_cpe(cpe_str)
        assert result is not None

    def test_short_cpe_no_crash(self):
        from modules.cve.src.cve_matcher import _parse_cpe
        # shorter CPE strings shouldn't crash (IndexError fix)
        result = _parse_cpe("cpe:2.3:a:vendor:product")
        assert result is not None

    def test_empty_events_list(self):
        from modules.cve.src.cve_matcher import _check_single_range
        assert _check_single_range("1.0.0", {"events": []}) is False
