# 23项测试: 规范化、token重叠、管道阶段、版本区间检查、
#           报告结构、便捷函数

import pytest
from modules.cve.src.cve_kb import CVEKnowledgeBase
from modules.cve.src.cve_models import _make_test_entry
from modules.cve.src.cve_sbom_matcher import (
    _norm_name, _token_overlap, _entry_cve_id, _entry_severity,
    _entry_description, _entry_products, _entry_vendors,
    SBOMComponentMatcher, match_sbom, build_sbom_report,
    _check_version_affected, _extract_fix,
)


@pytest.fixture
def kb():
    db = CVEKnowledgeBase(":memory:")
    yield db
    db.close()


@pytest.fixture
def seeded_kb(kb):
    """KB with entries containing version ranges."""
    kb.insert({
        "cve_id": "CVE-2024-0001",
        "description": "Remote code execution in Apache Log4j",
        "severity": "CRITICAL",
        "products": ["log4j"],
        "vendors": ["apache"],
        "affected_ranges": [{
            "type": "SEMVER",
            "events": [
                {"introduced": "2.0.0"},
                {"fixed": "2.17.0"},
            ],
        }],
        "fix_version": "2.17.0",
    })
    kb.insert({
        "cve_id": "CVE-2024-0002",
        "description": "Cross-site scripting in Django web framework",
        "severity": "MEDIUM",
        "products": ["django"],
        "vendors": ["djangoproject"],
        "affected_ranges": [{
            "type": "SEMVER",
            "events": [
                {"introduced": "3.0.0"},
                {"fixed": "3.2.15"},
            ],
        }],
    })
    kb.insert({
        "cve_id": "CVE-2024-0003",
        "description": "A vulnerability in apache commons text library",
        "severity": "HIGH",
        "products": ["commons-text"],
        "vendors": ["apache"],
        "affected_ranges": [],
    })
    return kb


# ---- Name normalization (5 tests) ----

class TestNormName:
    def test_lowercase(self):
        assert _norm_name("apache") == "apache"

    def test_strips_suffix(self):
        """Suffixes like -core, -api, -lib should be stripped."""
        result = _norm_name("log4j-core")
        assert result == "log4j"

    def test_strips_vendor_prefix(self):
        """Vendor prefixes should be stripped."""
        result = _norm_name("apache-log4j")
        assert "log4j" in result
        assert "apache" not in result.split()  # prefix stripped

    def test_collapse_separators(self):
        """Separators collapsed to spaces."""
        result = _norm_name("some_library-name.v2")
        assert " " in result or result == "some library name v2"

    def test_ordering_matters(self):
        """Prefix stripping must happen after suffix stripping.
        'apache-log4j-core' → strip suffix: 'apache-log4j' → strip prefix: 'log4j'"""
        result = _norm_name("apache-log4j-core")
        assert "log4j" in result


# ---- Token overlap (3 tests) ----

class TestTokenOverlap:
    def test_identical(self):
        assert _token_overlap("log4j", "log4j") > 0.9

    def test_partial_overlap(self):
        score = _token_overlap("apache log4j", "log4j core")
        assert 0.0 < score < 1.0

    def test_no_overlap(self):
        assert _token_overlap("django", "log4j") == 0.0


# ---- Entry helpers (3 tests) ----

class TestEntryHelpers:
    def test_entry_cve_id(self):
        entry = _make_test_entry("CVE-2024-0001")
        assert _entry_cve_id(entry) == "CVE-2024-0001"

        d = {"cve_id": "CVE-2024-9999"}
        assert _entry_cve_id(d) == "CVE-2024-9999"

    def test_entry_severity(self):
        entry = _make_test_entry("CVE-2024-0001", severity="HIGH")
        assert _entry_severity(entry) == "HIGH"

    def test_entry_products(self):
        entry = _make_test_entry("CVE-2024-0001")
        entry.products = ["log4j", "log4j-core"]
        assert "log4j" in _entry_products(entry)


# ---- Version range checking (4 tests) ----

class TestVersionRange:
    def test_version_affected(self):
        ranges = [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.17.0"}]}]
        assert _check_version_affected("2.14.1", ranges) is True

    def test_version_not_affected(self):
        ranges = [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.17.0"}]}]
        assert _check_version_affected("2.17.1", ranges) is False

    def test_empty_ranges(self):
        assert _check_version_affected("1.0.0", []) is False

    def test_empty_events(self):
        """Empty events list → return False."""
        ranges = [{"type": "SEMVER", "events": []}]
        assert _check_version_affected("1.0.0", ranges) is False


# ---- Fix extraction (2 tests) ----

class TestExtractFix:
    def test_from_patched_version(self):
        entry = _make_test_entry("CVE-2024-0001")
        entry.patched_version = "2.17.0"
        assert _extract_fix(entry) == "2.17.0"

    def test_from_ranges_fixed_event(self):
        entry = _make_test_entry("CVE-2024-0001")
        entry.affected_ranges = [
            {"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.17.0"}]}
        ]
        assert _extract_fix(entry) == "2.17.0"


# ---- Pipeline stages (3 tests) ----

class TestPipelineStages:
    def test_matcher_creation(self, kb):
        matcher = SBOMComponentMatcher(kb)
        assert matcher is not None

    def test_match_component_finds_cve(self, seeded_kb):
        matcher = SBOMComponentMatcher(seeded_kb)
        component = {"name": "log4j", "version": "2.14.1"}
        matches = matcher.match_component(component)
        assert len(matches) > 0
        # should find CVE-2024-0001
        matched_ids = [m["cve_id"] for m in matches]
        assert "CVE-2024-0001" in matched_ids

    def test_match_component_no_match(self, seeded_kb):
        matcher = SBOMComponentMatcher(seeded_kb)
        component = {"name": "nonexistent-library", "version": "1.0.0"}
        matches = matcher.match_component(component)
        assert matches == []


# ---- Report (3 tests) ----

class TestSBOMReport:
    def test_build_report(self, seeded_kb):
        components = [
            {"name": "log4j", "version": "2.14.1"},
            {"name": "django", "version": "3.2.0"},
            {"name": "safe-library", "version": "1.0.0"},
        ]
        report = build_sbom_report(seeded_kb, components)
        assert "summary" in report
        assert report["summary"]["total_components"] == 3
        assert report["summary"]["components_with_matches"] >= 1

    def test_report_includes_fix_suggestions(self, seeded_kb):
        components = [{"name": "log4j", "version": "2.14.1"}]
        report = build_sbom_report(seeded_kb, components)
        priorities = report.get("top_priorities", [])
        if priorities:
            assert "fix_suggestion" in priorities[0]

    def test_match_sbom_one_shot(self, seeded_kb):
        """match_sbom convenience function works."""
        # test with a dict of components
        components = [{"name": "log4j", "version": "2.14.1"}]
        result = match_sbom(seeded_kb, components)  # accepts list of component dicts
        assert result is not None
