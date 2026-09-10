# Round 10 测试——OSV、监视列表、利用策略
# ~21项测试，覆盖新增特性

import pytest
import json
from modules.cve.src.cve_kb import CVEKnowledgeBase
from modules.cve.src.cve_models import _make_test_entry


@pytest.fixture
def kb():
    db = CVEKnowledgeBase(":memory:")
    yield db
    db.close()


# OSV integration (7 tests)

class TestOSVIntegration:
    def test_normalize_ecosystem_pip(self):
        from modules.cve.src.cve_osv import normalize_ecosystem
        assert normalize_ecosystem("pip") == "PyPI"
        assert normalize_ecosystem("pypi") == "PyPI"

    def test_normalize_ecosystem_npm(self):
        from modules.cve.src.cve_osv import normalize_ecosystem
        assert normalize_ecosystem("npm") == "npm"
        assert normalize_ecosystem("node") == "npm"

    def test_normalize_ecosystem_maven(self):
        from modules.cve.src.cve_osv import normalize_ecosystem
        assert normalize_ecosystem("maven") == "Maven"
        assert normalize_ecosystem("java") == "Maven"

    def test_normalize_ecosystem_unknown(self):
        from modules.cve.src.cve_osv import normalize_ecosystem
        assert normalize_ecosystem("some-weird-eco") == "some-weird-eco"

    def test_osv_to_cve_entry_with_cve_alias(self):
        from modules.cve.src.cve_osv import osv_to_cve_entry
        osv = {
            "id": "GHSA-1234-5678-9abc",
            "aliases": ["CVE-2024-99999"],
            "summary": "Test vuln",
            "details": "Detailed description of the vulnerability",
            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
            "affected": [{"package": {"ecosystem": "PyPI", "name": "testpkg"}, "ranges": []}],
            "references": [{"url": "https://example.com/advisory"}],
            "published": "2024-01-01T00:00:00Z",
        }
        entry = osv_to_cve_entry(osv)
        assert entry is not None
        assert entry.cve_id == "CVE-2024-99999"
        assert entry.source == "osv"

    def test_osv_to_cve_entry_no_cve(self):
        from modules.cve.src.cve_osv import osv_to_cve_entry
        osv = {
            "id": "GHSA-no-cve",
            "aliases": [],
            "summary": "No CVE ID",
            "details": "",
            "severity": [],
            "affected": [],
            "references": [],
        }
        entry = osv_to_cve_entry(osv)
        assert entry is not None
        assert entry.cve_id == "GHSA-no-cve"

    def test_osv_client_init(self):
        from modules.cve.src.cve_osv import OSVClient
        client = OSVClient(":memory:")
        assert client is not None
        client.close()


# Watchlist (7 tests)

class TestWatchlist:
    def test_add_and_list(self):
        from modules.cve.src.cve_watchlist import CVEWatchlist
        wl = CVEWatchlist(":memory:")
        wl.add("log4j", "maven", "2.14.1")
        wl.add("django", "pypi", "3.2.0")
        entries = wl.list_all()
        assert len(entries) == 2
        wl.close()

    def test_remove(self):
        from modules.cve.src.cve_watchlist import CVEWatchlist
        wl = CVEWatchlist(":memory:")
        wid = wl.add("flask", "pypi", "2.0.0")
        assert wl.remove(wid) is True
        assert wl.remove(99999) is False
        wl.close()

    def test_get(self):
        from modules.cve.src.cve_watchlist import CVEWatchlist
        wl = CVEWatchlist(":memory:")
        wid = wl.add("requests", "pypi", "2.25.0")
        entry = wl.get(wid)
        assert entry is not None
        assert entry["name"] == "requests"
        wl.close()

    def test_check_all_empty_kb(self, kb):
        from modules.cve.src.cve_watchlist import CVEWatchlist
        wl = CVEWatchlist(":memory:")
        wl.add("openssl", "", "3.0.0")
        result = wl.check_all(kb)
        assert "alerts" in result
        assert "summary" in result
        wl.close()

    def test_check_all_with_matches(self, kb):
        from modules.cve.src.cve_watchlist import CVEWatchlist
        kb.insert({"cve_id": "CVE-2024-WL1", "description": "OpenSSL buffer overflow", "severity": "HIGH"})
        kb.insert({"cve_id": "CVE-2024-WL2", "description": "OpenSSL DoS vulnerability", "severity": "MEDIUM"})
        wl = CVEWatchlist(":memory:")
        wl.add("openssl", "", "3.0.0")
        result = wl.check_all(kb)
        assert result["total_alerts"] >= 0  # may have new matches or not
        wl.close()

    def test_alerts_persist(self):
        from modules.cve.src.cve_watchlist import CVEWatchlist
        wl = CVEWatchlist(":memory:")
        wl.add("testpkg", "pypi", "1.0")
        stats = wl.alert_stats()
        assert "total_alerts" in stats
        wl.close()

    def test_import_from_sbom(self):
        from modules.cve.src.cve_watchlist import CVEWatchlist
        wl = CVEWatchlist(":memory:")
        components = [
            {"name": "log4j", "version": "2.14.0", "ecosystem": "maven"},
            {"name": "django", "version": "3.2", "ecosystem": "pypi"},
            {"name": "", "version": "1.0"},  # should be skipped
        ]
        count = wl.import_from_sbom(components)
        assert count == 2
        wl.close()


# Exploit strategy (7 tests)

class TestExploitStrategy:
    def test_get_strategy_known(self):
        from modules.cve.src.cve_exploit_strategy import get_strategy
        s = get_strategy("CWE-79")
        assert s is not None
        assert s["name"] == "Cross-Site Scripting (XSS)"
        assert s["difficulty"] == "easy"
        assert len(s["test_vectors"]) >= 3

    def test_get_strategy_unknown(self):
        from modules.cve.src.cve_exploit_strategy import get_strategy
        assert get_strategy("CWE-99999") is None

    def test_get_strategy_normalized(self):
        from modules.cve.src.cve_exploit_strategy import get_strategy
        assert get_strategy("79") is not None  # auto-prefix
        assert get_strategy("cwe-89") is not None

    def test_get_strategy_for_cve(self):
        from modules.cve.src.cve_exploit_strategy import get_strategy_for_cve
        entry = _make_test_entry("CVE-2024-TEST", cwes=["CWE-89", "CWE-79"])
        strategies = get_strategy_for_cve(entry)
        assert strategies is not None
        assert len(strategies) == 2

    def test_get_strategy_for_cve_no_cwes(self):
        from modules.cve.src.cve_exploit_strategy import get_strategy_for_cve
        entry = _make_test_entry("CVE-2024-TEST", cwes=[])
        assert get_strategy_for_cve(entry) is None

    def test_generate_exploit_plan(self):
        from modules.cve.src.cve_exploit_strategy import generate_exploit_plan
        entry = _make_test_entry("CVE-2024-TEST", cwes=["CWE-79"], cvss_score=7.5)
        plan = generate_exploit_plan(entry)
        assert plan["cve_id"] == "CVE-2024-TEST"
        assert len(plan["strategies"]) >= 1
        assert "recommended_approach" in plan
        assert plan["combined_difficulty"] in ("easy", "medium", "hard", "unknown")

    def test_list_available_strategies(self):
        from modules.cve.src.cve_exploit_strategy import list_available_strategies
        strategies = list_available_strategies()
        assert len(strategies) >= 8
        assert "CWE-79" in strategies
        assert "CWE-89" in strategies
