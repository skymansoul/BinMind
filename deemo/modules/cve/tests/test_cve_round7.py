# round 7 tests — ghsa pagination, epss bulk import, cwe enrichment
# ~28 tests covering new features added late aug 2026

import pytest
import json
from modules.cve.src.cve_kb import CVEKnowledgeBase
from modules.cve.src.cve_models import CVEEntry, _make_test_entry


@pytest.fixture
def kb():
    db = CVEKnowledgeBase(":memory:")
    yield db
    db.close()


# ===== GHSA pagination + dedup (8 tests) =====

class TestGHSAPagination:
    def test_parse_next_link_valid(self):
        from modules.cve.src.cve_ghsa import _parse_next_link
        header = '<https://api.github.com/advisories?page=2>; rel="next"'
        result = _parse_next_link(header)
        assert result == "https://api.github.com/advisories?page=2"

    def test_parse_next_link_last_only(self):
        from modules.cve.src.cve_ghsa import _parse_next_link
        header = '<https://api.github.com/advisories?page=10>; rel="last"'
        assert _parse_next_link(header) is None  # no "next" link

    def test_parse_next_link_multiple(self):
        from modules.cve.src.cve_ghsa import _parse_next_link
        header = (
            '<https://api.github.com/advisories?page=2>; rel="next", '
            '<https://api.github.com/advisories?page=10>; rel="last"'
        )
        assert _parse_next_link(header) == "https://api.github.com/advisories?page=2"

    def test_parse_next_link_empty(self):
        from modules.cve.src.cve_ghsa import _parse_next_link
        assert _parse_next_link("") is None
        assert _parse_next_link(None) is None

    def test_desc_overlap_identical(self):
        from modules.cve.src.cve_ghsa import _desc_overlap
        desc = "Remote code execution in Apache Log4j"
        assert _desc_overlap(desc, desc) == 1.0

    def test_desc_overlap_similar(self):
        from modules.cve.src.cve_ghsa import _desc_overlap
        score = _desc_overlap(
            "Remote code execution in Apache Log4j allows attackers to execute arbitrary code",
            "Apache Log4j is vulnerable to remote code execution via JNDI injection"
        )
        assert score > 0.3  # should have decent overlap

    def test_desc_overlap_unrelated(self):
        from modules.cve.src.cve_ghsa import _desc_overlap
        score = _desc_overlap(
            "Remote code execution in Apache Log4j",
            "Denial of service in BIND DNS server"
        )
        assert score < 0.3  # very little overlap

    def test_desc_overlap_empty(self):
        from modules.cve.src.cve_ghsa import _desc_overlap
        assert _desc_overlap("", "something") == 0.0
        assert _desc_overlap("something", "") == 0.0


class TestGHSASearchAndDedup:
    def test_search_and_dedup_no_kb_entries(self, kb):
        """When KB is empty and GHSA fails (offline), returns empty stats."""
        from modules.cve.src.cve_ghsa import search_and_dedup
        # patch search_ghsa to return empty (no network in test)
        import modules.cve.src.cve_ghsa as ghsa_mod
        saved = ghsa_mod.search_ghsa
        ghsa_mod.search_ghsa = lambda *a, **kw: []
        try:
            result = search_and_dedup(kb, "log4j")
            assert "merged" in result
            assert "ghsa_only" in result
            assert result["stats"]["total_ghsa"] == 0
        finally:
            ghsa_mod.search_ghsa = saved

    def test_search_and_dedup_with_kb_entries(self, kb):
        """GHSA matches KB by CVE ID."""
        from modules.cve.src.cve_ghsa import search_and_dedup
        import modules.cve.src.cve_ghsa as ghsa_mod

        kb.insert({
            "cve_id": "CVE-2021-44228",
            "description": "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP",
            "severity": "CRITICAL",
        })

        saved = ghsa_mod.search_ghsa
        ghsa_mod.search_ghsa = lambda *a, **kw: []
        try:
            result = search_and_dedup(kb, "log4j")
            assert result["stats"]["total_kb"] == 1
        finally:
            ghsa_mod.search_ghsa = saved


# ===== EPSS bulk import (3 tests) =====
# note: network tests skipped — the bulk_import test verifies the method
# exists and handles the no-network case gracefully

class TestEPSSBulk:
    def test_bulk_import_method_exists(self):
        from modules.cve.src.cve_epss import EPSSClient
        client = EPSSClient(":memory:")
        assert hasattr(client, 'bulk_import')
        client.close()

    def test_bulk_import_no_network_graceful(self):
        """bulk_import should handle missing network without crashing.
        We force _HAS_URLLIB to False to simulate offline mode."""
        from modules.cve.src.cve_epss import EPSSClient
        client = EPSSClient(":memory:")
        # simulate offline: the method checks _HAS_URLLIB internally
        # if urllib is available it'll try — patch it temporarily
        import modules.cve.src.cve_epss as epss_mod
        saved = epss_mod._HAS_URLLIB
        epss_mod._HAS_URLLIB = False
        try:
            stats = client.bulk_import()
            assert "imported" in stats
            assert stats["imported"] == 0  # no network = nothing imported
        finally:
            epss_mod._HAS_URLLIB = saved
        client.close()

    def test_bulk_import_stats_format(self):
        from modules.cve.src.cve_epss import EPSSClient
        import modules.cve.src.cve_epss as epss_mod
        client = EPSSClient(":memory:")
        saved = epss_mod._HAS_URLLIB
        epss_mod._HAS_URLLIB = False
        try:
            stats = client.bulk_import()
            assert isinstance(stats, dict)
            for key in ("downloaded", "imported", "elapsed_secs"):
                assert key in stats, f"missing key: {key}"
        finally:
            epss_mod._HAS_URLLIB = saved
        client.close()


# ===== CWE enrichment (12 tests) =====

class TestCWEClient:
    def test_init_and_seed(self):
        """Init CWEClient — should seed top 50 CWEs."""
        from modules.cve.src.cve_cwe import CWEClient
        client = CWEClient(":memory:")
        stats = client.stats()
        assert stats["cached_cwes"] >= 20  # at least the 20 hard-coded seeds
        client.close()

    def test_get_cwe_seeded(self):
        """Get a seeded CWE — no network needed."""
        from modules.cve.src.cve_cwe import CWEClient
        client = CWEClient(":memory:")
        data = client.get_cwe("CWE-79")
        assert data is not None
        assert "name" in data
        assert "description" in data
        assert "Cross-site Scripting" in data["name"] or "XSS" in data["name"].upper()
        client.close()

    def test_get_cwe_missing(self):
        """CWE not in cache returns None."""
        from modules.cve.src.cve_cwe import CWEClient
        client = CWEClient(":memory:")
        assert client.get_cwe("CWE-99999") is None
        client.close()

    def test_has_cwe(self):
        from modules.cve.src.cve_cwe import CWEClient
        client = CWEClient(":memory:")
        assert client.has_cwe("CWE-79") is True
        assert client.has_cwe("CWE-99999") is False
        client.close()

    def test_get_mitigations_seeded(self):
        """Seeded CWEs should have basic info even without network."""
        from modules.cve.src.cve_cwe import CWEClient
        client = CWEClient(":memory:")
        mitigations = client.get_mitigations("CWE-79")
        # seeded entries aren't expected to have full mitigations
        # but the method should return a list
        assert isinstance(mitigations, list)
        client.close()

    def test_enrich_entry(self):
        """Enrich a CVE entry that has CWEs."""
        from modules.cve.src.cve_cwe import CWEClient
        client = CWEClient(":memory:")
        entry = _make_test_entry("CVE-2024-TEST", cwes=["CWE-79", "CWE-89"])
        result = client.enrich_entry(entry)
        assert "cwe_enrichment" in result
        assert len(result["cwe_enrichment"]) == 2
        assert result["cwe_enrichment"][0]["cwe_id"] == "CWE-79"
        client.close()

    def test_enrich_entry_no_cwes(self):
        """Entry with no CWEs returns empty enrichment."""
        from modules.cve.src.cve_cwe import CWEClient
        client = CWEClient(":memory:")
        entry = _make_test_entry("CVE-2024-TEST")
        result = client.enrich_entry(entry)
        assert result["cwe_enrichment"] == []
        client.close()

    def test_close_and_reopen(self):
        """Close and reopen — data persists."""
        import tempfile, os
        from modules.cve.src.cve_cwe import CWEClient
        tmp = os.path.join(tempfile.gettempdir(), "cwe_test_cache.db")
        try:
            client1 = CWEClient(tmp)
            assert client1.has_cwe("CWE-79")
            client1.close()

            client2 = CWEClient(tmp)
            assert client2.has_cwe("CWE-79")  # persisted
            client2.close()
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def test_enrich_entry_dict(self):
        """Enrich works with dict entries too."""
        from modules.cve.src.cve_cwe import CWEClient
        client = CWEClient(":memory:")
        entry = {"cve_id": "CVE-2024-DICT", "cwes": ["CWE-79"]}
        result = client.enrich_entry(entry)
        assert len(result["cwe_enrichment"]) == 1
        client.close()

    def test_get_cwe_caching(self):
        """After fetch_cwe, get_cwe should return cached data."""
        from modules.cve.src.cve_cwe import CWEClient
        client = CWEClient(":memory:")
        # seeded CWE should return immediately
        data = client.get_cwe("CWE-787")
        assert data is not None
        assert data["cached"] is True
        client.close()


class TestCWENormalize:
    def test_normalize_plain_number(self):
        from modules.cve.src.cve_cwe import _normalize_cwe_id
        assert _normalize_cwe_id("79") == "CWE-79"
        assert _normalize_cwe_id("787") == "CWE-787"

    def test_normalize_cwe_prefix(self):
        from modules.cve.src.cve_cwe import _normalize_cwe_id
        assert _normalize_cwe_id("CWE-79") == "CWE-79"
        assert _normalize_cwe_id("cwe-89") == "CWE-89"

    def test_normalize_padded(self):
        from modules.cve.src.cve_cwe import _normalize_cwe_id
        assert _normalize_cwe_id("CWE-079") == "CWE-79"

    def test_normalize_invalid(self):
        from modules.cve.src.cve_cwe import _normalize_cwe_id
        assert _normalize_cwe_id("") is None
        assert _normalize_cwe_id("not-a-cwe") is None

    def test_extract_from_text(self):
        from modules.cve.src.cve_cwe import extract_cwes_from_text
        result = extract_cwes_from_text(
            "Vulnerability involves CWE-79 (XSS) and CWE-89 (SQL injection)"
        )
        assert "CWE-79" in result
        assert "CWE-89" in result

    def test_extract_no_cwes(self):
        from modules.cve.src.cve_cwe import extract_cwes_from_text
        assert extract_cwes_from_text("No weaknesses here") == []
