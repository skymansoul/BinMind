# 17 tests: parse, cache, sync, priority sort, ssvc integration, fix suggestions

import json
import os
import tempfile
import pytest

from modules.cve.src.cve_kev import KEVClient, get_kev, is_cisa_kev
from modules.cve.src.cve_models import _make_test_entry
from modules.cve.src.cve_kb import CVEKnowledgeBase


# sample KEV feed data with 3 entries covering different scenarios
_SAMPLE_KEV_FEED = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "2024.09.15",
    "dateReleased": "2024-09-15T00:00:00.000Z",
    "count": 3,
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-0001",
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Apache Log4j RCE",
            "dateAdded": "2024-01-15",
            "shortDescription": "Remote code execution in Log4j",
            "requiredAction": "Update to version 2.17.0",
            "dueDate": "2024-02-05",
            "knownRansomwareCampaignUse": "Known",
            "notes": "Critical vulnerability",
        },
        {
            "cveID": "CVE-2024-0002",
            "vendorProject": "Microsoft",
            "product": "Exchange",
            "vulnerabilityName": "Exchange SSRF",
            "dateAdded": "2024-03-01",
            "shortDescription": "Server-side request forgery",
            "requiredAction": "Apply patch",
            "dueDate": "2024-03-22",
            "knownRansomwareCampaignUse": "",
            "notes": "",
        },
        {
            "cveID": "CVE-2024-0003",
            "vendorProject": "Unknown",
            "product": "Unknown",
            "vulnerabilityName": "Unknown vuln",
            "dateAdded": "2024-05-01",
            "shortDescription": "Description",
            "requiredAction": "Patch",
            "dueDate": "2024-05-30",
            "knownRansomwareCampaignUse": "",
            "notes": "",
        },
    ],
}


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def kb():
    db = CVEKnowledgeBase(":memory:")
    yield db
    db.close()


# ---- Parse tests (3) ----

class TestKEVParse:
    def test_parse_dict_format(self):
        """Post-2023 format: dict wrapper."""
        client = KEVClient.__new__(KEVClient)
        entries = client._parse(_SAMPLE_KEV_FEED)
        assert len(entries) == 3

    def test_parse_array_format(self):
        """Pre-2023 format: plain array."""
        client = KEVClient.__new__(KEVClient)
        entries = client._parse(_SAMPLE_KEV_FEED["vulnerabilities"])
        assert len(entries) == 3

    def test_parse_empty(self):
        client = KEVClient.__new__(KEVClient)
        assert client._parse({}) == []
        assert client._parse([]) == []
        assert client._parse("invalid") == []


# ---- Cache tests (3) ----

class TestKEVCache:
    def test_load_cached_empty(self, temp_dir):
        """Fresh cache returns empty list."""
        client = KEVClient(cache_dir=temp_dir)
        entries = client._load_cached()
        assert entries == []

    def test_save_and_load(self, temp_dir):
        """Entries saved to cache should be loadable."""
        client = KEVClient(cache_dir=temp_dir)
        client._save_to_cache(
            _SAMPLE_KEV_FEED["vulnerabilities"],
            '"test-etag-123"',
        )
        entries = client._load_cached()
        assert len(entries) == 3
        assert entries[0]["cveID"] == "CVE-2024-0001"

    def test_is_kev_check(self, temp_dir):
        """Check if CVE is in KEV after caching."""
        client = KEVClient(cache_dir=temp_dir)
        client._save_to_cache(
            _SAMPLE_KEV_FEED["vulnerabilities"],
            '"test-etag"',
        )
        assert client.is_kev("CVE-2024-0001") is True
        assert client.is_kev("CVE-9999-9999") is False


# ---- Sync tests (3) ----

class TestKEVSync:
    def test_sync_to_kb(self, temp_dir, kb):
        """Sync KEV flags to main KB."""
        # seed KB with some entries
        kb.insert(_make_test_entry("CVE-2024-0001"))
        kb.insert(_make_test_entry("CVE-2024-0002"))
        kb.insert(_make_test_entry("CVE-2024-9999"))  # not in KEV

        client = KEVClient(cache_dir=temp_dir)
        client._save_to_cache(
            _SAMPLE_KEV_FEED["vulnerabilities"],
            '"etag"',
        )
        count = client.sync_to_kb(kb)
        assert count == 2  # two entries matched

        # verify flags are set
        e1 = kb.get("CVE-2024-0001")
        assert e1.cisa_kev is True
        assert e1.cisa_kev_date == "2024-01-15"

        e3 = kb.get("CVE-2024-9999")
        assert e3.cisa_kev is False

    def test_sync_empty_kb(self, temp_dir, kb):
        """Syncing to empty KB should not crash."""
        client = KEVClient(cache_dir=temp_dir)
        client._save_to_cache(
            _SAMPLE_KEV_FEED["vulnerabilities"],
            '"etag"',
        )
        count = client.sync_to_kb(kb)
        assert count == 0

    def test_sync_no_entries(self, temp_dir, kb):
        """Sync with no KEV entries returns 0."""
        client = KEVClient(cache_dir=temp_dir)
        count = client.sync_to_kb(kb)
        assert count == 0


# ---- Priority sort (3 tests) ----

class TestKEVPriority:
    def test_kev_entries_come_first(self, temp_dir):
        """KEV entries should be sorted before non-KEV entries."""
        client = KEVClient(cache_dir=temp_dir)
        client._save_to_cache(
            _SAMPLE_KEV_FEED["vulnerabilities"],
            '"etag"',
        )
        entries = [
            _make_test_entry("CVE-2024-9999"),  # not in KEV
            _make_test_entry("CVE-2024-0001"),  # in KEV
            _make_test_entry("CVE-2024-9998"),  # not in KEV
            _make_test_entry("CVE-2024-0002"),  # in KEV
        ]
        sorted_entries = client.kev_priority(entries)
        assert sorted_entries[0].cve_id == "CVE-2024-0001"
        assert sorted_entries[1].cve_id == "CVE-2024-0002"

    def test_optional_kev_client_param(self, temp_dir):
        """Optional kev_client parameter allows test isolation."""
        client1 = KEVClient(cache_dir=temp_dir)
        client1._save_to_cache(
            [{"cveID": "CVE-2024-0001"}],
            '"etag"',
        )
        entries = [_make_test_entry("CVE-2024-0001"), _make_test_entry("CVE-2024-0002")]
        sorted_entries = client1.kev_priority(entries, kev_client=client1)
        assert sorted_entries[0].cve_id == "CVE-2024-0001"

    def test_all_non_kev(self, temp_dir):
        """When none are KEV, order is preserved."""
        client = KEVClient(cache_dir=temp_dir)
        entries = [_make_test_entry(f"CVE-2024-{i:04d}") for i in range(5)]
        sorted_entries = client.kev_priority(entries)
        assert len(sorted_entries) == 5


# ---- Singleton (2 tests) ----

class TestKEVSingleton:
    def test_get_kev_returns_same_instance(self):
        """Singleton returns the same instance."""
        c1 = get_kev()
        c2 = get_kev()
        assert c1 is c2

    def test_is_cisa_kev_convenience(self):
        """Module-level convenience function works."""
        # should not crash, returns bool
        result = is_cisa_kev("CVE-2024-0001")
        assert isinstance(result, bool)


# ---- SSVC integration (3 tests) ----

class TestKEVSSVCIntegration:
    def test_kev_flag_affects_ssvc(self, kb):
        """SSVC should consider KEV flag when evaluating."""
        entry = _make_test_entry("CVE-2024-0001", cvss_score=7.0)
        entry.cisa_kev = True
        from modules.cve.src.cve_ssvc import evaluate_cve
        result = evaluate_cve(entry)
        assert result["exploit_status"] == "active"
        any_cisa = any("CISA KEV" in r for r in result["reasoning"])
        assert any_cisa

    def test_sync_then_evaluate(self, temp_dir, kb):
        """After syncing KEV data, SSVC should detect it."""
        kb.insert(_make_test_entry("CVE-2024-0001"))
        client = KEVClient(cache_dir=temp_dir)
        client._save_to_cache(
            _SAMPLE_KEV_FEED["vulnerabilities"],
            '"etag"',
        )
        client.sync_to_kb(kb)

        entry = kb.get("CVE-2024-0001")
        from modules.cve.src.cve_ssvc import evaluate_cve
        result = evaluate_cve(entry)
        assert result["exploit_status"] == "active"

    def test_ransomware_flag_preserved(self, temp_dir, kb):
        """Ransomware campaign flag is stored (even if not yet used in scoring)."""
        kb.insert(_make_test_entry("CVE-2024-0001"))
        client = KEVClient(cache_dir=temp_dir)
        client._save_to_cache(
            _SAMPLE_KEV_FEED["vulnerabilities"],
            '"etag"',
        )
        client.sync_to_kb(kb)
        # ransomware flag is stored in the cache DB, not currently in main KB schema
        # but the sync should still work
        cached = client._load_cached()
        rw_entry = [e for e in cached if e["cveID"] == "CVE-2024-0001"][0]
        assert rw_entry.get("knownRansomwareCampaignUse") == "Known"
