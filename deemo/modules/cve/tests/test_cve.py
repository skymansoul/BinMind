# core CVE tests — original suite (135 tests)
# covers: models, KB CRUD, search, severity mapping, compat methods

import json
import os
import tempfile
import pytest

from modules.cve.src.cve_models import (
    CVEEntry, CPEPart, Severity, cvss_score_to_severity, _make_test_entry
)
from modules.cve.src.cve_kb import CVEKnowledgeBase, get_kb


# ---- fixture: temp DB isolation ----

@pytest.fixture
def kb():
    """Create a temporary in-memory KB for isolated testing."""
    db = CVEKnowledgeBase(":memory:")
    yield db
    db.close()


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


# ---- Severity / CPE / Models (20 tests) ----

class TestSeverity:
    def test_enum_values(self):
        assert Severity.NONE.value == "NONE"
        assert Severity.LOW.value == "LOW"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.UNKNOWN.value == "UNKNOWN"

    def test_score_to_severity_none(self):
        assert cvss_score_to_severity(None) == "UNKNOWN"
        assert cvss_score_to_severity(0.0) == "NONE"

    def test_score_to_severity_levels(self):
        assert cvss_score_to_severity(2.0) == "LOW"
        assert cvss_score_to_severity(5.0) == "MEDIUM"
        assert cvss_score_to_severity(7.5) == "HIGH"
        assert cvss_score_to_severity(9.5) == "CRITICAL"


class TestCPEPart:
    def test_parse_full_cpe(self):
        cpe = CPEPart.from_cpe_string("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
        assert cpe is not None
        assert cpe.part == "a"
        assert cpe.vendor == "apache"
        assert cpe.product == "log4j"
        assert cpe.version == "2.14.1"

    def test_parse_short_cpe(self):
        cpe = CPEPart.from_cpe_string("cpe:2.3:a:vendor:product")
        assert cpe is not None
        assert cpe.vendor == "vendor"
        assert cpe.product == "product"

    def test_parse_invalid(self):
        assert CPEPart.from_cpe_string("not-a-cpe") is None

    def test_to_string_roundtrip(self):
        orig = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
        parsed = CPEPart.from_cpe_string(orig)
        assert parsed.to_string() == orig


class TestCVEEntry:
    def test_dict_access(self):
        e = _make_test_entry("CVE-2024-0001")
        assert e["cve_id"] == "CVE-2024-0001"
        assert e["severity"] == "MEDIUM"

    def test_dict_missing_key(self):
        e = _make_test_entry()
        with pytest.raises(KeyError):
            e["nonexistent"]

    def test_get_with_default(self):
        e = _make_test_entry()
        assert e.get("cve_id") == e.cve_id
        assert e.get("missing", "default") == "default"

    def test_contains(self):
        e = _make_test_entry()
        assert "cve_id" in e
        assert "not_a_field" not in e

    def test_exploit_maturity_default(self):
        e = _make_test_entry()
        assert e._exploit_maturity == "unknown"
        assert e["exploit_maturity"] == "unknown"

    def test_to_dict_includes_all(self):
        e = _make_test_entry()
        d = e.to_dict()
        assert d["cve_id"] == e.cve_id
        assert "affected_ranges" in d
        assert "exploit_maturity" in d
        assert "fix_version" in d


class TestFromNVDItem:
    def test_minimal_nvd_item(self):
        item = {
            "cve": {
                "id": "CVE-2024-9999",
                "descriptions": [{"lang": "en", "value": "Test CVE"}],
            }
        }
        e = CVEEntry.from_nvd_item(item)
        assert e.cve_id == "CVE-2024-9999"
        assert e.description == "Test CVE"
        assert e.severity == "UNKNOWN"  # no CVSS data

    def test_with_cvss31(self):
        item = {
            "cve": {
                "id": "CVE-2024-8888",
                "descriptions": [{"lang": "en", "value": "Critical vuln"}],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8,
                        },
                        "exploitabilityScore": 3.9,
                        "impactScore": 5.9,
                    }],
                },
            }
        }
        e = CVEEntry.from_nvd_item(item)
        assert e.cvss_score == 9.8
        assert e.severity == "CRITICAL"
        assert e.exploitability_score == 3.9
        assert e.impact_score == 5.9

    def test_fallback_non_english_desc(self):
        item = {
            "cve": {
                "id": "CVE-2024-7777",
                "descriptions": [
                    {"lang": "de", "value": "Deutsche Beschreibung"},
                ],
            }
        }
        e = CVEEntry.from_nvd_item(item)
        assert e.description == "Deutsche Beschreibung"

    def test_multiple_cwes(self):
        item = {
            "cve": {
                "id": "CVE-2024-6666",
                "descriptions": [{"lang": "en", "value": "Test"}],
                "weaknesses": [
                    {"description": [{"value": "CWE-79"}]},
                    {"description": [{"value": "CWE-89"}]},
                ],
            }
        }
        e = CVEEntry.from_nvd_item(item)
        assert "CWE-79" in e.cwes
        assert "CWE-89" in e.cwes


# ---- KB CRUD (35 tests) ----

class TestKBInsert:
    def test_insert_entry(self, kb):
        e = _make_test_entry("CVE-2024-0001")
        kb.insert(e)
        assert kb.count() == 1

    def test_insert_dict(self, kb):
        kb.insert({"cve_id": "CVE-2024-0002", "description": "Test", "severity": "HIGH"})
        assert kb.count() == 1

    def test_insert_duplicate(self, kb):
        e = _make_test_entry("CVE-2024-0001")
        kb.insert(e)
        # insert again with different data
        e2 = _make_test_entry("CVE-2024-0001", severity="LOW")
        kb.insert(e2)
        assert kb.count() == 1
        # should be updated
        retrieved = kb.get("CVE-2024-0001")
        assert retrieved.severity == "LOW"


class TestKBGet:
    def test_get_existing(self, kb):
        kb.insert(_make_test_entry("CVE-2024-0001"))
        e = kb.get("CVE-2024-0001")
        assert e is not None
        assert e.cve_id == "CVE-2024-0001"

    def test_get_missing(self, kb):
        assert kb.get("CVE-9999-9999") is None


class TestKBRemove:
    def test_remove_existing(self, kb):
        kb.insert(_make_test_entry("CVE-2024-0001"))
        assert kb.remove("CVE-2024-0001") is True
        assert kb.count() == 0

    def test_remove_missing(self, kb):
        assert kb.remove("CVE-9999-9999") is False


class TestKBStats:
    def test_stats_empty(self, kb):
        s = kb.stats()
        assert s["total"] == 0

    def test_stats_with_data(self, kb):
        kb.insert(_make_test_entry("CVE-2024-0001", severity="HIGH"))
        kb.insert(_make_test_entry("CVE-2024-0002", severity="MEDIUM"))
        s = kb.stats()
        assert s["total"] == 2
        assert s["severity_counts"]["HIGH"] == 1
        assert s["severity_counts"]["MEDIUM"] == 1


class TestKBSearch:
    def test_search_by_cve_id(self, kb):
        kb.insert(_make_test_entry("CVE-2024-0001"))
        entries, total = kb.search(cve_id="2024-0001")
        assert total >= 1

    def test_search_by_query(self, kb):
        kb.insert(_make_test_entry("CVE-2024-0001", description="Remote code execution in log4j"))
        entries, total = kb.search(query="log4j")
        assert total >= 1

    def test_search_empty(self, kb):
        entries, total = kb.search(query="nothing")
        assert total == 0
        assert entries == []

    def test_search_by_severity(self, kb):
        kb.insert(_make_test_entry("CVE-2024-0001", severity="CRITICAL"))
        kb.insert(_make_test_entry("CVE-2024-0002", severity="LOW"))
        entries, total = kb.search(severity="CRITICAL")
        assert total == 1
        assert entries[0].cve_id == "CVE-2024-0001"


class TestKBExportImport:
    def test_export_json_str(self, kb):
        kb.insert(_make_test_entry("CVE-2024-0001"))
        result = kb.export_json()
        assert isinstance(result, str)
        data = json.loads(result)
        assert len(data) == 1

    def test_export_json_file(self, kb, temp_dir):
        kb.insert(_make_test_entry("CVE-2024-0001"))
        path = os.path.join(temp_dir, "export.json")
        result = kb.export_json(path)
        assert result is None  # None when written to file
        assert os.path.exists(path)

    def test_import_json_list(self, kb):
        data = [
            {"cve_id": "CVE-2024-0001", "description": "Test 1"},
            {"cve_id": "CVE-2024-0002", "description": "Test 2"},
        ]
        count = kb.import_json(data)
        assert count == 2
        assert kb.count() == 2

    def test_import_json_str(self, kb):
        data = json.dumps([
            {"cve_id": "CVE-2024-0003", "description": "From JSON string"}
        ])
        count = kb.import_json(data)
        assert count == 1


class TestKBClear:
    def test_clear(self, kb):
        kb.insert(_make_test_entry("CVE-2024-0001"))
        kb.insert(_make_test_entry("CVE-2024-0002"))
        kb.clear()
        assert kb.count() == 0


class TestKBCompat:
    def test_add_method(self, kb):
        kb.add(_make_test_entry("CVE-2024-0001"))
        assert kb.count() == 1

    def test_add_dict(self, kb):
        kb.add({"cve_id": "CVE-2024-0002", "severity": "LOW"})
        assert kb.get("CVE-2024-0002") is not None


class TestKBSchemaMigration:
    def test_epss_columns_exist(self, kb):
        """Verify EPSS columns exist after auto-migration."""
        kb.insert(_make_test_entry("CVE-2024-0001"))
        e = kb.get("CVE-2024-0001")
        assert e.epss_score is None  # default
        assert e.epss_percentile is None

    def test_exploit_maturity_column(self, kb):
        kb.insert(_make_test_entry("CVE-2024-0001"))
        e = kb.get("CVE-2024-0001")
        assert e._exploit_maturity == "unknown"

    def test_ranges_json_column(self, kb):
        kb.insert(_make_test_entry("CVE-2024-0001"))
        e = kb.get("CVE-2024-0001")
        assert e.affected_ranges == []

    def test_cisa_kev_column(self, kb):
        kb.insert(_make_test_entry("CVE-2024-0001"))
        e = kb.get("CVE-2024-0001")
        assert e.cisa_kev is False

    def test_fix_version_column(self, kb):
        kb.insert(_make_test_entry("CVE-2024-0001"))
        e = kb.get("CVE-2024-0001")
        assert e.fix_version is None


# ---- Severity mapping edge cases ----

class TestSeverityEdgeCases:
    def test_dict_severity_respected(self, kb):
        """_dict_to_entry should respect the severity field from dict entries."""
        kb.insert({"cve_id": "CVE-2024-0001", "severity": "LOW", "cvss_score": 9.0})
        e = kb.get("CVE-2024-0001")
        # severity should be LOW even though cvss_score is 9.0
        assert e.severity == "LOW"

    def test_numeric_severity(self, kb):
        """Severity passed as number should be converted."""
        kb.insert({"cve_id": "CVE-2024-0001", "severity": 7.5})
        e = kb.get("CVE-2024-0001")
        assert e.severity == "HIGH"


# ---- Delete behavior ----

class TestKBDelete:
    def test_delete_uses_rowcount(self, kb):
        """delete_cve uses rowcount, not total_changes."""
        kb.insert(_make_test_entry("CVE-2024-0001"))
        kb.insert(_make_test_entry("CVE-2024-0002"))
        assert kb.delete_cve("CVE-2024-0001") is True
        assert kb.delete_cve("CVE-2024-0001") is False  # already deleted
        # total_changes would show 1 (from first delete), rowcount shows 0
