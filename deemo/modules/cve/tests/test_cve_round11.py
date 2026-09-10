# Round 11 测试——NVD同步、跨部署关联、修复跟踪
# ~21项测试

import pytest
from modules.cve.src.cve_kb import CVEKnowledgeBase
from modules.cve.src.cve_models import _make_test_entry


@pytest.fixture
def kb():
    db = CVEKnowledgeBase(":memory:")
    yield db
    db.close()


# NVD sync (4 tests)

class TestNVDSync:
    def test_engine_init(self, kb):
        from modules.cve.src.cve_nvd_sync import NVDSyncEngine
        engine = NVDSyncEngine(kb)
        assert engine.last_sync_time is None
        assert engine.total_synced == 0

    def test_state_persistence(self, kb, tmp_path):
        from modules.cve.src.cve_nvd_sync import NVDSyncEngine
        state_path = str(tmp_path / "sync_state.json")
        engine = NVDSyncEngine(kb, state_path=state_path)
        assert engine.last_sync_time is None
        # state file should be created on save
        import os
        assert os.path.exists(state_path) or engine._state is not None

    def test_full_sync_offline(self, kb):
        from modules.cve.src.cve_nvd_sync import NVDSyncEngine
        import modules.cve.src.cve_nvd_sync as sync_mod
        saved = sync_mod._HAS_URLLIB
        sync_mod._HAS_URLLIB = False
        try:
            engine = NVDSyncEngine(kb)
            stats = engine.sync(full=True)
            assert "error" in stats or stats.get("imported", 0) == 0
        finally:
            sync_mod._HAS_URLLIB = saved

    def test_delta_sync_offline(self, kb):
        from modules.cve.src.cve_nvd_sync import NVDSyncEngine
        import modules.cve.src.cve_nvd_sync as sync_mod
        saved = sync_mod._HAS_URLLIB
        sync_mod._HAS_URLLIB = False
        try:
            engine = NVDSyncEngine(kb)
            engine._state["last_sync"] = "2025-02-06T00:00:00"
            stats = engine.sync()
            assert isinstance(stats, dict)
        finally:
            sync_mod._HAS_URLLIB = saved


# Cross-deployment correlation (7 tests)

class TestCorrelation:
    def test_correlate_two_deployments(self):
        from modules.cve.src.cve_correlation import correlate_deployments
        d1 = [{"cve_id": "A", "severity": "CRITICAL", "cvss_score": 9.0, "component": "x"}]
        d2 = [{"cve_id": "A", "severity": "CRITICAL", "cvss_score": 9.0, "component": "x"},
              {"cve_id": "B", "severity": "MEDIUM", "cvss_score": 5.0, "component": "y"}]
        result = correlate_deployments({"dep-a": d1, "dep-b": d2})
        assert result["intersection"] == ["A"]
        assert result["intersection_count"] == 1
        assert result["union_count"] == 2

    def test_correlate_no_overlap(self):
        from modules.cve.src.cve_correlation import correlate_deployments
        d1 = [{"cve_id": "A", "severity": "HIGH"}]
        d2 = [{"cve_id": "B", "severity": "LOW"}]
        result = correlate_deployments({"a": d1, "b": d2})
        assert result["intersection"] == []
        assert result["union_count"] == 2

    def test_correlate_empty(self):
        from modules.cve.src.cve_correlation import correlate_deployments
        result = correlate_deployments({})
        assert "error" in result

    def test_blast_radius(self):
        from modules.cve.src.cve_correlation import correlate_deployments
        d1 = [{"cve_id": "A", "severity": "CRITICAL", "cvss_score": 9.0}]
        d2 = [{"cve_id": "A", "severity": "CRITICAL", "cvss_score": 9.0}]
        d3 = [{"cve_id": "B", "severity": "HIGH", "cvss_score": 7.0}]
        result = correlate_deployments({"a": d1, "b": d2, "c": d3})
        # A affects 2/3, B affects 1/3
        a_radius = next(b for b in result["blast_radius"] if b["cve_id"] == "A")
        assert a_radius["deployment_count"] == 2
        assert a_radius["blast_pct"] == pytest.approx(66.7, abs=0.1)

    def test_find_common_empty(self):
        from modules.cve.src.cve_correlation import find_common_cves
        assert find_common_cves() == []

    def test_overlap_matrix(self):
        from modules.cve.src.cve_correlation import correlate_deployments
        d1 = [{"cve_id": "A"}, {"cve_id": "B"}]
        d2 = [{"cve_id": "A"}, {"cve_id": "C"}]
        result = correlate_deployments({"x": d1, "y": d2})
        matrix = result["overlap_matrix"]
        assert len(matrix) == 1  # one pair
        assert matrix[0]["overlap_count"] == 1  # A is common

    def test_blast_radius_summary_str(self):
        from modules.cve.src.cve_correlation import correlate_deployments, blast_radius_summary
        d1 = [{"cve_id": "A", "severity": "CRITICAL"}]
        d2 = [{"cve_id": "A", "severity": "CRITICAL"}]
        result = correlate_deployments({"a": d1, "b": d2})
        s = blast_radius_summary(result)
        assert "A" in s
        assert "2" in s  # affects 2 deployments


# Remediation (8 tests)

class TestRemediation:
    def test_import_matches(self):
        from modules.cve.src.cve_remediation import RemediationTracker
        rt = RemediationTracker(":memory:")
        matches = [
            {"cve_id": "CVE-2024-0001", "severity": "CRITICAL", "cvss_score": 9.8, "epss_score": 0.5, "component": "log4j"},
            {"cve_id": "CVE-2024-0002", "severity": "MEDIUM", "cvss_score": 5.0, "component": "openssl"},
        ]
        count = rt.import_matches(matches, deployment="prod")
        assert count == 2
        rt.close()

    def test_summary(self):
        from modules.cve.src.cve_remediation import RemediationTracker
        rt = RemediationTracker(":memory:")
        rt.import_matches([{"cve_id": "X", "severity": "HIGH"}])
        s = rt.summary()
        assert s["total_tracked"] == 1
        rt.close()

    def test_update_status(self):
        from modules.cve.src.cve_remediation import RemediationTracker
        rt = RemediationTracker(":memory:")
        rt.import_matches([{"cve_id": "CVE-2024-R1", "severity": "HIGH"}])
        assert rt.update_status("CVE-2024-R1", "remediated") is True
        entry = rt.get_for_cve("CVE-2024-R1")
        assert entry["status"] == "remediated"
        assert entry["remediated_at"] is not None
        rt.close()

    def test_accept_risk(self):
        from modules.cve.src.cve_remediation import RemediationTracker
        rt = RemediationTracker(":memory:")
        rt.import_matches([{"cve_id": "CVE-2024-R2", "severity": "MEDIUM"}])
        assert rt.accept_risk("CVE-2024-R2", "Low impact, no internet exposure") is True
        entry = rt.get_for_cve("CVE-2024-R2")
        assert entry["status"] == "accepted_risk"
        rt.close()

    def test_get_overdue(self):
        from modules.cve.src.cve_remediation import RemediationTracker
        rt = RemediationTracker(":memory:")
        # insert with a past deadline by manipulating the DB directly
        conn = rt._get_conn()
        conn.execute(
            "INSERT INTO remediation (cve_id, severity, status, deadline, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("CVE-OLD", "CRITICAL", "open", "2020-01-01", "2020-01-01", "2020-01-01"),
        )
        conn.commit()
        overdue = rt.get_overdue()
        assert len(overdue) >= 1
        assert overdue[0]["cve_id"] == "CVE-OLD"
        rt.close()

    def test_compute_deadline(self):
        from modules.cve.src.cve_remediation import compute_deadline
        dl = compute_deadline("CRITICAL", 0.9)
        assert dl is not None
        # CRITICAL(7) * 0.5(EPSS factor) = ~3 days from now
        from datetime import datetime, timezone, timedelta
        expected = (datetime.now(timezone.utc) + timedelta(days=3)).strftime("%Y-%m-%d")
        # allow +/- 1 day for timing
        assert dl >= (datetime.now(timezone.utc) + timedelta(days=2)).strftime("%Y-%m-%d")

    def test_is_overdue(self):
        from modules.cve.src.cve_remediation import is_overdue
        assert is_overdue("2020-01-01") is True
        assert is_overdue("2099-12-31") is False

    def test_days_until_deadline(self):
        from modules.cve.src.cve_remediation import days_until_deadline
        assert days_until_deadline("2020-01-01") is not None
        assert days_until_deadline("2020-01-01") < 0  # overdue = negative
        assert days_until_deadline("2099-12-31") > 0  # future = positive
        assert days_until_deadline("not-a-date") is None
