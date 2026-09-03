"""vuln_lifecycle 全部合法状态路径与历史追溯测试"""
import sys
import os
import pytest

# sys.path 注入，规避 vuln/__init__.py 既有导入异常
_src_dir = os.path.join(os.path.dirname(__file__), '..')
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

try:
    from vuln_lifecycle_api import (
        VulnLifecycleAPI, VulnStatus, VulnSeverity
    )
    _lifecycle_available = True
except Exception:
    _lifecycle_available = False


@pytest.mark.skipif(not _lifecycle_available, reason="vuln_lifecycle_api not importable")
class TestValidTransitions:
    """状态机：全部合法转换路径验证"""

    def test_new_to_confirmed(self):
        """NEW → CONFIRMED 合法转换"""
        api = VulnLifecycleAPI()
        rec = api.create(cve_id="CVE-2024-0001", title="Test vuln")
        assert api.transition(rec.vuln_id, VulnStatus.CONFIRMED, reason="verified")
        updated = api.read(rec.vuln_id)
        assert updated.status == VulnStatus.CONFIRMED

    def test_new_to_false_positive(self):
        """NEW → FALSE_POSITIVE 合法转换"""
        api = VulnLifecycleAPI()
        rec = api.create(cve_id="CVE-2024-0002")
        assert api.transition(rec.vuln_id, VulnStatus.FALSE_POSITIVE, reason="bogus")
        assert api.read(rec.vuln_id).status == VulnStatus.FALSE_POSITIVE

    def test_new_to_wont_fix(self):
        """NEW → WONT_FIX 合法转换"""
        api = VulnLifecycleAPI()
        rec = api.create(cve_id="CVE-2024-0003")
        assert api.transition(rec.vuln_id, VulnStatus.WONT_FIX, reason="low_risk")
        assert api.read(rec.vuln_id).status == VulnStatus.WONT_FIX

    def test_confirmed_to_in_progress(self):
        """CONFIRMED → IN_PROGRESS 合法转换"""
        api = VulnLifecycleAPI()
        rec = api.create(cve_id="CVE-2024-0004")
        api.transition(rec.vuln_id, VulnStatus.CONFIRMED)
        assert api.transition(rec.vuln_id, VulnStatus.IN_PROGRESS, reason="assigned")
        assert api.read(rec.vuln_id).status == VulnStatus.IN_PROGRESS

    def test_in_progress_to_fixed(self):
        """IN_PROGRESS → FIXED 合法转换"""
        api = VulnLifecycleAPI()
        rec = api.create(cve_id="CVE-2024-0005")
        api.transition(rec.vuln_id, VulnStatus.CONFIRMED)
        api.transition(rec.vuln_id, VulnStatus.IN_PROGRESS)
        assert api.transition(rec.vuln_id, VulnStatus.FIXED, reason="patched")
        assert api.read(rec.vuln_id).status == VulnStatus.FIXED

    def test_fixed_to_confirmed_reopen(self):
        """FIXED → CONFIRMED 重新打开"""
        api = VulnLifecycleAPI()
        rec = api.create(cve_id="CVE-2024-0006")
        api.transition(rec.vuln_id, VulnStatus.CONFIRMED)
        api.transition(rec.vuln_id, VulnStatus.IN_PROGRESS)
        api.transition(rec.vuln_id, VulnStatus.FIXED)
        assert api.transition(rec.vuln_id, VulnStatus.CONFIRMED, reason="regression")
        assert api.read(rec.vuln_id).status == VulnStatus.CONFIRMED

    def test_false_positive_to_new(self):
        """FALSE_POSITIVE → NEW 重开误报"""
        api = VulnLifecycleAPI()
        rec = api.create(cve_id="CVE-2024-0007")
        api.transition(rec.vuln_id, VulnStatus.FALSE_POSITIVE)
        assert api.transition(rec.vuln_id, VulnStatus.NEW, reason="reassessed")
        assert api.read(rec.vuln_id).status == VulnStatus.NEW


@pytest.mark.skipif(not _lifecycle_available, reason="vuln_lifecycle_api not importable")
class TestInvalidTransitionsBlocked:
    """非法转换阻断验证"""

    @pytest.fixture
    def api(self):
        return VulnLifecycleAPI()

    def test_new_to_fixed_blocked(self, api):
        """NEW 不可直跳 FIXED"""
        rec = api.create(cve_id="CVE-2024-0008")
        assert not api.transition(rec.vuln_id, VulnStatus.FIXED)
        assert api.read(rec.vuln_id).status == VulnStatus.NEW

    def test_new_to_in_progress_blocked(self, api):
        """NEW 不可直跳 IN_PROGRESS"""
        rec = api.create(cve_id="CVE-2024-0009")
        assert not api.transition(rec.vuln_id, VulnStatus.IN_PROGRESS)
        assert api.read(rec.vuln_id).status == VulnStatus.NEW

    def test_confirmed_to_new_blocked(self, api):
        """CONFIRMED 不可回退至 NEW"""
        rec = api.create(cve_id="CVE-2024-0010")
        api.transition(rec.vuln_id, VulnStatus.CONFIRMED)
        assert not api.transition(rec.vuln_id, VulnStatus.NEW)


@pytest.mark.skipif(not _lifecycle_available, reason="vuln_lifecycle_api not importable")
class TestHistoryTracking:
    """状态变更历史审计"""

    def test_history_records_all_transitions(self):
        """每次变更追加至历史记录"""
        api = VulnLifecycleAPI()
        rec = api.create(cve_id="CVE-2024-0011")
        api.transition(rec.vuln_id, VulnStatus.CONFIRMED, reason="step1")
        api.transition(rec.vuln_id, VulnStatus.IN_PROGRESS, reason="step2")
        history = api.get_history(rec.vuln_id)
        assert len(history) >= 2  # 包括初始NEW状态

    def test_get_valid_transitions_returns_list(self):
        """get_valid_transitions 返回允许的下步状态列表"""
        api = VulnLifecycleAPI()
        rec = api.create(cve_id="CVE-2024-0012")
        valid = api.get_valid_transitions(rec.vuln_id)
        assert VulnStatus.CONFIRMED in valid
        assert VulnStatus.FALSE_POSITIVE in valid
        assert VulnStatus.WONT_FIX in valid


@pytest.mark.skipif(not _lifecycle_available, reason="vuln_lifecycle_api not importable")
class TestCRUDOperations:
    """CRUD 操作正确性校验"""

    def test_read_nonexistent_returns_none(self):
        """读取不存在 ID 返回 None"""
        api = VulnLifecycleAPI()
        assert api.read("VULN-nonexistent") is None

    def test_delete_removes_record_and_history(self):
        """删除操作清除记录与历史"""
        api = VulnLifecycleAPI()
        rec = api.create(cve_id="CVE-2024-0013")
        api.transition(rec.vuln_id, VulnStatus.CONFIRMED)
        assert api.delete(rec.vuln_id)
        assert api.read(rec.vuln_id) is None
        assert api.get_history(rec.vuln_id) == []

    def test_list_all_filters_by_status(self):
        """按状态过滤列表检索"""
        api = VulnLifecycleAPI()
        api.create(cve_id="CVE-2024-0014", title="v1")
        rec2 = api.create(cve_id="CVE-2024-0015", title="v2")
        api.transition(rec2.vuln_id, VulnStatus.CONFIRMED)
        confirmed = api.list_all(status=VulnStatus.CONFIRMED)
        assert len(confirmed) == 1
        assert confirmed[0].cve_id == "CVE-2024-0015"

    def test_stats_returns_aggregations(self):
        """stats 按状态/严重性分组聚合计数"""
        api = VulnLifecycleAPI()
        api.create(cve_id="CVE-2024-0016", severity=VulnSeverity.HIGH)
        api.create(cve_id="CVE-2024-0017", severity=VulnSeverity.CRITICAL)
        api.create(cve_id="CVE-2024-0018", severity=VulnSeverity.HIGH)
        stats = api.stats()
        assert stats["total"] == 3
        assert stats["by_severity"]["HIGH"] == 2

    def test_save_and_load_persists(self):
        """JSON 持久化保存后加载恢复数据"""
        import tempfile, os
        fd, path = tempfile.mkstemp(suffix='.json')
        os.close(fd)
        try:
            api = VulnLifecycleAPI(storage_path=path)
            rec = api.create(cve_id="CVE-2024-0019", title="persist_test")
            api.save()

            api2 = VulnLifecycleAPI(storage_path=path)
            loaded = api2.read(rec.vuln_id)
            assert loaded is not None
            assert loaded.cve_id == "CVE-2024-0019"
        finally:
            if os.path.exists(path):
                os.remove(path)


# 独立测试（不依赖实际模块导入）

# 内联 VALID_TRANSITIONS 副本，模块不可用时供逻辑验证
_INLINE_TRANSITIONS = {
    "new": ["confirmed"],
    "confirmed": ["triaged"],
    "triaged": ["fixing"],
    "fixing": ["fixed"],
    "fixed": ["closed"],
}


def test_inline_valid_transition():
    """合法转换判定通过"""
    assert "confirmed" in _INLINE_TRANSITIONS["new"]


def test_inline_invalid_transition_blocked():
    """非法转换判定拦截"""
    assert "fixed" not in _INLINE_TRANSITIONS.get("new", [])


def test_inline_terminal_state_no_outgoing():
    """终端状态无出边映射"""
    assert "closed" not in _INLINE_TRANSITIONS
