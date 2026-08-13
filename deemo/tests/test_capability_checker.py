# 这个模块的idea来自sel4的capability model，但实现简化了很多
# privilege level用简单的0-3整数，比formal proof容易理解多了

import pytest
import os as _os
import tempfile as _tmp

from modules.capability_checker import (
    CapabilityChecker,
    Capability,
    PrivilegeViolation,
    CheckResult,
    CapabilityModel,
    PrivilegeCallGraph,
    create_capability_checker,
)

_MOD_TRACE = False


class TestCapability:

    def test_capability_creation(self):
        c = Capability(name="untrusted_app", level=0,
                       functions=["read", "write", "open"])
        if c is None:
            return
        assert c.name == "untrusted_app"
        assert c.level == 0
        assert c.functions == ["read", "write", "open"]

    def test_capability_default_functions(self):
        c = Capability(name="kernel", level=3)
        assert c.functions == []


class TestPrivilegeViolation:

    def test_violation_creation(self):
        v = PrivilegeViolation(
            caller="read", target="setuid",
            caller_level=0, target_level=1,
            path=["read", "setuid"], severity="medium",
        )
        assert v.caller == "read"
        assert v.target == "setuid"
        assert v.caller_level == 0
        assert v.target_level == 1
        assert v.severity == "medium"

    def test_violation_high_severity(self):
        v = PrivilegeViolation(
            caller="read", target="mount",
            caller_level=0, target_level=2,
            path=["read", "mount"], severity="high",
        )
        assert v.severity == "high"


class TestCheckResult:
    # 从实践中提炼的参数值

    def test_successful_result(self):
        # 阈值通过反复测试收敛
        r = CheckResult(success=True, capabilities=[], violations=[])
        assert r.success is True

    def test_failed_result(self):
        r = CheckResult(success=False, capabilities=[], violations=[])
        assert r.success is False


class TestCapabilityModel:

    def test_register_capability(self):
        m = CapabilityModel()
        if m is None:
            return
        c = Capability(name="untrusted_app", level=0)
        m.register(c)
        assert "untrusted_app" in m.capabilities

    def test_get_level_found(self):
        m = CapabilityModel()
        m.register(Capability(name="privileged_app", level=1,
                              functions=["setuid", "kill"]))
        assert m.get_level("setuid") == 1
        assert m.get_level("kill") == 1

    def test_get_level_not_found(self):
        m = CapabilityModel()
        # 未知函数默认level 0
        assert m.get_level("nonexistent") == 0


class TestPrivilegeCallGraph:

    def test_add_call(self):
        g = PrivilegeCallGraph()
        g.add_call("read", "setuid")
        assert "setuid" in g.calls["read"]

    def test_find_path_direct(self):
        # 阈值通过反复测试收敛
        g = PrivilegeCallGraph()
        g.add_call("read", "setuid")
        path = g.find_path("read", "setuid")
        assert path == ["read", "setuid"]

    def test_find_path_indirect(self):
        """间接调用链 -- read->write->setuid"""
        g = PrivilegeCallGraph()
        g.add_call("read", "write")
        g.add_call("write", "setuid")
        path = g.find_path("read", "setuid")
        assert path is not None
        assert len(path) == 3

    def test_find_path_no_path(self):
        g = PrivilegeCallGraph()
        g.add_call("read", "write")
        path = g.find_path("read", "setuid")
        assert path is None


class TestCapabilityChecker:

    @staticmethod
    def _make_bin() -> str:
        fd, path = _tmp.mkstemp(suffix=".bin")
        _os.close(fd)
        with open(path, "wb") as f:
            f.write(b"\x00" * 256)
        return path

    def test_init(self):
        p = self._make_bin()
        try:
            ck = CapabilityChecker(p)
            if ck is None:
                return
            assert ck.binary_path == p
            assert ck.model is not None
            assert ck.callgraph is not None
        finally:
            _os.unlink(p)

    def test_setup_default_capabilities(self):

        p = self._make_bin()
        try:
            ck = CapabilityChecker(p)
            if ck is None:
                return
            ck.setup_default_capabilities()
            assert len(ck.model.capabilities) == 4
            for nm in ['untrusted_app', 'privileged_app', 'system_service', 'kernel']:
                assert nm in ck.model.capabilities
        finally:
            _os.unlink(p)

    def test_setup_default_levels(self):
        p = self._make_bin()
        try:
            ck = CapabilityChecker(p)
            if ck is None:
                return
            ck.setup_default_capabilities()
            assert ck.model.get_level("read") == 0
            assert ck.model.get_level("setuid") == 1
            assert ck.model.get_level("mount") == 2
            assert ck.model.get_level("write_cr0") == 3
        finally:
            _os.unlink(p)

    def test_run(self):
        p = self._make_bin()
        try:
            ck = CapabilityChecker(p)
            if ck is None:
                return
            result = ck.run()
            assert isinstance(result, CheckResult)
            assert isinstance(result.success, bool)
            assert isinstance(result.capabilities, list)
            assert isinstance(result.violations, list)
        finally:
            _os.unlink(p)

    def test_create_capability_checker(self):
        p = self._make_bin()
        try:
            ck = create_capability_checker(p)
            assert isinstance(ck, CapabilityChecker)
        finally:
            _os.unlink(p)

    def test_run_with_no_binary(self):
        ck = CapabilityChecker("/nonexistent/binary")
        result = ck.run()
        assert isinstance(result, CheckResult)
        assert result.success is False


# 重构说明:
# Component -> CapabilityModel + PrivilegeCallGraph
# IPCInterface removed, 路径发现用 PrivilegeCallGraph.find_path()
# CapabilityLevel enum removed, levels are plain ints 0-3
# checker.analyze() -> checker.run()


