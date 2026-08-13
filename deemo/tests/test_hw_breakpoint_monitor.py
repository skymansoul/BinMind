#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# x86 debug registers, used to write kernel modules with these often
import os
import pytest


from modules.hw_breakpoint_monitor import (
    Breakpoint,
    BreakpointManager,
    CallStackTracker,
    HWBreakpointMonitor,
    ModificationEvent,
    MonitorResult,
    create_hw_breakpoint_monitor,
)


class TestBreakpointDataclass:
    """Breakpoint -- address + size + access_type"""

    def test_breakpoint_creation(self):
        bp = Breakpoint(address=0x1000, size=4, access_type="write")
        if bp is None:
            raise AssertionError("Breakpoint is None")
        assert bp.address == 0x1000
        assert bp.size == 4
        assert bp.access_type == "write"

    def test_read_breakpoint(self):
        bp = Breakpoint(address=0x2000, size=8, access_type="read")
        assert bp.access_type == "read"

    def test_exec_breakpoint(self):
        """Exec breakpoint -- size is usually 1"""
        bp = Breakpoint(address=0x3000, size=1, access_type="exec")
        assert bp.access_type == "exec"


class TestModificationEvent:
    """ModificationEvent -- records old/new value changes"""

    def test_event_creation(self):
        event = ModificationEvent(
            address=0x1000,
            old_value=b"\x00" * 4,
            new_value=b"\xff" * 4,
            timestamp=1234567890,
            call_stack=[0x4000, 0x5000],
        )
        assert event.address == 0x1000
        assert event.old_value == b"\x00\x00\x00\x00"
        assert event.new_value == b"\xff\xff\xff\xff"
        assert event.timestamp == 1234567890
        assert len(event.call_stack) == 2


class TestMonitorResult:
    """MonitorResult -- success and failure cases"""

    def test_success_result(self):
        bp = Breakpoint(address=0x1000, size=4, access_type="write")
        result = MonitorResult(success=True, events=[], breakpoints=[bp])
        assert result.success is True
        assert len(result.events) == 0
        assert len(result.breakpoints) == 1

    def test_failure_result(self):
        result = MonitorResult(success=False, events=[], breakpoints=[])
        assert result.success is False


class TestBreakpointManager:
    """Breakpoint manager -- max 4 hardware breakpoints"""

    def test_manager_init(self):
        mgr = BreakpointManager()
        assert mgr.max_breakpoints == 4
        assert mgr.breakpoints == []

    def test_add_breakpoint(self):
        mgr = BreakpointManager()
        bp = Breakpoint(address=0x1000, size=4, access_type="write")
        assert mgr.add_breakpoint(bp) is True
        assert len(mgr.breakpoints) == 1

    def test_max_breakpoints(self):
        """5th breakpoint should fail to add"""
        mgr = BreakpointManager()
        for j in range(4):
            assert (
                mgr.add_breakpoint(
                    Breakpoint(
                        address=0x1000 + j * 0x100, size=4, access_type="write"
                    )
                )
                is True
            )
        assert (
            mgr.add_breakpoint(
                Breakpoint(address=0x5000, size=4, access_type="write")
            )
            is False
        )


class TestHWBreakpointMonitor:
    """HW breakpoint monitor -- DR7 calculation + size-to-length encoding"""

    def test_initialization(self):
        monitor = HWBreakpointMonitor()
        assert monitor is not None
        assert monitor.manager is not None
        assert monitor.tracker is not None

    def test_dr7_constants(self):
        """DR7 bit definitions -- local enable, rw bits"""
        assert HWBreakpointMonitor.DR7_ENABLE_LOCAL[0] == (1 << 0)
        assert HWBreakpointMonitor.DR7_ENABLE_LOCAL[1] == (1 << 2)
        assert HWBreakpointMonitor.DR7_RW_WRITE == 0x1
        assert HWBreakpointMonitor.DR7_RW_READWRITE == 0x3

    def test_size_to_dr7_len(self):
        """1/2/4/8 bytes -> DR7 len encoding"""
        monitor = HWBreakpointMonitor()
        assert monitor._size_to_dr7_len(1) == HWBreakpointMonitor.DR7_LEN_1
        assert monitor._size_to_dr7_len(2) == HWBreakpointMonitor.DR7_LEN_2
        assert monitor._size_to_dr7_len(4) == HWBreakpointMonitor.DR7_LEN_4
        assert monitor._size_to_dr7_len(8) == HWBreakpointMonitor.DR7_LEN_8

    def test_compute_dr7(self):
        monitor = HWBreakpointMonitor()
        dr7 = monitor._compute_dr7(
            0, HWBreakpointMonitor.DR7_RW_WRITE, HWBreakpointMonitor.DR7_LEN_4
        )
        assert dr7 != 0  # enable bit must be set

    def test_create_hw_breakpoint_monitor(self):
        """factory function"""
        monitor = create_hw_breakpoint_monitor()
        assert isinstance(monitor, HWBreakpointMonitor)


class TestCallStackTracker:
    """Call stack tracker -- returns default stack when no binary"""

    def test_tracker_init(self):
        tracker = CallStackTracker()
        assert tracker.binary_path == ""

    def test_capture_no_binary(self):
        tracker = CallStackTracker()
        stack = tracker.capture()
        assert len(stack) > 0

    def test_capture_with_addr(self):
        tracker = CallStackTracker()
        stack = tracker.capture(at_addr=0x1000)
        assert stack[0] == 0x1000


class TestLegacyAPI:
    """Legacy API tests (removed features) -- all skipped"""

    def test_analyze(self):
        pytest.skip(
            "analyze_hw_breakpoint removed -- use HWBreakpointMonitor.monitor_address()"
        )

    def test_analyze_with_breakpoints(self):
        pytest.skip("analyze_hw_breakpoint with breakpoints config removed")

    def test_add_remove_breakpoint(self):
        pytest.skip(
            "add_breakpoint/remove_breakpoint on monitor removed -- use BreakpointManager"
        )

    def test_start_stop_monitoring(self):
        pytest.skip("start_monitoring/stop_monitoring removed")

    def test_breakpoint_types(self):
        pytest.skip(
            "BreakpointType enum removed -- access_type is now a plain string"
        )

    def test_breakpoint_sizes(self):
        pytest.skip("BreakpointSize enum removed -- size is now a plain int")

    def test_trigger_actions(self):
        pytest.skip("TriggerAction enum removed")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
