#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# x86 debug registers, used to write kernel modules with these often

from modules.hw_breakpoint_monitor import (
    DR7_GE,
    DR7_LE,
    Breakpoint,
    BreakpointCondition,
    BreakpointLength,
    BreakpointManager,
    CallStackTracker,
    DR6Status,
    HardwareBreakpoint,
    HWBreakpointMonitor,
    ModificationEvent,
    MonitorResult,
    ThreadContext,
    create_hw_breakpoint_monitor,
)

class TestBreakpointDataclass:
    """Breakpoint -- address + size + access_type"""

    def test_breakpoint_creation(self):
        bp = Breakpoint(address=0x1000, size=4, access_type="write")
        assert (bp.address, bp.size, bp.access_type) == (0x1000, 4, "write")

    def test_read_breakpoint(self):
        bp = Breakpoint(address=0x2000, size=8, access_type="read")
        assert bp.access_type == "read"

    def test_exec_breakpoint(self):
        bp = Breakpoint(address=0x3000, size=1, access_type="exec")
        assert bp.access_type == "exec"

class TestModificationEvent:
    """ModificationEvent -- records old/new value changes"""

    def test_event_creation(self):
        event = ModificationEvent(
            address=0x1000, old_value=b"\x00" * 4, new_value=b"\xff" * 4,
            timestamp=1234567890, call_stack=[0x4000, 0x5000])
        assert (event.address, event.old_value, event.new_value,
                event.timestamp, len(event.call_stack)) == (
                0x1000, b"\x00\x00\x00\x00", b"\xff\xff\xff\xff",
                1234567890, 2)

class TestMonitorResult:
    """MonitorResult -- success and failure cases"""

    def test_success_result(self):
        bp = Breakpoint(address=0x1000, size=4, access_type="write")
        result = MonitorResult(success=True, events=[], breakpoints=[bp])
        assert (result.success, len(result.events),
                len(result.breakpoints)) == (True, 0, 1)

    def test_failure_result(self):
        result = MonitorResult(success=False, events=[], breakpoints=[])
        assert result.success is False

class TestBreakpointManager:
    """Breakpoint manager -- max 4 hardware breakpoints"""

    def test_manager_add(self):
        mgr = BreakpointManager()
        assert (mgr.max_breakpoints, mgr.breakpoints) == (4, [])
        assert mgr.add_breakpoint(
            Breakpoint(address=0x1000, size=4, access_type="write")) is True
        assert len(mgr.breakpoints) == 1

    def test_max_breakpoints(self):
        """5th breakpoint should fail to add"""
        mgr = BreakpointManager()
        for j in range(4):
            assert mgr.add_breakpoint(
                Breakpoint(address=0x1000 + j * 0x100, size=4,
                           access_type="write")) is True
        assert mgr.add_breakpoint(
            Breakpoint(address=0x5000, size=4, access_type="write")) is False

class TestHWBreakpointMonitor:
    """HW breakpoint monitor -- DR7 calculation + size-to-length encoding"""

    def test_initialization(self):
        monitor = HWBreakpointMonitor()
        assert monitor.manager is not None and monitor.tracker is not None

    def test_dr7_constants(self):
        assert HWBreakpointMonitor.DR7_ENABLE_LOCAL[0] == (1 << 0)
        assert HWBreakpointMonitor.DR7_ENABLE_LOCAL[1] == (1 << 2)
        assert HWBreakpointMonitor.DR7_RW_WRITE == 0x1
        assert HWBreakpointMonitor.DR7_RW_READWRITE == 0x3

    def test_size_to_dr7_len(self):
        monitor = HWBreakpointMonitor()
        assert monitor._size_to_dr7_len(1) == HWBreakpointMonitor.DR7_LEN_1
        assert monitor._size_to_dr7_len(2) == HWBreakpointMonitor.DR7_LEN_2
        assert monitor._size_to_dr7_len(4) == HWBreakpointMonitor.DR7_LEN_4
        assert monitor._size_to_dr7_len(8) == HWBreakpointMonitor.DR7_LEN_8

    def test_compute_dr7(self):
        monitor = HWBreakpointMonitor()
        dr7 = monitor._compute_dr7(
            0, HWBreakpointMonitor.DR7_RW_WRITE, HWBreakpointMonitor.DR7_LEN_4)
        assert dr7 != 0  # enable bit must be set

    def test_create_hw_breakpoint_monitor(self):
        assert isinstance(create_hw_breakpoint_monitor(), HWBreakpointMonitor)

class TestCallStackTracker:
    """Call stack tracker -- returns default stack when no binary"""

    def test_capture(self):
        tracker = CallStackTracker()
        assert tracker.binary_path == ""
        assert tracker.capture() == [0x1000, 0x2000]
        assert tracker.capture(at_addr=0x1000)[0] == 0x1000

class TestBreakpointEnums:

    def test_condition_values(self):
        assert [c.value for c in BreakpointCondition] == [0, 1, 2, 3]

    def test_length_values(self):
        assert [c.value for c in BreakpointLength] == [0, 1, 2, 3]

    def test_from_byte_count(self):
        assert BreakpointLength.from_byte_count(1) is BreakpointLength.BYTE_1
        assert BreakpointLength.from_byte_count(2) is BreakpointLength.BYTE_2
        assert BreakpointLength.from_byte_count(4) is BreakpointLength.BYTE_4
        assert BreakpointLength.from_byte_count(8) is BreakpointLength.BYTE_8

class TestHardwareBreakpoint:
    """HardwareBreakpoint -- 槽位断点描述符及序列化"""

    def test_creation_defaults(self):
        bp = HardwareBreakpoint(
            slot=0, address=0x1000,
            condition=BreakpointCondition.WRITE,
            length=BreakpointLength.BYTE_4)
        assert (bp.slot, bp.address, bp.enabled,
                bp.global_scope, bp.label) == (0, 0x1000, True, False, "")

    def test_to_dict(self):
        bp = HardwareBreakpoint(
            slot=2, address=0x4000,
            condition=BreakpointCondition.READ_WRITE,
            length=BreakpointLength.BYTE_8,
            enabled=True, global_scope=True, label="buf")
        d = bp.to_dict()
        assert (d["slot"], d["address"], d["condition"], d["length"],
                d["enabled"], d["global_scope"], d["label"]) == (
                2, "0x4000", "READ_WRITE", "BYTE_8", True, True, "buf")

class TestThreadContext:
    """ThreadContext -- 线程寄存器快照"""

    def test_creation(self):
        ctx = ThreadContext(thread_id=42)
        assert (ctx.thread_id, ctx.dr0, ctx.dr6, ctx.dr7, ctx.eflags,
                ctx.rip, ctx.accessible) == (42, 0, 0, 0, 0, 0, False)

class TestMonitorBreakpointAPI:
    """HWBreakpointMonitor -- 断点槽位增删与冲突覆盖"""

    def test_add_and_list(self):
        monitor = HWBreakpointMonitor()
        bp = monitor.add_breakpoint(
            0x1000, BreakpointCondition.WRITE, BreakpointLength.BYTE_4)
        assert bp is not None and isinstance(bp, HardwareBreakpoint)
        assert len(monitor.list_breakpoints()) == 1

    def test_remove_breakpoint(self):
        monitor = HWBreakpointMonitor()
        monitor.add_breakpoint(
            0x1000, BreakpointCondition.WRITE, BreakpointLength.BYTE_4)
        assert monitor.remove_breakpoint(0) is True
        assert monitor.remove_breakpoint(0) is False
        assert monitor.list_breakpoints() == []

    def test_full_slots_reject_new(self):
        monitor = HWBreakpointMonitor()
        for addr in (0x1000, 0x1100, 0x1200, 0x1300):
            assert monitor.add_breakpoint(
                addr, BreakpointCondition.WRITE,
                BreakpointLength.BYTE_4) is not None
        assert monitor.add_breakpoint(
            0x9000, BreakpointCondition.WRITE,
            BreakpointLength.BYTE_4) is None

    def test_invalid_slot_rejected(self):
        monitor = HWBreakpointMonitor()
        assert monitor.add_breakpoint(
            0x1000, BreakpointCondition.WRITE, BreakpointLength.BYTE_4,
            slot=5) is None

    def test_slot_conflict_overwrites(self):
        monitor = HWBreakpointMonitor()
        assert monitor.add_breakpoint(
            0x1000, BreakpointCondition.WRITE, BreakpointLength.BYTE_4,
            slot=0) is not None
        second = monitor.add_breakpoint(
            0x2000, BreakpointCondition.READ_WRITE, BreakpointLength.BYTE_8,
            slot=0)
        assert second is not None and second.slot == 0
        assert [bp.address for bp in monitor.list_breakpoints()] == [0x2000]

    def test_global_scope_and_label(self):
        monitor = HWBreakpointMonitor()
        bp = monitor.add_breakpoint(
            0x1000, BreakpointCondition.WRITE, BreakpointLength.BYTE_4,
            global_scope=True, label="watch_buf")
        assert bp.global_scope is True and bp.label == "watch_buf"

class TestDR7Computation:
    """DR7 计算 -- 位编码一致性"""

    def test_compute_dr7_contains_enable(self):
        dr7 = HWBreakpointMonitor()._compute_dr7(
            0, HWBreakpointMonitor.DR7_RW_WRITE, HWBreakpointMonitor.DR7_LEN_4)
        assert dr7 & (1 << 0) and dr7 & (HWBreakpointMonitor.DR7_RW_WRITE << 16)

    def test_compute_dr7_for_slot(self):
        monitor = HWBreakpointMonitor()
        monitor.add_breakpoint(
            0x1000, BreakpointCondition.WRITE, BreakpointLength.BYTE_4, slot=0)
        assert monitor._compute_dr7_for_slot(0) != 0
        assert monitor._compute_dr7_for_slot(1) == 0

    def test_compute_dr7_consistency(self):
        monitor = HWBreakpointMonitor()
        monitor.add_breakpoint(
            0x1000, BreakpointCondition.WRITE, BreakpointLength.BYTE_4, slot=1)
        assert monitor.compute_dr7() == (
            DR7_LE | DR7_GE
            | monitor._compute_dr7_for_slot(1))

    def test_compute_dr7_mask_includes_le_ge(self):
        monitor = HWBreakpointMonitor()
        monitor.add_breakpoint(
            0x1000, BreakpointCondition.WRITE, BreakpointLength.BYTE_4, slot=0)
        mask = monitor.compute_dr7_mask()
        assert mask & DR7_LE
        assert mask & DR7_GE
        assert mask & (0x3 << 16) and mask & (0x3 << 18)

class TestDR6Decoding:
    """DR6 解码与清除"""

    def test_status_to_dict(self):
        status = DR6Status(raw_value=0x4000, breakpoint_hit=False, bs_flag=True)
        d = status.to_dict()
        assert (d["raw"], d["bs_flag"], d["breakpoint_hit"]) == (
            "0x4000", True, False)

    def test_decode_slot_hit(self):
        status = HWBreakpointMonitor().decode_dr6(1 << 0)
        assert (status.breakpoint_hit, status.triggered_slot,
                status.multiple_hits) == (True, 0, False)

    def test_decode_bs_flag(self):
        status = HWBreakpointMonitor().decode_dr6(0x4000)
        assert status.bs_flag is True and status.breakpoint_hit is False

    def test_decode_no_hit(self):
        status = HWBreakpointMonitor().decode_dr6(0)
        assert (status.breakpoint_hit, status.triggered_slot) == (False, None)

    def test_clear_dr6_active_slots(self):
        monitor = HWBreakpointMonitor()
        monitor.add_breakpoint(
            0x1000, BreakpointCondition.WRITE, BreakpointLength.BYTE_4, slot=2)
        assert monitor.clear_dr6() == (1 << 2)

class TestMonitorSummary:
    """状态汇总与命中日志"""

    def test_status_summary_keys(self):
        monitor = HWBreakpointMonitor()
        monitor.add_breakpoint(
            0x1000, BreakpointCondition.WRITE, BreakpointLength.BYTE_4)
        summary = monitor.get_status_summary()
        for key in ("target_pid", "active_breakpoints", "active_slots_bitmap",
                    "dr7_computed", "monitored_threads", "total_hits",
                    "breakpoints"):
            assert key in summary
        assert (summary["active_breakpoints"],
                len(summary["breakpoints"])) == (1, 1)

    def test_hit_log(self):
        monitor = HWBreakpointMonitor()
        monitor.log_breakpoint_hit(1, monitor.decode_dr6(1 << 1))
        assert len(monitor.get_hit_log()) == 1
        monitor.clear_hit_log()
        assert monitor.get_hit_log() == []

if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])