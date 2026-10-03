"""
污点精简 / gadget分类 / 崩溃距离估计 单元测试。
"""
from __future__ import annotations

import pytest


class TestTaintDebloat:
    """约束精简测试。"""

    def test_debloat_ratio_full(self):
        from core.taint_debloat import estimate_debloat_ratio
        r = estimate_debloat_ratio(100, 10)
        assert r == 0.9  # 90% 的字节不需要符号化

    def test_debloat_ratio_none(self):
        from core.taint_debloat import estimate_debloat_ratio
        assert estimate_debloat_ratio(100, 0) == 0.0
        assert estimate_debloat_ratio(0, 5) == 0.0

    def test_debloat_ratio_all_tainted(self):
        from core.taint_debloat import estimate_debloat_ratio
        r = estimate_debloat_ratio(50, 50)
        assert r == 0.0

    def test_build_debloated_input(self):
        from core.taint_debloat import build_debloated_input
        sym, conc = build_debloated_input(
            b"A" * 20, {2, 5, 8, 15},
        )
        assert sym == [2, 5, 8, 15]
        assert len(conc) == 16  # 20 - 4


class TestGadgetClassifier:
    """gadget 语义分类测试。"""

    def test_pop_rdi(self):
        from core.gadget_classifier import classify_gadget, SemType
        sem = classify_gadget("pop rdi; ret")
        assert sem.stype == SemType.LoadConst
        assert "rdi" in sem.operands
        assert "stack" in sem.operands

    def test_xor_zeroing(self):
        from core.gadget_classifier import classify_gadget, SemType
        sem = classify_gadget("xor eax, eax; ret")
        assert sem.stype == SemType.LoadConst
        assert "rax" in sem.operands  # 规范化

    def test_mov_reg(self):
        from core.gadget_classifier import classify_gadget, SemType
        sem = classify_gadget("mov rdi, rax; ret")
        assert sem.stype == SemType.MoveReg
        assert "rdi" in sem.operands

    def test_syscall(self):
        from core.gadget_classifier import classify_gadget, SemType
        sem = classify_gadget("pop rax; syscall")
        assert sem.stype == SemType.Syscall

    def test_load_mem(self):
        from core.gadget_classifier import classify_gadget, SemType
        sem = classify_gadget("mov rax, [rdi]; ret")
        assert sem.stype == SemType.LoadMem

    def test_unknown(self):
        from core.gadget_classifier import classify_gadget, SemType
        sem = classify_gadget("")
        assert sem.stype == SemType.Unknown

    def test_canonical_reg(self):
        from core.gadget_classifier import _canon_reg
        assert _canon_reg("eax") == "rax"
        assert _canon_reg("edi") == "rdi"
        assert _canon_reg("rax") == "rax"

    def test_classify_batch(self):
        from core.gadget_classifier import classify_gadget_batch
        gadgets = [
            {"raw_line": "pop rdi; ret", "description": "pop rdi"},
            {"raw_line": "pop rsi; pop r15; ret", "description": "pop rsi"},
        ]
        result = classify_gadget_batch(gadgets)
        assert len(result) == 2
        for g in result:
            assert "semantic" in g
            assert "semantic_template" in g


class TestCrashExploitDistance:
    """崩溃距离估计测试。"""

    def test_full_control(self):
        from core.crash_exploit_distance import estimate_crash_to_exploit
        crash = {
            "registers": {"rip": "0x4141414141414141",
                          "rsp": "0x41414141", "rbp": "0x41414141"},
            "crash_type": "SIGSEGV",
        }
        d = estimate_crash_to_exploit(crash)
        # rip/rsp/rbp 全部可控 → 距离极小
        assert d["register_control"] < 0.4
        assert d["exploitability_rating"] in ("high", "medium")

    def test_null_deref(self):
        from core.crash_exploit_distance import estimate_crash_to_exploit
        crash = {
            "registers": {"rip": "0x0", "rsp": "0x0"},
            "crash_type": "SIGSEGV",
        }
        d = estimate_crash_to_exploit(crash)
        assert d["register_control"] >= 0.8

    def test_bypass_all_defenses(self):
        from core.crash_exploit_distance import estimate_crash_to_exploit
        crash = {"registers": {"rip": "0x41414141"}, "crash_type": "stack"}
        checksec = {"nx": True, "pie": True, "canary": True,
                    "relro": "full", "aslr": True}
        d = estimate_crash_to_exploit(crash, checksec=checksec)
        assert d["bypass_distance"] > 0.5  # 多层防护

    def test_bypass_none(self):
        from core.crash_exploit_distance import estimate_crash_to_exploit
        crash = {"registers": {"rip": "0x41414141"}, "crash_type": "stack"}
        checksec = {"nx": False, "pie": False, "canary": False,
                    "relro": "none", "aslr": False}
        d = estimate_crash_to_exploit(crash, checksec=checksec)
        assert d["bypass_distance"] < 0.3

    def test_trace_jaccard(self):
        from core.crash_exploit_distance import _trace_distance
        assert _trace_distance({1, 2, 3}, {1, 2, 3}) == 0.0
        assert _trace_distance({1, 2}, {3, 4}) == 1.0
        d = _trace_distance({1, 2, 3}, {1, 2, 4, 5})
        assert 0.3 < d < 0.8  # partial overlap

    def test_rank_crashes(self):
        from core.crash_exploit_distance import rank_crashes_by_exploitability
        crashes = [
            {"registers": {"rip": "0x41414141"}, "crash_type": "SIGSEGV"},
            {"registers": {"rip": "0x0"}, "crash_type": "SIGABRT"},
        ]
        ranked = rank_crashes_by_exploitability(crashes)
        assert len(ranked) == 2
        # SIGSEGV with rip=0x41414141 should rank before NULL deref
        assert ranked[0]["exploit_distance"]["overall_distance"] < \
               ranked[1]["exploit_distance"]["overall_distance"]
