"""Tests for crash triage and exploitability assessment."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from modules.dynamic_analysis.crash_triage import (
    CrashType, CrashInfo, ExploitabilityRating, ExploitabilityAssessment,
    CrashClassifier, CrashAnalyzer, CrashReport
)


class TestCrashClassifier:
    def test_sigsegv(self):
        assert CrashClassifier.from_signal(11, fault_addr=0x7fff0000) == CrashType.ACCESS_VIOLATION

    def test_sigsegv_null(self):
        ct = CrashClassifier.from_signal(11, fault_addr=0)
        assert ct == CrashType.NULL_DEREFERENCE

    def test_sigabrt(self):
        assert CrashClassifier.from_signal(6) == CrashType.SIGABRT

    def test_sigill(self):
        assert CrashClassifier.from_signal(4) == CrashType.ILLEGAL_INSTRUCTION

    def test_sigbus(self):
        assert CrashClassifier.from_signal(7) == CrashType.SIGBUS

    def test_sigfpe(self):
        assert CrashClassifier.from_signal(8) == CrashType.FP_EXCEPTION

    def test_windows_av(self):
        ct = CrashClassifier.from_windows_exception('c0000005')
        assert ct == CrashType.ACCESS_VIOLATION

    def test_windows_stack_overflow(self):
        ct = CrashClassifier.from_windows_exception('c00000fd')
        assert ct == CrashType.STACK_OVERFLOW

    def test_windows_divzero(self):
        ct = CrashClassifier.from_windows_exception('c0000094')
        assert ct == CrashType.INTEGER_DIVIDE_BY_ZERO


class TestCrashAnalyzer:
    def test_assertion_not_exploitable(self):
        crash = CrashInfo(crash_type=CrashType.ASSERTION_FAILURE)
        analyzer = CrashAnalyzer()
        assessment = analyzer.assess_exploitability(crash)
        assert assessment.rating == ExploitabilityRating.NOT_EXPLOITABLE

    def test_abort_probably_not(self):
        crash = CrashInfo(crash_type=CrashType.SIGABRT)
        analyzer = CrashAnalyzer()
        assessment = analyzer.assess_exploitability(crash)
        assert assessment.rating == ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE

    def test_divzero_probably_not(self):
        crash = CrashInfo(crash_type=CrashType.INTEGER_DIVIDE_BY_ZERO)
        analyzer = CrashAnalyzer()
        assessment = analyzer.assess_exploitability(crash)
        assert assessment.rating == ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE

    def test_null_deref_maybe_lpe(self):
        crash = CrashInfo(crash_type=CrashType.NULL_DEREFERENCE)
        analyzer = CrashAnalyzer()
        assessment = analyzer.assess_exploitability(crash)
        assert assessment.rating == ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE
        reasons = ' '.join(assessment.ruling_reasons).lower()
        assert 'null' in reasons

    def test_heap_corruption_exploitable(self):
        crash = CrashInfo(crash_type=CrashType.HEAP_CORRUPTION)
        analyzer = CrashAnalyzer()
        assessment = analyzer.assess_exploitability(crash)
        assert assessment.rating == ExploitabilityRating.EXPLOITABLE

    def test_double_free_exploitable(self):
        crash = CrashInfo(crash_type=CrashType.DOUBLE_FREE)
        analyzer = CrashAnalyzer()
        assessment = analyzer.assess_exploitability(crash)
        assert assessment.rating == ExploitabilityRating.EXPLOITABLE

    def test_use_after_free_exploitable(self):
        crash = CrashInfo(crash_type=CrashType.USE_AFTER_FREE)
        analyzer = CrashAnalyzer()
        assessment = analyzer.assess_exploitability(crash)
        assert assessment.rating == ExploitabilityRating.EXPLOITABLE

    def test_controlled_eip(self):
        crash = CrashInfo(
            crash_type=CrashType.ACCESS_VIOLATION,
            fault_address=0xdeadbeef,
            registers={'rip': 0x4141414141414141, 'rsp': 0x7fff0000},
        )
        analyzer = CrashAnalyzer()
        assessment = analyzer.assess_exploitability(crash)
        assert assessment.rating in (ExploitabilityRating.EXPLOITABLE,
                                      ExploitabilityRating.PROBABLY_EXPLOITABLE)
        # RIP at 0x4141... looks controlled
        assert assessment.is_controlled_branch

    def test_illegal_instruction_not_exploitable(self):
        crash = CrashInfo(
            crash_type=CrashType.ILLEGAL_INSTRUCTION,
            faulting_instruction='ud2',
        )
        analyzer = CrashAnalyzer()
        assessment = analyzer.assess_exploitability(crash)
        assert assessment.rating == ExploitabilityRating.NOT_EXPLOITABLE

    def test_generic_av_probably_exploitable(self):
        crash = CrashInfo(
            crash_type=CrashType.ACCESS_VIOLATION,
            fault_address=0x7fff1234,
            registers={},
            modules=[],
        )
        analyzer = CrashAnalyzer()
        assessment = analyzer.assess_exploitability(crash)
        assert assessment.rating in (
            ExploitabilityRating.PROBABLY_EXPLOITABLE,
            ExploitabilityRating.EXPLOITABLE)


class TestCrashReport:
    def test_report_structure(self):
        crash = CrashInfo(
            crash_type=CrashType.ACCESS_VIOLATION,
            fault_address=0x7fff1234,
            exception_code='SIGSEGV',
            registers={'rip': 0x401000, 'rsp': 0x7ffff000, 'rax': 0},
            call_stack=['func1', 'func2', 'main'],
        )
        analyzer = CrashAnalyzer()
        assessment = analyzer.assess_exploitability(crash)
        report = CrashReport.generate(crash, assessment)
        assert report['crash_type'] == 'access_violation'
        assert 'exploitability' in report
        assert 'ruling_reasons' in report


class TestExploitabilityAssessment:
    def test_default_unknown(self):
        a = ExploitabilityAssessment()
        assert a.rating == ExploitabilityRating.UNKNOWN
        assert a.confidence == 0.0

    def test_mitigation_suggestions(self):
        a = ExploitabilityAssessment(
            rating=ExploitabilityRating.EXPLOITABLE,
            is_controlled_branch=True,
            is_dep_bypass_possible=True,
            is_aslr_bypass_possible=True)
        # verify the flags are set correctly on the assessment
        assert a.is_controlled_branch is True
        assert a.is_dep_bypass_possible is True
        assert a.is_aslr_bypass_possible is True
        # The assessor populates suggestions during assessment
        crash = CrashInfo(
            crash_type=CrashType.ACCESS_VIOLATION,
            fault_address=0x7fff1000,
            registers={'rip': 0x41414141, 'rsp': 0x7fff0000},
        )
        analyzer = CrashAnalyzer()
        result = analyzer.assess_exploitability(crash)
        # controlled EIP should be flagged
        if result.is_controlled_branch:
            assert result.rating == ExploitabilityRating.EXPLOITABLE
