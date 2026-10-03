# 重入检测器测试 — CALL先于SSTORE模式检测 (SWC-107)

import pytest
import os  # 保留: temp file fixture for large bytecode
from typing import List, Optional  # 保留: type hints for clarity

from modules.platform.smart_contract.src.parser.evm_parser import EVMBytecodeParser
from modules.platform.smart_contract.src.detectors.reentrancy import ReentrancyDetector
from modules.platform.smart_contract.src.core.models import VulnerabilityReport


# helpers

def _make_parser(hex_str):
  """从hex字节码字符串创建解析器。"""
  parser = EVMBytecodeParser(b"")
  parser.parse_hex(hex_str)
  return parser


def _detect(hex_str):
  """对hex字节码运行ReentrancyDetector并返回结果。"""
  parser = _make_parser(hex_str)
  detector = ReentrancyDetector(parser)
  return detector.detect()


# bytecode fixtures

# CALL直接后跟SSTORE — 典型重入模式
# PUSH1 00 (*7) for CALL args, CALL, SSTORE, STOP
_BC_CALL_SSTORE = "6000600060006000600060006000f15500"

# 仅CALL，后无SSTORE — 安全模式
# PUSH1 00 (*7), CALL, STOP
_BC_CALL_NO_SSTORE = "6000600060006000600060006000f100"

# CALL后4条指令再SSTORE（在5指令窗口内）
# PUSH1 00 (*7), CALL, PUSH1 01, PUSH1 02, ADD, SSTORE, STOP
_BC_CALL_DELAYED_SSTORE = "6000600060006000600060006000f160016002015500"

# 两组CALL+SSTORE链
# (PUSH1 00*7, CALL, SSTORE) x2, STOP
_BC_DOUBLE_CALL_SSTORE = "6000600060006000600060006000f1556000600060006000600060006000f15500"

# DELEGATECALL后跟SSTORE
_BC_DELEGATECALL_SSTORE = "600060006000600060006000f45500"

# CALLCODE后跟SSTORE
_BC_CALLCODE_SSTORE = "6000600060006000600060006000f25500"

# CALL后经JUMPDEST再到SSTORE（检测器在JUMPDEST处停止）
# PUSH1 00*7, CALL, JUMPDEST, PUSH1 01, SSTORE, STOP
_BC_CALL_JUMPDEST_SSTORE = "6000600060006000600060006000f15b60015500"

# STATICCALL后跟SSTORE（STATICCALL不在检测器的调用集合中）
_BC_STATICCALL_SSTORE = "600060006000600060006000fa5500"


# tests

class TestReentrancyDetector:
  """ReentrancyDetector测试: CALL先于SSTORE模式检测。"""

  def test_call_followed_by_sstore_detected(self):
    """CALL后紧跟SSTORE应被标记为重入。"""
    findings = _detect(_BC_CALL_SSTORE)
    assert len(findings) >= 1, f"expected at least 1 finding, got {len(findings)}"
    vuln = findings[0]
    assert vuln.vuln_type == "reentrancy"
    assert vuln.swc_id == "SWC-107"
    assert vuln.severity == "CRITICAL"
    assert vuln.confidence == 0.92

  def test_call_without_sstore_not_detected(self):
    """CALL后窗口内无SSTORE应不产生结果。"""
    findings = _detect(_BC_CALL_NO_SSTORE)
    assert len(findings) == 0, f"expected 0 findings, got {len(findings)}"

  def test_delayed_sstore_within_window_detected(self):
    """CALL后5条指令内出现SSTORE应被检测。"""
    findings = _detect(_BC_CALL_DELAYED_SSTORE)
    assert len(findings) >= 1

  def test_multiple_call_sstore_chains(self):
    """两组CALL+SSTORE链应产生至少2条结果。"""
    findings = _detect(_BC_DOUBLE_CALL_SSTORE)
    assert len(findings) >= 2, f"expected at least 2, got {len(findings)}"
    # all should be reentrancy type
    for f in findings:
      assert f.vuln_type == "reentrancy"

  def test_delegatecall_sstore_detected(self):
    """DELEGATECALL followed by SSTORE should also be detected."""
    findings = _detect(_BC_DELEGATECALL_SSTORE)
    assert len(findings) >= 1
    assert findings[0].vuln_type == "reentrancy"

  def test_callcode_sstore_detected(self):
    """CALLCODE followed by SSTORE should be detected."""
    findings = _detect(_BC_CALLCODE_SSTORE)
    assert len(findings) >= 1

  def test_staticcall_sstore_not_detected(self):
    """STATICCALL is NOT in the detector's target set — should be ignored."""
    findings = _detect(_BC_STATICCALL_SSTORE)
    for f in findings:
      assert f.opcode != "STATICCALL"

  def test_empty_bytecode(self):
    """Empty bytecode should produce no reentrancy findings."""
    findings = _detect("")
    assert len(findings) == 0

  def test_vulnerability_report_has_evidence(self):
    """Each VulnerabilityReport should include evidence and recommendation."""
    findings = _detect(_BC_CALL_SSTORE)
    assert len(findings) > 0
    report = findings[0]
    assert len(report.evidence) > 0
    assert "CALL" in report.opcode or report.opcode == "CALL"
    assert len(report.recommendation) > 0

  def test_detector_returns_list_of_reports(self):
    """detect() should always return a list (possibly empty)."""
    parser = _make_parser(_BC_CALL_SSTORE)
    detector = ReentrancyDetector(parser)
    result = detector.detect()
    assert isinstance(result, list)
    if result:
      assert isinstance(result[0], VulnerabilityReport)

  def test_confidence_between_zero_and_one(self):
    """All confidence values should be between 0.0 and 1.0."""
    findings = _detect(_BC_CALL_SSTORE)
    for f in findings:
      assert 0.0 <= f.confidence <= 1.0
