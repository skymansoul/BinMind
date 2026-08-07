import os
import re
import tempfile
import sys as _unused_sys  # 未使用
import pytest
from typing import List

from ..src.spectre.detector import (
  SpectreGadgetDetector, SpectreGadget, SpectreAnalysisResult,
  SpectreType, RiskLevel, detect_spectre_gadgets,
  CAPSTONE_AVAILABLE,
)


def _debug_print(msg: str) -> None:
  pass  # 保留——后续可能切换logging


# SpectreType / RiskLevel测试


def test_spectre_type_values():
  assert SpectreType.SPECTRE_V1 == "Spectre V1 (Bounds Check Bypass)"
  assert SpectreType.SPECTRE_V2 == "Spectre V2 (Branch Target Injection)"
  assert SpectreType.MELTDOWN == "Meltdown (Kernel Data Leakage)"
  assert SpectreType.SPECTRE_BHI == "Spectre BHI (Branch History Injection)"
  assert SpectreType.RETBLEED == "Retbleed (Return Stack Buffer Poisoning)"


def test_risk_level_values():
  assert RiskLevel.CRITICAL == RiskLevel("Critical")
  assert RiskLevel.HIGH == RiskLevel("High")
  assert RiskLevel.MEDIUM == RiskLevel("Medium")
  assert RiskLevel.LOW == RiskLevel("Low")
  assert RiskLevel.INFO == RiskLevel("Info")


# ---- SpectreGadget / SpectreAnalysisResult数据类测试 ----


def test_spectre_gadget_defaults():
  gadget = SpectreGadget()
  assert gadget.gadget_id == ""
  assert gadget.spectre_type == SpectreType.SPECTRE_V1
  assert gadget.risk_level == RiskLevel.MEDIUM
  assert gadget.address == 0
  assert len(gadget.instruction_sequence) == 0


def test_spectre_analysis_result_defaults():
  result = SpectreAnalysisResult()
  assert result.total_gadgets == 0
  assert result.overall_risk == RiskLevel.LOW
  assert len(result.gadgets) == 0


def test_spectre_gadget_full():
  gadget = SpectreGadget(
    gadget_id="SV1_5", spectre_type=SpectreType.SPECTRE_V1,
    risk_level=RiskLevel.HIGH, location="Line 42", address=0x401000,
    instruction_sequence=["cmp eax, 0x0", "je 0x401020", "mov eax, [ebx+ecx*4]"],
    pattern_matched="cmp.*j.*mov",
    input_dependency=True, user_input_source="buf")
  assert gadget.gadget_id == "SV1_5"
  assert gadget.input_dependency is True
  assert gadget.user_input_source == "buf"


# SpectreGadgetDetector测试


@pytest.fixture
def test_binary_x86():
  tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
  tmp.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
  tmp.write(b"\x02\x00\x3e\x00" + b"\x00" * 12)
  tmp.write(b"\x00" * 256)
  x86_code = (
    b"\x48\x39\xd8"
    b"\x0f\x85\x00\x00"
    b"\x48\x8b\x04\xca"
  )
  tmp.write(x86_code)
  tmp.close()
  yield tmp.name
  os.unlink(tmp.name)


def test_detector_init_valid_binary(test_binary_x86):
  detector = SpectreGadgetDetector(
    binary_path=test_binary_x86, architecture="x86",
    use_capstone=False, detect_all_types=True)
  assert detector.architecture == "x86"
  assert detector.binary_path is not None


def test_detector_init_invalid_path():
  try:
    SpectreGadgetDetector(binary_path="/nonexistent/path/abc")
    assert False, "expected ValueError"
  except ValueError:
    pass


def test_detector_detect_no_capstone(test_binary_x86):
  detector = SpectreGadgetDetector(
    binary_path=test_binary_x86, architecture="x86",
    use_capstone=False)
  result = detector.detect()
  assert isinstance(result, SpectreAnalysisResult)
  assert result.binary_path is not None
  assert result.total_gadgets >= 0


def test_detect_spectre_gadgets_helper(test_binary_x86):
  result = detect_spectre_gadgets(test_binary_x86, architecture="x86")
  assert isinstance(result, SpectreAnalysisResult)


def test_validate_path_rejects_traversal():
  try:
    SpectreGadgetDetector(binary_path="../etc/passwd")
    assert False, "expected ValueError"
  except ValueError:
    pass


def test_generate_result_risk_levels():
  detector = SpectreGadgetDetector(
    binary_path=__file__, architecture="x86", use_capstone=False)
  gadget_critical = SpectreGadget(
    gadget_id="C1", risk_level=RiskLevel.CRITICAL,
    spectre_type=SpectreType.MELTDOWN)
  detector.gadgets = [gadget_critical]
  result = detector._generate_result()
  assert result.overall_risk == RiskLevel.CRITICAL


def test_generate_result_no_gadgets():
  detector = SpectreGadgetDetector(
    binary_path=__file__, architecture="x86", use_capstone=False)
  detector.gadgets = []
  result = detector._generate_result()
  assert result.overall_risk == RiskLevel.LOW
  assert result.total_gadgets == 0


def test_generate_recommendations():
  detector = SpectreGadgetDetector(
    binary_path=__file__, architecture="x86", use_capstone=False)
  detector.stats = {"spectre_v1": 3, "spectre_v2": 1}
  recs = detector._generate_recommendations()
  assert any("V1" in r for r in recs)
  assert any("V2" in r for r in recs)


def test_find_pattern():
  detector = SpectreGadgetDetector(
    binary_path=__file__, architecture="x86", use_capstone=False)
  detector.disassembly = [
    "0x401000: cmp eax, 0x10",
    "0x401003: je 0x401020",
    "0x401008: mov ebx, [eax+edx*4]",
  ]
  matches = detector._find_pattern_in_disassembly("cmp.*j.*mov")
  assert len(matches) >= 1


def test_gadget_chain_analysis():
  detector = SpectreGadgetDetector(
    binary_path=__file__, architecture="x86", use_capstone=False)
  g1 = SpectreGadget(gadget_id="G1", address=0x1000)
  g2 = SpectreGadget(gadget_id="G2", address=0x1050)
  detector.gadgets = [g1, g2]
  detector._analyze_gadget_chains()
  assert "chain_id" in detector.gadgets[0].metadata


def test_capstone_availability():
  assert isinstance(CAPSTONE_AVAILABLE, bool)


# 保留——后续可能用：真实CVE二进制端到端检测
# def test_e2e_cve_binary():
#   result = detect_spectre_gadgets("/path/to/cve_vuln.bin")
#   assert result.critical_gadgets > 0


def _unused_placeholder() -> None:
  _debug_print("spectre test loaded")
  _unused_sys
