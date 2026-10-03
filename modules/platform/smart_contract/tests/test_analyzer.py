# SmartContractAnalyzer测试 — analyze()、get_metadata()、多检测器编排

import pytest
import os  # 保留: may need for file-based bytecode fixtures
import time  # 保留: for timing / performance regression tests
from typing import Dict, Any, Optional  # 保留: type annotations

from modules.platform.smart_contract.src.analyzer import SmartContractAnalyzer
from modules.platform.smart_contract.src.parser.wasm_parser import WASM_MAGIC


# 辅助函数

# PUSH1 00 (*7), CALL, SSTORE, STOP — 触发重入检测
_EVM_REENTRANCY = bytes.fromhex(
	"6000600060006000600060006000f15500"
)

# PUSH1 01, PUSH1 02, ADD, STOP — 触发溢出检测
_EVM_OVERFLOW = bytes.fromhex(
	"600160020100"
)

# PUSH1 01, PUSH1 02, ADD, ISZERO, STOP — 安全，无溢出检测
_EVM_SAFE_ADD = bytes.fromhex(
	"60016002011500"
)

# 无漏洞的简单字节码
_EVM_SIMPLE = bytes.fromhex(
	"6001600200"  # PUSH1 01, PUSH1 02, STOP
)


def _make_wasm_binary(module="env", name="read"):
	"""构建含一个导入的最小WASM二进制。"""
	parts = bytearray()
	parts.extend(WASM_MAGIC)
	parts.extend(b'\x01\x00\x00\x00')

	# type section
	parts.append(0x01)
	parts.append(0x01)
	parts.append(0x01)

	# import section
	mod = module.encode('utf-8')
	nm = name.encode('utf-8')
	payload = bytearray()
	payload.append(0x01)  # num_imports
	payload.append(len(mod))
	payload.extend(mod)
	payload.append(len(nm))
	payload.extend(nm)
	payload.append(0x00)  # kind

	parts.append(0x02)
	parts.append(len(payload))
	parts.extend(payload)

	return bytes(parts)


# 测试

class TestSmartContractAnalyzer:
	"""SmartContractAnalyzer测试: analyze API、元数据、编排。"""

# analyze() API

	def test_analyze_evm_simple(self):
		"""analyze()接收合法EVM字节码应返回成功。"""
		analyzer = SmartContractAnalyzer()
		result = analyzer.analyze(bytecode=_EVM_SIMPLE)
		assert result["success"] is True
		report = result["report"]
		assert report["contract_type"] == "evm"
		assert report["bytecode_length"] == len(_EVM_SIMPLE)
		assert "bytecode_hash" in report
		assert "total_vulnerabilities" in report
		assert "vulnerabilities" in report
		assert isinstance(report["vulnerabilities"], list)
		assert "tags" in report

	def test_analyze_evm_with_reentrancy(self):
		"""CALL+SSTORE字节码应产生重入检测结果。"""
		analyzer = SmartContractAnalyzer(
			config={
				"detect_reentrancy": True,
				"detect_overflow": False,
				"detect_unchecked_call": False,
				"detect_tx_origin": False,
				"enable_cfg_analysis": False,
				"enable_caching": False,
			}
		)
		result = analyzer.analyze(bytecode=_EVM_REENTRANCY)
		assert result["success"] is True
		report = result["report"]
		vulns = report["vulnerabilities"]
		reentrancy_vulns = [v for v in vulns if v["type"] == "reentrancy"]
		assert len(reentrancy_vulns) >= 1, (
			f"expected reentrancy finding, got vulns: {vulns}"
		)

	def test_analyze_evm_with_overflow(self):
		"""ADD无检查的字节码应产生溢出检测结果。"""
		analyzer = SmartContractAnalyzer(
			config={
				"detect_reentrancy": False,
				"detect_overflow": True,
				"detect_unchecked_call": False,
				"detect_tx_origin": False,
				"enable_cfg_analysis": False,
				"enable_caching": False,
			}
		)
		result = analyzer.analyze(bytecode=_EVM_OVERFLOW)
		assert result["success"] is True
		vulns = result["report"]["vulnerabilities"]
		overflow_vulns = [v for v in vulns
			if v["type"] in ("integer_overflow", "integer_underflow")]
		assert len(overflow_vulns) >= 1, (
			f"expected overflow finding, got: {vulns}"
		)

	def test_analyze_evm_safe_no_false_positives(self):
		"""安全字节码(ADD+ISZERO)不应产生溢出检测结果。"""
		analyzer = SmartContractAnalyzer(
			config={
				"detect_reentrancy": False,
				"detect_overflow": True,
				"detect_unchecked_call": False,
				"detect_tx_origin": False,
				"enable_cfg_analysis": False,
				"enable_caching": False,
			}
		)
		result = analyzer.analyze(bytecode=_EVM_SAFE_ADD)
		assert result["success"] is True
		vulns = result["report"]["vulnerabilities"]
		overflow_vulns = [v for v in vulns
			if v["type"] in ("integer_overflow", "integer_underflow")]
		assert len(overflow_vulns) == 0, (
			f"safe ADD+ISZERO should not be flagged, got: {overflow_vulns}"
		)

# get_metadata() API

	def test_get_metadata(self):
		"""get_metadata应返回分析器元数据字典。"""
		analyzer = SmartContractAnalyzer()
		meta = analyzer.get_metadata()
		assert isinstance(meta, dict)
		assert meta["name"] == "SmartContractAnalyzer"
		assert meta["type"] == "STATIC_ANALYZER"
		assert meta["version"] == "1.0.0"
		assert "description" in meta
		assert "author" in meta
		assert "dependencies" in meta
		assert "supported_platforms" in meta

# 缓存

	def test_analyze_caching(self):
		"""相同字节码的重复分析应使用缓存。"""
		analyzer = SmartContractAnalyzer(
			config={
				"detect_reentrancy": True,
				"detect_overflow": True,
				"detect_unchecked_call": False,
				"detect_tx_origin": False,
				"enable_cfg_analysis": False,
				"enable_caching": True,
			}
		)
		result1 = analyzer.analyze(bytecode=_EVM_SIMPLE)
		result2 = analyzer.analyze(bytecode=_EVM_SIMPLE)
		# 第二次调用应从缓存获取
		assert result2["report"].get("from_cache", False) is True
		# 结果应等价
		assert result1["report"]["bytecode_hash"] == result2["report"]["bytecode_hash"]

# 多检测器编排

	def test_multi_detector_orchestration(self):
		"""多个启用的检测器应各自产生结果。"""
		analyzer = SmartContractAnalyzer(
			config={
				"detect_reentrancy": True,
				"detect_overflow": True,
				"detect_unchecked_call": False,
				"detect_tx_origin": False,
				"enable_cfg_analysis": False,
				"enable_caching": False,
			}
		)
		result = analyzer.analyze(bytecode=_EVM_REENTRANCY)
		assert result["success"] is True
		report = result["report"]
		# CALL+SSTORE触发重入 + 算术运算触发溢出
		assert report["total_vulnerabilities"] >= 1
		vuln_types = {v["type"] for v in report["vulnerabilities"]}
		# 至少期望重入检测
		assert "reentrancy" in vuln_types

	def test_all_detectors_disabled(self):
		"""所有检测器禁用时应零发现。"""
		analyzer = SmartContractAnalyzer(
			config={
				"detect_reentrancy": False,
				"detect_overflow": False,
				"detect_unchecked_call": False,
				"detect_tx_origin": False,
				"enable_cfg_analysis": False,
				"enable_caching": False,
			}
		)
		result = analyzer.analyze(bytecode=_EVM_REENTRANCY)
		assert result["success"] is True
		assert result["report"]["total_vulnerabilities"] == 0

# 非法输入

	def test_analyze_missing_bytecode(self):
		"""analyze()未提供bytecode应返回success=False。"""
		analyzer = SmartContractAnalyzer()
		result = analyzer.analyze()
		assert result["success"] is False
		assert "error" in result

	def test_analyze_non_bytes_bytecode(self):
		"""analyze()非bytes类型bytecode应返回success=False。"""
		analyzer = SmartContractAnalyzer()
		result = analyzer.analyze(bytecode="not bytes")
		assert result["success"] is False

# text output format

	def test_analyze_text_format(self):
		"""Text output format should return a string report."""
		analyzer = SmartContractAnalyzer(
			config={
				"detect_reentrancy": False,
				"detect_overflow": False,
				"detect_unchecked_call": False,
				"detect_tx_origin": False,
				"enable_caching": False,
			}
		)
		result = analyzer.analyze(
			bytecode=_EVM_SIMPLE, output_format="text"
		)
		assert result["success"] is True
		assert isinstance(result["report"], str)
		assert "Smart Contract Security Analysis Report" in result["report"]

# confidence threshold

	def test_confidence_filtering(self):
		"""Findings below confidence threshold should be filtered out."""
		analyzer = SmartContractAnalyzer(
			config={
				"detect_reentrancy": True,
				"detect_overflow": True,
				"detect_unchecked_call": False,
				"detect_tx_origin": False,
				"enable_caching": False,
				"confidence_threshold": 0.95,  # reentrancy is 0.92, overflow is 0.70
			}
		)
		result = analyzer.analyze(bytecode=_EVM_REENTRANCY)
		assert result["success"] is True
		# All findings have confidence < 0.95 so should all be filtered
		report = result["report"]
		for v in report["vulnerabilities"]:
			assert v["confidence"] >= 0.95

# severity override

	def test_severity_override(self):
		"""Severity override config should change reported severity."""
		analyzer = SmartContractAnalyzer(
			config={
				"detect_reentrancy": False,
				"detect_overflow": True,
				"detect_unchecked_call": False,
				"detect_tx_origin": False,
				"enable_caching": False,
				"severity_override": {"integer_overflow": "LOW"},
			}
		)
		result = analyzer.analyze(bytecode=_EVM_OVERFLOW)
		assert result["success"] is True
		for v in result["report"]["vulnerabilities"]:
			if v["type"] == "integer_overflow":
				assert v["severity"] == "LOW"

# report structure

	def test_report_structure(self):
		"""Analysis report should have all expected top-level keys."""
		analyzer = SmartContractAnalyzer(
			config={
				"detect_reentrancy": False,
				"detect_overflow": False,
				"detect_unchecked_call": False,
				"detect_tx_origin": False,
				"enable_caching": False,
			}
		)
		result = analyzer.analyze(bytecode=_EVM_SIMPLE)
		assert result["success"] is True
		report = result["report"]
		expected_keys = [
			"contract_type", "bytecode_length", "bytecode_hash",
			"total_vulnerabilities", "high_severity", "medium_severity",
			"low_severity", "vulnerabilities", "tags",
			"function_selectors",
		]
		for key in expected_keys:
			assert key in report, f"missing key: {key}"

# analysis_time

	def test_analysis_time_present(self):
		"""Report should include analysis_time."""
		analyzer = SmartContractAnalyzer(
			config={
				"detect_reentrancy": False,
				"detect_overflow": False,
				"detect_unchecked_call": False,
				"detect_tx_origin": False,
				"enable_caching": False,
			}
		)
		result = analyzer.analyze(bytecode=_EVM_SIMPLE)
		assert result["success"] is True
		assert "analysis_time" in result["report"]

# max_vulns cap

	def test_max_vulns_cap(self):
		"""max_vulns should cap the number of returned vulnerabilities."""
		analyzer = SmartContractAnalyzer(
			config={
				"detect_reentrancy": True,
				"detect_overflow": True,
				"detect_unchecked_call": False,
				"detect_tx_origin": False,
				"enable_caching": False,
				"max_vulns": 1,
			}
		)
		result = analyzer.analyze(bytecode=_EVM_REENTRANCY)
		assert result["success"] is True
		assert len(result["report"]["vulnerabilities"]) <= 1


	