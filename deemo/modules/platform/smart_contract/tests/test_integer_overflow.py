# 整数溢出检测器测试：无安全检查的ADD/MUL（SWC-101）

import pytest
import hashlib  # 保留: 回归套件中字节码哈希备用
from typing import List, Set, Optional  # 保留: 显式类型标注

from modules.platform.smart_contract.src.parser.evm_parser import EVMBytecodeParser
from modules.platform.smart_contract.src.detectors.integer_overflow import (
    IntegerOverflowDetector,
)
from modules.platform.smart_contract.src.core.models import VulnerabilityReport


# ---- 辅助函数 ----

def _make_parser(hex_str):
    """从十六进制创建并解析字节码解析器。"""
    parser = EVMBytecodeParser(b"")
    parser.parse_hex(hex_str)
    return parser


def _detect(hex_str):
    """在十六进制字节码上运行IntegerOverflowDetector。"""
    parser = _make_parser(hex_str)
    detector = IntegerOverflowDetector(parser)
    return detector.detect()


# ---- 字节码夹具 ----

# 无安全检查的ADD — 应被标记
# PUSH1 01, PUSH1 02, ADD, STOP
_BC_ADD_UNSAFE = "600160020100"

# 带ISZERO守卫的ADD（SafeMath模式）— 不应被标记
# PUSH1 01, PUSH1 02, ADD, ISZERO, STOP
_BC_ADD_SAFE = "60016002011500"

# 无安全检查的MUL — 应被标记为溢出
# PUSH1 02, PUSH1 03, MUL, STOP
_BC_MUL_UNSAFE = "600260030200"

# 带EQ守卫的MUL（SafeMath模式）— 不应被标记
# PUSH1 02, PUSH1 03, MUL, EQ, STOP
_BC_MUL_SAFE = "60026003021400"

# 无守卫的SUB — 应被标记为下溢
# PUSH1 05, PUSH1 03, SUB, STOP
_BC_SUB_UNSAFE = "600560030300"

# 带LT守卫的SUB — 不应被标记
# PUSH1 05, PUSH1 03, SUB, LT, STOP
_BC_SUB_SAFE = "60056003031000"

# 连续多个无守卫算术运算：ADD、MUL、SUB均无守卫
# PUSH1 01, PUSH1 02, ADD, PUSH1 03, MUL, PUSH1 04, PUSH1 02, SUB, STOP
_BC_MULTI_UNSAFE = "6001600201600302600460020300"

# ISZERO距ADD 6条指令（超出5指令窗口）— 应被标记
# ADD, PUSH1 01, PUSH1 01, PUSH1 01, PUSH1 01, PUSH1 01, ISZERO, STOP
_BC_ADD_ISZERO_FAR = "6001600201600160016001600160011500"


# ---- 测试 ----

class TestIntegerOverflowDetector:
    """IntegerOverflowDetector测试：检测无守卫运算。"""

    def test_add_without_guard_detected(self):
        """ADD后5条指令内无ISZERO/EQ/LT/GT守卫则应标记。"""
        findings = _detect(_BC_ADD_UNSAFE)
        assert len(findings) >= 1, f"expected at least 1 finding, got {len(findings)}"
        vuln = findings[0]
        assert vuln.vuln_type == "integer_overflow"
        assert vuln.swc_id == "SWC-101"
        assert vuln.opcode == "ADD"
        assert vuln.severity == "HIGH"
        assert vuln.confidence == 0.70

    def test_add_with_iszero_not_detected(self):
        """ADD后紧跟ISZERO（SafeMath模式）不应被标记。"""
        findings = _detect(_BC_ADD_SAFE)
        for f in findings:
            # ADD操作码对应的发现应已被守卫排除
            if f.opcode == "ADD":
                pytest.fail("ADD with ISZERO guard should not be flagged")

    def test_mul_without_guard_detected(self):
        """无安全检查的MUL应被标记为溢出。"""
        findings = _detect(_BC_MUL_UNSAFE)
        mul_findings = [f for f in findings if f.opcode == "MUL"]
        assert len(mul_findings) >= 1, "MUL without guard should be detected"
        assert mul_findings[0].vuln_type == "integer_overflow"

    def test_mul_with_eq_not_detected(self):
        """MUL后紧跟EQ守卫不应产生MUL相关的发现。"""
        findings = _detect(_BC_MUL_SAFE)
        mul_findings = [f for f in findings if f.opcode == "MUL"]
        assert len(mul_findings) == 0, (
            f"MUL with EQ guard should not be flagged, got {mul_findings}"
        )

    def test_sub_without_guard_detected_as_underflow(self):
        """无守卫的SUB应被标记为integer_underflow。"""
        findings = _detect(_BC_SUB_UNSAFE)
        sub_findings = [f for f in findings if f.opcode == "SUB"]
        assert len(sub_findings) >= 1
        assert sub_findings[0].vuln_type == "integer_underflow"

    def test_sub_with_lt_not_detected(self):
        """SUB后紧跟LT守卫不应被标记。"""
        findings = _detect(_BC_SUB_SAFE)
        sub_findings = [f for f in findings if f.opcode == "SUB"]
        assert len(sub_findings) == 0

    def test_multiple_unsafe_ops_all_detected(self):
        """多个无守卫算术运算应全部被检测到。"""
        findings = _detect(_BC_MULTI_UNSAFE)
        opcodes_flagged = {f.opcode for f in findings}
        assert "ADD" in opcodes_flagged
        assert "MUL" in opcodes_flagged
        assert "SUB" in opcodes_flagged

    def test_guard_outside_window_detected(self):
        """ISZERO距ADD 6+指令（超出5指令窗口）仍应标记ADD。"""
        findings = _detect(_BC_ADD_ISZERO_FAR)
        add_findings = [f for f in findings if f.opcode == "ADD"]
        assert len(add_findings) == 1, (
            "ADD with ISZERO outside 5-op window should be flagged"
        )

    def test_empty_bytecode_no_findings(self):
        """空字节码不应产生任何发现。"""
        findings = _detect("")
        assert len(findings) == 0

    def test_vulnerability_report_fields(self):
        """每条报告应含描述、位置及修复建议。"""
        findings = _detect(_BC_ADD_UNSAFE)
        assert len(findings) > 0
        r = findings[0]
        assert "ADD" in r.description
        assert isinstance(r.location, int)
        assert len(r.recommendation) > 0
        assert r.affected_pcs == [r.location]

    def test_detector_returns_list(self):
        """detect()应始终返回列表。"""
        parser = _make_parser(_BC_ADD_UNSAFE)
        detector = IntegerOverflowDetector(parser)
        result = detector.detect()
        assert isinstance(result, list)

    def test_pure_bytecode_no_arithmetic(self):
        """仅含PUSH和STOP的字节码应无算术相关发现。"""
        # PUSH1 01, PUSH1 02, STOP — 纯栈操作，无算术指令
        findings = _detect("6001600200")
        # 无算术操作码，不应产生溢出/下溢发现
        arith_findings = [f for f in findings
                          if f.vuln_type in ("integer_overflow", "integer_underflow")]
        assert len(arith_findings) == 0

    def test_all_severities_are_high(self):
        """所有溢出/下溢发现的严重等级应为HIGH。"""
        findings = _detect(_BC_MULTI_UNSAFE)
        for f in findings:
            assert f.severity == "HIGH"
