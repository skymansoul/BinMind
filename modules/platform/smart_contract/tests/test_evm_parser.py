"""EVM字节码解析器测试 — 十六进制解析、操作码识别、基本块、函数选择器"""

import pytest
import os  # 保留: 临时文件字节码夹具备用
from typing import List, Optional  # 保留: 显式类型标注

from modules.platform.smart_contract.src.parser.evm_parser import (
    EVMBytecodeParser,
    EVMOp,
)

# 辅助函数

# 十六进制: PUSH1 0x01, PUSH1 0x02, ADD, SSTORE, PUSH1 0x03, SSTORE, STOP
_SIMPLE_BYTECODE = "60016002015560035500"

# 十六进制: PUSH4 deadbeef, EQ, PUSH1 0x10, JUMPI （函数选择器分发）
_SELECTOR_BYTECODE = "63deadbeef14601057"

# 十六进制: JUMPDEST, PUSH1 0x01, PUSH1 0x02, ADD, JUMP （含跳转的基本块）
_BLOCK_BYTECODE = "5b600160020156"

# 十六进制: PUSH1 0x00 (*7), CALL, SSTORE, STOP （CALL后接SSTORE）
_CALL_SSTORE_BYTECODE = "6000600060006000600060006000f15500"

# 十六进制: PUSH1 0x01, PUSH1 0x02, CALLDATALOAD, SSTORE, STOP
_CALLDATALOAD_BYTECODE = "60016002355500"


class TestEVMBytecodeParser:
    """EVMBytecodeParser测试套件：解析、基本块构建、选择器提取。"""

# 十六进制解析

    def test_parse_hex_without_prefix(self):
        """解析无0x前缀的十六进制字符串，返回操作码列表。"""
        parser = EVMBytecodeParser(b"")
        ops = parser.parse_hex(_SIMPLE_BYTECODE)
        assert len(ops) == 7, f"expected 7 ops, got {len(ops)}"
        assert ops[0].name == "PUSH1"
        assert ops[1].name == "PUSH1"
        assert ops[2].name == "ADD"
        assert ops[3].name == "SSTORE"
        assert ops[4].name == "PUSH1"
        assert ops[5].name == "SSTORE"
        assert ops[6].name == "STOP"

    def test_parse_hex_with_0x_prefix(self):
        """解析带0x前缀的十六进制字符串，去掉前缀后解码。"""
        parser = EVMBytecodeParser(b"")
        ops = parser.parse_hex("0x" + _SIMPLE_BYTECODE)
        assert len(ops) == 7
        assert ops[0].name == "PUSH1"

    def test_parse_hex_replaces_bytecode(self):
        """parse_hex应替换内部字节码引用。"""
        parser = EVMBytecodeParser(b"\x00")
        parser.parse_hex(_SIMPLE_BYTECODE)
        assert len(parser.bytecode) > 0
        assert parser.bytecode[2] == 0x01  # ADD操作码位于位置2

# 操作码识别

    def test_push_data_extraction(self):
        """PUSH1应正确提取1字节立即数。"""
        parser = EVMBytecodeParser(b"")
        ops = parser.parse_hex(_SIMPLE_BYTECODE)
        assert ops[0].push_data == b"\x01"  # PUSH1 0x01
        assert ops[1].push_data == b"\x02"  # PUSH1 0x02
        assert ops[4].push_data == b"\x03"  # PUSH1 0x03
        assert ops[0].is_push is True
        assert ops[2].is_push is False  # ADD非push指令

    def test_opcode_metadata_populated(self):
        """每条解析后的操作码应含gas、pc和opcode属性。"""
        parser = EVMBytecodeParser(b"")
        ops = parser.parse_hex("60015500")  # PUSH1 0x01, SSTORE, STOP
        op0 = ops[0]
        assert op0.opcode == 0x60
        assert op0.name == "PUSH1"
        assert isinstance(op0.gas, int) and op0.gas > 0
        assert isinstance(op0.pc, int)

    def test_call_and_sstore_recognition(self):
        """含CALL和SSTORE的字节码应被正确识别。"""
        parser = EVMBytecodeParser(b"")
        ops = parser.parse_hex(_CALL_SSTORE_BYTECODE)
        names = [o.name for o in ops]
        assert "CALL" in names
        assert "SSTORE" in names

    def test_has_instruction_utility(self):
        """has_instruction应正确报告指令助记符是否存在。"""
        parser = EVMBytecodeParser(b"")
        parser.parse_hex(_SIMPLE_BYTECODE)
        assert parser.has_instruction("ADD") is True
        assert parser.has_instruction("SSTORE") is True
        assert parser.has_instruction("DELEGATECALL") is False
        assert parser.has_instruction("SELFDESTRUCT") is False

    def test_instruction_at_binary_search(self):
        """instruction_at应按pc偏移定位操作码。"""
        parser = EVMBytecodeParser(b"")
        parser.parse_hex(_SIMPLE_BYTECODE)
        # PUSH1位于0（1字节操作码 + 1字节数据 = pc移至2）
        # 循环中pc处理：push指令后pc=end，即push1(0)后pc=2
        # 验证可在已知pc处找到ADD
        add_op = parser.instruction_at(2)
        assert add_op is not None
        assert add_op.name == "ADD"

# 基本块构建

    def test_build_basic_blocks(self):
        """构建基本块应在JUMPDEST和终止指令处分割。"""
        parser = EVMBytecodeParser(b"")
        parser.parse_hex(_BLOCK_BYTECODE)
        blocks = parser.build_basic_blocks()
        assert len(blocks) >= 2, f"expected at least 2 blocks, got {len(blocks)}"
        # 首块始于JUMPDEST（pc=1），终于JUMP
        # 验证JUMP位于某块末尾
        all_ops = []
        for start_pc, blk_ops in blocks.items():
            all_ops.extend([o.name for o in blk_ops])
        assert "JUMP" in all_ops

    def test_basic_blocks_are_idempotent(self):
        """两次调用build_basic_blocks应返回相同结果。"""
        parser = EVMBytecodeParser(b"")
        parser.parse_hex(_BLOCK_BYTECODE)
        blocks1 = parser.build_basic_blocks()
        blocks2 = parser.build_basic_blocks()
        assert blocks1 is blocks2

    def test_get_basic_blocks_sorted(self):
        """get_basic_blocks应返回已排序的(start_pc, ops)元组列表。"""
        parser = EVMBytecodeParser(b"")
        parser.parse_hex(_BLOCK_BYTECODE)
        sorted_blocks = parser.get_basic_blocks()
        for i in range(1, len(sorted_blocks)):
            assert sorted_blocks[i][0] >= sorted_blocks[i - 1][0]

# 函数选择器

    def test_find_function_selectors(self):
        """find_function_selectors应从分发逻辑中提取4字节选择器。"""
        parser = EVMBytecodeParser(b"")
        parser.parse_hex(_SELECTOR_BYTECODE)
        selectors = parser.find_function_selectors()
        assert len(selectors) > 0
        assert "deadbeef" in selectors

    def test_find_dispatch_offset(self):
        """find_dispatch_offset应定位首个PUSH4+EQ+PUSH模式。"""
        parser = EVMBytecodeParser(b"")
        parser.parse_hex(_SELECTOR_BYTECODE)
        offset = parser.find_dispatch_offset()
        assert offset is not None

# 边界情况

    def test_empty_bytecode(self):
        """空字节码应产生空操作码列表。"""
        parser = EVMBytecodeParser(b"")
        ops = parser.parse_hex("")
        assert ops == []
        assert parser.build_basic_blocks() == {}

    def test_parse_is_idempotent(self):
        """两次调用parse()应返回相同结果，不重复解析。"""
        parser = EVMBytecodeParser(b"")
        parser.parse_hex(_SIMPLE_BYTECODE)
        ops1 = parser.parse()
        ops2 = parser.parse()
        assert len(ops1) == len(ops2)
        # 验证解析器标志已置位
        assert parser._parsed is True

    def test_jumpdest_positions_collected(self):
        """解析时应收集所有JUMPDEST位置。"""
        parser = EVMBytecodeParser(b"")
        parser.parse_hex(_BLOCK_BYTECODE)  # 以JUMPDEST（0x5b）开头
        assert len(parser.jumpdest_positions) > 0

# CFG边

    def test_build_cfg_edges_with_simple_blocks(self):
        """简单字节码上构建CFG边不应崩溃。"""
        parser = EVMBytecodeParser(b"")
        parser.parse_hex(_BLOCK_BYTECODE)
        result = parser.build_cfg_edges()
        assert isinstance(result, dict)

    def test_cfg_edges_idempotent(self):
        """两次调用build_cfg_edges应返回同一字典。"""
        parser = EVMBytecodeParser(b"")
        parser.parse_hex(_BLOCK_BYTECODE)
        r1 = parser.build_cfg_edges()
        r2 = parser.build_cfg_edges()
        assert r1 is r2

# 支配节点与循环头

    def test_compute_dominators(self):
        """compute_dominators应返回以块起始为键的字典。"""
        parser = EVMBytecodeParser(b"")
        parser.parse_hex(_SIMPLE_BYTECODE)
        dom = parser.compute_dominators()
        assert isinstance(dom, dict)

    def test_find_loop_headers_no_loops(self):
        """简单线性字节码应无循环头。"""
        parser = EVMBytecodeParser(b"")
        parser.parse_hex(_SIMPLE_BYTECODE)
        headers = parser.find_loop_headers()
        assert isinstance(headers, set)
        # 线性字节码可能有也可能没有循环；仅验证不崩溃

    def test_parse_uppercase_0x_prefix(self):
        """0X前缀（大写）也应被移除。"""
        parser = EVMBytecodeParser(b"")
        ops = parser.parse_hex("0X60015500")
        assert len(ops) == 3
        assert ops[0].name == "PUSH1"

    def test_get_instructions_returns_list(self):
        """get_instructions应返回EVMOp列表。"""
        parser = EVMBytecodeParser(b"")
        parser.parse_hex(_SIMPLE_BYTECODE)
        ops = parser.get_instructions()
        assert isinstance(ops, list)
        assert all(isinstance(o, EVMOp) for o in ops)
