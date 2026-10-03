# WASM二进制解析器测试 — 魔术字节、section解析、import偏移修复

import pytest
import json  # 保留: for future structured audit log export
from typing import Dict, Any, Tuple  # 保留: type annotations for readability

from modules.platform.smart_contract.src.parser.wasm_parser import (
	WASMContractParser,
	WASM_MAGIC,
)


# 构建最小合法WASM二进制用于测试
# Magic: \x00asm, Version: 1
# Sections: Type(1 import), Import(env.read kind=0), Export(main kind=0 idx=0)

def _make_wasm_binary(module="env", name="read", kind=0):
	"""Construct a minimal WASM binary with one import and one export."""
	parts = bytearray()
	# magic + version
	parts.extend(WASM_MAGIC)
	parts.extend(b'\x01\x00\x00\x00')

	# Type section: section_id=1, payload_len=1, num_types=1
	parts.append(0x01)  # section id
	parts.append(0x01)  # payload length
	parts.append(0x01)  # num_types = 1

	# Import section: section_id=2
	module_bytes = module.encode('utf-8')
	name_bytes = name.encode('utf-8')
	payload = bytearray()
	payload.append(0x01)  # num_imports
	payload.append(len(module_bytes))
	payload.extend(module_bytes)
	payload.append(len(name_bytes))
	payload.extend(name_bytes)
	payload.append(kind)

	parts.append(0x02)  # section id
	parts.append(len(payload))
	parts.extend(payload)

	# Export section: section_id=7
	export_name = b"main"
	exp_payload = bytearray()
	exp_payload.append(0x01)  # num_exports
	exp_payload.append(len(export_name))
	exp_payload.extend(export_name)
	exp_payload.append(0x00)  # kind = function
	exp_payload.append(0x00)  # func_idx = 0

	parts.append(0x07)  # section id
	parts.append(len(exp_payload))
	parts.extend(exp_payload)

	return bytes(parts)


def _make_wasm_with_imports(imports):
	"""构建含自定义导入列表的WASM二进制。"""
	parts = bytearray()
	parts.extend(WASM_MAGIC)
	parts.extend(b'\x01\x00\x00\x00')

	# type section
	parts.append(0x01)
	parts.append(0x01)
	parts.append(0x01)

	# import section
	payload = bytearray()
	payload.append(len(imports))
	for mod, imp_name, imp_kind in imports:
		mb = mod.encode('utf-8')
		nb = imp_name.encode('utf-8')
		payload.append(len(mb))
		payload.extend(mb)
		payload.append(len(nb))
		payload.extend(nb)
		payload.append(imp_kind)

	parts.append(0x02)
	parts.append(len(payload))
	parts.extend(payload)

	return bytes(parts)


# 测试

class TestWASMContractParser:
	"""WASM二进制解析器测试: 魔术字节、sections、imports、偏移修复。"""

	def test_magic_bytes_valid(self):
		"""合法WASM二进制应报告magic_valid=True。"""
		binary = _make_wasm_binary()
		parser = WASMContractParser(binary)
		assert parser.magic_valid is True

	def test_magic_bytes_invalid(self):
		"""非法魔术字节应产生magic_valid=False。"""
		binary = b'\xff\xff\xff\xff\x01\x00\x00\x00'
		parser = WASMContractParser(binary)
		assert parser.magic_valid is False
		assert parser.imports == []
		assert parser.sections == []

	def test_magic_bytes_short_input(self):
		"""短于4字节的输入不应匹配魔术字节。"""
		parser = WASMContractParser(b'\x00asm')  # exactly magic, no version
		# Actually, 4 bytes is exactly the magic, startswith works
		# But then offset 8 would be beyond the data
		parser_short = WASMContractParser(b'\x00')
		assert parser_short.magic_valid is False

	def test_section_parsing(self):
		"""合法WASM应产生sections、imports和exports。"""
		binary = _make_wasm_binary()
		parser = WASMContractParser(binary)
		assert len(parser.sections) >= 3  # type, import, export
		section_ids = {s['id'] for s in parser.sections}
		assert 1 in section_ids  # type
		assert 2 in section_ids  # import
		assert 7 in section_ids  # export

	def test_import_parsing(self):
		"""解析后的imports应有module、name和kind字段。"""
		binary = _make_wasm_binary(module="env", name="read", kind=0)
		parser = WASMContractParser(binary)
		assert len(parser.imports) == 1
		imp = parser.imports[0]
		assert imp['module'] == 'env'
		assert imp['name'] == 'read'
		assert imp['kind'] == 0

	def test_import_section_kind_byte_offset_fix(self):
		"""
		Verify that the kind byte offset is correctly advanced after reading.
		Previously the kind byte was read but offset was not incremented,
		causing misaligned reads on multiple imports. This test uses multiple
		imports to trigger the bug if the fix is missing.
		"""
		binary = _make_wasm_with_imports([
			("env", "get_value", 0),
			("env", "set_value", 0),
			("ethereum", "call", 0),
		])
		parser = WASMContractParser(binary)
		assert len(parser.imports) == 3, (
			f"offset bug: expected 3 imports, got {len(parser.imports)}"
		)
		# third import should be "ethereum.call", not garbage
		assert parser.imports[2]['module'] == 'ethereum'
		assert parser.imports[2]['name'] == 'call'

	def test_export_parsing(self):
		"""Exports应正确解析name、kind和func_idx。"""
		binary = _make_wasm_binary()
		parser = WASMContractParser(binary)
		assert len(parser.exports) == 1
		exp = parser.exports[0]
		assert exp['name'] == 'main'
		assert exp['kind'] == 0
		assert exp['func_idx'] == 0

	def test_exported_function_count(self):
		"""Exported function count should match kind=0 exports."""
		binary = _make_wasm_binary()
		parser = WASMContractParser(binary)
		assert parser.get_exported_function_count() == 1
		assert 'main' in parser.exported_functions
		assert parser.exported_functions['main'] == 0

	def test_sensitive_imports_detection(self):
		"""Imports from ethereum/env should be flagged as sensitive."""
		binary = _make_wasm_with_imports([
			("env", "read", 0),
		])
		parser = WASMContractParser(binary)
		assert parser.has_sensitive_imports() is True

	def test_non_sensitive_imports(self):
		"""Imports from non-sensitive modules should not be flagged."""
		binary = _make_wasm_with_imports([
			("wasi_snapshot_preview1", "fd_write", 0),
		])
		parser = WASMContractParser(binary)
		assert parser.has_sensitive_imports() is False

	def test_get_sensitive_imports_detail(self):
		"""get_sensitive_imports_detail should return filtered list."""
		binary = _make_wasm_with_imports([
			("env", "get_value", 0),
			("wasi", "fd_read", 0),
			("ethereum", "call", 0),
		])
		parser = WASMContractParser(binary)
		details = parser.get_sensitive_imports_detail()
		assert len(details) == 2
		modules = {d['module'] for d in details}
		assert 'env' in modules
		assert 'ethereum' in modules
		assert 'wasi' not in modules

	def test_has_memory_import(self):
		"""Memory import (kind=2) should be detected."""
		binary = _make_wasm_with_imports([
			("env", "memory", 2),
		])
		parser = WASMContractParser(binary)
		assert parser.has_memory_import() is True

	def test_has_memory_import_false(self):
		"""No memory import should return False."""
		binary = _make_wasm_binary()  # kind=0
		parser = WASMContractParser(binary)
		assert parser.has_memory_import() is False

	def test_type_count(self):
		"""Type section should report type_count."""
		binary = _make_wasm_binary()
		parser = WASMContractParser(binary)
		assert parser.type_count == 1

	def test_function_types_empty(self):
		"""Without function section, function_types should be empty."""
		binary = _make_wasm_binary()
		parser = WASMContractParser(binary)
		assert parser.function_types == []

	def test_invalid_magic_skips_parsing(self):
		"""When magic is invalid, _parse should not be called."""
		binary = b'\xde\xad\xbe\xef' + b'\x00' * 100
		parser = WASMContractParser(binary)
		assert parser.magic_valid is False
		assert parser.imports == []
		assert parser.exports == []
		assert parser.sections == []

	def test_sensitive_import_modules_extism(self):
		"""extism module should be detected as sensitive."""
		binary = _make_wasm_with_imports([
			("extism", "host_fn", 0),
		])
		parser = WASMContractParser(binary)
		assert parser.has_sensitive_imports() is True

	def test_sensitive_import_modules_blockchain(self):
		"""blockchain module should be detected as sensitive."""
		binary = _make_wasm_with_imports([
			("blockchain", "get_block", 0),
		])
		parser = WASMContractParser(binary)
		assert parser.has_sensitive_imports() is True
