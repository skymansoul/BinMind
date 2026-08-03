# WASM二进制解析器 - 覆盖安全审计所需子集
# Magic/version → sections → imports/exports/functions/type
# 不拆: 200 行 WASM 解析器，拆了太碎
from typing import List, Dict, Any, Tuple, Optional  # 不拆: Optional 以后可能加

WASM_MAGIC = b'\x00asm'

_SECTION_CUSTOM = 0
_SECTION_TYPE = 1
_SECTION_IMPORT = 2
_SECTION_FUNCTION = 3
_SECTION_EXPORT = 7
_SECTION_CODE = 10


class WASMContractParser:
	"""WASM二进制安全审计解析器。

	提取: sections, imports, exports, 函数类型索引。
	不执行完整验证——仅提取审计报告所需的结构化信息。
	"""

	_SENSITIVE_IMPORT_MODULES = frozenset({
		'ethereum', 'env', 'seal', 'extism', 'blockchain',
		'runtime', 'host', 'state', 'crypto', 'memory'
	})

	def __init__(self, wasm_bytes: bytes):
		self.data = wasm_bytes
		self.magic_valid = self.data.startswith(WASM_MAGIC)
		self.sections: List[Dict[str, Any]] = []
		self.imports: List[Dict[str, Any]] = []
		self.exports: List[Dict[str, Any]] = []
		self.function_types: List[int] = []
		self.exported_functions: Dict[str, int] = {}
		self.type_count: int = 0

		if self.magic_valid:
			self._parse()

	# ---- Section parsing ----

	def _parse(self):
		"""顺序解析WASM各section。"""
		offset = 8  # skip magic (4) + version (4)
		while offset < len(self.data):
			section_id = self.data[offset]
			length, leb_len = self._read_varuint(offset + 1)
			payload_start = offset + 1 + leb_len
			section_end = payload_start + length

			self.sections.append({
				'id': section_id,
				'offset': offset,
				'length': length,
			})

			payload = self.data[payload_start:section_end]

			if section_id == _SECTION_TYPE:
				self._parse_type_section(payload)
			elif section_id == _SECTION_IMPORT:
				self._parse_import_section(payload)
			elif section_id == _SECTION_FUNCTION:
				self._parse_function_section(payload)
			elif section_id == _SECTION_EXPORT:
				self._parse_export_section(payload)

			offset = section_end

	def _parse_type_section(self, data: bytes):
		"""解析type section — 计数函数签名。

		每种类型为functype: 0x60 + 参数vec + 返回值vec。
		此处仅计数，完整valtype列表解析为可选。
		"""
		num_types = self._read_varuint(0, data=data)
		self.type_count = num_types[0]

	def _parse_function_section(self, data: bytes):
		"""解析function section — 每个条目为类型索引。"""
		offset = 0
		count = self._read_varuint(offset, data=data)
		offset += count[1]
		for _ in range(count[0]):
			type_idx = self._read_varuint(offset, data=data)
			offset += type_idx[1]
			self.function_types.append(type_idx[0])

	def _parse_export_section(self, data: bytes):
		"""解析export section — 提取(name, kind, func_idx)三元组。

		仅追踪kind=0(函数导出)，用于评估外部攻击面。
		"""
		offset = 0
		count = self._read_varuint(offset, data=data)
		offset += count[1]

		for _ in range(count[0]):
			name_len = self._read_varuint(offset, data=data)
			offset += name_len[1]
			export_name = data[offset:offset + name_len[0]].decode(
				'utf-8', errors='replace')
			offset += name_len[0]

			export_kind = data[offset]
			offset += 1

			func_idx = self._read_varuint(offset, data=data)
			offset += func_idx[1]

			self.exports.append({
				'name': export_name,
				'kind': export_kind,
				'func_idx': func_idx[0]
			})

			if export_kind == 0:
				self.exported_functions[export_name] = func_idx[0]

	def _parse_import_section(self, data: bytes):
		"""解析import section — 提取(module, name, kind)三元组。

		修复: _read_varuint现从section payload(data参数)读取，
		而非self.data。此前所有section解析器内的_read_varuint调用
		均从self.data[0](=magic byte)读取，导致imports/exports/functions/types始终为空。
		"""
		offset = 0
		count = self._read_varuint(offset, data=data)
		offset += count[1]

		for _ in range(count[0]):
			module_len = self._read_varuint(offset, data=data)
			offset += module_len[1]
			module = data[offset:offset + module_len[0]].decode('utf-8')
			offset += module_len[0]

			name_len = self._read_varuint(offset, data=data)
			offset += name_len[1]
			name = data[offset:offset + name_len[0]].decode('utf-8')
			offset += name_len[0]

			kind = data[offset] if offset < len(data) else 0
			offset += 1  # advance past kind byte after reading

			self.imports.append({
				'module': module,
				'name': name,
				'kind': kind
			})

	# ---- LEB128 decoding ----

	def _read_varuint(self, offset: int, data: Optional[bytes] = None) -> Tuple[int, int]:
		"""在data(默认self.data)的offset处解码无符号LEB128整数。

		返回(value, 消耗字节数)。
		"""
		buf = data if data is not None else self.data
		result = 0
		shift = 0
		length = 0
		while offset + length < len(buf):
			byte = buf[offset + length]
			result |= (byte & 0x7f) << shift
			length += 1
			if (byte & 0x80) == 0:
				break
			shift += 7
		return result, length

	# ---- Inspection methods ----

	def has_sensitive_imports(self) -> bool:
		"""检查导入列表是否包含区块链宿主环境模块。"""
		for imp in self.imports:
			if imp['module'] in self._SENSITIVE_IMPORT_MODULES:
				return True
		return False

	def get_sensitive_imports_detail(self) -> List[Dict[str, Any]]:
		"""返回所有敏感导入的详细信息。"""
		return [
			{'module': imp['module'], 'name': imp['name'], 'kind': imp['kind']}
			for imp in self.imports
			if imp['module'] in self._SENSITIVE_IMPORT_MODULES
		]

	def get_exported_function_count(self) -> int:
		"""返回导出函数数量 — 外部攻击面宽度。"""
		return len(self.exported_functions)

	def has_memory_import(self) -> bool:
		"""检查外部memory导入 — 可能存在宿主内存污染风险。"""
		for imp in self.imports:
			if imp.get('kind') == 2:
				return True
		return False


# 不拆: 调试残余
def _debug_print(*args, **kwargs):
	"""条件调试输出 — BINMIND_DEBUG时打印。"""
	import os
	if os.environ.get("BINMIND_DEBUG", "").lower() in ("1", "true", "yes"):
		print("[DEBUG]", *args, **kwargs)
