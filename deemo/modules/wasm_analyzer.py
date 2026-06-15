import os
import logging
import subprocess
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

WASM_MAGIC = b'\x00asm'

class WasmValueType(Enum):
    I32 = 'i32'
    I64 = 'i64'
    F32 = 'f32'
    F64 = 'f64'
    V128 = 'v128'
    ANYFUNC = 'anyfunc'
    FUNC = 'func'
    EMPTY = 'empty'

class WasmExternalKind(Enum):
    FUNCTION = 0
    TABLE = 1
    MEMORY = 2
    GLOBAL = 3

@dataclass
class WasmFunction:
    name: str
    index: int
    params: List[str]
    returns: List[str]
    is_import: bool = False
    import_module: str = ''
    import_name: str = ''

@dataclass
class WasmGlobal:
    name: str
    index: int
    value_type: str
    mutable: bool
    init_value: int = 0
    is_import: bool = False
    import_module: str = ''
    import_name: str = ''

@dataclass
class WasmMemory:
    index: int
    initial_pages: int
    max_pages: Optional[int] = None
    is_import: bool = False
    import_module: str = ''
    import_name: str = ''

@dataclass
class WasmTable:
    index: int
    element_type: str
    initial_size: int
    max_size: Optional[int] = None
    is_import: bool = False
    import_module: str = ''
    import_name: str = ''

@dataclass
class WasmDataSegment:
    index: int
    offset_expression: List[int]
    data: bytes
    memory_index: int = 0

@dataclass
class WasmCodeSection:
    function_index: int
    locals: List[Tuple[str, int]]
    instructions: List[dict]

@dataclass
class WasmRisk:
    type: str
    description: str
    severity: str
    location: str
    confidence: float
    details: Dict[str, Any] = None

class WasmBinaryAnalyzer:
    def __init__(self, wasm_path: str):
        self.wasm_path = wasm_path
        self.raw_data = b''
        self.parsed = False
        self.imports: List[Dict[str, Any]] = []
        self.exports: List[Dict[str, Any]] = []
        self.functions: List[WasmFunction] = []
        self.globals: List[WasmGlobal] = []
        self.memories: List[WasmMemory] = []
        self.tables: List[WasmTable] = []
        self.data_segments: List[WasmDataSegment] = []
        self.code_sections: List[WasmCodeSection] = []
        self.risk_assessments: List[WasmRisk] = []
        self.wat_content: Optional[str] = None
        self.wabt_available = self._check_wabt_available()
        logger.info(f"WasmBinaryAnalyzer 初始化，WABT 可用: {self.wabt_available}")

    def _check_wabt_available(self) -> bool:
        try:
            result = subprocess.run(
                ['wasm2wat', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def is_wasm_file(self) -> bool:
        """检查文件是否为 WebAssembly 格式"""
        if not os.path.exists(self.wasm_path):
            return False
        
        try:
            with open(self.wasm_path, 'rb') as f:
                header = f.read(8)
            return header.startswith(WASM_MAGIC)
        except Exception as e:
            logger.error(f"检查 WASM 文件失败: {e}")
            return False

    def parse(self) -> bool:
        """解析 WASM 二进制文件"""
        if not self.is_wasm_file():
            logger.error(f"不是有效的 WASM 文件: {self.wasm_path}")
            return False

        try:
            with open(self.wasm_path, 'rb') as f:
                self.raw_data = f.read()
            
            self._parse_binary()
            
            if self.wabt_available:
                self._convert_to_wat()
            
            self._analyze_risks()
            self.parsed = True
            logger.info(f"WASM 文件解析完成: {self.wasm_path}")
            return True
        except Exception as e:
            logger.error(f"解析 WASM 文件失败: {e}")
            return False

    def _parse_binary(self):
        """解析 WASM 二进制格式"""
        data = self.raw_data
        offset = 8
        
        while offset < len(data):
            section_id = data[offset]
            offset += 1
            
            length = self._read_leb128(data, offset)
            offset += self._leb128_size(data[offset:])
            
            section_end = offset + length
            
            if section_id == 1:
                self._parse_type_section(data[offset:section_end])
            elif section_id == 2:
                self._parse_import_section(data[offset:section_end])
            elif section_id == 3:
                self._parse_function_section(data[offset:section_end])
            elif section_id == 4:
                self._parse_table_section(data[offset:section_end])
            elif section_id == 5:
                self._parse_memory_section(data[offset:section_end])
            elif section_id == 6:
                self._parse_global_section(data[offset:section_end])
            elif section_id == 7:
                self._parse_export_section(data[offset:section_end])
            elif section_id == 8:
                self._parse_start_section(data[offset:section_end])
            elif section_id == 9:
                self._parse_element_section(data[offset:section_end])
            elif section_id == 10:
                self._parse_code_section(data[offset:section_end])
            elif section_id == 11:
                self._parse_data_section(data[offset:section_end])
            elif section_id == 12:
                self._parse_data_count_section(data[offset:section_end])
            
            offset = section_end

    def _read_leb128(self, data: bytes, offset: int) -> int:
        """读取 LEB128 编码的整数"""
        result = 0
        shift = 0
        current_offset = offset
        while current_offset < len(data):
            byte = data[current_offset]
            current_offset += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        return result

    def _leb128_size(self, data: bytes) -> int:
        """计算 LEB128 编码的字节长度"""
        size = 0
        while size < len(data):
            byte = data[size]
            size += 1
            if (byte & 0x80) == 0:
                break
        return size

    def _parse_type_section(self, data: bytes):
        """解析类型段"""
        offset = 0
        count = self._read_leb128(data, offset)
        offset += self._leb128_size(data[offset:])
        
        for _ in range(count):
            form = data[offset]
            offset += 1
            if form == 0x60:
                param_count = self._read_leb128(data, offset)
                offset += self._leb128_size(data[offset:])
                
                params = []
                for _ in range(param_count):
                    params.append(self._parse_valtype(data[offset]))
                    offset += 1
                
                return_count = self._read_leb128(data, offset)
                offset += self._leb128_size(data[offset:])
                
                returns = []
                for _ in range(return_count):
                    returns.append(self._parse_valtype(data[offset]))
                    offset += 1

    def _parse_valtype(self, byte: int) -> str:
        """解析值类型"""
        valtype_map = {
            0x7F: 'i32',
            0x7E: 'i64',
            0x7D: 'f32',
            0x7C: 'f64',
            0x7B: 'v128',
            0x70: 'anyfunc',
            0x60: 'func',
            0x40: 'empty'
        }
        return valtype_map.get(byte, 'unknown')

    def _parse_import_section(self, data: bytes):
        """解析导入段"""
        offset = 0
        count = self._read_leb128(data, offset)
        offset += self._leb128_size(data[offset:])
        
        for i in range(count):
            module_len = self._read_leb128(data, offset)
            offset += self._leb128_size(data[offset:])
            module_name = data[offset:offset + module_len].decode('utf-8')
            offset += module_len
            
            name_len = self._read_leb128(data, offset)
            offset += self._leb128_size(data[offset:])
            name = data[offset:offset + name_len].decode('utf-8')
            offset += name_len
            
            kind = data[offset]
            offset += 1
            
            import_info = {
                'index': i,
                'module': module_name,
                'name': name,
                'kind': WasmExternalKind(kind).name.lower(),
                'type': {}
            }
            
            if kind == WasmExternalKind.FUNCTION.value:
                type_idx = self._read_leb128(data, offset)
                offset += self._leb128_size(data[offset:])
                import_info['type']['function_type'] = type_idx
                
                func = WasmFunction(
                    name=name,
                    index=len(self.functions),
                    params=[],
                    returns=[],
                    is_import=True,
                    import_module=module_name,
                    import_name=name
                )
                self.functions.append(func)
                
            elif kind == WasmExternalKind.TABLE.value:
                elem_type = self._parse_valtype(data[offset])
                offset += 1
                limits = self._parse_limits(data, offset)
                offset += 2 if limits['has_max'] else 1
                import_info['type']['element_type'] = elem_type
                import_info['type']['limits'] = limits
                
                table = WasmTable(
                    index=len(self.tables),
                    element_type=elem_type,
                    initial_size=limits['min'],
                    max_size=limits['max'] if limits['has_max'] else None,
                    is_import=True,
                    import_module=module_name,
                    import_name=name
                )
                self.tables.append(table)
                
            elif kind == WasmExternalKind.MEMORY.value:
                limits = self._parse_limits(data, offset)
                offset += 2 if limits['has_max'] else 1
                import_info['type']['limits'] = limits
                
                mem = WasmMemory(
                    index=len(self.memories),
                    initial_pages=limits['min'],
                    max_pages=limits['max'] if limits['has_max'] else None,
                    is_import=True,
                    import_module=module_name,
                    import_name=name
                )
                self.memories.append(mem)
                
            elif kind == WasmExternalKind.GLOBAL.value:
                val_type = self._parse_valtype(data[offset])
                offset += 1
                mutable = data[offset] == 1
                offset += 1
                import_info['type']['value_type'] = val_type
                import_info['type']['mutable'] = mutable
                
                global_ = WasmGlobal(
                    name=name,
                    index=len(self.globals),
                    value_type=val_type,
                    mutable=mutable,
                    is_import=True,
                    import_module=module_name,
                    import_name=name
                )
                self.globals.append(global_)
            
            self.imports.append(import_info)

    def _parse_limits(self, data: bytes, offset: int) -> Dict[str, Any]:
        """解析 limits 结构"""
        has_max = data[offset] & 0x01
        min_val = self._read_leb128(data, offset + 1)
        result = {'min': min_val, 'has_max': bool(has_max)}
        
        if has_max:
            max_val = self._read_leb128(data, offset + 2)
            result['max'] = max_val
        
        return result

    def _parse_function_section(self, data: bytes):
        """解析函数段"""
        offset = 0
        count = self._read_leb128(data, offset)
        offset += self._leb128_size(data[offset:])
        
        for _ in range(count):
            type_idx = self._read_leb128(data, offset)
            offset += self._leb128_size(data[offset:])
            
            func = WasmFunction(
                name=f'func_{len(self.functions)}',
                index=len(self.functions),
                params=[],
                returns=[],
                is_import=False
            )
            self.functions.append(func)

    def _parse_global_section(self, data: bytes):
        """解析全局变量段"""
        offset = 0
        count = self._read_leb128(data, offset)
        offset += self._leb128_size(data[offset:])
        
        for _ in range(count):
            val_type = self._parse_valtype(data[offset])
            offset += 1
            mutable = data[offset] == 1
            offset += 1
            
            offset = self._skip_const_expression(data, offset)
            
            global_ = WasmGlobal(
                name=f'global_{len(self.globals)}',
                index=len(self.globals),
                value_type=val_type,
                mutable=mutable,
                is_import=False
            )
            self.globals.append(global_)

    def _skip_const_expression(self, data: bytes, offset: int) -> int:
        """跳过常量表达式"""
        while offset < len(data):
            opcode = data[offset]
            offset += 1
            
            if opcode == 0x41:
                offset += self._leb128_size(data[offset:])
            elif opcode == 0x42:
                offset += 8
            elif opcode == 0x43:
                offset += 4
            elif opcode == 0x44:
                offset += 8
            elif opcode == 0x0B:
                break
        
        return offset

    def _parse_export_section(self, data: bytes):
        """解析导出段"""
        offset = 0
        count = self._read_leb128(data, offset)
        offset += self._leb128_size(data[offset:])
        
        for i in range(count):
            name_len = self._read_leb128(data, offset)
            offset += self._leb128_size(data[offset:])
            name = data[offset:offset + name_len].decode('utf-8')
            offset += name_len
            
            kind = data[offset]
            offset += 1
            
            idx = self._read_leb128(data, offset)
            offset += self._leb128_size(data[offset:])
            
            export_info = {
                'index': i,
                'name': name,
                'kind': WasmExternalKind(kind).name.lower(),
                'internal_index': idx
            }
            
            if kind == WasmExternalKind.FUNCTION.value and idx < len(self.functions):
                self.functions[idx].name = name
            elif kind == WasmExternalKind.GLOBAL.value and idx < len(self.globals):
                self.globals[idx].name = name
            
            self.exports.append(export_info)

    def _parse_start_section(self, data: bytes):
        """解析起始函数段"""
        pass

    def _parse_element_section(self, data: bytes):
        """解析元素段"""
        pass

    def _parse_code_section(self, data: bytes):
        """解析代码段"""
        offset = 0
        count = self._read_leb128(data, offset)
        offset += self._leb128_size(data[offset:])
        
        for func_idx in range(count):
            body_size = self._read_leb128(data, offset)
            offset += self._leb128_size(data[offset:])
            
            local_count = self._read_leb128(data, offset)
            offset += self._leb128_size(data[offset:])
            
            locals = []
            for _ in range(local_count):
                local_type = self._parse_valtype(data[offset])
                offset += 1
                local_num = self._read_leb128(data, offset)
                offset += self._leb128_size(data[offset:])
                locals.append((local_type, local_num))
            
            code_end = offset + body_size - self._leb128_size(data[offset:]) - 1
            
            instructions = []
            while offset < code_end:
                opcode = data[offset]
                instr_info = {'opcode': opcode, 'name': self._get_opcode_name(opcode)}
                
                if opcode in [0x28, 0x29, 0x2A, 0x2B]:
                    instr_info['align'] = data[offset + 1]
                    instr_info['offset'] = self._read_leb128(data, offset + 2)
                    offset += 3 + self._leb128_size(data[offset + 2:])
                elif opcode in [0x36, 0x37, 0x38, 0x39]:
                    instr_info['align'] = data[offset + 1]
                    instr_info['offset'] = self._read_leb128(data, offset + 2)
                    instr_info['index'] = self._read_leb128(data, offset + 3)
                    offset += 4 + self._leb128_size(data[offset + 2:]) + self._leb128_size(data[offset + 3:])
                elif opcode == 0x10:
                    instr_info['index'] = self._read_leb128(data, offset + 1)
                    offset += 1 + self._leb128_size(data[offset + 1:])
                elif opcode == 0x11:
                    instr_info['index'] = self._read_leb128(data, offset + 1)
                    offset += 1 + self._leb128_size(data[offset + 1:])
                elif opcode in [0x41, 0x45]:
                    instr_info['value'] = self._read_leb128(data, offset + 1)
                    offset += 1 + self._leb128_size(data[offset + 1:])
                elif opcode in [0x42, 0x46]:
                    instr_info['value'] = int.from_bytes(data[offset + 1:offset + 9], 'little')
                    offset += 9
                elif opcode in [0x43]:
                    instr_info['value'] = int.from_bytes(data[offset + 1:offset + 5], 'little')
                    offset += 5
                elif opcode in [0x44]:
                    instr_info['value'] = int.from_bytes(data[offset + 1:offset + 9], 'little')
                    offset += 9
                else:
                    offset += 1
                
                instructions.append(instr_info)
            
            code_section = WasmCodeSection(
                function_index=func_idx,
                locals=locals,
                instructions=instructions
            )
            self.code_sections.append(code_section)

    def _get_opcode_name(self, opcode: int) -> str:
        """获取操作码名称"""
        opcode_map = {
            0x00: 'unreachable',
            0x01: 'nop',
            0x02: 'block',
            0x03: 'loop',
            0x04: 'if',
            0x05: 'else',
            0x0B: 'end',
            0x0C: 'br',
            0x0D: 'br_if',
            0x0E: 'br_table',
            0x0F: 'return',
            0x10: 'call',
            0x11: 'call_indirect',
            0x1A: 'drop',
            0x1B: 'select',
            0x28: 'i32.load',
            0x29: 'i64.load',
            0x2A: 'f32.load',
            0x2B: 'f64.load',
            0x2C: 'i32.load8_s',
            0x2D: 'i32.load8_u',
            0x2E: 'i32.load16_s',
            0x2F: 'i32.load16_u',
            0x30: 'i64.load8_s',
            0x31: 'i64.load8_u',
            0x32: 'i64.load16_s',
            0x33: 'i64.load16_u',
            0x34: 'i64.load32_s',
            0x35: 'i64.load32_u',
            0x36: 'i32.store',
            0x37: 'i64.store',
            0x38: 'f32.store',
            0x39: 'f64.store',
            0x3A: 'i32.store8',
            0x3B: 'i32.store16',
            0x3C: 'i64.store8',
            0x3D: 'i64.store16',
            0x3E: 'i64.store32',
            0x3F: 'memory.size',
            0x40: 'memory.grow',
            0x41: 'i32.const',
            0x42: 'i64.const',
            0x43: 'f32.const',
            0x44: 'f64.const',
            0x6A: 'i32.add',
            0x6B: 'i32.sub',
            0x6C: 'i32.mul',
            0x6D: 'i32.div_s',
            0x6E: 'i32.div_u',
            0x6F: 'i32.rem_s',
            0x70: 'i32.rem_u',
            0x71: 'i32.and',
            0x72: 'i32.or',
            0x73: 'i32.xor',
            0x74: 'i32.shl',
            0x75: 'i32.shr_s',
            0x76: 'i32.shr_u',
            0x77: 'i32.rotl',
            0x78: 'i32.rotr',
            0x7C: 'i32.eqz',
            0x7D: 'i32.eq',
            0x7E: 'i32.ne',
            0x7F: 'i32.lt_s',
            0x80: 'i32.lt_u',
            0x81: 'i32.gt_s',
            0x82: 'i32.gt_u',
            0x83: 'i32.le_s',
            0x84: 'i32.le_u',
            0x85: 'i32.ge_s',
            0x86: 'i32.ge_u',
        }
        return opcode_map.get(opcode, f'unknown_0x{opcode:02x}')

    def _parse_data_section(self, data: bytes):
        """解析数据段"""
        offset = 0
        count = self._read_leb128(data, offset)
        offset += self._leb128_size(data[offset:])
        
        for i in range(count):
            memory_idx = self._read_leb128(data, offset)
            offset += self._leb128_size(data[offset:])
            
            offset = self._skip_const_expression(data, offset)
            
            data_len = self._read_leb128(data, offset)
            offset += self._leb128_size(data[offset:])
            
            segment_data = data[offset:offset + data_len]
            offset += data_len
            
            data_segment = WasmDataSegment(
                index=i,
                offset_expression=[],
                data=segment_data,
                memory_index=memory_idx
            )
            self.data_segments.append(data_segment)

    def _parse_data_count_section(self, data: bytes):
        """解析数据计数段"""
        pass

    def _convert_to_wat(self):
        """将 WASM 转换为 WAT 格式"""
        try:
            result = subprocess.run(
                ['wasm2wat', self.wasm_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                self.wat_content = result.stdout
                logger.info("WASM 转换为 WAT 成功")
            else:
                logger.warning(f"WASM 转换失败: {result.stderr}")
        except Exception as e:
            logger.error(f"转换 WASM 为 WAT 时出错: {e}")

    def _analyze_risks(self):
        """分析潜在安全风险"""
        self.risk_assessments = []
        
        self._check_call_indirect_risks()
        self._check_memory_access_risks()
        self._check_table_risks()
        self._check_import_risks()

    def _check_call_indirect_risks(self):
        """检查 call_indirect 风险"""
        call_indirect_count = 0
        
        for code_section in self.code_sections:
            for instr in code_section.instructions:
                if instr.get('name') == 'call_indirect':
                    call_indirect_count += 1
                    
        if call_indirect_count > 0:
            has_imported_table = any(t.is_import for t in self.tables)
            
            if has_imported_table:
                self.risk_assessments.append(WasmRisk(
                    type='call_indirect_with_imported_table',
                    description='使用 call_indirect 但函数表是从外部导入的，可能被恶意 JavaScript 控制',
                    severity='High',
                    location='导入表',
                    confidence=0.85,
                    details={'call_indirect_count': call_indirect_count}
                ))
            else:
                self.risk_assessments.append(WasmRisk(
                    type='call_indirect_usage',
                    description='使用 call_indirect 指令，如果表索引可被控制可能导致函数表劫持',
                    severity='Medium',
                    location='代码段',
                    confidence=0.7,
                    details={'call_indirect_count': call_indirect_count}
                ))

    def _check_memory_access_risks(self):
        """检查内存访问风险"""
        memory_access_count = 0
        unchecked_access_count = 0
        
        for code_section in self.code_sections:
            for instr in code_section.instructions:
                if 'load' in instr.get('name', '') or 'store' in instr.get('name', ''):
                    memory_access_count += 1
                    
                    if instr.get('name') in ['i32.load', 'i32.store']:
                        prev_instrs = []
                        for idx, prev in enumerate(code_section.instructions):
                            if prev == instr:
                                prev_instrs = code_section.instructions[max(0, idx-3):idx]
                                break
                        
                        has_bound_check = False
                        for prev in prev_instrs:
                            if prev.get('name') in ['i32.lt_u', 'i32.le_u', 'i32.lt_s', 'i32.le_s', 'i32.eq', 'i32.ne']:
                                has_bound_check = True
                                break
                        
                        if not has_bound_check:
                            unchecked_access_count += 1
        
        if unchecked_access_count > 0:
            self.risk_assessments.append(WasmRisk(
                type='unchecked_memory_access',
                description=f'检测到 {unchecked_access_count} 次无边界检查的内存访问操作',
                severity='Medium',
                location='代码段',
                confidence=0.65,
                details={
                    'total_memory_access': memory_access_count,
                    'unchecked_access': unchecked_access_count
                }
            ))

    def _check_table_risks(self):
        """检查表相关风险"""
        for table in self.tables:
            if table.max_size is None or table.max_size > 1024:
                self.risk_assessments.append(WasmRisk(
                    type='large_or_unbounded_table',
                    description=f'表 {table.index} 的大小限制过大或无限制，可能被利用进行表溢出攻击',
                    severity='Low',
                    location=f'表 {table.index}',
                    confidence=0.5,
                    details={
                        'initial_size': table.initial_size,
                        'max_size': table.max_size,
                        'is_import': table.is_import
                    }
                ))

    def _check_import_risks(self):
        """检查导入函数风险"""
        dangerous_imports = []
        
        for imp in self.imports:
            if imp.get('kind') == 'function':
                module = imp.get('module', '')
                name = imp.get('name', '')
                
                if module == 'env' and name in ['memory', 'table', 'abort', 'trace']:
                    continue
                
                if module == 'globalThis' or 'document' in module.lower():
                    dangerous_imports.append(f'{module}.{name}')
        
        if dangerous_imports:
            self.risk_assessments.append(WasmRisk(
                type='dangerous_imports',
                description=f'导入了可能危险的外部函数: {", ".join(dangerous_imports)}',
                severity='Medium',
                location='导入段',
                confidence=0.75,
                details={'dangerous_imports': dangerous_imports}
            ))

    def get_basic_info(self) -> Dict[str, Any]:
        """获取基本信息"""
        return {
            'file_path': self.wasm_path,
            'size': len(self.raw_data),
            'num_imports': len(self.imports),
            'num_exports': len(self.exports),
            'num_functions': len(self.functions),
            'num_globals': len(self.globals),
            'num_memories': len(self.memories),
            'num_tables': len(self.tables),
            'num_data_segments': len(self.data_segments),
            'num_code_sections': len(self.code_sections)
        }

    def get_imports_info(self) -> List[Dict[str, Any]]:
        """获取导入信息"""
        result = []
        for imp in self.imports:
            result.append({
                'module': imp.get('module'),
                'name': imp.get('name'),
                'kind': imp.get('kind'),
                'type': imp.get('type', {})
            })
        return result

    def get_exports_info(self) -> List[Dict[str, Any]]:
        """获取导出信息"""
        result = []
        for exp in self.exports:
            result.append({
                'name': exp.get('name'),
                'kind': exp.get('kind'),
                'internal_index': exp.get('internal_index')
            })
        return result

    def get_functions_info(self) -> List[Dict[str, Any]]:
        """获取函数信息"""
        result = []
        for func in self.functions:
            result.append({
                'name': func.name,
                'index': func.index,
                'params': func.params,
                'returns': func.returns,
                'is_import': func.is_import,
                'import_module': func.import_module
            })
        return result

    def get_memory_info(self) -> List[Dict[str, Any]]:
        """获取内存信息"""
        result = []
        for mem in self.memories:
            result.append({
                'index': mem.index,
                'initial_pages': mem.initial_pages,
                'max_pages': mem.max_pages,
                'is_import': mem.is_import,
                'import_module': mem.import_module,
                'initial_size_bytes': mem.initial_pages * 65536,
                'max_size_bytes': mem.max_pages * 65536 if mem.max_pages else None
            })
        return result

    def get_table_info(self) -> List[Dict[str, Any]]:
        """获取表信息"""
        result = []
        for table in self.tables:
            result.append({
                'index': table.index,
                'element_type': table.element_type,
                'initial_size': table.initial_size,
                'max_size': table.max_size,
                'is_import': table.is_import,
                'import_module': table.import_module
            })
        return result

    def get_risk_summary(self) -> Dict[str, Any]:
        """获取风险摘要"""
        summary = {
            'total_risks': len(self.risk_assessments),
            'high_severity': [],
            'medium_severity': [],
            'low_severity': []
        }
        
        for risk in self.risk_assessments:
            if risk.severity == 'High':
                summary['high_severity'].append({
                    'type': risk.type,
                    'description': risk.description,
                    'location': risk.location,
                    'confidence': risk.confidence
                })
            elif risk.severity == 'Medium':
                summary['medium_severity'].append({
                    'type': risk.type,
                    'description': risk.description,
                    'location': risk.location,
                    'confidence': risk.confidence
                })
            else:
                summary['low_severity'].append({
                    'type': risk.type,
                    'description': risk.description,
                    'location': risk.location,
                    'confidence': risk.confidence
                })
        
        return summary

    def get_analysis_report(self) -> Dict[str, Any]:
        """获取完整分析报告"""
        return {
            'basic_info': self.get_basic_info(),
            'imports': self.get_imports_info(),
            'exports': self.get_exports_info(),
            'functions': self.get_functions_info(),
            'memories': self.get_memory_info(),
            'tables': self.get_table_info(),
            'risk_summary': self.get_risk_summary(),
            'has_wat': self.wat_content is not None
        }

    def get_wat_content(self) -> Optional[str]:
        """获取 WAT 内容"""
        return self.wat_content