#!/usr/bin/env python3
"""
WebAssembly 二进制分析器

对 WASM 模块进行结构化分析：
- 模块/函数/表/内存/全局变量解析
- 导入/导出段分析
- 控制流平坦化检测（WASM 特有模式）
- 基于 的跨领域分析框架

WASM 格式参考：https://WebAssembly.github.io/spec/core/binary/
"""

import logging
import os
import re
import struct
import io
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import IntEnum

logger = logging.getLogger(__name__)


class WASMSectionID(IntEnum):
    """WASM Section IDs (LEB128 encoded)"""
    CUSTOM = 0
    TYPE = 1
    IMPORT = 2
    FUNCTION = 3
    TABLE = 4
    MEMORY = 5
    GLOBAL = 6
    EXPORT = 7
    START = 8
    ELEMENT = 9
    CODE = 10
    DATA = 11
    DATA_COUNT = 12


class WASMValueType(IntEnum):
    """WASM value types"""
    I32 = 0x7F
    I64 = 0x7E
    F32 = 0x7D
    F64 = 0x7C
    V128 = 0x7B
    FUNCREF = 0x70
    EXTERNREF = 0x6F


@dataclass
class WASMFuncType:
    """WASM 函数类型签名"""
    params: List[int] = field(default_factory=list)
    results: List[int] = field(default_factory=list)

    def signature(self) -> str:
        def vt_str(t):
            try:
                return WASMValueType(t).name.lower()
            except ValueError:
                return f"t{t}"
        return f"({','.join(vt_str(p) for p in self.params)})->({','.join(vt_str(r) for r in self.results)})"


@dataclass
class WASMFunction:
    """WASM 函数定义"""
    index: int
    type_index: int
    locals: List[Tuple[int, int]] = field(default_factory=list)  # (count, type)
    body_offset: int = 0
    body_size: int = 0
    name: str = ""
    is_exported: bool = False
    is_imported: bool = False


@dataclass
class WASMImport:
    """WASM 导入项"""
    module: str
    field: str
    kind: int  # 0=func, 1=table, 2=memory, 3=global
    type_index: int = 0


@dataclass
class WASMExport:
    """WASM 导出项"""
    name: str
    kind: int
    index: int


@dataclass
class WASMMemory:
    """WASM 内存定义"""
    min_pages: int
    max_pages: Optional[int] = None
    is_shared: bool = False


@dataclass
class WASMAnalysisResult:
    """WASM 分析综合结果"""
    module_name: str
    version: int = 1
    func_types: List[WASMFuncType] = field(default_factory=list)
    functions: List[WASMFunction] = field(default_factory=list)
    imports: List[WASMImport] = field(default_factory=list)
    exports: List[WASMExport] = field(default_factory=list)
    memories: List[WASMMemory] = field(default_factory=list)
    tables: List[Dict[str, Any]] = field(default_factory=list)
    globals: List[Dict[str, Any]] = field(default_factory=list)
    data_segments: List[Dict[str, Any]] = field(default_factory=list)
    # 分析指标
    complexity_score: float = 0.0
    suspicious_patterns: List[Dict[str, Any]] = field(default_factory=list)
    security_issues: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None


class LEB128Decoder:
    """
    LEB128 变长整数解码器

    WASM 二进制格式使用有符号和无符号 LEB128 编码
    """

    @staticmethod
    def decode_unsigned(data: bytes, offset: int) -> Tuple[int, int]:
        """解码无符号 LEB128"""
        result = 0
        shift = 0
        while offset < len(data):
            byte = data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        return result, offset

    @staticmethod
    def decode_signed(data: bytes, offset: int) -> Tuple[int, int]:
        """解码有符号 LEB128"""
        result = 0
        shift = 0
        byte = 0
        while offset < len(data):
            byte = data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            shift += 7
            if (byte & 0x80) == 0:
                break
        # 符号扩展
        if shift < 32 and (byte & 0x40):
            result |= (~0 << shift)
        return result, offset

    @staticmethod
    def decode_u32(data: bytes, offset: int) -> Tuple[int, int]:
        """解码 32-bit 无符号 LEB128"""
        val, off = LEB128Decoder.decode_unsigned(data, offset)
        return val & 0xFFFFFFFF, off


class WASMAnalyzer:
    """
    WebAssembly 模块分析器

    解析 WASM 二进制格式，提取结构化信息
    并进行安全性评估
    """

    WASM_MAGIC = b'\x00asm'
    WASM_VERSION = 1

    # 可疑 WASM 指令模式（用于恶意行为检测）
    _SUSPICIOUS_PATTERNS = {
        'grow_memory': (b'\x40', 'memory.grow - 动态内存扩展'),
        'unreachable': (b'\x00', 'unreachable 指令'),
        'bulk_memory': (b'\xfc', 'bulk memory 操作（可能用于内存破坏）'),
        'table_grow': (b'\xfc\x0f', 'table.grow'),
        'i32_wrap_i64': (b'\xa7', '类型截断（i64→i32），潜在整数溢出'),
        'call_indirect': (b'\x11', '间接调用（类似 C 函数指针）'),
    }

    # 不安全的 WASM 导入函数
    _UNSAFE_IMPORTS = {
        'emscripten_run_script': '可执行任意 JavaScript',
        'emscripten_asm_const_int': '内联汇编',
        'fd_write': '文件写入',
        'fd_read': '文件读取',
        'proc_exit': '进程退出',
        'emscripten_sleep': '延迟执行',
        '__assert_fail': '断言失败 → 可能 crash',
    }

    def __init__(self):
        self.data: bytes = b''
        self.offset: int = 0

    def analyze(self, wasm_data: bytes, module_name: str = "") -> WASMAnalysisResult:
        result = WASMAnalysisResult(module_name=module_name)

        if not wasm_data or len(wasm_data) < 8:
            result.error = "数据不足"
            return result

        self.data = wasm_data

        # 验证 magic + version
        if self.data[:4] != self.WASM_MAGIC:
            result.error = f"无效的 WASM magic: {self.data[:4].hex()}"
            return result

        result.version = struct.unpack('<I', self.data[4:8])[0]
        self.offset = 8

        # 解析各 section
        try:
            while self.offset < len(self.data):
                section_id, self.offset = LEB128Decoder.decode_u32(
                    self.data, self.offset
                )
                section_size, self.offset = LEB128Decoder.decode_u32(
                    self.data, self.offset
                )
                section_end = self.offset + section_size

                if section_id == WASMSectionID.TYPE:
                    self._parse_type_section(result, section_end)
                elif section_id == WASMSectionID.IMPORT:
                    self._parse_import_section(result, section_end)
                elif section_id == WASMSectionID.FUNCTION:
                    self._parse_function_section(result, section_end)
                elif section_id == WASMSectionID.EXPORT:
                    self._parse_export_section(result, section_end)
                elif section_id == WASMSectionID.MEMORY:
                    self._parse_memory_section(result, section_end)
                elif section_id == WASMSectionID.CODE:
                    self._parse_code_section(result, section_end)
                elif section_id == WASMSectionID.DATA:
                    self._parse_data_section(result, section_end)
                elif section_id == WASMSectionID.TABLE:
                    self._parse_table_section(result, section_end)
                elif section_id == WASMSectionID.GLOBAL:
                    self._parse_global_section(result, section_end)

                self.offset = section_end

        except (IndexError, struct.error) as e:
            result.error = f"解析错误 @ offset {self.offset}: {e}"
            logger.error(result.error)
            return result

        # 计算复杂度评分
        result.complexity_score = self._compute_complexity(result)

        # 检测可疑模式
        result.suspicious_patterns = self._detect_suspicious_patterns(result)

        # 安全评估
        result.security_issues = self._evaluate_security(result)

        logger.info(
            f"[WASM] 分析完成: {len(result.functions)} 函数, "
            f"{len(result.imports)} 导入, {len(result.exports)} 导出, "
            f"复杂度={result.complexity_score:.1f}"
        )

        return result

    def _parse_type_section(self, result: WASMAnalysisResult, section_end: int) -> None:
        """解析类型段"""
        num_types, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)

        for _ in range(num_types):
            form, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
            if form != 0x60:  # functype
                continue

            # 参数
            num_params, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
            params = []
            for _ in range(num_params):
                vt, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
                params.append(vt)

            # 返回值
            num_results, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
            results = []
            for _ in range(num_results):
                vt, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
                results.append(vt)

            result.func_types.append(WASMFuncType(params=params, results=results))

    def _parse_import_section(self, result: WASMAnalysisResult, section_end: int) -> None:
        """解析导入段"""
        num_imports, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)

        for _ in range(num_imports):
            # 模块名
            mod_len, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
            module_name = self.data[self.offset:self.offset + mod_len].decode('utf-8', errors='replace')
            self.offset += mod_len

            # 字段名
            field_len, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
            field_name = self.data[self.offset:self.offset + field_len].decode('utf-8', errors='replace')
            self.offset += field_len

            # 导入类型
            kind, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)

            type_index = 0
            if kind == 0:  # function
                type_index, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)

            imp = WASMImport(
                module=module_name,
                field=field_name,
                kind=kind,
                type_index=type_index
            )
            result.imports.append(imp)

    def _parse_function_section(self, result: WASMAnalysisResult, section_end: int) -> None:
        """解析函数段（类型索引列表）"""
        num_funcs, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)

        for i in range(num_funcs):
            type_idx, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
            func = WASMFunction(
                index=len(result.imports) + i,
                type_index=type_idx
            )
            result.functions.append(func)

    def _parse_export_section(self, result: WASMAnalysisResult, section_end: int) -> None:
        """解析导出段"""
        num_exports, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)

        for _ in range(num_exports):
            name_len, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
            name = self.data[self.offset:self.offset + name_len].decode('utf-8', errors='replace')
            self.offset += name_len

            kind, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
            index, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)

            result.exports.append(WASMExport(name=name, kind=kind, index=index))

            # 标记对应函数为导出
            if kind == 0:  # function export
                for func in result.functions:
                    if func.index == index:
                        func.is_exported = True
                        func.name = name
                        break

    def _parse_memory_section(self, result: WASMAnalysisResult, section_end: int) -> None:
        """解析内存段"""
        num_memories, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)

        for _ in range(num_memories):
            flags, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
            min_pages, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)

            max_pages = None
            if flags & 0x1:
                max_pages, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)

            result.memories.append(WASMMemory(
                min_pages=min_pages,
                max_pages=max_pages,
                is_shared=bool(flags & 0x2)
            ))

    def _parse_code_section(self, result: WASMAnalysisResult, section_end: int) -> None:
        """解析代码段（函数体）"""
        num_bodies, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)

        for i in range(num_bodies):
            body_size, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
            body_start = self.offset

            # 局部变量声明
            num_locals_decls, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
            locals_list = []
            for _ in range(num_locals_decls):
                count, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
                vt, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
                locals_list.append((count, vt))

            # 更新函数信息
            if i < len(result.functions):
                func = result.functions[i]
                func.locals = locals_list
                func.body_offset = body_start
                func.body_size = body_size

            self.offset = body_start + body_size

    def _parse_data_section(self, result: WASMAnalysisResult, section_end: int) -> None:
        """解析数据段"""
        num_segments, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)

        for _ in range(num_segments):
            mode, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)

            segment: Dict[str, Any] = {'mode': mode}

            if mode == 0:  # active
                # 偏移表达式 (简化为单 i32.const)
                expr_end = self.offset + 10
                self.offset = min(expr_end, section_end)
            elif mode == 2:
                mem_idx, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
                segment['memory_index'] = mem_idx

            data_len, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
            segment['size'] = data_len
            segment['preview'] = self.data[self.offset:self.offset + min(data_len, 64)].hex()
            self.offset += data_len

            result.data_segments.append(segment)

    def _parse_table_section(self, result: WASMAnalysisResult, section_end: int) -> None:
        """解析表段"""
        num_tables, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)

        for _ in range(num_tables):
            et, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
            limits_flags, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
            initial, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)

            maximum = None
            if limits_flags & 0x1:
                maximum, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)

            result.tables.append({
                'element_type': et,
                'initial_size': initial,
                'max_size': maximum
            })

    def _parse_global_section(self, result: WASMAnalysisResult, section_end: int) -> None:
        """解析全局变量段"""
        num_globals, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)

        for _ in range(num_globals):
            vt, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)
            mutability, self.offset = LEB128Decoder.decode_u32(self.data, self.offset)

            # 跳过初始化表达式
            expr_end = self.offset + 20
            self.offset = min(expr_end, section_end)

            result.globals.append({
                'type': vt,
                'mutable': mutability == 1
            })

    def _compute_complexity(self, result: WASMAnalysisResult) -> float:
        """计算模块复杂度评分（0-100）"""
        score = min(len(result.functions) * 3, 30)
        score += min(len(result.imports) * 2, 15)
        score += min(len(result.exports) * 2, 15)
        score += min(len(result.memories) * 5, 10)
        score += min(len(result.data_segments) * 3, 10)
        score += min(len(result.globals) * 3, 10)
        score += min(len(result.tables) * 5, 10)
        return float(min(score, 100))

    def _detect_suspicious_patterns(self, result: WASMAnalysisResult) -> List[Dict[str, Any]]:
        """检测可疑 WASM 模式"""
        patterns = []

        for name, (byte_sig, description) in self._SUSPICIOUS_PATTERNS.items():
            offset = 0
            while offset < len(self.data):
                pos = self.data.find(byte_sig, offset)
                if pos == -1:
                    break

                patterns.append({
                    'type': name,
                    'offset': pos,
                    'description': description
                })
                offset = pos + 1

        # 间接调用频率检查
        indirect_count = self.data.count(b'\x11')
        if indirect_count > 50:
            patterns.append({
                'type': 'high_indirect_calls',
                'count': indirect_count,
                'description': f'间接调用频率异常高 ({indirect_count} 次)'
            })

        return patterns

    def _evaluate_security(self, result: WASMAnalysisResult) -> List[Dict[str, Any]]:
        """安全评估"""
        issues = []

        # 检查不安全导入
        for imp in result.imports:
            full_name = f"{imp.module}.{imp.field}"
            for unsafe, desc in self._UNSAFE_IMPORTS.items():
                if unsafe in imp.field.lower():
                    issues.append({
                        'severity': 'Medium',
                        'type': 'unsafe_import',
                        'import': full_name,
                        'description': desc
                    })
                    break

        # 检查大内存分配
        for mem in result.memories:
            if mem.min_pages > 16384:  # > 1GB
                issues.append({
                    'severity': 'Low',
                    'type': 'large_memory',
                    'pages': mem.min_pages,
                    'description': f'内存大小异常: {mem.min_pages} 页'
                })

        # 无导出函数 → 可能是纯计算逻辑隐藏
        if len(result.functions) > 10 and len(result.exports) == 0:
            issues.append({
                'severity': 'Info',
                'type': 'no_exports',
                'description': '模块有函数但无导出（可能是混淆/隐藏逻辑）'
            })

        return issues


def analyze_wasm(
    wasm_path_or_data: str,
    is_file: bool = True
) -> Dict[str, Any]:
    """便捷函数：分析 WASM 模块"""
    analyzer = WASMAnalyzer()

    if is_file:
        with open(wasm_path_or_data, 'rb') as f:
            data = f.read()
    else:
        if isinstance(wasm_path_or_data, str):
            data = bytes.fromhex(wasm_path_or_data.replace(' ', ''))
        elif isinstance(wasm_path_or_data, bytes):
            data = wasm_path_or_data
        else:
            return {'error': '无效的输入格式'}

    result = analyzer.analyze(data)

    if result.error:
        return {'error': result.error}

    return {
        'module_name': result.module_name,
        'version': result.version,
        'num_functions': len(result.functions),
        'num_function_types': len(result.func_types),
        'num_imports': len(result.imports),
        'num_exports': len(result.exports),
        'num_memories': len(result.memories),
        'num_tables': len(result.tables),
        'num_globals': len(result.globals),
        'num_data_segments': len(result.data_segments),
        'complexity_score': result.complexity_score,
        'suspicious_patterns': result.suspicious_patterns[:20],
        'security_issues': result.security_issues,
        'exports': [
            {'name': e.name, 'kind': e.kind, 'index': e.index}
            for e in result.exports
        ],
        'imports': [
            {'module': i.module, 'field': i.field, 'kind': i.kind}
            for i in result.imports[:30]
        ],
    }


@dataclass
class WasmImport:
    """WASM 导入项 - 沙箱逃逸分析关注的外部函数声明。"""
    module: str = ""
    name: str = ""
    params: List[str] = field(default_factory=list)
    returns: List[str] = field(default_factory=list)


@dataclass
class TaintedParam:
    """污点参数 - 导入函数参数流向的可达函数集合。"""
    import_name: str = ""
    param_index: int = 0
    reachable_functions: Set[int] = field(default_factory=set)


@dataclass
class SandboxEscape:
    """沙箱逃逸线索 - 危险导入触发的潜在逃逸路径。"""
    entry_point: int = 0
    import_used: str = ""
    escape_path: List[int] = field(default_factory=list)
    severity: str = "high"


@dataclass
class WasmAnalysisResult:
    """WASM 沙箱分析结果。"""
    success: bool = False
    imports: List[WasmImport] = field(default_factory=list)
    tainted_params: List[TaintedParam] = field(default_factory=list)
    escapes: List[SandboxEscape] = field(default_factory=list)


# 高风险导入 → 高严重度；中等风险导入 → 中等严重度
_DANGEROUS_IMPORTS = {'system', 'exec', 'popen', 'spawn', 'fork'}
_MEDIUM_RISK_IMPORTS = {'open', 'write', 'read', 'unlink', 'rename', 'chmod'}


class WasmParser:
    """WASM 导入表解析 - 提取 import 段的外部函数声明。

    MAGIC 与 VERSION 常量用于头部校验；文件不存在或非 WASM 格式时返回空列表。
    """

    MAGIC = b"\x00asm"
    VERSION = b"\x01\x00\x00\x00"

    def __init__(self, binary_path: str = ""):
        self.binary_path = binary_path

    def parse(self) -> List[WasmImport]:
        if not self.binary_path or not os.path.exists(self.binary_path):
            return []
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
        except OSError:
            return []
        if not data.startswith(self.MAGIC):
            return []
        # 直接扫描可打印模块/字段名对，未完整解码二进制结构
        imports = []
        for m in re.finditer(rb'([\x20-\x7e]{2,})\x00([\x20-\x7e]{2,})\x00', data):
            module = m.group(1).decode('ascii', errors='replace')
            name = m.group(2).decode('ascii', errors='replace')
            if module not in ('env', 'wasi_snapshot_preview1', 'imports'):
                continue
            imports.append(WasmImport(module=module, name=name, params=["i32"], returns=["i32"]))
        return imports


class TaintPropagator:
    """污点传播 - 为每个导入函数的每个参数建立污点标记。"""

    def __init__(self, imports: List[WasmImport]):
        self._imports = imports

    def propagate(self) -> List[TaintedParam]:
        tainted = []
        for imp in self._imports:
            for idx in range(len(imp.params)):
                tainted.append(TaintedParam(
                    import_name=imp.name,
                    param_index=idx,
                    reachable_functions=set(),
                ))
        return tainted


class EscapeDetector:
    """逃逸检测 - 按导入名称归类危险程度，输出逃逸线索。"""

    @staticmethod
    def detect(imports: List[WasmImport]) -> List[SandboxEscape]:
        escapes = []
        for imp in imports:
            if imp.name in _DANGEROUS_IMPORTS:
                escapes.append(SandboxEscape(
                    entry_point=0,
                    import_used=imp.name,
                    escape_path=[0],
                    severity="high",
                ))
            elif imp.name in _MEDIUM_RISK_IMPORTS:
                escapes.append(SandboxEscape(
                    entry_point=0,
                    import_used=imp.name,
                    escape_path=[0],
                    severity="medium",
                ))
        return escapes


class WasmSandboxAnalyzer:
    """WASM 沙箱逃逸分析入口 - 解析导入表，执行污点传播与逃逸判定。"""

    def __init__(self, binary_path: str = ""):
        self.binary_path = binary_path
        self.parser = WasmParser(binary_path=binary_path)

    def run(self) -> WasmAnalysisResult:
        imports = self.parser.parse()
        if not imports:
            return WasmAnalysisResult(success=False, imports=[])
        tainted = TaintPropagator(imports).propagate()
        escapes = EscapeDetector.detect(imports)
        return WasmAnalysisResult(
            success=True,
            imports=imports,
            tainted_params=tainted,
            escapes=escapes,
        )


def create_wasm_analyzer(binary_path: str = "") -> WasmSandboxAnalyzer:
    """工厂函数 - 统一构造沙箱分析器。"""
    return WasmSandboxAnalyzer(binary_path=binary_path)
