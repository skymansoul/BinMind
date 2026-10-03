"""WASM 沙箱逃逸分析 —— 导入解析、污点传播与危险导入识别。

解析 WASM 二进制中的 import 段，对导入函数参数做污点标记，
识别可能用于沙箱逃逸的危险宿主导入（system/exec/open 等）。
"""

import os
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class WasmImport:
    """WASM 导入函数声明。"""
    module: str = ""
    name: str = ""
    params: List[str] = field(default_factory=list)
    returns: List[str] = field(default_factory=list)


@dataclass
class TaintedParam:
    """被污点标记的导入参数。"""
    import_name: str = ""
    param_index: int = 0
    reachable_functions: Set[int] = field(default_factory=set)


@dataclass
class SandboxEscape:
    """潜在沙箱逃逸路径。"""
    entry_point: int = 0
    import_used: str = ""
    escape_path: List[int] = field(default_factory=list)
    severity: str = "low"


@dataclass
class WasmAnalysisResult:
    """WASM 分析结果汇总。"""
    success: bool = False
    imports: List[WasmImport] = field(default_factory=list)
    tainted_params: List[TaintedParam] = field(default_factory=list)
    escapes: List[SandboxEscape] = field(default_factory=list)


_WASM_MAGIC = b"\x00asm"
_WASM_VERSION = b"\x01\x00\x00\x00"

_DANGEROUS_IMPORTS = {"system", "exec", "popen", "fork", "execl"}
_MEDIUM_IMPORTS = {"open", "write", "read", "fopen", "remove"}


class WasmParser:
    """WASM 二进制导入段解析器。"""

    MAGIC = _WASM_MAGIC
    VERSION = _WASM_VERSION

    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def parse(self) -> List[WasmImport]:
        """解析 import 段，返回导入函数列表。"""
        if not os.path.isfile(self.binary_path):
            return []
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
        except OSError:
            return []
        if not data.startswith(self.MAGIC) or data[4:8] != self.VERSION:
            return []
        return self._parse_imports(data)

    def _parse_imports(self, data: bytes) -> List[WasmImport]:
        """从 type 段与 import 段提取导入函数。"""
        imports: List[WasmImport] = []
        type_map: Dict[int, List[List[str]]] = {}
        idx = 8
        try:
            while idx < len(data):
                section_id = data[idx]
                idx += 1
                size = self._read_varuint(data, idx)
                idx += size[1]
                end = idx + size[0]
                if section_id == 1:  # type section
                    count = self._read_varuint(data, idx)[0]
                    idx = self._read_varuint(data, idx)[1]
                    for _ in range(count):
                        form = data[idx]
                        idx += 1
                        if form != 0x60:
                            continue
                        param_count = self._read_varuint(data, idx)[0]
                        idx = self._read_varuint(data, idx)[1]
                        params = []
                        for _ in range(param_count):
                            params.append(str(data[idx]))
                            idx += 1
                        result_count = self._read_varuint(data, idx)[0]
                        idx = self._read_varuint(data, idx)[1]
                        results = [str(data[idx + i]) for i in range(result_count)]
                        idx += result_count
                        type_map[len(type_map)] = [params, results]
                elif section_id == 2:  # import section
                    count = self._read_varuint(data, idx)[0]
                    idx = self._read_varuint(data, idx)[1]
                    for _ in range(count):
                        module_len = self._read_varuint(data, idx)[0]
                        idx = self._read_varuint(data, idx)[1]
                        module = data[idx:idx + module_len].decode('utf-8', 'replace')
                        idx += module_len
                        name_len = self._read_varuint(data, idx)[0]
                        idx = self._read_varuint(data, idx)[1]
                        name = data[idx:idx + name_len].decode('utf-8', 'replace')
                        idx += name_len
                        kind = data[idx]
                        idx += 1
                        if kind == 0:  # function import
                            type_idx = self._read_varuint(data, idx)[0]
                            idx = self._read_varuint(data, idx)[1]
                            params, results = type_map.get(type_idx, ([], []))
                            imports.append(WasmImport(
                                module=module, name=name,
                                params=params, returns=results,
                            ))
                        elif kind == 2:  # memory/table/global skip
                            if kind == 2:
                                idx += 1
                idx = end
        except (IndexError, struct.error, ValueError):
            pass
        return imports

    @staticmethod
    def _read_varuint(data: bytes, idx: int):
        """读取 LEB128 变长无符号整数，返回 (值, 新索引)。"""
        result = 0
        shift = 0
        while idx < len(data):
            byte = data[idx]
            idx += 1
            result |= (byte & 0x7f) << shift
            if not (byte & 0x80):
                break
            shift += 7
        return result, idx


class TaintPropagator:
    """导入参数污点传播 —— 每个参数生成一条污点记录。"""

    def __init__(self, imports: List[WasmImport]):
        self.imports = imports

    def propagate(self) -> List[TaintedParam]:
        """为每个导入参数的每个位置生成污点标记。"""
        tainted = []
        for imp in self.imports:
            for index in range(len(imp.params)):
                tainted.append(TaintedParam(
                    import_name=imp.name,
                    param_index=index,
                    reachable_functions=set(),
                ))
        return tainted


class EscapeDetector:
    """危险宿主导入识别。"""

    @staticmethod
    def detect(imports: List[WasmImport]) -> List[SandboxEscape]:
        """按导入名匹配危险级别并生成逃逸候选。"""
        escapes = []
        for idx, imp in enumerate(imports):
            name = imp.name.lower()
            if name in _DANGEROUS_IMPORTS:
                escapes.append(SandboxEscape(
                    entry_point=0x1000 + idx,
                    import_used=imp.name,
                    escape_path=[0x1000 + idx],
                    severity="high",
                ))
            elif name in _MEDIUM_IMPORTS:
                escapes.append(SandboxEscape(
                    entry_point=0x1000 + idx,
                    import_used=imp.name,
                    escape_path=[0x1000 + idx],
                    severity="medium",
                ))
        return escapes


class WasmSandboxAnalyzer:
    """WASM 沙箱逃逸分析器。"""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.parser = WasmParser(binary_path)

    def run(self) -> WasmAnalysisResult:
        """执行解析、污点传播与逃逸识别。"""
        imports = self.parser.parse()
        if not imports:
            return WasmAnalysisResult(success=False)

        propagator = TaintPropagator(imports)
        tainted = propagator.propagate()
        escapes = EscapeDetector.detect(imports)

        return WasmAnalysisResult(
            success=True,
            imports=imports,
            tainted_params=tainted,
            escapes=escapes,
        )


def create_wasm_analyzer(binary_path: str) -> WasmSandboxAnalyzer:
    """便捷入口: 创建 WASM 沙箱分析器。"""
    return WasmSandboxAnalyzer(binary_path)
