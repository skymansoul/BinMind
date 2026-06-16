"""
WebAssembly WASI 组件分析模块

功能：
1. WASM 二进制解析
2. WASI 组件分析
3. 漏洞检测
"""

import struct
import logging
import hashlib
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class SectionType(Enum):
    """WASM Section 类型"""
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


@dataclass
class TypeEntry:
    """类型定义"""
    form: int
    param_types: List[int]
    return_type: Optional[int]


@dataclass
class Function:
    """函数定义"""
    type_idx: int
    local_count: int
    local_types: List[int]
    code_size: int


@dataclass
class Export:
    """导出项"""
    name: str
    kind: int
    index: int


@dataclass
class Import:
    """导入项"""
    module: str
    name: str
    kind: int
    index: int


@dataclass
class Global:
    """全局变量"""
    type: int
    mut: bool
    init: List[int]


@dataclass
class Table:
    """表定义"""
    elem_type: int
    flags: int
    initial: int
    maximum: Optional[int]


@dataclass
class Memory:
    """内存定义"""
    flags: int
    initial: int
    maximum: Optional[int]


@dataclass
class WasmAnalysisResult:
    """分析结果"""
    version: int
    functions: List[Function] = field(default_factory=list)
    types: List[TypeEntry] = field(default_factory=list)
    exports: List[Export] = field(default_factory=list)
    imports: List[Import] = field(default_factory=list)
    globals: List[Global] = field(default_factory=list)
    tables: List[Table] = field(default_factory=list)
    memories: List[Memory] = field(default_factory=list)
    custom_sections: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)


class WasmParser:
    """
    WebAssembly 二进制解析器
    
    解析 WASM 文件结构
    """
    
    WASM_MAGIC = b'\x00asm'
    
    def __init__(self, data: bytes):
        """
        初始化解析器
        
        Args:
            data: WASM 文件数据
        """
        self.data = data
        self.offset = 0
        self.result = WasmAnalysisResult(version=0)
    
    def _read_byte(self) -> int:
        """读取一个字节"""
        if self.offset >= len(self.data):
            return 0
        byte = self.data[self.offset]
        self.offset += 1
        return byte
    
    def _read_bytes(self, count: int) -> bytes:
        """读取多个字节"""
        if self.offset + count > len(self.data):
            return b''
        result = self.data[self.offset:self.offset + count]
        self.offset += count
        return result
    
    def _read_varuint(self) -> int:
        """读取无符号变长整数"""
        result = 0
        shift = 0
        while True:
            byte = self._read_byte()
            result |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                break
            shift += 7
        return result
    
    def _read_varsint(self) -> int:
        """读取有符号变长整数"""
        result = 0
        shift = 0
        while True:
            byte = self._read_byte()
            result |= (byte & 0x7F) << shift
            shift += 7
            if not (byte & 0x80):
                break
        
        if shift < 64 and (result & (1 << (shift - 1))):
            result -= (1 << shift)
        
        return result
    
    def _read_name(self) -> str:
        """读取名称（UTF-8）"""
        length = self._read_varuint()
        name_bytes = self._read_bytes(length)
        return name_bytes.decode('utf-8', errors='replace')
    
    def _read_type_entry(self) -> TypeEntry:
        """读取类型定义"""
        form = self._read_byte()
        param_count = self._read_varuint()
        param_types = [self._read_byte() for _ in range(param_count)]
        return_count = self._read_varuint()
        return_type = self._read_byte() if return_count > 0 else None
        
        return TypeEntry(
            form=form,
            param_types=param_types,
            return_type=return_type
        )
    
    def parse_header(self) -> bool:
        """解析 WASM 头部"""
        magic = self._read_bytes(4)
        if magic != self.WASM_MAGIC:
            logger.error(f"无效的 WASM 文件魔数: {magic}")
            return False
        
        version = struct.unpack('<I', self._read_bytes(4))[0]
        self.result.version = version
        
        logger.info(f"WASM 版本: {version}")
        return True
    
    def parse_sections(self) -> None:
        """解析所有段"""
        while self.offset < len(self.data):
            section_id = self._read_byte()
            
            if section_id == 0:
                self._parse_custom_section()
            elif section_id == 1:
                self._parse_type_section()
            elif section_id == 2:
                self._parse_import_section()
            elif section_id == 3:
                self._parse_function_section()
            elif section_id == 4:
                self._parse_table_section()
            elif section_id == 5:
                self._parse_memory_section()
            elif section_id == 6:
                self._parse_global_section()
            elif section_id == 7:
                self._parse_export_section()
            elif section_id == 8:
                self._parse_start_section()
            elif section_id == 9:
                self._parse_element_section()
            elif section_id == 10:
                self._parse_code_section()
            elif section_id == 11:
                self._parse_data_section()
            else:
                logger.warning(f"未知段类型: {section_id}")
                break
    
    def _parse_type_section(self) -> None:
        """解析类型段"""
        count = self._read_varuint()
        
        for _ in range(count):
            self.result.types.append(self._read_type_entry())
        
        logger.info(f"解析 {count} 个类型定义")
    
    def _parse_import_section(self) -> None:
        """解析导入段"""
        count = self._read_varuint()
        
        for _ in range(count):
            module = self._read_name()
            name = self._read_name()
            kind = self._read_byte()
            index = self._read_varuint()
            
            self.result.imports.append(Import(
                module=module,
                name=name,
                kind=kind,
                index=index
            ))
        
        logger.info(f"解析 {count} 个导入项")
    
    def _parse_function_section(self) -> None:
        """解析函数段"""
        count = self._read_varuint()
        
        for _ in range(count):
            type_idx = self._read_varuint()
            self.result.functions.append(Function(
                type_idx=type_idx,
                local_count=0,
                local_types=[],
                code_size=0
            ))
        
        logger.info(f"解析 {count} 个函数签名")
    
    def _parse_export_section(self) -> None:
        """解析导出段"""
        count = self._read_varuint()
        
        for _ in range(count):
            name = self._read_name()
            kind = self._read_byte()
            index = self._read_varuint()
            
            self.result.exports.append(Export(
                name=name,
                kind=kind,
                index=index
            ))
        
        logger.info(f"解析 {count} 个导出项")
    
    def _parse_memory_section(self) -> None:
        """解析内存段"""
        count = self._read_varuint()
        
        for _ in range(count):
            flags = self._read_varuint()
            initial = self._read_varuint()
            maximum = self._read_varuint() if flags & 1 else None
            
            self.result.memories.append(Memory(
                flags=flags,
                initial=initial,
                maximum=maximum
            ))
        
        logger.info(f"解析 {count} 个内存定义")
    
    def _parse_global_section(self) -> None:
        """解析全局变量段"""
        count = self._read_varuint()
        
        for _ in range(count):
            gtype = self._read_byte()
            mut = bool(self._read_byte())
            
            init = []
            while True:
                opcode = self._read_byte()
                if opcode == 0x0B:
                    break
                init.append(opcode)
            
            self.result.globals.append(Global(
                type=gtype,
                mut=mut,
                init=init
            ))
        
        logger.info(f"解析 {count} 个全局变量")
    
    def _parse_table_section(self) -> None:
        """解析表段"""
        count = self._read_varuint()
        
        for _ in range(count):
            elem_type = self._read_byte()
            flags = self._read_varuint()
            initial = self._read_varuint()
            maximum = self._read_varuint() if flags & 1 else None
            
            self.result.tables.append(Table(
                elem_type=elem_type,
                flags=flags,
                initial=initial,
                maximum=maximum
            ))
        
        logger.info(f"解析 {count} 个表定义")
    
    def _parse_code_section(self) -> None:
        """解析代码段"""
        count = self._read_varuint()
        
        for i, func in enumerate(self.result.functions[:count]):
            body_size = self._read_varuint()
            
            local_count = self._read_varuint()
            local_types = [self._read_byte() for _ in range(local_count)]
            
            func.local_count = local_count
            func.local_types = local_types
            func.code_size = body_size - 1 - local_count
        
        logger.info(f"解析 {count} 个函数体")
    
    def _parse_custom_section(self) -> None:
        """解析自定义段"""
        section_size = self._read_varuint()
        name = self._read_name()
        content_size = len(self.data) - self.offset
        
        if name == 'name':
            self._parse_name_section()
        elif name == 'sourceMappingURL':
            self.result.custom_sections['source_map'] = self._read_bytes(content_size).decode('utf-8', errors='replace')
        else:
            self._read_bytes(section_size - len(name) - 1)
    
    def _parse_name_section(self) -> None:
        """解析名称段"""
        pass
    
    def _parse_start_section(self) -> None:
        """解析开始段"""
        start_func = self._read_varuint()
        logger.info(f"开始函数索引: {start_func}")
    
    def _parse_element_section(self) -> None:
        """解析元素段"""
        count = self._read_varuint()
        logger.info(f"解析 {count} 个元素")
    
    def _parse_data_section(self) -> None:
        """解析数据段"""
        count = self._read_varuint()
        logger.info(f"解析 {count} 个数据段")
    
    def parse(self) -> WasmAnalysisResult:
        """
        解析整个 WASM 文件
        
        Returns:
            分析结果
        """
        if not self.parse_header():
            return self.result
        
        self.parse_sections()
        self._detect_vulnerabilities()
        
        return self.result
    
    def _detect_vulnerabilities(self) -> None:
        """检测 WASM 特有漏洞"""
        vulns = []
        
        for imp in self.result.imports:
            if imp.module in ['env', 'wasi_unstable', 'wasi_snapshot_preview1']:
                if imp.name in ['fd_write', 'fd_read']:
                    vulns.append({
                        'type': 'File Operation',
                        'severity': 'Medium',
                        'description': f'导入函数 {imp.module}.{imp.name} 可能访问敏感文件',
                        'location': f'import:{imp.index}'
                    })
        
        for mem in self.result.memories:
            if mem.maximum is None:
                vulns.append({
                    'type': 'Unbounded Memory',
                    'severity': 'Medium',
                    'description': '内存没有最大限制，可能导致内存耗尽',
                    'location': 'memory:0'
                })
            
            if mem.initial > 32768:
                vulns.append({
                    'type': 'Large Memory Allocation',
                    'severity': 'Low',
                    'description': f'初始内存分配过大: {mem.initial} 页',
                    'location': 'memory:0'
                })
        
        dangerous_exports = ['memory', 'table', '_start', '__main_argc_argv']
        for exp in self.result.exports:
            if exp.name in dangerous_exports:
                vulns.append({
                    'type': 'Dangerous Export',
                    'severity': 'Medium',
                    'description': f'导出危险符号: {exp.name}',
                    'location': f'export:{exp.index}'
                })
        
        for glob in self.result.globals:
            if glob.type == 0x7F and glob.mut:
                vulns.append({
                    'type': 'Mutable Global',
                    'severity': 'Low',
                    'description': '导出的可变全局变量可能影响执行环境',
                    'location': f'global:{self.result.globals.index(glob)}'
                })
        
        self.result.vulnerabilities = vulns


class WASIAnalyzer:
    """
    WASI 组件分析器
    
    分析 WASI 组件和系统调用
    """
    
    WASI_FUNCTIONS = {
        'args_sizes_get': '获取命令行参数大小',
        'args_get': '获取命令行参数',
        'fd_write': '写入文件描述符',
        'fd_read': '读取文件描述符',
        'fd_close': '关闭文件描述符',
        'fd_seek': '移动文件指针',
        'fd_tell': '获取文件位置',
        'fd_fdstat_get': '获取文件状态',
        'path_open': '打开路径',
        'path_create_directory': '创建目录',
        'path_unlink_file': '删除文件',
        'proc_exit': '退出进程',
        'proc_raise': '发送信号',
        'sched_yield': '让出调度',
        'random_get': '获取随机数',
        'clock_time_get': '获取时间',
        'clock_res_get': '获取时钟分辨率',
    }
    
    def __init__(self, wasm_data: bytes):
        """
        初始化 WASI 分析器
        
        Args:
            wasm_data: WASM 文件数据
        """
        self.wasm_data = wasm_data
        self.parser = WasmParser(wasm_data)
        self.result = self.parser.parse()
    
    def analyze_wasi_usage(self) -> Dict[str, Any]:
        """
        分析 WASI 函数使用
        
        Returns:
            WASI 使用分析结果
        """
        wasi_functions = {}
        
        for imp in self.result.imports:
            if imp.module in ['wasi_unstable', 'wasi_snapshot_preview1', 'env']:
                func_name = imp.name
                description = self.WASI_FUNCTIONS.get(func_name, '未知 WASI 函数')
                
                wasi_functions[func_name] = {
                    'module': imp.module,
                    'description': description,
                    'kind': ['function', 'table', 'memory', 'global'][imp.kind] if imp.kind < 4 else 'unknown'
                }
        
        return wasi_functions
    
    def analyze_capabilities(self) -> Dict[str, Any]:
        """
        分析能力集
        
        Returns:
            能力分析结果
        """
        capabilities = {
            'file_system': [],
            'network': [],
            'process': [],
            'memory': [],
            'time': [],
            'random': []
        }
        
        for imp in self.result.imports:
            name = imp.name.lower()
            
            if 'fd_' in name or 'path_' in name:
                capabilities['file_system'].append(imp.name)
            elif 'sock_' in name or 'tcp' in name or 'udp' in name:
                capabilities['network'].append(imp.name)
            elif 'proc_' in name or 'sched' in name:
                capabilities['process'].append(imp.name)
            elif 'clock' in name or 'time' in name:
                capabilities['time'].append(imp.name)
            elif 'random' in name:
                capabilities['random'].append(imp.name)
        
        return capabilities
    
    def analyze(self) -> Dict[str, Any]:
        """
        执行完整分析
        
        Returns:
            分析结果
        """
        return {
            'wasi_functions': self.analyze_wasi_usage(),
            'capabilities': self.analyze_capabilities(),
            'vulnerabilities': self.result.vulnerabilities
        }


def analyze_wasm(binary_path: str) -> Dict[str, Any]:
    """
    分析 WebAssembly 二进制文件
    
    Args:
        binary_path: WASM 文件路径
        
    Returns:
        分析结果
    """
    with open(binary_path, 'rb') as f:
        data = f.read()
    
    parser = WasmParser(data)
    result = parser.parse()
    
    wasi_analyzer = WASIAnalyzer(data)
    wasi_info = wasi_analyzer.analyze()
    
    return {
        'version': result.version,
        'function_count': len(result.functions),
        'type_count': len(result.types),
        'export_count': len(result.exports),
        'import_count': len(result.imports),
        'global_count': len(result.globals),
        'memory_count': len(result.memories),
        'exports': [
            {'name': e.name, 'kind': e.kind, 'index': e.index}
            for e in result.exports
        ],
        'imports': [
            {'module': i.module, 'name': i.name, 'kind': i.kind, 'index': i.index}
            for i in result.imports
        ],
        'vulnerabilities': result.vulnerabilities,
        'wasi': wasi_info
    }
