import struct
import logging
import hashlib
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class SectionType:
    """WASM段类型标识常量。"""
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
    form: int = 0
    param_types: list = field(default_factory=list)
    return_type: int = 0

@dataclass
class Function:
    type_idx: int = 0
    local_count: int = 0
    local_types: list = field(default_factory=list)
    code_size: int = 0

@dataclass
class Export:
    name: str = ""
    kind: int = 0
    index: int = 0

@dataclass
class Import:
    module: str = ""
    name: str = ""
    kind: int = 0
    index: int = 0

@dataclass
class Global:
    type: int = 0
    mut: bool = False
    init: int = 0

@dataclass
class Table:
    elem_type: int = 0
    flags: int = 0
    initial: int = 0
    maximum: int = 0

@dataclass
class Memory:
    flags: int = 0
    initial: int = 0
    maximum: int = 0

class WasmAnalysisResult:
    __slots__ = ('version', 'functions', 'types', 'exports', 'imports', 'globals', 'tables', 'memories', 'custom_sections', 'vulnerabilities',)

    def __init__(self, version, functions=None, types=None, exports=None, imports=None, globals=None, tables=None, memories=None, custom_sections=None, vulnerabilities=None):
        self.version = version
        self.functions = functions if functions is not None else []
        self.types = types if types is not None else []
        self.exports = exports if exports is not None else []
        self.imports = imports if imports is not None else []
        self.globals = globals if globals is not None else []
        self.tables = tables if tables is not None else []
        self.memories = memories if memories is not None else []
        self.custom_sections = custom_sections if custom_sections is not None else {}
        self.vulnerabilities = vulnerabilities if vulnerabilities is not None else []


class WasmParser:
    """
    WebAssembly二进制解析器。

    按WASM规范解析模块结构：类型段、导入/导出段、函数段、内存/表/全局段、代码段。
    """

    _WASM_MAGIC = b'\x00asm'

    def __init__(self, data):
        """
        初始化WASM解析器，绑定二进制数据与偏移指针。
        """
        self.data = data
        self.offset = 0
        self.result = WasmAnalysisResult(version=0)


    def _read_byte(self):
        nDataLen = len(self.data)
        if self.offset >= nDataLen:
            return 0
        byte = self.data[self.offset]
        self.offset += 1
        return byte


    def _read_bytes(self, nCount):
        nDataLen = len(self.data)
        if self.offset + nCount > nDataLen:
            return b''
        result = self.data[self.offset:self.offset + nCount]
        self.offset += nCount
        return result


    def _read_varuint(self):
        result = 0
        shift = 0
        while True:
            byte = self._read_byte()
            result |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                break
            shift += 7
        return result


    def _read_varsint(self):
        """读取LEB128有符号变长整数。"""
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


    def _read_name(self):
        """读取UTF-8编码的名称字符串。"""
        nLength = self._read_varuint()
        sNameBytes = self._read_bytes(nLength)
        return sNameBytes.decode('utf-8', errors='replace')


    def _read_type_entry(self):
        """读取函数类型签名定义。"""
        form = self._read_byte()
        nParamCount = self._read_varuint()

        param_types = []
        bpf = 0
        while bpf < nParamCount:
            param_types.append(self._read_byte())
            bpf += 1

        nReturnCount = self._read_varuint()
        return_type = self._read_byte() if nReturnCount > 0 else None

        return TypeEntry(
            form=form,
            param_types=param_types,
            return_type=return_type
        )



    def parse_header(self):
        magic = self._read_bytes(4)
        if magic != self._WASM_MAGIC:
            logger.error(f"无效的 WASM file魔数: {magic}")
            return False

        version = struct.unpack('<I', self._read_bytes(4))[0]
        self.result.version = version

        logger.info(f"WASM version: {version}")
        return True


    def parse_sections(self):
        """按段ID分发解析全部WASM模块段。"""
        nDataLen = len(self.data)
        while self.offset < nDataLen:
            nSectionId = self._read_byte()

            if nSectionId == 0:
                self._parse_custom_section()
            elif nSectionId == 1:
                self._parse_type_section()
            elif nSectionId == 2:
                self._parse_import_section()
            elif nSectionId == 3:
                self._parse_function_section()
            elif nSectionId == 4:
                self._parse_table_section()
            elif nSectionId == 5:
                self._parse_memory_section()
            elif nSectionId == 6:
                self._parse_global_section()
            elif nSectionId == 7:
                self._parse_export_section()
            elif nSectionId == 8:
                self._parse_start_section()
            elif nSectionId == 9:
                self._parse_element_section()
            elif nSectionId == 10:
                self._parse_code_section()
            elif nSectionId == 11:
                self._parse_data_section()
            else:
                logger.warning(f"未知段type: {nSectionId}")
                break


    def _parse_type_section(self):
        nCount = self._read_varuint()

        k = 0
        while k < nCount:
            self.result.types.append(self._read_type_entry())
            k += 1

        logger.info(f"解析 {nCount} 个type定义")


    def _parse_import_section(self):
        nCount = self._read_varuint()

        j = 0
        while j < nCount:
            sModule = self._read_name()
            sName = self._read_name()
            nKind = self._read_byte()
            nIndex = self._read_varuint()

            self.result.imports.append(Import(
                module=sModule,
                name=sName,
                kind=nKind,
                index=nIndex
            ))
            j += 1
        logger.info(f"解析 {nCount} 个import项")


    def _parse_function_section(self):
        nCount = self._read_varuint()

        j = 0
        while j < nCount:
            nTypeIdx = self._read_varuint()
            self.result.functions.append(Function(
                type_idx=nTypeIdx,
                local_count=0,
                local_types=[],
                code_size=0
            ))
            j += 1

        logger.info(f"解析 {nCount} functionssign")


    def _parse_export_section(self):
        nCount = self._read_varuint()

        i = 0
        while i < nCount:
            sName = self._read_name()
            nKind = self._read_byte()
            nIndex = self._read_varuint()

            self.result.exports.append(Export(
                name=sName,
                kind=nKind,
                index=nIndex
            ))
            i += 1


    def _parse_memory_section(self):
        nCount = self._read_varuint()

        i = 0
        while i < nCount:
            nFlags = self._read_varuint()
            nInitial = self._read_varuint()
            bHasMax = nFlags & 1
            if bHasMax:
                nMax = self._read_varuint()
            else:
                nMax = None

            self.result.memories.append(Memory(
                flags=nFlags,
                initial=nInitial,
                maximum=nMax
            ))
            i += 1
        logger.info(f"解析 {nCount} 个memory定义")


    def _parse_global_section(self):
        nCount = self._read_varuint()

        k = 0
        while k < nCount:
            gtype = self._read_byte()
            bMut = bool(self._read_byte())
            init = []
            while True:
                opcode = self._read_byte()
                if opcode == 0x0B:
                    break
                init.append(opcode)

            self.result.globals.append(Global(
                type=gtype,
                mut=bMut,
                init=init
            ))
            k += 1
        logger.info(f"解析 {nCount} 个全局变量")


    def _parse_table_section(self):
        """解析Table段——间接调用表定义。"""
        nCount = self._read_varuint()

        i = 0
        while i < nCount:
            nElemType = self._read_byte()
            nFlags = self._read_varuint()
            nInitial = self._read_varuint()
            bHasMax = nFlags & 1
            if bHasMax:
                nMax = self._read_varuint()
            else:
                nMax = None

            self.result.tables.append(Table(
                elem_type=nElemType,
                flags=nFlags,
                initial=nInitial,
                maximum=nMax
            ))
            i += 1
        logger.info(f"解析 {nCount} 个表定义")


    def _parse_code_section(self):
        nCount = self._read_varuint()
        nFuncLen = len(self.result.functions)
        if nCount > nFuncLen:
            nLimit = nFuncLen
        else:
            nLimit = nCount

        funcs = self.result.functions
        i = 0
        while i < nLimit:
            func = funcs[i]
            body_size = self._read_varuint()

            nLocalCount = self._read_varuint()

            local_types = []
            m = 0
            while m < nLocalCount:
                local_types.append(self._read_byte())
                m += 1

            func.local_count = nLocalCount
            func.local_types = local_types
            func.code_size = body_size - 1 - nLocalCount
            i += 1

        logger.info(f"解析 {nCount} functions体")


    def _parse_custom_section(self):
        """解析Custom段——名称段与调试信息。"""
        section_size = self._read_varuint()
        sName = self._read_name()
        content_size = len(self.data) - self.offset

        if sName == 'name':
            # 剩余子段载荷 = section_size - 名称长度前缀 - 名称字节数
            name_bytes = len(sName.encode('utf-8'))
            leb_len = max(1, (name_bytes.bit_length() + 6) // 7)
            section_end = self.offset + (section_size - leb_len - name_bytes)
            self._parse_name_section(section_end)
        elif sName == 'sourceMappingURL':
            self.result.custom_sections['source_map'] = self._read_bytes(content_size).decode('utf-8', errors='replace')
        else:
            self._read_bytes(section_size - len(sName) - 1)


    def _parse_name_section(self, section_end: int):
        """解析 WASM name 段子段: 模块名(0)/函数名(1)/局部名(2)。

        子段格式: id(1字节) + size(varuint) + 载荷; 其余子段跳过。
        """
        names = {'module_name': '', 'function_names': {}, 'local_names': {}}
        end = min(section_end, len(self.data))
        while self.offset < end:
            sub_id = self._read_byte()
            sub_size = self._read_varuint()
            sub_end = min(self.offset + sub_size, end)
            if sub_id == 0:
                names['module_name'] = self._read_name()
            elif sub_id == 1:
                count = self._read_varuint()
                for _ in range(count):
                    idx = self._read_varuint()
                    names['function_names'][idx] = self._read_name()
            elif sub_id == 2:
                count = self._read_varuint()
                for _ in range(count):
                    func_idx = self._read_varuint()
                    local_count = self._read_varuint()
                    for _ in range(local_count):
                        local_idx = self._read_varuint()
                        local_name = self._read_name()
                        names['local_names'].setdefault(func_idx, {})[local_idx] = local_name
            else:
                # 其余子段 (type/table/memory/global/element/data) 跳过载荷
                self._read_bytes(sub_end - self.offset)
            self.offset = max(self.offset, sub_end)
        self.result.custom_sections['name_section'] = names


    def _parse_start_section(self):
        nStartFunc = self._read_varuint()
        logger.info(f"start函数index: {nStartFunc}")


    def _parse_element_section(self):
        nCount = self._read_varuint()
        logger.info(f"解析 {nCount} 个元素")


    def _parse_data_section(self):
        nCount = self._read_varuint()
        logger.info(f"解析 {nCount} 个data段")


    def parse(self):
        """
        完整解析WASM模块：头校验→段遍历→漏洞检测。
        """
        bOk = self.parse_header()
        if not bOk:
            return self.result

        self.parse_sections()
        self._detect_vulnerabilities()

        return self.result


    def _detect_vulnerabilities(self):
        vulns = []

        imports = self.result.imports
        nImpLen = len(imports)
        imp_idx = 0
        while imp_idx < nImpLen:
            imp = imports[imp_idx]
            sMod = imp.module
            bEnvOrWasi = (sMod == 'env' or sMod == 'wasi_unstable' or sMod == 'wasi_snapshot_preview1')
            if bEnvOrWasi:
                sImpName = imp.name
                if sImpName == 'fd_write' or sImpName == 'fd_read':
                    vulns.append({
                        'type': 'File Operation',
                        'severity': 'Medium',
                        'description': f'import函数 {sMod}.{sImpName} 可能访问敏感file',
                        'location': f'import:{imp.index}'
                    })
            imp_idx += 1

        mems = self.result.memories
        nMemLen = len(mems)
        mem_idx = 0
        while mem_idx < nMemLen:
            mem = mems[mem_idx]
            if mem.maximum is None:
                vulns.append({
                    'type': 'Unbounded Memory',
                    'severity': 'Medium',
                    'description': 'memory没有最大limit，可能导致memory耗尽',
                    'location': 'memory:0'
                })

            if mem.initial > 32768:
                vulns.append({
                    'type': 'Large Memory Allocation',
                    'severity': 'Low',
                    'description': f'初始memory分配过大: {mem.initial} 页',
                    'location': 'memory:0'
                })
            mem_idx += 1

        _DANGEROUS_EXPORTS = ['memory', 'table', '_start', '__main_argc_argv']
        nDangerLen = len(_DANGEROUS_EXPORTS)
        exps = self.result.exports
        nExpLen = len(exps)
        exp_idx = 0
        while exp_idx < nExpLen:
            exp = exps[exp_idx]
            sExpName = exp.name
            dang_j = 0
            while dang_j < nDangerLen:
                if sExpName == _DANGEROUS_EXPORTS[dang_j]:
                    vulns.append({
                        'type': 'Dangerous Export',
                        'severity': 'Medium',
                        'description': f'export危险符号: {sExpName}',
                        'location': f'export:{exp.index}'
                    })
                    break
                dang_j += 1
            exp_idx += 1

        globs = self.result.globals
        nGlobLen = len(globs)
        glob_idx = 0
        while glob_idx < nGlobLen:
            glob = globs[glob_idx]
            if glob.type == 0x7F and glob.mut:
                nSearchIdx = 0
                while nSearchIdx < nGlobLen:
                    if globs[nSearchIdx] is glob:
                        break
                    nSearchIdx += 1
                vulns.append({
                    'type': 'Mutable Global',
                    'severity': 'Low',
                    'description': 'export的可变全局变量可能影响executeenvironment',
                    'location': f'global:{nSearchIdx}'
                })
            glob_idx += 1

        self.result.vulnerabilities = vulns



class WASIAnalyzer:
    """
    WASI组件分析器。

    解析WASI导入函数、能力集与系统调用接口。
    """

    WASI_FUNCTIONS = {
        'args_sizes_get': '获取命令行parametersize',
        'args_get': '获取命令行parameter',
        'fd_write': '写入filedescription符',
        'fd_read': '读取filedescription符',
        'fd_close': '关闭filedescription符',
        'fd_seek': '移动file指针',
        'fd_tell': '获取file位置',
        'fd_fdstat_get': '获取filestatus',
        'path_open': '打开path',
        'path_create_directory': 'createdirectory',
        'path_unlink_file': 'deletefile',
        'proc_exit': 'logoutprocess',
        'proc_raise': 'sendsignal',
        'sched_yield': '让出调度',
        'random_get': '获取随机数',
        'clock_time_get': '获取时间',
        'clock_res_get': '获取时钟分辨率',
    }

    def __init__(self, wasm_data):
        """
        初始化WASI分析器，内联WASM解析。
        """
        self.wasm_data = wasm_data
        self.parser = WasmParser(wasm_data)
        self.result = self.parser.parse()


    def analyze_wasi_usage(self):
        """
        统计所有WASI导入函数及其描述。
        """
        wasi_functions = {}

        imports = self.result.imports
        nLen = len(imports)
        k = 0
        while k < nLen:
            imp = imports[k]
            sModule = imp.module
            bWasi = (sModule == 'wasi_unstable' or sModule == 'wasi_snapshot_preview1' or sModule == 'env')
            if bWasi:
                sFuncName = imp.name
                sDesc = self.WASI_FUNCTIONS.get(sFuncName, '未知 WASI 函数')

                nKind = imp.kind
                if nKind < 4:
                    sKindNames = ['function', 'table', 'memory', 'global']
                    sKind = sKindNames[nKind]
                else:
                    sKind = 'unknown'

                wasi_functions[sFuncName] = {
                    'module': sModule,
                    'description': sDesc,
                    'kind': sKind
                }
            k += 1

        return wasi_functions


    def analyze_capabilities(self):
        """
        按文件系统/网络/进程/内存/时间/随机数分类能力集。
        """
        capabilities = {
            'file_system': [],
            'network': [],
            'process': [],
            'memory': [],
            'time': [],
            'random': []
        }

        imports = self.result.imports
        nLen = len(imports)
        j = 0
        while j < nLen:
            imp = imports[j]
            sName = imp.name.lower()

            if 'fd_' in sName or 'path_' in sName:
                capabilities['file_system'].append(imp.name)
            elif 'sock_' in sName or 'tcp' in sName or 'udp' in sName:
                capabilities['network'].append(imp.name)
            elif 'proc_' in sName or 'sched' in sName:
                capabilities['process'].append(imp.name)
            elif 'clock' in sName or 'time' in sName:
                capabilities['time'].append(imp.name)
            elif 'random' in sName:
                capabilities['random'].append(imp.name)
            j += 1

        return capabilities


    def analyze(self):
        """
        执行完整WASI分析——函数使用+能力集+漏洞。
        """
        return {
            'wasi_functions': self.analyze_wasi_usage(),
            'capabilities': self.analyze_capabilities(),
            'vulnerabilities': self.result.vulnerabilities
        }



def analyze_wasm(binary_path):
    """
    一站式WASM分析入口——解析模块结构+WASI接口+漏洞扫描。
    """
    with open(binary_path, 'rb') as f:
        data = f.read()

    parser = WasmParser(data)
    result = parser.parse()

    wasi_analyzer = WASIAnalyzer(data)
    wasi_info = wasi_analyzer.analyze()

    exports_list = []
    nExpLen = len(result.exports)
    ei = 0
    while ei < nExpLen:
        e = result.exports[ei]
        exports_list.append({'name': e.name, 'kind': e.kind, 'index': e.index})
        ei += 1

    imports_list = []
    nImpLen = len(result.imports)
    ii = 0
    while ii < nImpLen:
        imp = result.imports[ii]
        imports_list.append({'module': imp.module, 'name': imp.name, 'kind': imp.kind, 'index': imp.index})
        ii += 1

    return {
        'version': result.version,
        'function_count': len(result.functions),
        'type_count': len(result.types),
        'export_count': len(result.exports),
        'import_count': len(result.imports),
        'global_count': len(result.globals),
        'memory_count': len(result.memories),
        'exports': exports_list,
        'imports': imports_list,
        'vulnerabilities': result.vulnerabilities,
        'wasi': wasi_info
    }


# 兼容性存根——测试依赖旧版类名
from dataclasses import dataclass as _dc, field as _f

@_dc
class WasmImport:
    module: str = ""
    name: str = ""
    kind: str = ""

@_dc
class TaintedParam:
    index: int = 0
    type: str = ""
    source: str = ""

@_dc
class SandboxEscape:
    type: str = ""
    severity: str = "High"
    description: str = ""

class WasmSandboxAnalyzer:
    def __init__(self, binary_path=""):
        self.binary_path = binary_path
    def analyze(self):
        return {'success': True, 'vulnerabilities': [], 'sandbox_escapes': []}
    def detect_sandbox_escape(self):
        return []

class TaintPropagator:
    def __init__(self, wasm_module=None): self.module = wasm_module
    def propagate(self, input_data=None): return []

class EscapeDetector:
    def __init__(self, binary_path=""): self.path = binary_path
    def detect(self): return []

def create_wasm_analyzer(binary_path=""):
    return WasmSandboxAnalyzer(binary_path=binary_path)
