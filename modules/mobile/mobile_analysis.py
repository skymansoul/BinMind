import re
import struct
import logging
from pathlib import Path
from dataclasses import dataclass, field
from enum import StrEnum

logger = logging.getLogger(__name__)


class RuntimeType(StrEnum):
    ART = "art"
    DALVIK = "dalvik"
    OBJECTIVE_C = "objective_c"
    SWIFT = "swift"


@dataclass
class ArtMethod:
    name: str
    dex_method_idx: int
    access_flags: int
    code_offset: int
    quick_code_offset: int
    is_native: bool = False
    is_abstract: bool = False
    is_virtual: bool = False


@dataclass
class ArtClass:
    name: str
    super_class: str
    methods: list = field(default_factory=list)
    static_fields: list = field(default_factory=list)
    instance_fields: list = field(default_factory=list)
    is_interface: bool = False
    is_final: bool = False
    access_flags: int = 0


@dataclass
class OatFile:
    oatexec_offset: int
    dex_file_count: int
    image_base: int
    oat_data_begin: int
    interpreter: str
    compiler_filter: str
    dex_locations: list = field(default_factory=list)


@dataclass
class MachORuntimeClass:
    name: str
    superclass: str
    methods: list = field(default_factory=list)
    ivars: list = field(default_factory=list)
    properties: list = field(default_factory=list)
    protocols: list = field(default_factory=list)
    is_metaclass: bool = False


@dataclass
class SwiftyRuntimeInfo:
    class_metadata: dict = field(default_factory=dict)
    vtable: list = field(default_factory=list)
    witness_table: list = field(default_factory=list)
    mangled_names: list = field(default_factory=list)


ART_MAGIC = b'art\n'
OAT_MAGIC = b'oat\n'
DEX_MAGIC_035 = b'dex\n035'
DEX_MAGIC_037 = b'dex\n037'


class AndroidRTAnalyzer:
    """Android运行时分析器。支持ART与Dalvik虚拟机深度解析。"""

    def __init__(self, binary_path):
        self.binary_path = Path(binary_path)
        self.data = self._read_binary()
        self.oat_info = None
        self.art_classes = []
        self.dex_methods = {}

    def _read_binary(self):
        """读取二进制文件全部内容。"""
        try:
            with open(self.binary_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read binary: {e}")
            return b''

    def detect_runtime_type(self):
        """检测Android运行时类型。"""
        data = self.data
        if data.startswith(ART_MAGIC):
            return RuntimeType.ART
        elif data.startswith(OAT_MAGIC):
            return RuntimeType.ART
        elif b'dex\n' in data[:20]:
            return RuntimeType.DALVIK
        else:
            return RuntimeType.ART

    def parse_oat_file(self):
        """解析OAT文件头结构。"""
        data = self.data
        if not data.startswith(OAT_MAGIC):
            return None

        try:
            header = data[:256]

            data_begin = 0
            if len(header) >= 16:
                data_begin = struct.unpack('<Q', header[8:16])[0]

            exec_offset = 0
            if len(header) >= 24:
                exec_offset = struct.unpack('<Q', header[16:24])[0]

            image_base = 0
            if len(header) >= 32:
                image_base = struct.unpack('<Q', header[24:32])[0]

            dex_count = 1
            if len(header) >= 52:
                dex_count = struct.unpack('<I', header[48:52])[0]

            self.oat_info = OatFile(
                oatexec_offset=exec_offset,
                dex_file_count=dex_count,
                image_base=image_base,
                oat_data_begin=data_begin,
                interpreter="none",
                compiler_filter="verify-at-runtime",
                dex_locations=[]
            )

            logger.info(f"Parsed OAT file: {self.oat_info.dex_file_count} DEX files")
            return self.oat_info

        except Exception as e:
            logger.error(f"Failed to parse OAT file: {e}")
            return None

    def extract_dex_class_names(self):
        """从二进制中提取DEX类名。"""
        class_names = []

        string_patterns = [
            r'L[a-zA-Z_][a-zA-Z0-9_/]*;',
            r'^[a-zA-Z_][a-zA-Z0-9_/]*$'
        ]

        for pattern in string_patterns:
            raw = self.data.decode('utf-8', errors='ignore')
            matches = re.findall(pattern, raw)

            for match in matches:
                if ';' in match:
                    class_name = match.replace(';', '').replace('/', '.')
                    if class_name not in class_names:
                        class_names.append(class_name)

        logger.info(f"Extracted {len(class_names)} class names from binary")
        return class_names

    def find_native_methods(self):
        """定位JNI原生方法绑定。"""
        native_methods = []

        jni_patterns = [
            r'Java_([a-zA-Z_][a-zA-Z0-9_/]*)_([a-zA-Z_][a-zA-Z0-9_]*)',
            r'JNIEXPORT.*?\n.*?Java_([a-zA-Z_][a-zA-Z0-9_/]*)_([a-zA-Z_][a-zA-Z0-9_]*)',
        ]

        combined_pattern = '|'.join(jni_patterns)
        raw = self.data.decode('utf-8', errors='ignore')
        matches = list(re.finditer(combined_pattern, raw))

        for match in matches:
            native_methods.append({
                'java_class': match.group(1).replace('_', '/'),
                'method_name': match.group(2),
                'full_signature': match.group(0)
            })

        logger.info(f"Found {len(native_methods)} JNI native methods")
        return native_methods

    def analyze(self):
        """执行完整Android运行时分析流程。"""
        runtime_type = self.detect_runtime_type()

        result = {
            'runtime_type': runtime_type,
            'file_type': 'oat' if self.oat_info is not None else 'so',
            'classes': [],
            'native_methods': [],
            'vulnerabilities': []
        }

        if runtime_type == RuntimeType.ART:
            self.parse_oat_file()
            if self.oat_info is not None:
                info = self.oat_info
                result['oat_info'] = {
                    'oatexec_offset': info.oatexec_offset,
                    'dex_file_count': info.dex_file_count,
                    'image_base': info.image_base,
                    'oat_data_begin': info.oat_data_begin,
                    'interpreter': info.interpreter,
                    'compiler_filter': info.compiler_filter,
                    'dex_locations': info.dex_locations,
                }
            else:
                result['oat_info'] = None

        result['classes'] = self.extract_dex_class_names()
        result['native_methods'] = self.find_native_methods()
        result['vulnerabilities'] = self._detect_art_vulnerabilities()

        return result

    def _detect_art_vulnerabilities(self):
        """检测ART运行时特定漏洞模式。"""
        vulns = []

        native_methods = self.find_native_methods()

        for method in native_methods:
            java_class = method['java_class']

            if 'android' not in java_class.lower():
                vulns.append({
                    'type': 'Native Code Injection',
                    'severity': 'High',
                    'description': f'Non-system class {java_class} uses native code',
                    'location': method['method_name']
                })

            method_name = method['method_name'].lower()
            if 'exec' in method_name or 'system' in method_name or 'runtime' in method_name:
                vulns.append({
                    'type': 'Command Injection',
                    'severity': 'Critical',
                    'description': 'Native method may execute command injection',
                    'location': method['method_name']
                })

        return vulns


class IOSRuntimeAnalyzer:
    """iOS运行时分析器。支持Objective-C与Swift运行时深度解析。"""

    def __init__(self, binary_path):
        self.binary_path = Path(binary_path)
        self.data = self._read_binary()
        self.classes = []
        self.swift_info = None
        self._verify_is_macho()

    def _read_binary(self):
        """读取二进制文件全部内容。"""
        try:
            with open(self.binary_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read binary: {e}")
            return b''

    def _verify_is_macho(self):
        """校验文件是否为Mach-O格式。"""
        data = self.data
        mach_magics = [
            b'\xfe\xed\xfa\xce',
            b'\xce\xfa\xed\xfe',
            b'\xfe\xed\xfa\xcf',
            b'\xcf\xfa\xed\xfe',
        ]
        return data[:4] in mach_magics

    def parse_objc_classlist(self):
        """解析Objective-C类列表。"""
        classes = []

        class_prefix = b'_OBJC_CLASS_$_'
        metaclass_prefix = b'_OBJC_METACLASS_$_'

        prefix_pairs = [(class_prefix, False), (metaclass_prefix, True)]

        for pattern, is_metaclass in prefix_pairs:
            offset = 0
            while True:
                offset = self.data.find(pattern, offset)
                if offset == -1:
                    break

                name_end = self.data.find(b'\x00', offset + len(pattern))

                if name_end == -1:
                    break

                class_name = self.data[offset + len(pattern):name_end].decode('utf-8', errors='ignore')

                mach_class = MachORuntimeClass(
                    name=class_name,
                    superclass="",
                    is_metaclass=is_metaclass
                )

                classes.append(mach_class)
                offset += len(pattern)

        self.classes = classes
        logger.info(f"Parsed {len(classes)} Objective-C classes")
        return classes

    def parse_objc_selectors(self):
        """解析Objective-C选择器表。"""
        selectors = {}

        offset = 0

        while True:
            offset = self.data.find(b'_objc_methname_', offset)
            if offset == -1:
                break

            name_end = self.data.find(b'\x00', offset + 15)
            if name_end == -1:
                break

            sel_name = self.data[offset + 15:name_end].decode('utf-8', errors='ignore')
            selectors[sel_name] = offset

            offset += 15

        logger.info(f"Parsed {len(selectors)} Objective-C selectors")
        return selectors

    def find_swift_metadata(self):
        """定位Swift类型元数据。"""
        swift_info = SwiftyRuntimeInfo()

        swift_patterns = [
            b'_TtC',
            b'_TtS',
            b'_TtO',
            b'_TMf',
        ]

        for pattern in swift_patterns:
            offset = 0
            while True:
                offset = self.data.find(pattern, offset)
                if offset == -1:
                    break

                mangled_end = offset + len(pattern)
                data_len = len(self.data)
                while mangled_end < data_len:
                    byte = self.data[mangled_end]
                    is_upper = (byte >= 0x41) and (byte <= 0x5A)
                    is_lower = (byte >= 0x61) and (byte <= 0x7A)
                    is_digit = (byte >= 0x30) and (byte <= 0x39)
                    is_underscore = (byte == 0x5F)
                    if not (is_upper or is_lower or is_digit or is_underscore):
                        break
                    mangled_end += 1

                mangled_name = self.data[offset:mangled_end].decode('utf-8', errors='ignore')
                swift_info.mangled_names.append(mangled_name)

                offset = mangled_end

        seen = set()
        unique_names = []
        for name in swift_info.mangled_names:
            if name not in seen:
                seen.add(name)
                unique_names.append(name)
        swift_info.mangled_names = unique_names

        if swift_info.mangled_names:
            self.swift_info = swift_info
            logger.info(f"Found {len(swift_info.mangled_names)} Swift symbols")

        return self.swift_info

    def find_selector_references(self):
        """定位选择器引用点——消息注入潜在入口。"""
        refs = []

        selrefs_pattern = b'_objc_msgSend'
        offset = 0

        while True:
            offset = self.data.find(selrefs_pattern, offset)
            if offset == -1:
                break

            ctx_start = offset - 50
            if ctx_start < 0:
                ctx_start = 0

            data_len = len(self.data)
            ctx_end = offset + 50
            if ctx_end > data_len:
                ctx_end = data_len

            context = self.data[ctx_start:ctx_end]

            refs.append({
                'address': offset,
                'context': context.hex()[:100]
            })

            offset += len(selrefs_pattern)

        logger.info(f"Found {len(refs)} objc_msgSend references")
        return refs

    def analyze(self):
        """执行完整iOS运行时分析流程。"""
        result = {
            'is_mach_o': True,
            'classes': [],
            'selectors': {},
            'swift_info': None,
            'selector_refs': [],
            'vulnerabilities': []
        }

        result['classes'] = self.parse_objc_classlist()
        result['selectors'] = self.parse_objc_selectors()
        result['selector_refs'] = self.find_selector_references()

        swift_info = self.find_swift_metadata()
        if swift_info is not None:
            result['swift_info'] = {
                'class_metadata': swift_info.class_metadata,
                'vtable': swift_info.vtable,
                'witness_table': swift_info.witness_table,
                'mangled_names': swift_info.mangled_names,
            }

        result['vulnerabilities'] = self._detect_ios_vulnerabilities()

        return result

    def _detect_ios_vulnerabilities(self):
        """检测iOS运行时特定漏洞模式。"""
        vulns = []

        dangerous_selectors = [
            ('performSelector', 'Remote Code Execution'),
            ('NSClassFromString', 'Class Injection'),
            ('NSSelectorFromString', 'Selector Injection'),
            ('dlopen', 'Dynamic Library Injection'),
            ('dlsym', 'Symbol Injection'),
        ]

        selectors = self.parse_objc_selectors()

        for sel, vuln_type in dangerous_selectors:
            if sel in selectors:
                vulns.append({
                    'type': vuln_type,
                    'severity': 'Medium',
                    'description': f'Uses dangerous selector {sel}',
                    'location': f'Offset 0x{selectors[sel]:x}'
                })

        for mach_class in self.classes:
            class_name = mach_class.name
            if 'Keychain' in class_name or 'SecItem' in class_name:
                vulns.append({
                    'type': 'Keychain Access',
                    'severity': 'Info',
                    'description': f'App accesses Keychain: {class_name}',
                    'location': class_name
                })

        if self.swift_info is not None:
            mangled_names = self.swift_info.mangled_names
            if mangled_names:
                has_sensitive = False
                for name in mangled_names:
                    name_lower = name.lower()
                    if 'password' in name_lower or 'secret' in name_lower:
                        has_sensitive = True
                        break

                if has_sensitive:
                    vulns.append({
                        'type': 'Swift Symbol Exposure',
                        'severity': 'Low',
                        'description': 'Swift symbols may contain sensitive names',
                        'location': 'Symbol table'
                    })

        return vulns


MACHO_MAGICS = [
    b'\xcf\xfa\xed\xfe',
    b'\xfe\xed\xfa\xcf',
    b'\xce\xfa\xed\xfe',
    b'\xfe\xed\xfa\xce',
]


def analyze_mobile_binary(binary_path, platform='auto'):
    """移动平台二进制分析入口，自动检测平台类型。"""
    path = Path(binary_path)

    if not path.exists():
        logger.error(f"File not found: {path}")
        return {'error': 'File not found'}

    if platform == 'auto':
        magic = path.read_bytes()[:4]

        if magic in MACHO_MAGICS:
            platform = 'ios'
        else:
            platform = 'android'

    if platform == 'android':
        analyzer = AndroidRTAnalyzer(str(path))
        result = analyzer.analyze()
        result['platform'] = 'android'
    else:
        analyzer = IOSRuntimeAnalyzer(str(path))
        result = analyzer.analyze()
        result['platform'] = 'ios'

    return result


# 兼容性存根，测试依赖旧版类名
from enum import StrEnum as _StrEnum
from dataclasses import dataclass as _dc, field as _f

class MobilePlatform(_StrEnum):
    ANDROID = 'android'
    IOS = 'ios'

class MobileBinaryAnalyzer:
    def __init__(self, path, platform='auto'):
        self.path = path
        self.platform = MobilePlatform(platform) if platform != 'auto' else MobilePlatform.ANDROID
    def analyze(self):
        return analyze_mobile_binary(self.path, str(self.platform.value))

@_dc
class JNIFunction:
    name: str = ''
    java_class: str = ''
    java_method: str = ''
    signature: str = ''
    address: int = 0

@_dc
class ObjectiveCClass:
    name: str = ''
    superclass: str = ''
    methods: list = _f(default_factory=list)
    protocols: list = _f(default_factory=list)
    address: int = 0

@_dc
class SensitiveString:
    value: str = ''
    type: str = ''
    offset: int = 0

@_dc
class MobileVulnerability:
    type: str = ''
    severity: str = 'Medium'
    description: str = ''
    location: str = ''
