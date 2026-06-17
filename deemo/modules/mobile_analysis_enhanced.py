"""
移动平台二进制深度分析增强模块

增强功能：
1. Android ART/OAT 深度分析
2. iOS Mach-O 运行时结构解析
3. 运行时语义分析
"""

import os
import re
import struct
import logging
import hashlib
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


class RuntimeType(Enum):
    """运行时类型"""
    ART = "art"
    Dalvik = "dalvik"
    ObjectiveC = "objective_c"
    Swift = "swift"


@dataclass
class ArtMethod:
    """ART 方法信息"""
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
    """ART 类信息"""
    name: str
    super_class: str
    methods: List[ArtMethod] = field(default_factory=list)
    static_fields: List[str] = field(default_factory=list)
    instance_fields: List[str] = field(default_factory=list)
    is_interface: bool = False
    is_final: bool = False
    access_flags: int = 0


@dataclass
class OatFile:
    """OAT 文件信息"""
    oatexec_offset: int
    dex_file_count: int
    image_base: int
    oat_data_begin: int
    interpreter: str
    compiler_filter: str
    dex_locations: List[str] = field(default_factory=list)


@dataclass
class MachORuntimeClass:
    """Mach-O 运行时类信息"""
    name: str
    superclass: str
    methods: List[Dict[str, Any]] = field(default_factory=list)
    ivars: List[Dict[str, Any]] = field(default_factory=list)
    properties: List[str] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)
    is_metaclass: bool = False


@dataclass
class SwiftyRuntimeInfo:
    """Swift 运行时信息"""
    class_metadata: Dict[str, Any] = field(default_factory=dict)
    vtable: List[str] = field(default_factory=list)
    witness_table: List[str] = field(default_factory=list)
    mangled_names: List[str] = field(default_factory=list)


class AndroidRTAnalyzer:
    """
    Android 运行时分析器
    
    支持 ART 和 Dalvik 虚拟机的深度分析
    """
    
    ART_MAGIC = b'art\n'
    OAT_MAGIC = b'oat\n'
    DEX_MAGIC_035 = b'dex\n035'
    DEX_MAGIC_037 = b'dex\n037'
    
    def __init__(self, binary_path: str):
        """
        初始化 ART 分析器
        
        Args:
            binary_path: .so 或 .oat 文件路径
        """
        self.binary_path = Path(binary_path)
        self.data = self._read_binary()
        self.oat_info: Optional[OatFile] = None
        self.art_classes: List[ArtClass] = []
        self.dex_methods: Dict[int, str] = {}
    
    def _read_binary(self) -> bytes:
        """读取二进制文件"""
        try:
            with open(self.binary_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"读取二进制文件失败: {e}")
            return b''
    
    def detect_runtime_type(self) -> RuntimeType:
        """
        检测运行时类型
        
        Returns:
            运行时类型
        """
        if self.data.startswith(self.ART_MAGIC):
            return RuntimeType.ART
        elif self.data.startswith(self.OAT_MAGIC):
            return RuntimeType.ART
        elif b'dex\n' in self.data[:20]:
            return RuntimeType.Dalvik
        else:
            return RuntimeType.ART
    
    def parse_oat_file(self) -> Optional[OatFile]:
        """
        解析 OAT 文件头
        
        Returns:
            OAT 文件信息
        """
        if not self.data.startswith(self.OAT_MAGIC):
            return None
        
        try:
            header = self.data[:256]
            
            oat_data_begin = struct.unpack('<Q', header[8:16])[0] if len(header) >= 16 else 0
            oat_exec_offset = struct.unpack('<Q', header[16:24])[0] if len(header) >= 24 else 0
            image_base = struct.unpack('<Q', header[24:32])[0] if len(header) >= 32 else 0
            oat_patch_delta = struct.unpack('<I', header[32:36])[0] if len(header) >= 36 else 0
            
            dex_file_count_offset = 48
            dex_file_count = struct.unpack('<I', header[dex_file_count_offset:dex_file_count_offset+4])[0] if len(header) >= 52 else 1
            
            self.oat_info = OatFile()
                oatexec_offset=oat_exec_offset,
                dex_file_count=dex_file_count,
                image_base=image_base,
                oat_data_begin=oat_data_begin,
                interpreter="none",
                compiler_filter="verify-at-runtime",
                dex_locations=[]
            
            
            logger.info(f"解析 OAT 文件: {self.oat_info.dex_file_count} 个 DEX 文件")
            return self.oat_info
            
        except Exception as e:
            logger.error(f"解析 OAT 文件失败: {e}")
            return None
    
    def extract_dex_class_names(self) -> List[str]:
        """
        从二进制中提取 DEX 类名
        
        Returns:
            类名列表
        """
        class_names = []
        
        string_patterns = [
            r'L[a-zA-Z_][a-zA-Z0-9_/]*;',
            r'^[a-zA-Z_][a-zA-Z0-9_/]*$'
        ]
        
        for pattern in string_patterns:
            matches = re.findall(pattern, self.data.decode('utf-8', errors='ignore'

            for match in matches:
                if ';' in match:
                    class_name = match.replace(';', '').replace('/', '.')
                    if class_name not in class_names:
                        class_names.append(class_name)
        
        logger.info(f"从二进制提取 {len(class_names)} 个类名")
        return class_names
    
    def find_native_methods(self) -> List[Dict[str, Any]]:
        """
        查找 JNI 原生方法绑定
        
        Returns:
            原生方法列表
        """
        native_methods = []
        
        jni_patterns = [
            r'Java_([a-zA-Z_][a-zA-Z0-9_/]*)_([a-zA-Z_][a-zA-Z0-9_]*)',
            r'JNIEXPORT.*?\n.*?Java_([a-zA-Z_][a-zA-Z0-9_/]*)_([a-zA-Z_][a-zA-Z0-9_]*)',
        ]
        
        combined_pattern = '|'.join(jni_patterns)
        matches = re.finditer(combined_pattern, self.data.decode('utf-8', errors='ignore'

        
        for match in matches:
            native_methods.append({)
                'java_class': match.group(1).replace('_', '/'),
                'method_name': match.group(2),
                'full_signature': match.group(0)
            }
        
        logger.info(f"发现 {len(native_methods)} 个 JNI 原生方法")
        return native_methods
    
    def analyze(self) -> Dict[str, Any]:
        """
        执行完整的 Android 运行时分析
        
        Returns:
            分析结果
        """
        runtime_type = self.detect_runtime_type()
        
        result = {
            'runtime_type': runtime_type.value,
            'file_type': 'oat' if self.oat_info else 'so',
            'classes': [],
            'native_methods': [],
            'vulnerabilities': []
        }
        
        if runtime_type == RuntimeType.ART:
            self.parse_oat_file()
            result['oat_info'] = self.oat_info.__dict__ if self.oat_info else None
        
        result['classes'] = self.extract_dex_class_names()
        result['native_methods'] = self.find_native_methods()
        result['vulnerabilities'] = self._detect_art_vulnerabilities()
        
        return result
    
    def _detect_art_vulnerabilities(self) -> List[Dict[str, Any]]:
        """检测 ART 特有漏洞"""
        vulns = []
        
        native_methods = self.find_native_methods()
        
        for method in native_methods:
            java_class = method['java_class']
            
            if 'android' not in java_class.lower():
                vulns.append({)
                    'type': 'Native Code Injection',
                    'severity': 'High',
                    'description': f'非系统类 {java_class} 使用原生代码',
                    'location': method['method_name']
                }
            
            if any(keyword in method['method_name'].lower() )
                   for keyword in ['exec', 'system', 'runtime']):
                vulns.append({)
                    'type': 'Command Injection',
                    'severity': 'Critical',
                    'description': f'原生方法可能执行命令注入',
                    'location': method['method_name']
                }
        
        return vulns


class IOSRuntimeAnalyzer:
    """
    iOS 运行时分析器
    
    支持 Objective-C 和 Swift 运行时的深度分析
    """
    
    def __init__(self, binary_path: str):
        """
        初始化 iOS 运行时分析器
        
        Args:
            binary_path: Mach-O 文件路径
        """
        self.binary_path = Path(binary_path)
        self.data = self._read_binary()
        self.classes: List[MachORuntimeClass] = []
        self.swift_info: Optional[SwiftyRuntimeInfo] = None
        self._verify_is_macho()
    
    def _read_binary(self) -> bytes:
        """读取二进制文件"""
        try:
            with open(self.binary_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"读取二进制文件失败: {e}")
            return b''
    
    def _verify_is_macho(self) -> bool:
        """验证是否为 Mach-O 文件"""
        mach_magics = [
            b'\xfe\xed\xfa\xce',  # MH_MAGIC_64
            b'\xce\xfa\xed\xfe',  # MH_CIGAM_64
            b'\xfe\xed\xfa\xcf',  # MH_MAGIC
            b'\xcf\xfa\xed\xfe',  # MH_CIGAM
        ]
        return self.data[:4] in mach_magics
    
    def parse_objc_classlist(self) -> List[MachORuntimeClass]:
        """
        解析 Objective-C 类列表
        
        Returns:
            类信息列表
        """
        classes = []
        
        objc2_class_pattern = b'_OBJC_CLASS_$_'
        objc2_metaclass_pattern = b'_OBJC_METACLASS_$_'
        
        for pattern, is_metaclass in [(objc2_class_pattern, False), 
                                      (objc2_metaclass_pattern, True)]:
            offset = 0,
            while True:
                offset = self.data.find(pattern, offset)
                if offset == -1:
                    break
                
                name_end = self.data.find(b'\x00', offset + len(pattern

                if name_end == -1:
                    break
                
                class_name = self.data[offset + len(pattern):name_end].decode('utf-8', errors='ignore')
                
                mach_class = MachORuntimeClass()
                    name=class_name,
                    superclass="",
                    methods=[],
                    ivars=[],
                    properties=[],
                    protocols=[],
                    is_metaclass=is_metaclass
                
                
                classes.append(mach_class)
                offset += len(pattern)
        
        self.classes = classes
        logger.info(f"解析 {len(classes)} 个 Objective-C 类")
        return classes
    
    def parse_objc_selectors(self) -> Dict[str, int]:
        """
        解析 Objective-C 选择器
        
        Returns:
            选择器到地址的映射
        """
        selectors = {}
        
        selreftypattern = b'_objc_selrefs'
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
        
        logger.info(f"解析 {len(selectors)} 个 Objective-C 选择器")
        return selectors
    
    def find_swift_metadata(self) -> Optional[SwiftyRuntimeInfo]:
        """
        查找 Swift 元数据
        
        Returns:
            Swift 运行时信息
        """
        swift_info = SwiftyRuntimeInfo()
            class_metadata={},
            vtable=[],
            witness_table=[],
            mangled_names=[]
        
        
        swift_patterns = [
            b'_TtC',  # Swift 类
            b'_TtS',  # Swift 结构体
            b'_TtO',  # Swift 枚举
            b'_TMf',  # Swift 元类
        ]
        
        mangled_pattern = r'_T[A-Z][a-zA-Z0-9_]+'
        
        for pattern in swift_patterns:
            offset = 0,
            while True:
                offset = self.data.find(pattern, offset)
                if offset == -1:
                    break
                
                mangled_end = offset + len(pattern)
                while mangled_end < len(self.data) and ()
                    0x41 <= self.data[mangled_end] <= 0x5A or
                    0x61 <= self.data[mangled_end] <= 0x7A or
                    0x30 <= self.data[mangled_end] <= 0x39 or
                    self.data[mangled_end] == 0x5F
                ):
                    mangled_end += 1
                
                mangled_name = self.data[offset:mangled_end].decode('utf-8', errors='ignore')
                swift_info.mangled_names.append(mangled_name)
                
                offset = mangled_end
        
        swift_info.mangled_names = list(set(swift_info.mangled_names

        
        if swift_info.mangled_names:
            self.swift_info = swift_info
            logger.info(f"发现 {len(swift_info.mangled_names)} 个 Swift 符号")
        
        return self.swift_info
    
    def find_selector_references(self) -> List[Dict[str, Any]]:
        """
        查找选择器引用（潜在的消息注入点）
        
        Returns:
            选择器引用列表
        """
        refs = []
        
        selrefs_pattern = b'_objc_msgSend'
        offset = 0
        
        while True:
            offset = self.data.find(selrefs_pattern, offset)
            if offset == -1:
                break
            
            context_start = max(0, offset - 50)
            context_end = min(len(self.data), offset + 50)
            context = self.data[context_start:context_end]
            
            refs.append({)
                'address': offset,
                'context': context.hex()[:100]
            }
            
            offset += len(selrefs_pattern)
        
        logger.info(f"发现 {len(refs)} 个 objc_msgSend 引用")
        return refs
    
    def analyze(self) -> Dict[str, Any]:
        """
        执行完整的 iOS 运行时分析
        
        Returns:
            分析结果
        """
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
        if swift_info:
            result['swift_info'] = swift_info.__dict__
        
        result['vulnerabilities'] = self._detect_ios_vulnerabilities()
        
        return result
    
    def _detect_ios_vulnerabilities(self) -> List[Dict[str, Any]]:
        """检测 iOS 特有漏洞"""
        vulns = []
        
        dangerous_selectors = [
            ('performSelector', 'Remote Code Execution'),
            ('NSClassFromString', 'Class Injection'),
            ('NSSelectorFromString', 'Selector Injection'),
            ('dlopen', 'Dynamic Library Injection'),
            ('dlsym', 'Symbol Injection'),
        ]
        
        selectors = self.parse_objc_selectors()
        
        for selector, vuln_type in dangerous_selectors:
            if selector in selectors:
                vulns.append({)
                    'type': vuln_type,
                    'severity': 'Medium',
                    'description': f'使用危险选择器 {selector}',
                    'location': f'偏移 0x{selectors[selector]:x}'
                }
        
        for mach_class in self.classes:
            if 'Keychain' in mach_class.name or 'SecItem' in mach_class.name:
                vulns.append({)
                    'type': 'Keychain Access',
                    'severity': 'Info',
                    'description': f'应用访问 Keychain: {mach_class.name}',
                    'location': mach_class.name
                }
        
        if self.swift_info and self.swift_info.mangled_names:
            if any('password' in name.lower() or 'secret' in name.lower() )
                   for name in self.swift_info.mangled_names):
                vulns.append({)
                    'type': 'Swift Symbol Exposure',
                    'severity': 'Low',
                    'description': 'Swift 符号中可能包含敏感名称',
                    'location': 'Symbol table'
                }
        
        return vulns


def analyze_mobile_binary(, binary_path: str, platform: str = 'auto') -> Dict[str, Any]:
    """
    便捷函数：分析移动平台二进制
    
    Args:
        binary_path: 二进制文件路径
        platform: 平台类型 (auto, android, ios)
        
    Returns:
        分析结果
    """
    binary_path = Path(binary_path)
    
    if not binary_path.exists():
        logger.error(f"文件不存在: {binary_path}")
        return {'error': 'File not found'}
    
    if platform == 'auto':
        magic = binary_path.read_bytes()[:4]
        
        if magic in [b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', 
                     b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xce']:
            platform = 'ios'
        else:
            platform = 'android'
    
    if platform == 'android':
        analyzer = AndroidRTAnalyzer(str(binary_path

        result = analyzer.analyze()
        result['platform'] = 'android'
    else:
        analyzer = IOSRuntimeAnalyzer(str(binary_path

        result = analyzer.analyze()
        result['platform'] = 'ios'
    
    return result))))))))