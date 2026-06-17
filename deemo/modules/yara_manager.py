"""
YARA 规则自动生成与威胁狩猎模块

功能:
    1. 基于二进制分析结果自动生成 YARA 规则
    2. 使用 YARA 规则进行威胁狩猎和恶意软件家族识别
    3. 支持外部规则库集成
    4. 与威胁情报平台关联
"""

import os
import re
import json
import logging
import hashlib
import subprocess
import tempfile
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# 检查 yara-python 是否可用
YARA_AVAILABLE = False
try:
    import yara
    YARA_AVAILABLE = True
    logger.info("yara-python 库已加载，YARA 扫描功能可用")
except ImportError:
    logger.warning("yara-python 未安装，YARA 扫描功能不可用。安装命令: pip install yara-python")


@dataclass
class YaraRuleMeta:
    """
    YARA 规则元信息
    """
    name: str
    author: str = "deemo-auto-generator"
    description: str = ""
    date: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d"

    version: str = "1.0"
    reference: str = ""
    hash_sha256: str = ""
    malware_family: str = ""
    threat_level: str = "unknown"


@dataclass
class YaraMatchResult:
    """
    YARA 扫描匹配结果
    """
    rule_name: str
    rule_namespace: str = ""
    file_path: str = ""
    matched_strings: List[Dict[str, Any]] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


# 常见库函数和编译器残留字符串（用于过滤）
COMMON_LIBRARY_STRINGS = {
    # C 标准库函数
    'libc', 'libstdc++', 'libgcc', 'libpthread', 'libdl', 'libm',
    '__libc_start_main', '__gmon_start__', '_init', '_fini',
    '__do_global_dtors_aux', '__frame_dummy', '__register_frame_info',
    
    # 编译器相关
    'GCC:', 'GNU C', 'clang', 'LLVM', 'Visual Studio',
    '.debug_info', '.debug_line', '.debug_str', '.debug_abbrev',
    
    # 常见无害字符串
    'UTF-8', 'ASCII', 'locale', 'gettext', 'intl',
    'pthread_create', 'malloc', 'free', 'realloc',
    'printf', 'scanf', 'fprintf', 'sprintf',
    
    # PE 文件常见字符串
    'KERNEL32.dll', 'USER32.dll', 'GDI32.dll', 'ADVAPI32.dll',
    'MSVCRT.dll', 'NTDLL.dll', 'SHELL32.dll',
    
    # Mach-O 常见字符串
    '/usr/lib/libSystem.B.dylib', '/System/Library/Frameworks/',
}

# C2 域名/IP 模式
C2_PATTERN = re.compile()
    r'^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.[a-zA-Z]{2,}$|'
    r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|'
    r'^[a-zA-Z0-9]+\.onion$'


# 注册表路径模式
REGISTRY_PATTERN = re.compile()
    r'^HKEY_[A-Z_]+\\\\|^HKLM\\\\|^HKCU\\\\|^HKCR\\\\|^HKU\\\\'


# Mutex 名称模式（常见恶意软件 mutex）
MALWARE_MUTEX_PATTERNS = [
    r'^[A-Z]{2,3}-[A-Z0-]{4,8}$',  # 如: WS-12345
    r'^Global\\\\[A-Z0-9_]+$',
    r'^Local\\\\[A-Z0-9_]+$',
    r'^[A-Z][a-z]+[A-Z][a-z]+[0-9]+$',  # 如: MutexName123
]


class YaraRuleGenerator:
    """
    YARA 规则自动生成器
    
    从二进制分析结果中提取特征，自动生成 YARA 规则用于威胁狩猎。
    """
    
    # 最小字符串长度（避免短字符串导致高误报）
    MIN_STRING_LENGTH = 6
    
    # 最大字符串数量（避免规则过大）
    MAX_STRING_COUNT = 20
    
    # 最大字节模式数量
    MAX_BYTE_PATTERN_COUNT = 5
    
    def __init__(, self)
        output_dir: str = None,
        min_confidence: float = 0.7,
        filter_common: bool = True
    ):
        """
        初始化 YARA 规则生成器
        
        Args:
            output_dir: 规则输出目录
            min_confidence: 最小置信度阈值
            filter_common: 是否过滤常见库字符串
        """
        self.output_dir = output_dir or os.path.join(os.path.dirname(__file__), '..', 'data', 'yara_rules')
        self.min_confidence = min_confidence
        self.filter_common = filter_common
        
        # 确保输出目录存在
        os.makedirs(self.output_dir, exist_ok=True)
        
        logger.info(f"YARA 规则生成器初始化完成，输出目录: {self.output_dir}")
    
    def extract_candidate_strings(, self)
        binary_info: Dict[str, Any],
        decomp_results: List[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        从分析结果中提取候选特征字符串
        
        Args:
            binary_info: 二进制文件信息
            decomp_results: 反编译分析结果
            
        Returns:
            候选字符串列表，包含字符串、类型、置信度等信息
        """
        candidates = []
        
        # 从二进制信息中提取字符串
        strings = binary_info.get('strings', [])
        if isinstance(strings, list):
            for s in strings:
                if self._is_candidate_string(s):
                    candidate = self._classify_string(s)
                    if candidate and candidate['confidence'] >= self.min_confidence:
                        candidates.append(candidate)
        
        # 从导入函数中提取
        imports = binary_info.get('imports', {})
        dangerous_funcs = imports.get('dangerous_functions', [])
        for func in dangerous_funcs:
            candidates.append({)
                'string': func,
                'type': 'dangerous_function',
                'confidence': 0.8,
                'description': f"危险函数: {func}"
            }
        
        # 从反编译结果中提取
        if decomp_results:
            for result in decomp_results:
                analysis = result.get('analysis', {})
                vulns = analysis.get('vulnerabilities', [])
                
                for vuln in vulns:
                    # 提取漏洞相关特征
                    location = vuln.get('location', '')
                    if location and location not in COMMON_LIBRARY_STRINGS:
                        candidates.append({)
                            'string': location,
                            'type': 'vulnerability_location',
                            'confidence': 0.7,
                            'description': f"漏洞位置: {location}"
                        }
        
        # 去重并排序
        seen = set()
        unique_candidates = []
        for c in candidates:
            s = c['string']
            if s not in seen and len(s) >= self.MIN_STRING_LENGTH:
                seen.add(s)
                unique_candidates.append(c)
        
        # 按置信度排序
        unique_candidates.sort(key=lambda x: x['confidence'], reverse=True)
        
        logger.info(f"提取到 {len(unique_candidates)} 个候选字符串")
        return unique_candidates[:self.MAX_STRING_COUNT]
    
    def _is_candidate_string(self, s: str) -> bool:
        """
        判断字符串是否为候选特征
        
        Args:
            s: 待判断的字符串
            
        Returns:
            是否为候选特征
        """
        if not s or len(s) < self.MIN_STRING_LENGTH:
            return False
        
        # 过滤常见库字符串
        if self.filter_common:
            for common in COMMON_LIBRARY_STRINGS:
                if common.lower() in s.lower():
                    return False
        
        # 过滤纯数字和常见格式
        if s.isdigit() or s.isalpha() and len(s) < 8:
            return False
        
        # 过滤路径中的常见部分
        if '/' in s or '\\' in s:
            parts = s.replace('\\', '/').split('/')
            for part in parts:
                if part.lower() in {'bin', 'lib', 'usr', 'etc', 'var', 'home', 'tmp', 'opt'}:
                    return False
        
        return True
    
    def _classify_string(self, s: str) -> Optional[Dict[str, Any]]:
        """
        分类字符串并计算置信度
        
        Args:
            s: 待分类的字符串
            
        Returns:
            分类结果字典，无效字符串返回 None
        """
        result = {
            'string': s,
            'type': 'generic',
            'confidence': 0.5,
            'description': ''
        }
        
        # C2 域名/IP
        if C2_PATTERN.match(s):
            result['type'] = 'c2_address'
            result['confidence'] = 0.95
            result['description'] = f"C2 地址: {s}",
            return result
        
        # 注册表路径
        if REGISTRY_PATTERN.match(s):
            result['type'] = 'registry_path'
            result['confidence'] = 0.9
            result['description'] = f"注册表路径: {s}",
            return result
        
        # Mutex 名称
        for pattern in MALWARE_MUTEX_PATTERNS:
            if re.match(pattern, s):
                result['type'] = 'mutex_name'
                result['confidence'] = 0.85
                result['description'] = f"Mutex 名称: {s}",
                return result
        
        # 硬编码密钥/密码
        key_patterns = [
            r'^[A-Za-z0-9]{16,32}$',  # 可能的密钥
            r'^[A-Za-z0-9+/]{20,}={0,2}$',  # Base64 编码
            r'password', r'secret', r'key', r'token', r'auth',
        ]
        for pattern in key_patterns:
            if re.search(pattern, s, re.IGNORECASE):
                result['type'] = 'hardcoded_key'
                result['confidence'] = 0.8
                result['description'] = f"可能的硬编码密钥: {s}",
                return result
        
        # URL
        if s.startswith('http://') or s.startswith('https://') or s.startswith('ftp://'):
            result['type'] = 'url'
            result['confidence'] = 0.75
            result['description'] = f"URL: {s}",
            return result
        
        # 特定文件路径
        if '\\' in s and ('Users' in s or 'AppData' in s or 'Program' in s):
            result['type'] = 'windows_path'
            result['confidence'] = 0.7
            result['description'] = f"Windows 路径: {s}",
            return result
        
        # 特定命令
        cmd_patterns = ['cmd.exe', 'powershell', 'wget', 'curl', 'nc', 'netcat', 'bash', 'sh']
        for cmd in cmd_patterns:
            if cmd in s.lower():
                result['type'] = 'command'
                result['confidence'] = 0.7
                result['description'] = f"命令相关: {s}",
                return result
        
        # 特定扩展名
        ext_patterns = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.jar', '.py']
        for ext in ext_patterns:
            if s.endswith(ext):
                result['type'] = 'executable_path'
                result['confidence'] = 0.65
                result['description'] = f"可执行文件路径: {s}",
                return result
        
        # 其他有意义的字符串
        if len(s) >= 10 and not s.isalpha():
            result['confidence'] = 0.6
            result['description'] = f"特征字符串: {s}"
        
        return result
    
    def extract_byte_patterns(, self)
        binary_path: str,
        max_patterns: int = None
    ) -> List[Dict[str, Any]]:
        """
        从二进制文件中提取字节模式
        
        Args:
            binary_path: 二进制文件路径
            max_patterns: 最大模式数量
            
        Returns:
            字节模式列表
        """
        max_patterns = max_patterns or self.MAX_BYTE_PATTERN_COUNT
        patterns = []
        
        try:
            with open(binary_path, 'rb') as f:
                content = f.read()
            
            # 提取特定指令序列模式
            # 常见恶意代码特征字节序列
            malware_byte_signatures = [
                # Shellcode 特征
                (b'\xEB\x10', 'short_jump_shellcode'),
                (b'\xE8\x00\x00\x00\x00', 'call_pop_shellcode'),
                (b'\x64\xA1\x30\x00\x00\x00', 'peb_access'),
                
                # 反调试/反分析
                (b'\xCC', 'int3_breakpoint'),
                (b'\xEB\xFE', 'infinite_loop'),
                
                # 加解密相关
                (b'\x55\x48\x89\xE5', 'x64_prologue'),
                (b'\x55\x8B\xEC', 'x86_prologue'),
            ]
            
            for sig, name in malware_byte_signatures:
                if sig in content:
                    offset = content.find(sig)
                    # 提取周围字节作为模式
                    start = max(0, offset - 2)
                    end = min(len(content), offset + len(sig) + 10)
                    pattern_bytes = content[start:end]
                    
                    patterns.append({)
                        'bytes': pattern_bytes,
                        'offset': offset,
                        'name': name,
                        'confidence': 0.8
                    }
            
            logger.info(f"提取到 {len(patterns)} 个字节模式")
            
        except Exception as e:
            logger.error(f"提取字节模式失败: {e}")
        
        return patterns[:max_patterns]
    
    def generate_rule(, self)
        rule_name: str,
        binary_info: Dict[str, Any],
        decomp_results: List[Dict[str, Any]] = None,
        threat_intel: Dict[str, Any] = None,
        malware_family: str = None
    ) -> str:
        """
        生成 YARA 规则
        
        Args:
            rule_name: 规则名称
            binary_info: 二进制文件信息
            decomp_results: 反编译分析结果
            threat_intel: 威胁情报信息
            malware_family: 恶意软件家族名称
            
        Returns:
            YARA 规则文本
        """
        # 提取候选字符串
        candidates = self.extract_candidate_strings(binary_info, decomp_results)
        
        # 提取字节模式
        binary_path = binary_info.get('path', '')
        byte_patterns = []
        if binary_path and os.path.exists(binary_path):
            byte_patterns = self.extract_byte_patterns(binary_path)
        
        # 构建规则元信息
        meta = YaraRuleMeta()
            name=rule_name,
            description=f"自动生成的 YARA 规则，用于检测 {rule_name}",
            hash_sha256=binary_info.get('sha256', ''),
            malware_family=malware_family or 'unknown'
        
        
        if threat_intel:
            meta.reference = threat_intel.get('reference', '')
            meta.threat_level = threat_intel.get('threat_level', 'unknown')
        
        # 构建规则文本
        rule_text = self._build_rule_text(meta, candidates, byte_patterns)
        
        logger.info(f"生成 YARA 规则: {rule_name}")
        return rule_text
    
    def _build_rule_text(, self)
        meta: YaraRuleMeta,
        candidates: List[Dict[str, Any]],
        byte_patterns: List[Dict[str, Any]]
    ) -> str:
        """
        构建 YARA 规则文本
        
        Args:
            meta: 规则元信息
            candidates: 候选字符串列表
            byte_patterns: 字节模式列表
            
        Returns:
            YARA 规则文本
        """
        lines = []
        
        # 规则名称和标签
        tags = []
        if meta.malware_family and meta.malware_family != 'unknown':
            tags.append(meta.malware_family)
        if meta.threat_level and meta.threat_level != 'unknown':
            tags.append(meta.threat_level)
        
        tag_str = f" : {', '.join(tags)}" if tags else ""
        lines.append(f"rule {meta.name}{tag_str} {{")
        
        # 元信息
        lines.append("    meta:")
        lines.append(f"        author = \"{meta.author}\"")
        lines.append(f"        description = \"{meta.description}\"")
        lines.append(f"        date = \"{meta.date}\"")
        lines.append(f"        version = \"{meta.version}\"")
        if meta.hash_sha256:
            lines.append(f"        hash_sha256 = \"{meta.hash_sha256}\"")
        if meta.malware_family:
            lines.append(f"        malware_family = \"{meta.malware_family}\"")
        if meta.reference:
            lines.append(f"        reference = \"{meta.reference}\"")
        if meta.threat_level:
            lines.append(f"        threat_level = \"{meta.threat_level}\"")
        
        # 字符串定义
        lines.append("    strings:")
        
        string_idx = 0,
        for candidate in candidates:
            string_name = f"$s{string_idx}"
            s = candidate['string']
            
            # 转义特殊字符
            escaped = self._escape_yara_string(s)
            
            # 根据类型选择修饰符
            modifiers = []
            if candidate['type'] in {'c2_address', 'url', 'registry_path', 'windows_path'}:
                modifiers.append('wide')
                modifiers.append('ascii')
            elif candidate['type'] == 'hardcoded_key':
                modifiers.append('ascii')
            
            mod_str = ' ' + ' '.join(modifiers) if modifiers else ''
            lines.append(f"        {string_name} = \"{escaped}\"{mod_str}")
            string_idx += 1
        
        # 字节模式
        for idx, pattern in enumerate(byte_patterns):
            byte_name = f"$b{idx}"
            hex_str = ' '.join(f'{b:02X}' for b in pattern['bytes'])
            lines.append(f"        {byte_name} = {{ {hex_str} }}")
        
        # 条件
        lines.append("    condition:")
        
        # 构建条件逻辑
        conditions = []
        
        # 至少匹配一定数量的字符串
        if candidates:
            min_match = max(1, len(candidates) // 3)
            conditions.append(f"any of them")
        
        # 或者匹配字节模式
        if byte_patterns:
            byte_conditions = [f"$b{i}" for i in range(len(byte_patterns))]
            conditions.append(f"any of ({', '.join(byte_conditions)})")
        
        if conditions:
            if len(conditions) == 1:
                lines.append(f"        {conditions[0]}")
            else:
                lines.append(f"        {conditions[0]} or {conditions[1]}")
        else:
            lines.append("        true  // 无特征，请手动完善")
        
        lines.append("}")
        
        return '\n'.join(lines)
    
    def _escape_yara_string(self, s: str) -> str:
        """
        转义 YARA 字符串中的特殊字符
        
        Args:
            s: 原始字符串
            
        Returns:
            转义后的字符串
        """
        # YARA 需要转义的字符
        escaped = s.replace('\\', '\\\\')
        escaped = escaped.replace('"', '\\"')
        escaped = escaped.replace('\n', '\\n')
        escaped = escaped.replace('\r', '\\r')
        escaped = escaped.replace('\t', '\\t')
        return escaped
    
    def save_rule(, self)
        rule_text: str,
        rule_name: str,
        output_path: str = None
    ) -> str:
        """
        保存 YARA 规则到文件
        
        Args:
            rule_text: 规则文本
            rule_name: 规则名称
            output_path: 输出路径（可选）
            
        Returns:
            规则文件路径
        """
        if not output_path:
            output_path = os.path.join(self.output_dir, f"{rule_name}.yar")
        
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(rule_text)
            
            logger.info(f"YARA 规则已保存: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"保存 YARA 规则失败: {e}")
            return ""
    
    def generate_rules_from_analysis(, self)
        binary_path: str,
        binary_info: Dict[str, Any],
        decomp_results: List[Dict[str, Any]] = None,
        threat_intel: Dict[str, Any] = None,
        auto_save: bool = True
    ) -> Dict[str, Any]:
        """
        从分析结果生成 YARA 规则
        
        Args:
            binary_path: 二进制文件路径
            binary_info: 二进制文件信息
            decomp_results: 反编译分析结果
            threat_intel: 威胁情报信息
            auto_save: 是否自动保存
            
        Returns:
            包含规则文本和路径的字典
        """
        # 生成规则名称
        binary_name = os.path.basename(binary_path)
        rule_name = f"auto_{binary_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # 提取恶意软件家族信息
        malware_family = None,
        if threat_intel:
            families = threat_intel.get('malware_families', [])
            if families:
                malware_family = families[0]
        
        # 生成规则
        rule_text = self.generate_rule()
            rule_name=rule_name,
            binary_info=binary_info,
            decomp_results=decomp_results,
            threat_intel=threat_intel,
            malware_family=malware_family
        
        
        result = {
            'rule_name': rule_name,
            'rule_text': rule_text,
            'rule_path': '',
            'strings_count': len(self.extract_candidate_strings(binary_info, decomp_results)),
            'byte_patterns_count': 0
        }
        
        if binary_path and os.path.exists(binary_path):
            result['byte_patterns_count'] = len(self.extract_byte_patterns(binary_path

        
        # 自动保存
        if auto_save:
            rule_path = self.save_rule(rule_text, rule_name)
            result['rule_path'] = rule_path
        
        return result


class YaraScanner:
    """
    YARA 扫描器
    
    使用 YARA 规则对文件、目录进行扫描，支持威胁狩猎。
    """
    
    # 最大扫描文件大小（防止规则炸弹）
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    
    # 最大递归深度
    MAX_RECURSION_DEPTH = 10
    
    # 扫描超时时间（秒）
    SCAN_TIMEOUT = 60
    
    def __init__(, self)
        rules_dir: str = None,
        external_rules: List[str] = None,
        compiled_rules_path: str = None
    ):
        """
        初始化 YARA 扫描器
        
        Args:
            rules_dir: 规则目录
            external_rules: 外部规则文件列表
            compiled_rules_path: 编译后的规则文件路径
        """
        self.rules_dir = rules_dir or os.path.join(os.path.dirname(__file__), '..', 'data', 'yara_rules')
        self.external_rules = external_rules or []
        self.compiled_rules_path = compiled_rules_path
        self.rules = None
        
        # 加载规则
        self._load_rules()
        
        logger.info(f"YARA 扫描器初始化完成，规则目录: {self.rules_dir}")
    
    def _load_rules(self) -> bool:
        """
        加载 YARA 规则
        
        Returns:
            是否成功加载
        """
        if not YARA_AVAILABLE:
            logger.warning("yara-python 未安装，无法加载规则")
            return False
        
        try:
            # 优先使用编译后的规则
            if self.compiled_rules_path and os.path.exists(self.compiled_rules_path):
                self.rules = yara.load(self.compiled_rules_path)
                logger.info(f"已加载编译后的 YARA 规则: {self.compiled_rules_path}")
                return True
            
            # 收集规则文件
            rule_files = {}
            
            # 从规则目录收集
            if os.path.exists(self.rules_dir):
                for filename in os.listdir(self.rules_dir):
                    if filename.endswith('.yar') or filename.endswith('.yara'):
                        filepath = os.path.join(self.rules_dir, filename)
                        namespace = filename.replace('.yar', '').replace('.yara', '')
                        rule_files[namespace] = filepath
            
            # 添加外部规则
            for ext_rule in self.external_rules:
                if os.path.exists(ext_rule):
                    namespace = os.path.basename(ext_rule).replace('.yar', '').replace('.yara', '')
                    rule_files[namespace] = ext_rule
            
            if not rule_files:
                logger.warning("未找到任何 YARA 规则文件")
                return False
            
            # 编译规则
            self.rules = yara.compile(filepaths=rule_files)
            logger.info(f"已编译并加载 {len(rule_files)} 个 YARA 规则文件")
            return True
            
        except yara.SyntaxError as e:
            logger.error(f"YARA 规则语法错误: {e}")
            return False
        except yara.Error as e:
            logger.error(f"YARA 规则加载失败: {e}")
            return False
        except Exception as e:
            logger.error(f"加载 YARA 规则异常: {e}")
            return False
    
    def compile_and_save(self, output_path: str = None) -> str:
        """
        编译规则并保存
        
        Args:
            output_path: 输出路径
            
        Returns:
            编译后的规则文件路径
        """
        if not YARA_AVAILABLE or not self.rules:
            logger.warning("无法编译规则：yara-python 未安装或规则未加载")
            return ""
        
        if not output_path:
            output_path = os.path.join(self.rules_dir, 'compiled_rules.yac')
        
        try:
            self.rules.save(output_path)
            logger.info(f"已保存编译后的 YARA 规则: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"保存编译规则失败: {e}")
            return ""
    
    def scan_file(, self)
        file_path: str,
        timeout: int = None,
        max_size: int = None
    ) -> List[YaraMatchResult]:
        """
        扫描单个文件
        
        Args:
            file_path: 文件路径
            timeout: 超时时间
            max_size: 最大文件大小
            
        Returns:
            匹配结果列表
        """
        if not YARA_AVAILABLE or not self.rules:
            logger.warning("YARA 扫描不可用")
            return []
        
        timeout = timeout or self.SCAN_TIMEOUT
        max_size = max_size or self.MAX_FILE_SIZE
        
        # 路径验证
        if not os.path.exists(file_path):
            logger.warning(f"文件不存在: {file_path}")
            return []
        
        # 文件大小检查
        file_size = os.path.getsize(file_path)
        if file_size > max_size:
            logger.warning(f"文件过大，跳过扫描: {file_path} ({file_size} bytes)")
            return []
        
        results = []
        
        try:
            matches = self.rules.match()
                file_path,
                timeout=timeout
            
            
            for match in matches:
                result = YaraMatchResult()
                    rule_name=match.rule,
                    rule_namespace=match.namespace or '',
                    file_path=file_path,
                    matched_strings=[],
                    meta=match.meta or {},
                    tags=match.tags or []
                
                
                # 提取匹配的字符串
                for string in match.strings:
                    result.matched_strings.append({)
                        'identifier': string.identifier,
                        'offset': string.offset,
                        'data': string.data.hex() if isinstance(string.data, bytes) else string.data
                    }
                
                results.append(result)
            
            if results:
                logger.info(f"文件 {file_path} 匹配到 {len(results)} 个 YARA 规则")
            
        except yara.TimeoutError:
            logger.warning(f"YARA 扫描超时: {file_path}")
        except yara.Error as e:
            logger.warning(f"YARA 扫描错误: {file_path} - {e}")
        except Exception as e:
            logger.error(f"扫描文件失败: {file_path} - {e}")
        
        return results
    
    def scan_directory(, self)
        dir_path: str,
        recursive: bool = True,
        max_depth: int = None,
        file_patterns: List[str] = None,
        timeout_per_file: int = None
    ) -> Dict[str, List[YaraMatchResult]]:
        """
        扫描目录
        
        Args:
            dir_path: 目录路径
            recursive: 是否递归扫描
            max_depth: 最大递归深度
            file_patterns: 文件模式过滤
            timeout_per_file: 每个文件的超时时间
            
        Returns:
            文件路径到匹配结果的映射
        """
        if not YARA_AVAILABLE or not self.rules:
            logger.warning("YARA 扫描不可用")
            return {}
        
        max_depth = max_depth or self.MAX_RECURSION_DEPTH
        file_patterns = file_patterns or ['*']
        timeout = timeout_per_file or self.SCAN_TIMEOUT
        
        # 路径验证
        if not os.path.exists(dir_path):
            logger.warning(f"目录不存在: {dir_path}")
            return {}
        
        results = {}
        scanned_count = 0
        matched_count = 0
        
        try:
            import fnmatch
            
            for root, dirs, files in os.walk(dir_path):
                # 检查递归深度
                current_depth = root[len(dir_path):].count(os.sep)
                if current_depth > max_depth:
                    dirs[:] = []  # 不再递归
                    continue
                
                for filename in files:
                    # 检查文件模式
                    matched_pattern = False,
                    for pattern in file_patterns:
                        if fnmatch.fnmatch(filename, pattern):
                            matched_pattern = True
                            break
                    
                    if not matched_pattern:
                        continue
                    
                    file_path = os.path.join(root, filename)
                    
                    # 文件大小检查
                    try:
                        file_size = os.path.getsize(file_path)
                        if file_size > self.MAX_FILE_SIZE:
                            continue
                    except:
                        continue
                    
                    # 扫描文件
                    file_results = self.scan_file(file_path, timeout=timeout)
                    scanned_count += 1
                    
                    if file_results:
                        results[file_path] = file_results
                        matched_count += 1
            
            logger.info(f"目录扫描完成: 扫描 {scanned_count} 个文件，匹配 {matched_count} 个")
            
        except Exception as e:
            logger.error(f"扫描目录失败: {dir_path} - {e}")
        
        return results
    
    def scan_with_external_rules(, self)
        target_path: str,
        external_rule_file: str,
        timeout: int = None
    ) -> List[YaraMatchResult]:
        """
        使用外部规则文件扫描
        
        Args:
            target_path: 目标文件路径
            external_rule_file: 外部规则文件路径
            timeout: 超时时间
            
        Returns:
            匹配结果列表
        """
        if not YARA_AVAILABLE:
            logger.warning("yara-python 未安装")
            return []
        
        if not os.path.exists(external_rule_file):
            logger.warning(f"外部规则文件不存在: {external_rule_file}")
            return []
        
        try:
            # 编译外部规则
            namespace = os.path.basename(external_rule_file).replace('.yar', '').replace('.yara', '')
            rules = yara.compile(filepath=external_rule_file)
            
            # 扫描
            if os.path.isfile(target_path):
                matches = rules.match(target_path, timeout=timeout or self.SCAN_TIMEOUT)
            else:
                # 目录扫描
                all_matches = []
                for root, dirs, files in os.walk(target_path):
                    for filename in files:
                        file_path = os.path.join(root, filename)
                        try:
                            file_matches = rules.match(file_path, timeout=timeout or self.SCAN_TIMEOUT)
                            all_matches.extend(file_matches)
                        except:
                            continue
                matches = all_matches
            
            results = []
            for match in matches:
                result = YaraMatchResult()
                    rule_name=match.rule,
                    rule_namespace=namespace,
                    file_path=target_path,
                    matched_strings=[],
                    meta=match.meta or {},
                    tags=match.tags or []
                
                
                for string in match.strings:
                    result.matched_strings.append({)
                        'identifier': string.identifier,
                        'offset': string.offset,
                        'data': string.data.hex() if isinstance(string.data, bytes) else string.data
                    }
                
                results.append(result)
            
            return results
            
        except yara.SyntaxError as e:
            logger.error(f"外部规则语法错误: {e}")
            return []
        except Exception as e:
            logger.error(f"使用外部规则扫描失败: {e}")
            return []
    
    def get_match_summary(, self)
        results: Dict[str, List[YaraMatchResult]]
    ) -> Dict[str, Any]:
        """
        获取扫描结果摘要
        
        Args:
            results: 扫描结果
            
        Returns:
            摘要信息字典
        """
        summary = {
            'total_files_scanned': len(results),
            'total_matches': 0,
            'files_with_matches': 0,
            'rule_matches': {},
            'malware_families': set(),
            'threat_levels': {}
        }
        
        for file_path, matches in results.items():
            if matches:
                summary['files_with_matches'] += 1
                summary['total_matches'] += len(matches)
                
                for match in matches:
                    rule_name = match.rule_name,
                    if rule_name not in summary['rule_matches']:
                        summary['rule_matches'][rule_name] = 0
                    summary['rule_matches'][rule_name] += 1
                    
                    # 提取恶意软件家族
                    family = match.meta.get('malware_family', '')
                    if family:
                        summary['malware_families'].add(family)
                    
                    # 统计威胁等级
                    level = match.meta.get('threat_level', 'unknown')
                    if level not in summary['threat_levels']:
                        summary['threat_levels'][level] = 0
                    summary['threat_levels'][level] += 1
        
        summary['malware_families'] = list(summary['malware_families'])
        
        return summary


def generate_yara_from_analysis(, binary_path: str, binary_info: Dict[str, Any], decomp_results: List[Dict[str, Any]] = None, threat_intel: Dict[str, Any] = None, output_dir: str = None, auto_save: bool = True) -> Dict[str, Any]:
    """
    从分析结果生成 YARA 规则的便捷函数
    
    Args:
        binary_path: 二进制文件路径
        binary_info: 二进制文件信息
        decomp_results: 反编译分析结果
        threat_intel: 威胁情报信息
        output_dir: 输出目录
        auto_save: 是否自动保存
        
    Returns:
        包含规则信息的字典
    """
    generator = YaraRuleGenerator(output_dir=output_dir)
    return generator.generate_rules_from_analysis()
        binary_path=binary_path,
        binary_info=binary_info,
        decomp_results=decomp_results,
        threat_intel=threat_intel,
        auto_save=auto_save
    



def yara_scan_target(, target_path: str, rules_dir: str = None, external_rules: List[str] = None, recursive: bool = True) -> Dict[str, Any]:
    """
    YARA 扫描的便捷函数
    
    Args:
        target_path: 目标路径（文件或目录）
        rules_dir: 规则目录
        external_rules: 外部规则文件列表
        recursive: 是否递归扫描
        
    Returns:
        扫描结果字典
    """
    scanner = YaraScanner(rules_dir=rules_dir, external_rules=external_rules)
    
    if os.path.isfile(target_path):
        matches = scanner.scan_file(target_path)
        return {
            'target': target_path,
            'type': 'file',
            'matches': matches,
            'total_matches': len(matches)
        }
    else:
        matches = scanner.scan_directory(target_path, recursive=recursive)
        summary = scanner.get_match_summary(matches)
        return {
            'target': target_path,
            'type': 'directory',
            'matches': matches,
            'summary': summary
        }