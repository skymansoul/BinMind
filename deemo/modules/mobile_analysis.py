#!/usr/bin/env python3
"""
移动平台二进制深度分析模块

支持 Android .so 和 iOS Mach-O 文件的深度分析，识别移动平台特有的运行时结构
和漏洞模式。
"""

import os
import re
import struct
from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

import logging

logger = logging.getLogger(__name__)


class MobilePlatform(Enum):
    """移动平台类型"""
    AUTO = 'auto'
    ANDROID = 'android'
    IOS = 'ios'


@dataclass
class JNIFunction:
    """JNI 函数信息"""
    name: str
    java_class: str
    java_method: str
    signature: str
    address: int = 0


@dataclass
class ObjectiveCClass:
    """Objective-C 类信息"""
    name: str
    superclass: str
    methods: List[str]
    protocols: List[str]
    address: int = 0


@dataclass
class SensitiveString:
    """敏感字符串信息"""
    string: str
    type: str
    address: int
    score: float


@dataclass
class MobileVulnerability:
    """移动平台漏洞信息"""
    type: str
    severity: str
    description: str
    location: str
    code_snippet: str = ""
    remediation: str = ""


@dataclass
class MobileAnalysisResult:
    """移动平台分析结果"""
    platform: MobilePlatform
    jni_functions: List[JNIFunction]
    objective_c_classes: List[ObjectiveCClass]
    sensitive_strings: List[SensitiveString]
    vulnerabilities: List[MobileVulnerability]
    android_specific: Dict[str, Any]
    ios_specific: Dict[str, Any]


class MobileBinaryAnalyzer:
    """
    移动平台二进制分析器
    
    支持 Android .so 和 iOS Mach-O 文件的深度分析。
    """

    def __init__(self, binary_path: str, platform: str = 'auto'):
        """
        初始化移动平台分析器
        
        Args:
            binary_path: 二进制文件路径
            platform: 平台类型 (auto, android, ios)
        """
        self.binary_path = Path(binary_path)
        self.platform = self._detect_platform(platform)
        self.binary_data = self._read_binary()
        self.result = MobileAnalysisResult()
            platform=self.platform,
            jni_functions=[],
            objective_c_classes=[],
            sensitive_strings=[],
            vulnerabilities=[],
            android_specific={},
            ios_specific={}
        

    def _detect_platform(self, platform: str) -> MobilePlatform:
        """
        检测或验证平台类型
        
        Args:
            platform: 用户指定的平台类型
            
        Returns:
            检测到的平台类型
        """
        if platform != 'auto':
            try:
                return MobilePlatform(platform.lower(

            except ValueError:
                logger.warning(f"无效的平台类型: {platform}，使用自动检测")
        
        # 自动检测平台
        filename = self.binary_path.name.lower()
        
        # 根据文件扩展名判断
        if filename.endswith('.so'):
            return MobilePlatform.ANDROID
        elif filename.endswith('.mach-o') or filename.endswith('.o'):
            return MobilePlatform.IOS
        
        # 根据文件魔数判断
        try:
            with open(self.binary_path, 'rb') as f:
                magic = f.read(4)
                if magic == b'\x7fELF':
                    return MobilePlatform.ANDROID
                elif magic in [b'\xcf\xfa\xed\xfe', b'\xfa\xcf\xfe\xed']:
                    return MobilePlatform.IOS
        except Exception as e:
            logger.warning(f"检测平台时出错: {e}")
        
        return MobilePlatform.ANDROID

    def _read_binary(self) -> bytes:
        """
        读取二进制文件内容
        
        Returns:
            二进制文件内容
        """
        try:
            with open(self.binary_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"读取二进制文件失败: {e}")
            return b''

    def _extract_strings(self, min_length: int = 4) -> List[Tuple[str, int]]:
        """
        从二进制数据中提取可打印字符串
        
        Args:
            min_length: 最小字符串长度
            
        Returns:
            字符串及其偏移量列表
        """
        strings = []
        current_string = []
        for i, byte in enumerate(self.binary_data):
            if 0x20 <= byte <= 0x7E:
                current_string.append(chr(byte

            else:
                if len(current_string) >= min_length:
                    strings.append((''.join(current_string), i - len(current_string

                current_string = []
        
        if len(current_string) >= min_length:
            strings.append((''.join(current_string), len(self.binary_data) - len(current_string

        
        return strings

    def _parse_jni_functions(self) -> List[JNIFunction]:
        """
        解析 JNI 函数
        
        Returns:
            JNI 函数列表
        """
        jni_functions = []
        strings = self._extract_strings()
        
        # JNI 函数签名模式: Java_包名_类名_方法名
        jni_pattern = re.compile(r'Java_([a-zA-Z_]+)_([a-zA-Z_]+)_([a-zA-Z_]+)(_[a-zA-Z_]+)?')
        
        for string, offset in strings:
            match = jni_pattern.match(string)
            if match:
                pkg = match.group(1)
                cls = match.group(2)
                method_parts = [match.group(3)]
                if match.group(4):
                    method_parts.append(match.group(4)[1:])
                
                java_class = f"{pkg.replace('_', '/')}.{cls}"
                java_method = '_'.join(method_parts)
                
                jni_func = JNIFunction()
                    name=string,
                    java_class=java_class,
                    java_method=java_method,
                    signature="",
                    address=offset
                
                jni_functions.append(jni_func)
        
        logger.info(f"发现 {len(jni_functions)} 个 JNI 函数")
        return jni_functions

    def _parse_objective_c_classes(self) -> List[ObjectiveCClass]:
        """
        解析 Objective-C 类结构
        
        Returns:
            Objective-C 类列表
        """
        classes = []
        
        # 搜索 Objective-C 类列表 section
        # __objc_classlist 通常包含类定义
        classlist_pattern = b'__objc_classlist'
        idx = self.binary_data.find(classlist_pattern)
        
        if idx != -1:
            logger.debug(f"找到 __objc_classlist 在偏移 {idx}")
            # 简单提取类名（实际实现需要更复杂的解析）
            strings = self._extract_strings()
            objc_prefixes = ['_OBJC_CLASS_$_', '_OBJC_METACLASS_$_']
            
            for string, offset in strings:
                for prefix in objc_prefixes:
                    if string.startswith(prefix):
                        class_name = string[len(prefix):]
                        classes.append(ObjectiveCClass(
                            name=class_name,
                            superclass="",
                            methods=[],
                            protocols=[],
                            address=offset
                        

        
        logger.info(f"发现 {len(classes)} 个 Objective-C 类")
        return classes

    def _find_sensitive_strings(self) -> List[SensitiveString]:
        """
        查找敏感字符串
        
        Returns:
            敏感字符串列表
        """
        sensitive_strings = []
        strings = self._extract_strings()
        
        # 敏感模式定义
        sensitive_patterns = [
            (r'[A-Za-z0-9+/]{40,}', 'base64_data'),
            (r'[A-Fa-f0-9]{32}', 'aes_key'),
            (r'[A-Fa-f0-9]{40}', 'sha1_hash'),
            (r'[A-Fa-f0-9]{64}', 'sha256_hash'),
            (r'http[s]?://[^\s\"\'<>]+', 'url'),
            (r'[a-zA-Z0-9.-]+\.(com|net|org|io|cn|gov|mil|edu)', 'domain'),
            (r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', 'uuid'),
            (r'[a-zA-Z0-9]{32,}', 'api_key'),
            (r'Intent.*filter', 'intent_filter'),
            (r'URL.*scheme', 'url_scheme'),
            (r'NSUserDefaults', 'ns_user_defaults'),
        ]
        
        for string, offset in strings:
            for pattern, type_name in sensitive_patterns:
                if re.search(pattern, string):
                    # 计算风险分数
                    score = self._calculate_sensitivity_score(string, type_name)
                    sensitive_strings.append(SensitiveString(
                        string=string[:200],  # 截断长字符串
                        type=type_name,
                        address=offset,
                        score=score
                    

                    break
        
        # 去重
        seen = set()
        unique_strings = []
        for s in sensitive_strings:
            key = (s.string, s.type)
            if key not in seen:
                seen.add(key)
                unique_strings.append(s)
        
        logger.info(f"发现 {len(unique_strings)} 个敏感字符串")
        return unique_strings

    def _calculate_sensitivity_score(self, string: str, type_name: str) -> float:
        """
        计算字符串敏感度分数
        
        Args:
            string: 字符串内容
            type_name: 敏感类型
            
        Returns:
            敏感度分数 (0-1)
        """
        base_scores = {
            'aes_key': 0.9,
            'api_key': 0.85,
            'base64_data': 0.7,
            'sha256_hash': 0.6,
            'sha1_hash': 0.5,
            'url': 0.3,
            'domain': 0.4,
            'uuid': 0.2,
            'intent_filter': 0.6,
            'url_scheme': 0.55,
            'ns_user_defaults': 0.45,
        }
        
        score = base_scores.get(type_name, 0.3)
        
        # 如果字符串看起来像是密钥或 token，增加分数
        if any(keyword in string.lower() for keyword in ['key', 'secret', 'token', 'password']):
            score = min(1.0, score + 0.2)
        
        return score

    def _detect_android_specific_patterns(self) -> Dict[str, Any]:
        """
        检测 Android 特定模式
        
        Returns:
            Android 特定信息字典
        """
        patterns = {
            'android_log_print': b'__android_log_print',
            'asset_manager': b'AAssetManager_open',
            'jni_env': b'JNIEnv',
            'get_string_utf_chars': b'GetStringUTFChars',
            'find_class': b'FindClass',
            'get_method_id': b'GetMethodID',
            'call_method': b'CallVoidMethod',
            'intent': b'Intent',
            'binder': b'Binder',
            'parcel': b'Parcel',
        }
        
        found_patterns = {}
        for name, pattern in patterns.items():
            if pattern in self.binary_data:
                found_patterns[name] = True
        
        return found_patterns

    def _detect_ios_specific_patterns(self) -> Dict[str, Any]:
        """
        检测 iOS 特定模式
        
        Returns:
            iOS 特定信息字典
        """
        patterns = {
            'ns_user_defaults': b'NSUserDefaults',
            'sqlite': b'sqlite3_',
            'keychain': b'SecItem',
            'jailbreak_check': b'sbin/sshd',
            'private_api': b'_objc_msgSend',
            'bundle': b'NSBundle',
            'plist': b'plist',
        }
        
        found_patterns = {}
        for name, pattern in patterns.items():
            if pattern in self.binary_data:
                found_patterns[name] = True
        
        return found_patterns

    def _detect_mobile_vulnerabilities(self) -> List[MobileVulnerability]:
        """
        检测移动平台特有漏洞
        
        Returns:
            漏洞列表
        """
        vulnerabilities = []
        strings = self._extract_strings()
        
        # 检测 Intent 劫持风险
        intent_patterns = [
            (r'android.intent.action.', 'Intent action 暴露'),
            (r'android.intent.category.', 'Intent category 暴露'),
            (r'com\.android\..*\.ACTION_', '系统 Intent 滥用'),
        ]
        
        for string, offset in strings:
            for pattern, desc in intent_patterns:
                if re.search(pattern, string):
                    vulnerabilities.append(MobileVulnerability(
                        type='Intent Hijacking',
                        severity='High',
                        description=f"检测到 {desc}，可能存在 Intent 劫持风险",
                        location=f"字符串偏移 0x{offset:x}",
                        code_snippet=string
                    

        
        # 检测 URL Scheme 劫持风险
        url_scheme_pattern = r'urlscheme|URLScheme|scheme.*://',
        for string, offset in strings:
            if re.search(url_scheme_pattern, string, re.IGNORECASE):
                vulnerabilities.append(MobileVulnerability(
                    type='URL Scheme Hijacking',
                    severity='Medium',
                    description="检测到 URL Scheme 定义，可能存在劫持风险",
                    location=f"字符串偏移 0x{offset:x}",
                    code_snippet=string
                

        
        # 检测硬编码密钥
        for sensitive in self.result.sensitive_strings:
            if sensitive.type in ['aes_key', 'api_key'] and sensitive.score > 0.8:
                vulnerabilities.append(MobileVulnerability(
                    type='Hardcoded Secret',
                    severity='Critical',
                    description=f"发现硬编码的 {sensitive.type.replace('_', ' ')}",
                    location=f"偏移 0x{sensitive.address:x}",
                    remediation="不应将敏感密钥硬编码在二进制文件中，应使用安全的密钥管理方案"
                

        
        # 检测不安全的数据存储
        if self.platform == MobilePlatform.IOS:
            if 'ns_user_defaults' in self.result.ios_specific:
                vulnerabilities.append(MobileVulnerability(
                    type='Insecure Data Storage',
                    severity='Medium',
                    description="使用 NSUserDefaults 存储数据，可能导致敏感信息泄露",
                    location="iOS 二进制",
                    remediation="敏感数据应使用 Keychain 或加密存储"
                

        
        # 检测 JNI 参数验证缺失
        if self.platform == MobilePlatform.ANDROID:
            for jni_func in self.result.jni_functions:
                if 'get' in jni_func.java_method.lower() or 'set' in jni_func.java_method.lower():
                    vulnerabilities.append(MobileVulnerability(
                        type='JNI Parameter Validation',
                        severity='Medium',
                        description=f"JNI 方法 {jni_func.name} 可能缺少参数验证",
                        location=jni_func.name,
                        remediation="JNI 方法应验证所有输入参数的合法性"
                    

        
        logger.info(f"发现 {len(vulnerabilities)} 个移动平台特有漏洞")
        return vulnerabilities

    def analyze(self) -> MobileAnalysisResult:
        """
        执行完整的移动平台分析
        
        Returns:
            分析结果
        """
        logger.info(f"开始移动平台分析，平台: {self.platform.value}")
        
        if self.platform == MobilePlatform.ANDROID:
            self.result.jni_functions = self._parse_jni_functions()
            self.result.android_specific = self._detect_android_specific_patterns()
        
        elif self.platform == MobilePlatform.IOS:
            self.result.objective_c_classes = self._parse_objective_c_classes()
            self.result.ios_specific = self._detect_ios_specific_patterns()
        
        self.result.sensitive_strings = self._find_sensitive_strings()
        self.result.vulnerabilities = self._detect_mobile_vulnerabilities()
        
        logger.info("移动平台分析完成")
        return self.result

    def get_summary(self) -> Dict[str, Any]:
        """
        获取分析摘要
        
        Returns:
            摘要字典
        """
        return {
            'platform': self.platform.value,
            'jni_functions_count': len(self.result.jni_functions),
            'objective_c_classes_count': len(self.result.objective_c_classes),
            'sensitive_strings_count': len(self.result.sensitive_strings),
            'vulnerabilities_count': len(self.result.vulnerabilities),
            'high_risk_vulnerabilities': [
                v for v in self.result.vulnerabilities if v.severity in ['Critical', 'High']
            ]
        }))))))))))))))))))))))))"'