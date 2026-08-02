#!/usr/bin/env python3
"""
移动应用混淆检测与解混淆辅助分析。

检测能力:
  1. Java/Kotlin 混淆器识别 — ProGuard, R8, DexGuard, DashO, Allatori, Stringer, Zelix KlassMaster
  2. 原生层混淆 — OLLVM (Obfuscator-LLVM), Hikari, Arxan, DexProtector 原生层检测
  3. 字符串加密检测 — 熵分析 + 解码函数交叉引用
  4. 控制流平坦化 (CFF) 识别 — 状态变量 + dispatcher block 模式
  5. 虚假控制流 (BCF) 检测 — opaque predicate 模式匹配
  6. 跨平台框架混淆 — Flutter (Dart AOT), React Native (Hermes), Xamarin (.NET), Unity (il2cpp)
  7. 反调试/反篡改检测 — ptrace, /proc/self/status, inotify, CRC 校验
  8. 动态加载混淆 — DexClassLoader, InMemoryDexClassLoader, dlsym 延迟绑定

技术基础:
  - DEX/APK 包结构分析 (classes.dex 数量, multidex)
  - Smali 类/方法命名熵分析
  - SO 二进制符号表 & 字符串表分析
  - Mach-O __TEXT 段混淆指标
  - 商业加固器特征签名匹配

算法参考:
  - APKiD 规则引擎思路 (yara-like signature matching)
  - ObfDetector (ICSE'26): package hierarchy flattening detection
  - Promon 2026 Q1: layered obfuscation AI resistance scoring
"""

import re
import struct
import logging
import os
import zipfile
import hashlib
import math
from pathlib import Path
from dataclasses import dataclass, field
from enum import StrEnum, IntEnum
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ObfuscationType(StrEnum):
    """混淆技术分类。"""
    IDENTIFIER_RENAMING = "identifier_renaming"
    STRING_ENCRYPTION = "string_encryption"
    CONTROL_FLOW_FLATTENING = "control_flow_flattening"
    BOGUS_CONTROL_FLOW = "bogus_control_flow"
    INSTRUCTION_SUBSTITUTION = "instruction_substitution"
    CODE_VIRTUALIZATION = "code_virtualization"
    PACKING = "packing"
    ANTI_DEBUG = "anti_debug"
    ANTI_TAMPER = "anti_tamper"
    RESOURCE_OBFUSCATION = "resource_obfuscation"
    API_HIDING = "api_hiding"
    REFLECTION_OBFUSCATION = "reflection_obfuscation"
    ASSET_ENCRYPTION = "asset_encryption"
    DEX_HIDING = "dex_hiding"


class ObfuscatorTool(StrEnum):
    """已知混淆/加固工具。"""
    PROGUARD = "proguard"
    R8 = "r8"                    # Android Gradle plugin 默认
    DEXGUARD = "dexguard"        # Guardsquare 商业版
    DASHD = "dasho"
    ALLATORI = "allatori"
    STRINGER = "stringer"
    ZELIX = "zelix_klassmaster"
    OLLVM = "ollvm"              # Obfuscator-LLVM
    HIKARI = "hikari"            # OLLVM fork, 支持更多平台
    ARXAN = "arxan"              # 商业加固
    DEXPROTECTOR = "dexprotector"
    IJIALE = "ijiamle"           # 360加固保 (国内常见)
    BANGUL = "bangcle"           # 梆梆加固
    ALIBABU = "alibaba_protect"  # 阿里加固
    TENCENT = "tencent_legu"     # 腾讯乐固
    BAIDU = "baidu_protect"      # 百度加固
    FLUTTER_AOT = "flutter_aot"  # Dart snapshot 混淆
    HERMES = "hermes"            # React Native Hermes 字节码
    IL2CPP = "il2cpp"            # Unity IL2CPP
    XAMARIN = "xamarin"          # .NET MAUI/Xamarin
    UNKNOWN = "unknown"


class ObfuscationSeverity(StrEnum):
    NONE = "none"          # 未混淆
    LIGHT = "light"        # 仅标识符重命名 (ProGuard/R8默认)
    MODERATE = "moderate"  # 字符串加密 + 标识符混淆
    HEAVY = "heavy"        # CFF + 字符串加密 + 反调试
    EXTREME = "extreme"    # 代码虚拟化 + 多层加固


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class ObfuscationIndicator:
    """单个混淆指标。"""
    indicator_type: str          # 检测到的特征类型
    tool: ObfuscatorTool = ObfuscatorTool.UNKNOWN
    technique: ObfuscationType = ObfuscationType.IDENTIFIER_RENAMING
    confidence: float = 0.0      # 0~1
    evidence: str = ""
    location: str = ""           # class/method/offset


@dataclass
class ObfuscationReport:
    """完整混淆检测报告。"""
    file_path: str = ""
    overall_severity: ObfuscationSeverity = ObfuscationSeverity.NONE
    detected_tools: List[ObfuscatorTool] = field(default_factory=list)
    indicators: List[ObfuscationIndicator] = field(default_factory=list)
    entropy_scores: Dict[str, float] = field(default_factory=dict)
    layered_count: int = 0       # 检测到的混淆层数
    deobfuscation_difficulty: str = ""


# ---------------------------------------------------------------------------
# 签名数据库
# ---------------------------------------------------------------------------

# 商业加固器的包/类签名
_PACKER_SIGNATURES: Dict[bytes, ObfuscatorTool] = {
    # DexGuard
    b'com.guardsquare.dexguard': ObfuscatorTool.DEXGUARD,
    b'dexguard': ObfuscatorTool.DEXGUARD,
    # 360加固保 (Ijiale/Ijiami)
    b'com.qihoo': ObfuscatorTool.IJIALE,
    b'com.stub.StubApp': ObfuscatorTool.IJIALE,
    b'jiagu': ObfuscatorTool.IJIALE,
    # 梆梆加固
    b'com.secneo.apkwrapper': ObfuscatorTool.BANGUL,
    b'secneo': ObfuscatorTool.BANGUL,
    # 阿里加固
    b'com.alibaba.wireless.security': ObfuscatorTool.ALIBABU,
    b'libsgmain.so': ObfuscatorTool.ALIBABU,
    b'libsgsecuritybody.so': ObfuscatorTool.ALIBABU,
    # 腾讯乐固
    b'com.tencent.StubShell': ObfuscatorTool.TENCENT,
    b'libtup.so': ObfuscatorTool.TENCENT,
    b'libshella': ObfuscatorTool.TENCENT,
    # 百度加固
    b'com.baidu.protect': ObfuscatorTool.BAIDU,
    b'libbaiduprotect': ObfuscatorTool.BAIDU,
    # Arxan
    b'Arxan': ObfuscatorTool.ARXAN,
    b'arxan': ObfuscatorTool.ARXAN,
    # DexProtector
    b'DexProtector': ObfuscatorTool.DEXPROTECTOR,
    b'dexprotector': ObfuscatorTool.DEXPROTECTOR,
    # Allatori
    b'allatori': ObfuscatorTool.ALLATORI,
    # DashO
    b'DashO': ObfuscatorTool.DASHD,
    # Stringer
    b'STRINGER': ObfuscatorTool.STRINGER,
    # Zelix
    b'ZKM': ObfuscatorTool.ZELIX,
    b'zelix': ObfuscatorTool.ZELIX,
}

# ProGuard/R8 特征 (注意: R8 是 Android 默认混淆器, 几乎每个 release APK 都有)
_PROGUARD_INDICATORS = [
    b'proguard',                    # class/method name prefix
    b'proguard.config',             # config reference
    b'a/a/a/',                      # R8 典型类路径
    b'-keep',                       # ProGuard 规则残留
    b'-dontwarn',
    b'-optimizationpasses',
    b'proguard-rules.pro',
]

# OLLVM 原生层签名
_OLLVM_NATIVE_SIGNATURES: Dict[bytes, str] = {
    b'llvm.obfuscator': 'OLLVM banner',
    b'bcf': 'bogus control flow pass',
    b'fla': 'control flow flattening pass',
    b'sub': 'instruction substitution pass',
    b'split': 'basic block splitting pass',
    b'funcannotate': 'OLLVM function annotation',
}

# 字符串加密检测 (DEX/SO)
_STRING_DECRYPT_PATTERNS = [
    # 常见解密函数名称模式
    rb'(?:decrypt|decode|deobfuscate|unwrap|__unscramble)[a-zA-Z]*\s*\(',
    rb'decrypt_string',
    rb'xor_string',
    rb'__gcry_decrypt',
    # 大量 xor/add/sub 操作后跟字符串使用
    rb'(?:char|byte|wchar_t)\s*\*\s*(?:decrypt|get|dec)',
]

# 反调试特征
_ANTI_DEBUG_PATTERNS: Dict[bytes, str] = {
    b'ptrace': 'ptrace self-attach (PTRACE_TRACEME)',
    b'/proc/self/status': '/proc/self/status 读取检测 TracerPid',
    b'/proc/self/maps': '/proc/self/maps 扫描断点/异常内存',
    b'TracerPid': 'TracerPid 字段检查',
    b'android.os.Debug.isDebuggerConnected': 'Java层调试检测',
    b'android.os.Debug.waitingForDebugger': 'waitingForDebugger 阻塞',
    b'isDebuggerConnected': 'isDebuggerConnected 检查',
    b'Debug.MemoryInfo': '内存调试信息获取',
    b'/system/bin/frida': 'Frida server 检测',
    b'frida-server': 'Frida server 检测',
    b'REJECT': 'libfrida-gadget 检测',
    b'xposed': 'Xposed 框架检测',
    b'de.robv.android.xposed': 'Xposed 包名检测',
    b'substrate': 'Cydia Substrate 检测',
    b'com.saurik.substrate': 'Substrate检测',
}

# 反篡改特征
_ANTI_TAMPER_PATTERNS: Dict[bytes, str] = {
    b'inotify_add_watch': 'inotify 文件变化监控',
    b'signature': 'APK 签名校验',
    b'getPackageManager': 'PackageManager 签名获取',
    b'PackageInfo': '包信息获取 (签名校验)',
    b'checkSignatures': '签名比对',
    b'crc32': 'CRC32 完整性校验',
    b'CRC32': 'CRC32 完整性校验',
    b'MD5': 'MD5 文件哈希校验',
    b'SHA1': 'SHA1 文件哈希校验 (注意区分 SSL pinning)',
    b'verifyManifest': 'Manifest 完整性验证',
    b'SHA-256 digest': 'APK SHA-256 签名校验',
}

# 动态加载混淆
_DYNAMIC_LOADING_PATTERNS: Dict[bytes, str] = {
    b'DexClassLoader': 'DexClassLoader 动态加载DEX',
    b'InMemoryDexClassLoader': 'InMemoryDexClassLoader 内存DEX加载',
    b'PathClassLoader': 'PathClassLoader 路径加载',
    b'dlopen': 'dlopen 动态库加载',
    b'dlsym': 'dlsym 符号解析 (延迟绑定)',
    b'System.load': 'System.load 原生库加载',
    b'System.loadLibrary': 'System.loadLibrary 原生库加载',
    b'Class.forName': 'Class.forName 反射类加载',
    b'java.lang.reflect': '反射调用',
    b'getDeclaredMethod': 'getDeclaredMethod 反射方法获取',
    b'setAccessible': 'setAccessible 绕过访问控制',
    b'DexFile': 'DexFile 直接DEX操作',
}

# 跨平台框架指标 (用于判断是 native 混淆还是跨平台混淆)
_CROSS_PLATFORM_SIGNATURES: Dict[bytes, ObfuscatorTool] = {
    b'libflutter.so': ObfuscatorTool.FLUTTER_AOT,
    b'libapp.so': ObfuscatorTool.FLUTTER_AOT,   # Dart AOT snapshot
    b'dart:': ObfuscatorTool.FLUTTER_AOT,
    b'libhermes.so': ObfuscatorTool.HERMES,
    b'hermes': ObfuscatorTool.HERMES,
    b'hbcdump': ObfuscatorTool.HERMES,
    b'il2cpp': ObfuscatorTool.IL2CPP,
    b'libil2cpp.so': ObfuscatorTool.IL2CPP,
    b'global-metadata.dat': ObfuscatorTool.IL2CPP,
    b'mono_image_open': ObfuscatorTool.XAMARIN,
    b'Mono.Android': ObfuscatorTool.XAMARIN,
    b'xamarin': ObfuscatorTool.XAMARIN,
}


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def _compute_shannon_entropy(data: bytes) -> float:
    """计算字节级香农熵 (0-8 bits)。"""
    if not data:
        return 0.0
    total = len(data)
    freq = Counter(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _compute_class_name_entropy(names: List[str]) -> float:
    """类名熵评估 - 混淆后的类名通常短且随机。"""
    if not names:
        return 0.0
    chars = ''.join(names)
    return _compute_shannon_entropy(chars.encode('utf-8', errors='ignore'))


def _extract_class_names_from_bytes(data: bytes) -> List[str]:
    """从 DEX/Smali 中提取类名。"""
    pattern = re.compile(rb'L([a-zA-Z0-9_/$]+);')
    names: List[str] = []
    for m in pattern.finditer(data):
        name = m.group(1).decode('ascii', errors='ignore')
        if len(name) > 2 and '/' in name:
            names.append(name)
    return names


def _detect_single_char_class_names(names: List[str]) -> float:
    """检测单字符类名占比 — ProGuard/R8 典型特征。"""
    if not names:
        return 0.0
    short_names = []
    for full_name in names:
        parts = full_name.split('/')
        for part in parts:
            if len(part) == 1:
                short_names.append(part)
    return len(short_names) / max(len(names), 1)


def _detect_package_flattening(names: List[str]) -> float:
    """检测包层级扁平化 — DexGuard/Allatori 典型高级混淆。
    正常: com/example/app/MainActivity -> 深度 >= 2
    扁平化后: a/a/a/a -> 深度可能仍高但每层仅单字符
    """
    if not names:
        return 0.0
    flattened = 0
    for name in names:
        parts = name.split('/')
        if len(parts) >= 2:
            short_count = sum(1 for p in parts if len(p) <= 2)
            if short_count == len(parts):
                flattened += 1
    return flattened / max(len(names), 1)


# ---------------------------------------------------------------------------
# DEX 混淆检测
# ---------------------------------------------------------------------------

class DEXObfuscationDetector:
    """从 DEX/JAR/APK 中检测 Java 层混淆。"""

    def __init__(self, data: bytes = b""):
        self.data = data
        self.indicators: List[ObfuscationIndicator] = []

    def detect_packer(self) -> List[ObfuscatorTool]:
        """识别商业加固器。"""
        found: List[ObfuscatorTool] = []
        for sig, tool in _PACKER_SIGNATURES.items():
            if sig in self.data:
                if tool not in found:
                    found.append(tool)
                self.indicators.append(ObfuscationIndicator(
                    indicator_type='packer_signature',
                    tool=tool,
                    technique=ObfuscationType.PACKING,
                    confidence=0.95,
                    evidence=f'字节匹配: {sig.decode("ascii", errors="replace")[:60]}',
                    location='binary',
                ))
        return found

    def detect_proguard_r8(self) -> bool:
        """检测 ProGuard/R8 混淆痕迹。"""
        found_any = False
        for indicator in _PROGUARD_INDICATORS:
            if indicator in self.data:
                found_any = True
                self.indicators.append(ObfuscationIndicator(
                    indicator_type='proguard_r8',
                    tool=ObfuscatorTool.PROGUARD,
                    technique=ObfuscationType.IDENTIFIER_RENAMING,
                    confidence=0.8,
                    evidence=f'发现: {indicator.decode("ascii", errors="replace")[:50]}',
                ))
                break  # 一个就够了，避免噪音
        return found_any

    def detect_class_obfuscation(self) -> Dict[str, float]:
        """评估类/方法命名混淆程度。"""
        names = _extract_class_names_from_bytes(self.data)
        scores = {
            'total_classes': len(names),
            'class_name_entropy': _compute_class_name_entropy(names),
            'single_char_class_ratio': _detect_single_char_class_names(names),
            'package_flattening_ratio': _detect_package_flattening(names),
        }

        if scores['single_char_class_ratio'] > 0.3:
            self.indicators.append(ObfuscationIndicator(
                indicator_type='single_char_classes',
                tool=ObfuscatorTool.PROGUARD,
                technique=ObfuscationType.IDENTIFIER_RENAMING,
                confidence=scores['single_char_class_ratio'],
                evidence=f'{scores["single_char_class_ratio"]:.1%} 类名为单字符',
                location='class namespace',
            ))

        if scores['package_flattening_ratio'] > 0.5:
            self.indicators.append(ObfuscationIndicator(
                indicator_type='package_flattening',
                tool=ObfuscatorTool.DEXGUARD,
                technique=ObfuscationType.IDENTIFIER_RENAMING,
                confidence=scores['package_flattening_ratio'],
                evidence=f'{scores["package_flattening_ratio"]:.1%} 包层级扁平化',
                location='package hierarchy',
            ))

        return scores

    def detect_string_encryption(self) -> bool:
        """检测 DEX 层字符串加密模式。"""
        found = False
        for pattern in _STRING_DECRYPT_PATTERNS:
            if re.search(pattern, self.data):
                found = True
                self.indicators.append(ObfuscationIndicator(
                    indicator_type='string_decryption_routine',
                    technique=ObfuscationType.STRING_ENCRYPTION,
                    confidence=0.7,
                    evidence=f'解密函数模式: {pattern.pattern.decode()[:50]}',
                ))
                break
        return found

    def detect_dynamic_loading(self) -> bool:
        """检测动态代码加载。"""
        found = False
        for pattern, evidence in _DYNAMIC_LOADING_PATTERNS.items():
            if pattern in self.data:
                found = True
                self.indicators.append(ObfuscationIndicator(
                    indicator_type=f'dynamic_loading:{pattern.decode("ascii", errors="replace")[:40]}',
                    technique=ObfuscationType.PACKING,
                    confidence=0.6,
                    evidence=evidence,
                    location='code',
                ))
        return found

    def detect_reflection_abuse(self) -> bool:
        """反射混淆检测 — 大量的 Class.forName/Method.invoke 调用。"""
        refl_count = len(re.findall(rb'Class\.forName|getDeclaredMethod|Method\.invoke|Field\.set',
                                    self.data))
        if refl_count > 10:
            self.indicators.append(ObfuscationIndicator(
                indicator_type='reflection_obfuscation',
                technique=ObfuscationType.REFLECTION_OBFUSCATION,
                confidence=min(refl_count / 50.0, 1.0),
                evidence=f'{refl_count} 反射调用点',
                location='code',
            ))
            return True
        return False

    def analyze(self) -> List[ObfuscationIndicator]:
        """完整 DEX 混淆检测。"""
        self.detect_packer()
        self.detect_proguard_r8()
        self.detect_class_obfuscation()
        self.detect_string_encryption()
        self.detect_dynamic_loading()
        self.detect_reflection_abuse()
        return self.indicators


# ---------------------------------------------------------------------------
# 原生层混淆检测 (SO/dylib)
# ---------------------------------------------------------------------------

class NativeObfuscationDetector:
    """从原生库 (.so, .dylib) 中检测 C/C++ 混淆。

    基于字节级模式匹配，不需要反汇编器。
    """

    def __init__(self, data: bytes = b""):
        self.data = data
        self.indicators: List[ObfuscationIndicator] = []

    def detect_ollvm(self) -> bool:
        """检测 OLLVM 及其 fork (Hikari, etc.)。"""
        found = False
        for sig, description in _OLLVM_NATIVE_SIGNATURES.items():
            if sig in self.data:
                found = True
                tool = ObfuscatorTool.HIKARI if b'hikari' in self.data.lower() else ObfuscatorTool.OLLVM
                self.indicators.append(ObfuscationIndicator(
                    indicator_type=f'ollvm:{description}',
                    tool=tool,
                    technique=ObfuscationType.CONTROL_FLOW_FLATTENING,
                    confidence=0.9,
                    evidence=f'OLLVM pass: {description}',
                    location='native binary',
                ))
        return found

    def detect_cff_patterns(self) -> bool:
        """控制流平坦化启发式检测。

        在 ARM64 原生代码中，CFF 典型模式：
          - 大量的 ADRP/LDR 加载状态变量
          - switch-case dispatcher 密集的间接跳转
          - 相对地址表 (跳转表) 连续分布

        用简化的字节级模式匹配 (不完美但快速)。
        """
        # ARM64: ADRP + LDR + BR 组合 ≈ dispatcher 块
        # 搜索密集的间接分支模式
        br_reg_count = len(re.findall(rb'\x60\x01\x1f\xd6', self.data))  # BR Xn encoding
        adrp_count = len(re.findall(rb'[\x00-\xff]\x00\x00\x90', self.data))

        if br_reg_count > 20 and adrp_count > 50:
            self.indicators.append(ObfuscationIndicator(
                indicator_type='cff_arm64_dispatcher',
                technique=ObfuscationType.CONTROL_FLOW_FLATTENING,
                confidence=min((br_reg_count / 100.0), 0.85),
                evidence=f'{br_reg_count} 间接分支, {adrp_count} ADRP 指令 — CFF 可疑',
                location='native arm64',
            ))
            return True
        return False

    def detect_bcf_patterns(self) -> bool:
        """虚假控制流检测。

        BCF 典型特征:
          - 不可达的基本块 (opaque predicate)
          - 永真/永假条件跳转 (如 `CMP X0, X0; B.NE` — 永远不跳)
        """
        # ARM64: CMP Xn, Xn (compare register with itself) + B.cond
        # CMP X0,X0 = 0xEB00001F (subs xzr, x0, x0)
        cmp_self = len(re.findall(rb'\x1f\x00\x00\xeb', self.data))   # subs xzr, xx, xx
        if cmp_self > 5:
            self.indicators.append(ObfuscationIndicator(
                indicator_type='bcf_opaque_predicate',
                technique=ObfuscationType.BOGUS_CONTROL_FLOW,
                confidence=min(cmp_self / 20.0, 0.8),
                evidence=f'{cmp_self} opaque predicate (CMP Xn, Xn) 检测',
                location='native arm64',
            ))
            return True
        return False

    def detect_anti_debug(self) -> bool:
        found = False
        for pattern, desc in _ANTI_DEBUG_PATTERNS.items():
            if pattern in self.data:
                found = True
                self.indicators.append(ObfuscationIndicator(
                    indicator_type=f'anti_debug:{desc[:50]}',
                    technique=ObfuscationType.ANTI_DEBUG,
                    confidence=0.85,
                    evidence=desc,
                ))
        return found

    def detect_anti_tamper(self) -> bool:
        found = False
        for pattern, desc in _ANTI_TAMPER_PATTERNS.items():
            if pattern in self.data:
                found = True
                self.indicators.append(ObfuscationIndicator(
                    indicator_type=f'anti_tamper:{desc[:50]}',
                    technique=ObfuscationType.ANTI_TAMPER,
                    confidence=0.8,
                    evidence=desc,
                ))
        return found

    def compute_symbol_entropy(self) -> float:
        """符号表熵 — 混淆后符号名高度随机化。"""
        # 从 .dynsym 或导出表中提取符号名
        symbol_pattern = re.compile(rb'[\x00-\x1f]([a-zA-Z_][a-zA-Z0-9_]{2,60})\x00')
        symbols = [m.group(1) for m in symbol_pattern.finditer(self.data)]
        if not symbols:
            return 0.0
        all_sym_chars = b''.join(symbols)
        return _compute_shannon_entropy(all_sym_chars)

    def detect_cross_platform(self) -> List[ObfuscatorTool]:
        """检测跨平台框架。"""
        found: List[ObfuscatorTool] = []
        for sig, tool in _CROSS_PLATFORM_SIGNATURES.items():
            if sig in self.data:
                if tool not in found:
                    found.append(tool)
                self.indicators.append(ObfuscationIndicator(
                    indicator_type=f'cross_platform:{tool.value}',
                    tool=tool,
                    technique=ObfuscationType.PACKING,
                    confidence=0.95,
                    evidence=f'跨平台框架: {tool.value}',
                ))
        return found

    def assess_entropy(self) -> Dict[str, float]:
        """全面熵评估。"""
        return {
            'overall_entropy': _compute_shannon_entropy(self.data),
            'symbol_entropy': self.compute_symbol_entropy(),
            # 高整体熵可能意味着整体加密/packed
        }

    def analyze(self) -> List[ObfuscationIndicator]:
        self.detect_ollvm()
        self.detect_cff_patterns()
        self.detect_bcf_patterns()
        self.detect_anti_debug()
        self.detect_anti_tamper()
        self.detect_cross_platform()
        return self.indicators


# ---------------------------------------------------------------------------
# 综合混淆分析器
# ---------------------------------------------------------------------------

class MobileObfuscationAnalyzer:
    """移动应用混淆综合分析器。

    接受 APK, IPA, DEX, SO, dylib 等多种格式。
    自动检测并路由到合适的子分析器。
    """

    def __init__(self, path: str = ""):
        self.path = path
        self.file_data: bytes = b""
        self.file_list: Dict[str, bytes] = {}  # 对APK/ZIP: 内部文件列表
        self._indicators: List[ObfuscationIndicator] = []
        self._entropy_scores: Dict[str, float] = {}
        self._detected_tools: Set[ObfuscatorTool] = set()

        if path and os.path.exists(path):
            self._load_file(path)

    def _load_file(self, path: str):
        p = Path(path)
        self.file_data = p.read_bytes()

        # 如果是 ZIP/APK，解包
        if p.suffix.lower() in ('.apk', '.zip', '.jar', '.aab', '.ipa'):
            try:
                with zipfile.ZipFile(path, 'r') as zf:
                    for entry in zf.namelist():
                        try:
                            self.file_list[entry] = zf.read(entry)
                        except Exception:
                            pass  # ignore unreadable entries
                logger.info(f"Loaded {len(self.file_list)} entries from {p.name}")
            except zipfile.BadZipFile:
                logger.warning(f"Not a valid ZIP: {path}")

    def _analyze_dex(self, name: str, data: bytes):
        """分析单个 DEX 文件。"""
        detector = DEXObfuscationDetector(data)
        for ind in detector.analyze():
            ind.location = f'{name}:{ind.location}'
            self._indicators.append(ind)
        for tool in detector.detect_packer():
            self._detected_tools.add(tool)

    def _analyze_native(self, name: str, data: bytes):
        """分析单个原生库。"""
        detector = NativeObfuscationDetector(data)
        for ind in detector.analyze():
            ind.location = f'{name}:{ind.location}'
            self._indicators.append(ind)
        cross_tools = detector.detect_cross_platform()
        for t in cross_tools:
            self._detected_tools.add(t)

        self._entropy_scores[name] = _compute_shannon_entropy(data)

    def analyze(self) -> ObfuscationReport:
        """主分析入口。"""
        report = ObfuscationReport(file_path=self.path)

        # 判断文件类型
        suffix = Path(self.path).suffix.lower()

        if suffix in ('.apk', '.aab') and self.file_list:
            # APK: 分别分析 DEX 和 SO
            for fname, fdata in self.file_list.items():
                fn_lower = fname.lower()
                if fn_lower.endswith('.dex') or fn_lower == 'classes.dex':
                    self._analyze_dex(fname, fdata)
                elif fn_lower.endswith('.so'):
                    self._analyze_native(fname, fdata)
                elif fn_lower.endswith('.dylib'):
                    self._analyze_native(fname, fdata)
        elif suffix in ('.dex',):
            self._analyze_dex(self.path, self.file_data)
        elif suffix in ('.so', '.dylib', '.elf'):
            self._analyze_native(self.path, self.file_data)
        elif suffix == '.ipa':
            for fname, fdata in self.file_list.items():
                fn_lower = fname.lower()
                if fn_lower.endswith('.dylib') or fn_lower.endswith('.so') or 'framework' in fn_lower:
                    self._analyze_native(fname, fdata)
        else:
            # 通用：分别尝试 DEX 和 SO 检测
            self._analyze_dex(self.path, self.file_data)
            self._analyze_native(self.path, self.file_data)

        # 汇总
        report.indicators = self._indicators
        report.detected_tools = list(self._detected_tools)
        report.entropy_scores = self._entropy_scores
        report.overall_severity = self._assess_severity()
        report.layered_count = self._count_layers()
        report.deobfuscation_difficulty = self._estimate_difficulty()

        return report

    def _assess_severity(self) -> ObfuscationSeverity:
        techs = {ind.technique for ind in self._indicators}
        count = len(self._indicators)

        if count == 0:
            return ObfuscationSeverity.NONE
        if count <= 2:
            return ObfuscationSeverity.LIGHT
        if count <= 5:
            return ObfuscationSeverity.MODERATE
        if ObfuscationType.CODE_VIRTUALIZATION in techs:
            return ObfuscationSeverity.EXTREME
        if count <= 10:
            return ObfuscationSeverity.HEAVY
        return ObfuscationSeverity.EXTREME

    def _count_layers(self) -> int:
        layers: Set[ObfuscationType] = set()
        for ind in self._indicators:
            layers.add(ind.technique)
        return len(layers)

    def _estimate_difficulty(self) -> str:
        """估算解混淆难度 (经验公式)。"""
        layers = self._count_layers()
        entropy_avg = (sum(self._entropy_scores.values()) / max(len(self._entropy_scores), 1)
                       if self._entropy_scores else 0)

        if layers == 0:
            return "无需解混淆 — 未检测到混淆"
        if layers <= 1:
            return "简单 — ProGuard/R8 默认混淆，可用 jadx/CFR 直接反编译"
        if layers <= 2:
            return "中等 — 需配合 deobfuscation 脚本 + 手工分析"
        if layers <= 3:
            return "困难 — 多层混淆，需要 Frida hook + 动态调试 + 定制解混淆器"
        return "极难 — 商业加固+代码虚拟化，需要 VM 逆向 + 内核级调试"


def analyze_obfuscation(file_path: str) -> ObfuscationReport:
    """便利入口函数。"""
    analyzer = MobileObfuscationAnalyzer(file_path)
    return analyzer.analyze()


# 兼容性存根
class MobileObfuscationResult:
    def __init__(self):
        self.tools: List[str] = []
        self.severity: str = ""
        self.findings: List[Dict] = []


def quick_obfuscation_check(file_path: str) -> Dict[str, Any]:
    """快速混淆检查 — 返回轻量 JSON。"""
    report = analyze_obfuscation(file_path)
    return {
        'file': file_path,
        'severity': report.overall_severity.value,
        'tools': [t.value for t in report.detected_tools],
        'layers': report.layered_count,
        'difficulty': report.deobfuscation_difficulty,
        'indicators': [
            {
                'type': ind.indicator_type,
                'tool': ind.tool.value,
                'confidence': ind.confidence,
                'evidence': ind.evidence,
            }
            for ind in report.indicators
        ],
    }
