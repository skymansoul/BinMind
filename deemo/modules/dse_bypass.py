import os
import re
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class DSEBypassIndicator:
    """DSE绕过指示器数据类"""
    indicator_type: str
    severity: str  # 'high', 'medium', 'low'
    description: str
    evidence: str
    recommendation: str


@dataclass
class DSEAnalysisResult:
    """DSE分析结果数据类"""
    filename: str
    is_signed: bool
    certificate_info: Dict[str, str]
    bypass_indicators: List[DSEBypassIndicator]
    risk_score: int


class DSEBypassDetector:
    """Windows驱动签名强制绕过检测器"""
    
    DSE_BYPASS_KEYWORDS = [
        ('EfiGuard', 'EfiGuard引导加载器，用于绕过DSE'),
        ('DSEFix', 'DSEFix工具，用于禁用驱动签名强制'),
        ('g_CiEnabled', '内核全局变量，控制代码完整性'),
        ('g_CiOptions', '内核全局变量，控制CI选项'),
        ('CiInitialize', '代码完整性初始化函数'),
        ('CiValidateImageHeader', '验证镜像头部'),
        ('CiValidateImageData', '验证镜像数据'),
        ('CiVerifyHashInCatalog', '验证目录哈希'),
        ('SEHOP', '结构化异常处理覆盖保护'),
        ('testsigning', '测试签名模式'),
        ('loadoptions', '启动选项修改'),
        ('bcdedit', 'BCD编辑器'),
        ('NoIntegrityChecks', '禁用完整性检查'),
        ('DisableDriverSignatureVerification', '禁用驱动签名验证'),
    ]
    
    DSE_BYPASS_PATTERNS = [
        (r'g_CiEnabled\s*=\s*0', '直接禁用代码完整性'),
        (r'g_CiOptions\s*&=\s*~0x1', '禁用强制签名'),
        (r'g_CiOptions\s*=\s*0', '完全禁用CI选项'),
        (r'CiValidateImageHeader\s*ret', '跳过镜像头部验证'),
        (r'CiValidateImageData\s*ret', '跳过镜像数据验证'),
        (r'MmCopyVirtualMemory.*Ci', '内存复制绕过CI检查'),
        (r'NtLoadDriver.*\\System32\\Drivers', '直接加载驱动'),
        (r'ZwLoadDriver.*\\System32\\Drivers', '直接加载驱动'),
    ]
    
    TEST_SIGNATURE_PATTERNS = [
        ('Microsoft Windows Hardware Compatibility Publisher', '测试签名证书'),
        ('Microsoft Corporation - WDDM', 'WDDM测试签名'),
        ('Test Certificate', '测试证书'),
        ('Self-signed', '自签名证书'),
    ]
    
    def __init__(self, driver_path: str = ""):
        self.driver_path = driver_path
        self.bypass_indicators: List[DSEBypassIndicator] = []
        self.strings: List[str] = []
        self.is_signed = False
        self.certificate_info = {}
    
    def _extract_strings(self) -> List[str]:
        """从驱动文件中提取字符串"""
        strings = []
        try:
            with open(self.driver_path, 'rb') as f:
                data = f.read()
            
            current_string = []
            for byte in data:
                if 32 <= byte <= 126:
                    current_string.append(chr(byte))
                else:
                    if len(current_string) >= 4:
                        strings.append(''.join(current_string))
                    current_string = []
            
            if len(current_string) >= 4:
                strings.append(''.join(current_string))
            
        except Exception as e:
            logger.error(f"提取字符串失败: {e}")
        
        return strings
    
    def _check_signature(self) -> bool:
        """检查驱动是否有有效签名"""
        try:
            import pefile
            
            pe = pefile.PE(self.driver_path)
            
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                security_dir = pe.DIRECTORY_ENTRY_SECURITY
                if security_dir is not None:
                    self.is_signed = True
                    self.certificate_info['has_signature'] = 'True'
                    return True
            
            self.is_signed = False
            return False
        
        except ImportError:
            logger.warning("pefile 模块未安装，无法检查签名")
            return False
        except Exception as e:
            logger.error(f"检查签名失败: {e}")
            return False
    
    def _check_certificate_info(self):
        """检查证书信息"""
        for cert_name, desc in self.TEST_SIGNATURE_PATTERNS:
            for string in self.strings:
                if cert_name.lower() in string.lower():
                    self.certificate_info['issuer'] = cert_name
                    self.certificate_info['type'] = desc
                    if 'test' in desc.lower():
                        self.bypass_indicators.append(DSEBypassIndicator(
                            indicator_type='TEST_SIGNING_CERTIFICATE',
                            severity='medium',
                            description=f"驱动使用{desc}",
                            evidence=f"证书信息: {cert_name}",
                            recommendation="检查是否在测试环境中运行，生产环境不应使用测试签名"
                        ))
                    break
    
    def _check_bypass_keywords(self):
        """检查DSE绕过关键字"""
        for keyword, desc in self.DSE_BYPASS_KEYWORDS:
            found = False
            for string in self.strings:
                if keyword.lower() in string.lower():
                    found = True
                    break
            
            if found:
                severity = 'high' if keyword in ['g_CiEnabled', 'g_CiOptions', 'DSEFix', 'EfiGuard'] else 'medium'
                self.bypass_indicators.append(DSEBypassIndicator(
                    indicator_type='BYPASS_KEYWORD_FOUND',
                    severity=severity,
                    description=f"检测到DSE绕过相关关键字: {desc}",
                    evidence=f"关键字: {keyword}",
                    recommendation="检查驱动是否包含恶意代码或绕过技术"
                ))
    
    def _check_bypass_patterns(self):
        """检查DSE绕过代码模式"""
        try:
            with open(self.driver_path, 'rb') as f:
                data = f.read().hex()
            
            for pattern, desc in self.DSE_BYPASS_PATTERNS:
                if re.search(pattern, data, re.IGNORECASE):
                    self.bypass_indicators.append(DSEBypassIndicator(
                        indicator_type='BYPASS_CODE_PATTERN',
                        severity='high',
                        description=f"检测到DSE绕过代码模式: {desc}",
                        evidence=f"模式: {pattern}",
                        recommendation="此驱动可能包含DSE绕过代码，需要进一步分析"
                    ))
        except Exception as e:
            logger.error(f"检查代码模式失败: {e}")
    
    def _check_imports(self):
        """检查导入函数"""
        bypass_imports = [
            ('ZwLoadDriver', '直接加载驱动'),
            ('NtLoadDriver', '直接加载驱动'),
            ('NtOpenSection', '打开内存段'),
            ('NtMapViewOfSection', '映射内存段'),
            ('MmCopyVirtualMemory', '复制虚拟内存'),
            ('NtWriteVirtualMemory', '写入虚拟内存'),
            ('NtProtectVirtualMemory', '修改内存保护'),
        ]
        
        try:
            import pefile
            
            pe = pefile.PE(self.driver_path)
            
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                
                for imp in entry.imports:
                    func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else ''
                    
                    for bypass_func, desc in bypass_imports:
                        if bypass_func.lower() == func_name.lower():
                            self.bypass_indicators.append(DSEBypassIndicator(
                                indicator_type='SUSPICIOUS_IMPORT',
                                severity='medium',
                                description=f"导入可疑函数: {desc}",
                                evidence=f"函数: {func_name} 来自 {dll_name}",
                                recommendation="这些函数可能被用于驱动加载或内存操作"
                            ))
        
        except ImportError:
            pass
        except Exception as e:
            logger.error(f"检查导入失败: {e}")
    
    def analyze(self) -> DSEAnalysisResult:
        """执行DSE绕过检测"""
        self.bypass_indicators = []
        
        if self.driver_path:
            self.strings = self._extract_strings()
            self._check_signature()
            self._check_certificate_info()
            self._check_bypass_keywords()
            self._check_bypass_patterns()
            self._check_imports()
        
        risk_score = self._calculate_risk_score()
        
        return DSEAnalysisResult(
            filename=os.path.basename(self.driver_path) if self.driver_path else 'unknown',
            is_signed=self.is_signed,
            certificate_info=self.certificate_info,
            bypass_indicators=self.bypass_indicators,
            risk_score=risk_score
        )
    
    def _calculate_risk_score(self) -> int:
        """计算风险评分"""
        score = 100
        
        if not self.is_signed:
            score -= 30
        
        for indicator in self.bypass_indicators:
            if indicator.severity == 'high':
                score -= 25
            elif indicator.severity == 'medium':
                score -= 10
            elif indicator.severity == 'low':
                score -= 5
        
        return max(0, score)
    
    def generate_report(self) -> str:
        """生成分析报告"""
        result = self.analyze()
        
        lines = [
            "Windows 驱动签名强制绕过检测报告",
            "===============================",
            "",
            f"文件: {result.filename}",
            f"已签名: {'是' if result.is_signed else '否'}",
            f"风险评分: {result.risk_score}/100",
            ""
        ]
        
        if result.certificate_info:
            lines.append("证书信息:")
            lines.append("----------")
            for key, value in result.certificate_info.items():
                lines.append(f"- {key}: {value}")
            lines.append("")
        
        if result.bypass_indicators:
            lines.append("发现的绕过迹象:")
            lines.append("----------------")
            for i, indicator in enumerate(result.bypass_indicators, 1):
                lines.append(f"{i}. [{indicator.severity.upper()}] {indicator.indicator_type}")
                lines.append(f"   描述: {indicator.description}")
                lines.append(f"   证据: {indicator.evidence}")
                lines.append(f"   建议: {indicator.recommendation}")
                lines.append("")
        
        if not result.bypass_indicators and result.is_signed:
            lines.append("未发现DSE绕过迹象，驱动签名有效。")
        
        return '\n'.join(lines)


def detect_dse_bypass(driver_path: str) -> DSEAnalysisResult:
    """检测DSE绕过的便捷函数"""
    detector = DSEBypassDetector(driver_path)
    return detector.analyze()


def check_driver_signature(driver_path: str) -> Dict[str, Any]:
    """检查驱动签名"""
    detector = DSEBypassDetector(driver_path)
    detector._check_signature()
    return {
        'is_signed': detector.is_signed,
        'certificate_info': detector.certificate_info
    }


def scan_for_bypass_keywords(driver_path: str) -> List[DSEBypassIndicator]:
    """扫描DSE绕过关键字"""
    detector = DSEBypassDetector(driver_path)
    detector.strings = detector._extract_strings()
    detector._check_bypass_keywords()
    return detector.bypass_indicators
