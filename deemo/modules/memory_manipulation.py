import os
import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class InjectionIndicator:
    """注入指示器数据类"""
    indicator_type: str
    severity: str  # 'high', 'medium', 'low'
    description: str
    evidence: str
    recommendation: str


@dataclass
class MemoryManipulationResult:
    """内存操作检测结果"""
    filename: str
    injection_indicators: List[InjectionIndicator]
    suspicious_imports: List[str]
    injection_risk: str  # 'high', 'medium', 'low', 'none'
    risk_score: int


class MemoryManipulationDetector:
    """内存扫描与注入技术对抗分析器"""
    
    INJECTION_IMPORTS = {
        'high': [
            'CreateRemoteThread',
            'CreateRemoteThreadEx',
            'NtCreateThreadEx',
            'RtlCreateUserThread',
            'WriteProcessMemory',
            'NtWriteVirtualMemory',
            'VirtualAllocEx',
            'VirtualAllocExNuma',
            'VirtualProtectEx',
            'NtProtectVirtualMemory',
            'SetWindowsHookEx',
            'SetWindowsHookExA',
            'SetWindowsHookExW',
            'NtQueueApcThread',
            'NtQueueApcThreadEx',
            'QueueUserAPC',
            'InjectLibrary',
            'InjectDll',
            'LoadRemoteLibraryR',
        ],
        'medium': [
            'OpenProcess',
            'OpenThread',
            'NtOpenProcess',
            'NtOpenThread',
            'GetProcessHandleFromHwnd',
            'GetWindowThreadProcessId',
            'EnumProcesses',
            'EnumProcessModules',
            'ReadProcessMemory',
            'NtReadVirtualMemory',
            'CreateToolhelp32Snapshot',
            'Process32First',
            'Process32Next',
            'Thread32First',
            'Thread32Next',
        ],
        'low': [
            'GetModuleHandle',
            'GetProcAddress',
            'LoadLibrary',
            'LoadLibraryA',
            'LoadLibraryW',
            'GetModuleFileName',
            'GetModuleFileNameA',
            'GetModuleFileNameW',
        ]
    }
    
    INJECTION_PATTERNS = [
        (r'VirtualAllocEx.*MEM_COMMIT.*PAGE_EXECUTE', '分配可执行内存并写入', 'high'),
        (r'VirtualAllocEx.*MEM_RESERVE.*PAGE_EXECUTE', '预留可执行内存', 'high'),
        (r'WriteProcessMemory.*VirtualAllocEx', '先分配后写入模式', 'high'),
        (r'VirtualProtectEx.*PAGE_EXECUTE', '修改内存为可执行', 'high'),
        (r'CreateRemoteThread.*WriteProcessMemory', '写入后创建远程线程', 'high'),
        (r'QueueUserAPC.*WriteProcessMemory', 'APC注入模式', 'high'),
        (r'SetWindowsHookEx.*WH_KEYBOARD', '键盘钩子注入', 'medium'),
        (r'SetWindowsHookEx.*WH_MOUSE', '鼠标钩子注入', 'medium'),
        (r'CreateRemoteThreadEx.*LPTHREAD_START_ROUTINE', '远程线程启动', 'high'),
    ]
    
    INJECTION_STRINGS = [
        ('RemoteThread', '远程线程操作'),
        ('Inject', '注入操作'),
        ('Shellcode', 'Shellcode相关'),
        ('Payload', '载荷相关'),
        ('ProcessInjection', '进程注入'),
        ('DLLInject', 'DLL注入'),
        ('ReflectiveDLL', '反射式DLL注入'),
        ('QueueUserAPC', 'APC注入'),
        ('SetWindowsHook', '钩子注入'),
    ]
    
    def __init__(self, binary_path: str = ""):
        self.binary_path = binary_path
        self.injection_indicators: List[InjectionIndicator] = []
        self.suspicious_imports: List[str] = []
        self.strings: List[str] = []
    
    def _extract_strings(self) -> List[str]:
        """从二进制文件中提取字符串"""
        strings = []
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            
            current_string = []
            for byte in data:
                if 32 <= byte <= 126:
                    current_string.append(chr(byte

                else:
                    if len(current_string) >= 4:
                        strings.append(''.join(current_string

                    current_string = []
            
            if len(current_string) >= 4:
                strings.append(''.join(current_string

            
        except Exception as e:
            logger.error(f"提取字符串失败: {e}")
        
        return strings
    
    def _extract_imports(self) -> List[str]:
        """提取导入函数"""
        imports = []
        
        try:
            import pefile
            
            pe = pefile.PE(self.binary_path)
            
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                
                for imp in entry.imports:
                    func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else '',
                    if func_name:
                        imports.append(func_name)
            
        except ImportError:
            logger.warning("pefile 模块未安装，无法提取导入")
        except Exception as e:
            logger.error(f"提取导入失败: {e}")
        
        return imports
    
    def _check_imports(self):
        """检查注入相关导入"""
        imports = self._extract_imports()
        
        for severity, func_list in self.INJECTION_IMPORTS.items():
            for func_name in func_list:
                if func_name in imports:
                    self.suspicious_imports.append(func_name)
                    
                    description = self._get_import_description(func_name)
                    self.injection_indicators.append(InjectionIndicator(
                        indicator_type='SUSPICIOUS_IMPORT',
                        severity=severity,
                        description=f"导入注入相关函数: {description}",
                        evidence=f"函数: {func_name}",
                        recommendation=self._get_import_recommendation(func_name)
                    

    
    def _get_import_description(self, func_name: str) -> str:
        """获取导入函数描述"""
        descriptions = {
            'CreateRemoteThread': '创建远程线程，常用于代码注入',
            'WriteProcessMemory': '写入进程内存，常用于注入shellcode',
            'VirtualAllocEx': '在远程进程中分配内存',
            'VirtualProtectEx': '修改远程进程内存保护属性',
            'SetWindowsHookEx': '设置Windows钩子，可用于注入',
            'NtQueueApcThread': '队列APC，可用于APC注入',
            'OpenProcess': '打开进程句柄',
            'ReadProcessMemory': '读取进程内存',
        }
        return descriptions.get(func_name, '注入相关函数')
    
    def _get_import_recommendation(self, func_name: str) -> str:
        """获取导入函数建议"""
        if func_name in self.INJECTION_IMPORTS['high']:
            return "此函数常用于恶意代码注入，需进一步分析用途"
        elif func_name in self.INJECTION_IMPORTS['medium']:
            return "此函数可能被用于进程枚举或内存操作，需关注上下文"
        else:
            return "此函数本身无害，但可能与其他函数配合用于注入"
    
    def _check_patterns(self):
        """检查注入代码模式"""
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read().hex()
            
            for pattern, desc, severity in self.INJECTION_PATTERNS:
                if re.search(pattern, data, re.IGNORECASE):
                    self.injection_indicators.append(InjectionIndicator(
                        indicator_type='INJECTION_PATTERN',
                        severity=severity,
                        description=f"检测到注入代码模式: {desc}",
                        evidence=f"模式: {pattern}",
                        recommendation="此代码模式表明可能存在注入功能"
                    

        
        except Exception as e:
            logger.error(f"检查代码模式失败: {e}")
    
    def _check_strings(self):
        """检查注入相关字符串"""
        self.strings = self._extract_strings()
        
        for keyword, desc in self.INJECTION_STRINGS:
            for string in self.strings:
                if keyword.lower() in string.lower():
                    self.injection_indicators.append(InjectionIndicator(
                        indicator_type='INJECTION_STRING',
                        severity='medium',
                        description=f"检测到注入相关字符串: {desc}",
                        evidence=f"字符串: {string[:50]}",
                        recommendation="检查是否包含注入相关功能"
                    

                    break
    
    def _detect_injection_sequence(self):
        """检测注入序列模式"""
        imports = self._extract_imports()
        
        injection_sequences = [
            (['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'])
             '标准注入序列: OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread'),
            (['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'])
             '简化注入序列'),
            (['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'VirtualProtectEx', 'CreateRemoteThread'])
             '带保护修改的注入序列'),
            (['NtOpenProcess', 'NtAllocateVirtualMemory', 'NtWriteVirtualMemory', 'NtCreateThreadEx'])
             'Native API注入序列'),
            (['SetWindowsHookEx', 'GetModuleHandle', 'GetProcAddress'])
             '钩子注入序列'),
        ]
        
        for sequence, desc in injection_sequences:
            if all(func in imports for func in sequence):
                self.injection_indicators.append(InjectionIndicator(
                    indicator_type='INJECTION_SEQUENCE',
                    severity='high',
                    description=f"检测到完整的注入序列: {desc}",
                    evidence=f"函数序列: {', '.join(sequence)}",
                    recommendation="此程序包含完整的注入功能，可能是恶意软件或合法工具"
                

    
    def analyze(self) -> MemoryManipulationResult:
        """执行内存操作分析"""
        self.injection_indicators = []
        self.suspicious_imports = []
        
        if self.binary_path:
            self._check_imports()
            self._check_patterns()
            self._check_strings()
            self._detect_injection_sequence()
        
        risk_score, risk_level = self._calculate_risk()
        
        return MemoryManipulationResult(
            filename=os.path.basename(self.binary_path) if self.binary_path else 'unknown',
            injection_indicators=self.injection_indicators,
            suspicious_imports=self.suspicious_imports,
            injection_risk=risk_level,
            risk_score=risk_score)
        

    
    def _calculate_risk(self) -> Tuple[int, str]:
        """计算风险评分和级别"""
        score = 100
        high_count = sum(1 for i in self.injection_indicators if i.severity == 'high')
        medium_count = sum(1 for i in self.injection_indicators if i.severity == 'medium')
        
        score -= high_count * 25
        score -= medium_count * 10
        
        if score <= 30:
            risk_level = 'high'
        elif score <= 60:
            risk_level = 'medium'
        elif score <= 80:
            risk_level = 'low'
        else:
            risk_level = 'none'
        
        return max(0, score), risk_level
    
    def generate_report(self) -> str:
        """生成分析报告"""
        result = self.analyze()
        
        lines = [
            "内存扫描与注入技术分析报告",
            "=========================",
            "",
            f"文件: {result.filename}",
            f"注入风险: {result.injection_risk.upper()}",
            f"风险评分: {result.risk_score}/100",
            ""
        ]
        
        if result.suspicious_imports:
            lines.append("可疑导入函数:")
            lines.append("--------------")
            for imp in sorted(result.suspicious_imports):
                lines.append(f"- {imp}")
            lines.append("")
        
        if result.injection_indicators:
            lines.append("注入指示器:")
            lines.append("------------")
            for i, indicator in enumerate(result.injection_indicators, 1):
                lines.append(f"{i}. [{indicator.severity.upper()}] {indicator.indicator_type}")
                lines.append(f"   描述: {indicator.description}")
                lines.append(f"   证据: {indicator.evidence}")
                lines.append(f"   建议: {indicator.recommendation}")
                lines.append("")
        
        if result.injection_risk == 'none':
            lines.append("未发现注入相关功能。")
        
        return '\n'.join(lines)


def detect_memory_manipulation(binary_path: str) -> MemoryManipulationResult:
    """检测内存操作的便捷函数"""
    detector = MemoryManipulationDetector(binary_path)
    return detector.analyze()


def scan_for_injection_imports(binary_path: str) -> List[str]:
    """扫描注入相关导入"""
    detector = MemoryManipulationDetector(binary_path)
    detector._check_imports()
    return detector.suspicious_imports


def analyze_injection_risk(binary_path: str) -> Dict[str, Any]:
    """分析注入风险"""
    result = detect_memory_manipulation(binary_path)
    return {
        'risk_level': result.injection_risk,
        'risk_score': result.risk_score,
        'indicators': [i.__dict__ for i in result.injection_indicators]
    })))))))))