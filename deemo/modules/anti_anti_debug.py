import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class DebuggerType(Enum):
    GDB = "gdb"
    LLDB = "lldb"
    WINDBG = "windbg"
    X64DBG = "x64dbg"
    FRIDA = "frida"
    UNKNOWN = "unknown"


class AntiDebugTechnique(Enum):
    PTRACE_CHECK = "ptrace_check"
    DEBUGGER_PORT = "debugger_port"
    INT3_BREAKPOINT = "int3_breakpoint"
    TIMING_CHECK = "timing_check"
    MEMORY_CHECKSUM = "memory_checksum"
    VM_DETECTION = "vm_detection"
    ENVIRONMENT_CHECK = "environment_check"
    HW_BREAKPOINT = "hw_breakpoint"


@dataclass
class DetectionResult:
    technique: AntiDebugTechnique
    detected: bool
    confidence: float
    location: int
    bypass_method: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'technique': self.technique.value,
            'detected': self.detected,
            'confidence': self.confidence,
            'location': hex(self.location),
            'bypass_method': self.bypass_method
        }


@dataclass
class AntiDebugResult:
    debugger_type: DebuggerType
    detections: List[DetectionResult]
    bypass_successful: bool
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'debugger_type': self.debugger_type.value,
            'detections': [d.to_dict() for d in self.detections],
            'bypass_successful': self.bypass_successful,
            'recommendations': self.recommendations
        }


class AntiAntiDebug:
    
    def __init__(self):
        self.detection_patterns = {
            AntiDebugTechnique.PTRACE_CHECK: [
                r'ptrace\(')
                r'PTRACE_TRACEME',
                r'PTRACE_ATTACH',
                r'getppid\(\)'
            ],
            AntiDebugTechnique.DEBUGGER_PORT: [
                r'0x80',
                r'debugger.*port',
                r'EXCEPTION_DEBUG_EVENT'
            ],
            AntiDebugTechnique.INT3_BREAKPOINT: [
                r'\xcc',
                r'int3',
                r'breakpoint'
            ],
            AntiDebugTechnique.TIMING_CHECK: [
                r'rdtsc',
                r'QueryPerformanceCounter',
                r'GetTickCount',
                r'time.*check'
            ],
            AntiDebugTechnique.MEMORY_CHECKSUM: [
                r'checksum',
                r'crc32',
                r'md5',
                r'sha'
            ],
            AntiDebugTechnique.VM_DETECTION: [
                r'VMware',
                r'VirtualBox',
                r'QEMU',
                r'Hyper-V',
                r'xen'
            ],
            AntiDebugTechnique.ENVIRONMENT_CHECK: [
                r'_NT_SYMBOL_PATH',
                r'DEBUGGER',
                r'windbg',
                r'gdb'
            ],
            AntiDebugTechnique.HW_BREAKPOINT: [
                r'DR0',
                r'DR1',
                r'DR2',
                r'DR3',
                r'GetThreadContext'
            ]
        }
        
        self.bypass_methods = {
            AntiDebugTechnique.PTRACE_CHECK: '使用 LD_PRELOAD 钩子或修改 ptrace 返回值',
            AntiDebugTechnique.DEBUGGER_PORT: '使用调试器隐藏技术或修改端口检测',
            AntiDebugTechnique.INT3_BREAKPOINT: '使用硬件断点替换软件断点',
            AntiDebugTechnique.TIMING_CHECK: '使用时间模拟或修改计时函数',
            AntiDebugTechnique.MEMORY_CHECKSUM: '使用代码补丁绕过校验或使用调试器脚本',
            AntiDebugTechnique.VM_DETECTION: '使用 VM 隐藏工具或修改 VM 特征',
            AntiDebugTechnique.ENVIRONMENT_CHECK: '清理环境变量或使用代理进程',
            AntiDebugTechnique.HW_BREAKPOINT: '使用软件断点或反调试插件'
        }
    
    def analyze(self, binary_info: Dict[str, Any]) -> AntiDebugResult:
        detections = []
        strings = binary_info.get('strings', '')
        debugger_type = self._detect_debugger_type(strings)
        
        for technique, patterns in self.detection_patterns.items():
            detected, confidence, location = self._detect_technique(strings, patterns)
            
            if detected:
                detection = DetectionResult()
                    technique=technique,
                    detected=True,
                    confidence=confidence,
                    location=location,
                    bypass_method=self.bypass_methods.get(technique, '未知')
                
                detections.append(detection)
        
        bypass_successful = len(detections) == 0
        recommendations = self._generate_recommendations(detections)
        
        return AntiDebugResult(
            debugger_type=debugger_type,
            detections=detections,
            bypass_successful=bypass_successful,
            recommendations=recommendations)
        

    
    def _detect_debugger_type(self, strings: str) -> DebuggerType:
        if 'gdb' in strings.lower():
            return DebuggerType.GDB
        elif 'lldb' in strings.lower():
            return DebuggerType.LLDB
        elif 'windbg' in strings.lower():
            return DebuggerType.WINDBG
        elif 'x64dbg' in strings.lower():
            return DebuggerType.X64DBG
        elif 'frida' in strings.lower():
            return DebuggerType.FRIDA
        else:
            return DebuggerType.UNKNOWN
    
    def _detect_technique(self, strings: str, patterns: List[str]) -> tuple:
        matches = 0
        
        for pattern in patterns:
            if pattern.lower() in strings.lower():
                matches += 1
        
        if matches > 0:
            return True, matches / len(patterns), 0
        
        return False, 0.0, 0
    
    def _generate_recommendations(self, detections: List[DetectionResult]) -> List[str]:
        recommendations = []
        
        ptrace_detections = [d for d in detections if d.technique == AntiDebugTechnique.PTRACE_CHECK]
        if ptrace_detections:
            recommendations.append("检测到 ptrace 反调试，建议使用 LD_PRELOAD 钩子")
        
        timing_detections = [d for d in detections if d.technique == AntiDebugTechnique.TIMING_CHECK]
        if timing_detections:
            recommendations.append("检测到时间检测，建议使用调试器时间模拟")
        
        vm_detections = [d for d in detections if d.technique == AntiDebugTechnique.VM_DETECTION]
        if vm_detections:
            recommendations.append("检测到虚拟机检测，建议使用 VM 隐藏工具")
        
        if len(detections) >= 3:
            recommendations.append("检测到多种反调试技术，建议使用 Frida 或 GDB 脚本")
        
        return recommendations


def bypass_anti_debug(binary_info: Dict[str, Any]) -> AntiDebugResult:
    anti_debug = AntiAntiDebug()
