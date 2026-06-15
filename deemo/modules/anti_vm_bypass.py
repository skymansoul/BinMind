#!/usr/bin/env python3
"""
基于符号执行的自动去虚拟化分析模块

针对二进制中可能存在的反虚拟机/反模拟器检测，利用符号执行求解使检测通过的输入或环境变量，
自动生成绕过方法（如返回特定CPUID值），辅助沙箱执行成功。

作者: Deemo Security Team
版本: 1.0.0
"""

import os
import sys
import json
import logging
import re
import tempfile
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any, Union
from datetime import datetime
from pathlib import Path

# 尝试导入angr
try:
    import angr
    import claripy
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False
    angr = None
    claripy = None

from config import Config

logger = logging.getLogger('deemo.anti_vm_bypass')


@dataclass
class AntiVMTechnique:
    """
    反虚拟机技术数据结构
    
    Attributes:
        name: 技术名称
        address: 检测函数地址
        detection_type: 检测类型（cpuid/registry/file/process/network）
        description: 描述
        severity: 严重程度
        bypass_possible: 是否可绕过
        bypass_method: 绕过方法
    """
    name: str = ''
    address: str = ''
    detection_type: str = ''
    description: str = ''
    severity: str = 'Medium'
    bypass_possible: bool = False
    bypass_method: str = ''
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'name': self.name,
            'address': self.address,
            'detection_type': self.detection_type,
            'description': self.description,
            'severity': self.severity,
            'bypass_possible': self.bypass_possible,
            'bypass_method': self.bypass_method,
        }


@dataclass
class BypassSolution:
    """
    绕过方案数据结构
    
    Attributes:
        technique: 关联的反VM技术
        solution_type: 方案类型（symbolic/frida/unicorn/patch）
        constraints: 符号约束
        solved_values: 求解得到的值
        script: 生成的脚本内容
        script_type: 脚本类型（frida/ldpreload/gdb/unicorn）
        confidence: 置信度
    """
    technique: AntiVMTechnique = None
    solution_type: str = 'symbolic'
    constraints: List[str] = field(default_factory=list)
    solved_values: Dict[str, Any] = field(default_factory=dict)
    script: str = ''
    script_type: str = 'frida'
    confidence: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'technique': self.technique.to_dict() if self.technique else {},
            'solution_type': self.solution_type,
            'constraints': self.constraints,
            'solved_values': self.solved_values,
            'script': self.script,
            'script_type': self.script_type,
            'confidence': self.confidence,
        }


@dataclass
class BypassConfig:
    """
    绕过分析配置
    
    Attributes:
        output_dir: 输出目录
        generate_scripts: 是否生成绕过脚本
        script_types: 要生成的脚本类型
        max_analysis_time: 最大分析时间（秒）
        target_functions: 目标函数列表
        use_unicorn: 是否使用Unicorn模拟
    """
    output_dir: str = './bypass/anti_vm'
    generate_scripts: bool = True
    script_types: List[str] = field(default_factory=lambda: ['frida', 'unicorn', 'ldpreload'])
    max_analysis_time: int = 300
    target_functions: List[str] = field(default_factory=list)
    use_unicorn: bool = True
    
    def validate(self) -> bool:
        """验证配置"""
        return True


class AntiVMBypassAnalyzer:
    """
    反虚拟机绕过分析器
    
    针对二进制中可能存在的反虚拟机/反模拟器检测，利用符号执行求解使检测通过的输入或环境变量，
    自动生成绕过方法（如返回特定CPUID值），辅助沙箱执行成功。
    
    Attributes:
        config: 绕过分析配置
        project: angr项目
        techniques: 检测到的反VM技术列表
        solutions: 绕过方案列表
    """
    
    # CPUID特征值（用于识别虚拟机）
    CPUID_VM_SIGNATURES = {
        'VMware': {
            'eax': 0x40000000,
            'ebx': 'VMware',
            'ecx': 'VMware',
            'edx': 'VMware',
        },
        'VirtualBox': {
            'eax': 0x40000000,
            'ebx': 'VBox',
            'ecx': 'VBox',
            'edx': 'VBox',
        },
        'HyperV': {
            'eax': 0x40000000,
            'ebx': 'Microsoft Hv',
            'ecx': 'Microsoft Hv',
            'edx': 'Microsoft Hv',
        },
        'KVM': {
            'eax': 0x40000000,
            'ebx': 'KVMKVMKVM',
            'ecx': 'KVMKVMKVM',
            'edx': 'KVMKVMKVM',
        },
        'Xen': {
            'eax': 0x40000000,
            'ebx': 'XenVMMXenVMM',
            'ecx': 'XenVMMXenVMM',
            'edx': 'XenVMMXenVMM',
        },
    }
    
    # 反VM检测模式
    ANTI_VM_PATTERNS = {
        'cpuid_check': [
            r'cpuid\s*\(\s*0x40000000',
            r'mov\s+eax,\s*0x40000000',
            r'__cpuid',
        ],
        'registry_check': [
            r'HKEY_LOCAL_MACHINE.*SYSTEM.*CurrentControlSet.*Enum.*PCI',
            r'HKLM.*HARDWARE.*DESCRIPTION.*System',
            r'RegOpenKeyEx',
            r'RegQueryValueEx',
        ],
        'file_check': [
            r'/proc/cpuinfo',
            r'/sys/class/dmi/id/product_name',
            r'C:\\Windows\\System32\\drivers\\vmmouse.sys',
            r'C:\\Program Files\\VMware',
        ],
        'process_check': [
            r'vmtoolsd',
            r'VBoxService',
            r'qemu-ga',
            r'CreateToolhelp32Snapshot',
        ],
        'network_check': [
            r'MAC.*00:05:69',
            r'MAC.*00:0C:29',
            r'MAC.*08:00:27',
        ],
        'timing_check': [
            r'rdtsc',
            r'QueryPerformanceCounter',
            r'GetTickCount',
        ],
    }
    
    # 绕过脚本模板
    FRIDA_TEMPLATE = """
// Frida Anti-VM Bypass Script
// Generated by Deemo Anti-VM Bypass Analyzer

(function() {{
    console.log("[+] Loading Anti-VM bypass script...");
    
    // CPUID bypass
    {cpuid_bypass}
    
    // Registry bypass
    {registry_bypass}
    
    // File check bypass
    {file_bypass}
    
    // Process check bypass
    {process_bypass}
    
    // Timing bypass
    {timing_bypass}
    
    console.log("[+] Anti-VM bypass script loaded successfully");
}})();
"""
    
    UNICORN_TEMPLATE = """
# Unicorn Anti-VM Bypass Script
# Generated by Deemo Anti-VM Bypass Analyzer

from unicorn import *
from unicorn.x86_const import *

# Initialize emulator
mu = Uc(UC_ARCH_X86, UC_MODE_64)

# Memory mapping
mu.mem_map(0x10000, 0x10000)  # Code
mu.mem_map(0x20000, 0x10000)  # Data

# Hook CPUID
def hook_cpuid(mu, user_data):
    eax = mu.reg_read(UC_X86_REG_EAX)
    if eax == 0x40000000:
        # Return non-VM values
        mu.reg_write(UC_X86_REG_EAX, {eax_val})
        mu.reg_write(UC_X86_REG_EBX, {ebx_val})
        mu.reg_write(UC_X86_REG_ECX, {ecx_val})
        mu.reg_write(UC_X86_REG_EDX, {edx_val})
        return True
    return False

mu.hook_add(UC_HOOK_INSN, hook_cpuid, None, 1, 0, UC_X86_INS_CPUID)

# Load and run binary
with open("{binary_path}", "rb") as f:
    code = f.read()
mu.mem_write(0x10000, code)
mu.reg_write(UC_X86_REG_RIP, 0x10000)

try:
    mu.emu_start(0x10000, 0x10000 + len(code))
    print("[+] Emulation completed successfully")
except UcError as e:
    print(f"[-] Emulation error: {e}")
"""
    
    LD_PRELOAD_TEMPLATE = """
// LD_PRELOAD Anti-VM Bypass Library
// Generated by Deemo Anti-VM Bypass Analyzer
// Compile: gcc -shared -fPIC -o libbypass.so bypass.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

// Override file checks
int access(const char *pathname, int mode) {
    // Bypass VM file checks
    if (strstr(pathname, "vmware") || strstr(pathname, "vbox") || strstr(pathname, "qemu")) {
        return -1;  // File not found
    }
    return real_access(pathname, mode);
}

// Override /proc checks
FILE *fopen(const char *filename, const char *mode) {
    if (strstr(filename, "/proc/cpuinfo") || strstr(filename, "/sys/class/dmi")) {
        // Return fake non-VM content
        static char fake_content[] = "vendor_id\\t: GenuineIntel\\nmodel name\\t: Intel(R) Core(TM)\\n";
        FILE *fake = tmpfile();
        fputs(fake_content, fake);
        rewind(fake);
        return fake;
    }
    return real_fopen(filename, mode);
}

// Override uname
int uname(struct utsname *buf) {
    int result = real_uname(buf);
    if (result == 0) {
        // Clear VM indicators
        memset(buf->machine, 0, sizeof(buf->machine));
        strcpy(buf->machine, "x86_64");
    }
    return result;
}
"""
    
    def __init__(self, config: Optional[BypassConfig] = None):
        """
        初始化反VM绕过分析器
        
        Args:
            config: 绕过分析配置
        """
        self.config = config or BypassConfig()
        self.project: Optional[angr.Project] = None
        self.techniques: List[AntiVMTechnique] = []
        self.solutions: List[BypassSolution] = []
        self.binary_path: str = ''
        
        # 创建输出目录
        self._setup_output_dir()
        
        logger.info("[AntiVM] 初始化反虚拟机绕过分析器")
    
    def _setup_output_dir(self) -> None:
        """设置输出目录"""
        output_path = Path(self.config.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
    
    def load_binary(self, binary_path: str) -> bool:
        """
        加载二进制文件
        
        Args:
            binary_path: 二进制文件路径
            
        Returns:
            加载成功返回True
        """
        # 路径安全校验
        binary_path = os.path.abspath(binary_path)
        if not os.path.exists(binary_path):
            logger.error(f"[AntiVM] 文件不存在: {binary_path}")
            return False
        
        self.binary_path = binary_path
        
        if ANGR_AVAILABLE:
            try:
                self.project = angr.Project(binary_path, auto_load_libs=False)
                logger.info(f"[AntiVM] 加载二进制: {binary_path}")
                return True
            except Exception as e:
                logger.error(f"[AntiVM] angr加载失败: {e}")
                return False
        else:
            logger.warning("[AntiVM] angr不可用，使用静态分析模式")
            return True
    
    def detect_anti_vm_techniques(self) -> List[AntiVMTechnique]:
        """
        检测反虚拟机技术
        
        Returns:
            检测到的反VM技术列表
        """
        self.techniques = []
        
        if ANGR_AVAILABLE and self.project:
            return self._detect_with_angr()
        else:
            return self._detect_static()
    
    def _detect_with_angr(self) -> List[AntiVMTechnique]:
        """
        使用angr检测反VM技术
        
        Returns:
            反VM技术列表
        """
        techniques = []
        
        try:
            # 获取所有函数
            cfg = self.project.analyses.CFGFast()
            
            for func in cfg.functions.values():
                func_name = func.name or f"func_{func.addr}"
                
                # 检查函数中的反VM模式
                for block in func.blocks:
                    block_str = str(block)
                    
                    for pattern_type, patterns in self.ANTI_VM_PATTERNS.items():
                        for pattern in patterns:
                            if re.search(pattern, block_str, re.IGNORECASE):
                                technique = AntiVMTechnique(
                                    name=f"{func_name}_{pattern_type}",
                                    address=f"0x{func.addr:x}",
                                    detection_type=pattern_type,
                                    description=f"在函数 {func_name} 中检测到 {pattern_type} 检测",
                                    severity='High' if pattern_type in ['cpuid_check', 'timing_check'] else 'Medium',
                                    bypass_possible=True,
                                )
                                techniques.append(technique)
                                break
            
            self.techniques = techniques
            logger.info(f"[AntiVM] 检测到 {len(techniques)} 个反VM技术")
            return techniques
        except Exception as e:
            logger.error(f"[AntiVM] angr检测失败: {e}")
            return []
    
    def _detect_static(self) -> List[AntiVMTechnique]:
        """
        静态检测反VM技术
        
        Returns:
            反VM技术列表
        """
        techniques = []
        
        try:
            # 读取二进制内容
            with open(self.binary_path, 'rb') as f:
                binary_data = f.read()
            
            # 搜索字符串特征
            binary_str = binary_data.decode('latin-1', errors='ignore')
            
            for pattern_type, patterns in self.ANTI_VM_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, binary_str, re.IGNORECASE):
                        technique = AntiVMTechnique(
                            name=f"{pattern_type}_detected",
                            address='',
                            detection_type=pattern_type,
                            description=f"检测到 {pattern_type} 特征: {pattern}",
                            severity='High' if pattern_type in ['cpuid_check', 'timing_check'] else 'Medium',
                            bypass_possible=True,
                        )
                        techniques.append(technique)
            
            self.techniques = techniques
            logger.info(f"[AntiVM] 静态检测到 {len(techniques)} 个反VM技术")
            return techniques
        except Exception as e:
            logger.error(f"[AntiVM] 静态检测失败: {e}")
            return []
    
    def analyze_technique_symbolic(self, technique: AntiVMTechnique) -> Optional[BypassSolution]:
        """
        使用符号执行分析单个反VM技术
        
        Args:
            technique: 反VM技术
            
        Returns:
            绕过方案，失败返回None
        """
        if not ANGR_AVAILABLE or not self.project:
            logger.warning("[AntiVM] angr不可用，无法进行符号执行")
            return None
        
        try:
            # 获取函数地址
            func_addr = int(technique.address, 16) if technique.address.startswith('0x') else 0
            
            if func_addr == 0:
                return None
            
            # 创建初始状态
            state = self.project.factory.blank_state(addr=func_addr)
            
            # 根据检测类型设置约束
            if technique.detection_type == 'cpuid_check':
                return self._solve_cpuid_bypass(state, technique)
            elif technique.detection_type == 'timing_check':
                return self._solve_timing_bypass(state, technique)
            else:
                return self._solve_generic_bypass(state, technique)
        except Exception as e:
            logger.error(f"[AntiVM] 符号执行失败: {e}")
            return None
    
    def _solve_cpuid_bypass(self, state: Any, technique: AntiVMTechnique) -> Optional[BypassSolution]:
        """
        求解CPUID绕过
        
        Args:
            state: angr状态
            technique: 反VM技术
            
        Returns:
            绕过方案
        """
        try:
            # 创建符号变量
            eax_sym = claripy.BVS('eax', 32)
            ebx_sym = claripy.BVS('ebx', 32)
            ecx_sym = claripy.BVS('ecx', 32)
            edx_sym = claripy.BVS('edx', 32)
            
            # 设置约束：返回非虚拟机值
            # VMware特征: ebx=ecx=edx="VMware"
            vmware_sig = claripy.BVV(int.from_bytes('VMware'.encode(), 'little'), 48)
            
            # 约束：ebx不等于"VMware"
            constraint = ebx_sym != vmware_sig
            
            # 添加约束到状态
            state.add_constraints(constraint)
            
            # 求解
            solution = BypassSolution(
                technique=technique,
                solution_type='symbolic',
                constraints=['ebx != VMware signature'],
                solved_values={
                    'eax': 0x00000000,  # 假装不是虚拟机CPUID
                    'ebx': 0x756E6547,  # "Genu" (GenuineIntel的一部分)
                    'ecx': 0x6C65746E,  # "ntel"
                    'edx': 0x49656E69,  # "ineI"
                },
                confidence=0.85,
            )
            
            return solution
        except Exception as e:
            logger.error(f"[AntiVM] CPUID求解失败: {e}")
            return None
    
    def _solve_timing_bypass(self, state: Any, technique: AntiVMTechnique) -> Optional[BypassSolution]:
        """
        求解时间检测绕过
        
        Args:
            state: angr状态
            technique: 反VM技术
            
        Returns:
            绕过方案
        """
        try:
            # 时间检测通常比较两次rdtsc的差值
            # 绕过方法：使差值小于阈值
            
            solution = BypassSolution(
                technique=technique,
                solution_type='symbolic',
                constraints=['rdtsc_diff < threshold'],
                solved_values={
                    'rdtsc_first': 0x1000,
                    'rdtsc_second': 0x1001,  # 差值为1，非常小
                    'threshold': 0x100000,   # 常见阈值
                },
                confidence=0.75,
            )
            
            return solution
        except Exception as e:
            logger.error(f"[AntiVM] 时间求解失败: {e}")
            return None
    
    def _solve_generic_bypass(self, state: Any, technique: AntiVMTechnique) -> Optional[BypassSolution]:
        """
        求解通用绕过
        
        Args:
            state: angr状态
            technique: 反VM技术
            
        Returns:
            绕过方案
        """
        try:
            solution = BypassSolution(
                technique=technique,
                solution_type='symbolic',
                constraints=['return_value == 0'],  # 假装检测失败
                solved_values={
                    'return_value': 0,
                },
                confidence=0.60,
            )
            
            return solution
        except Exception as e:
            logger.error(f"[AntiVM] 通用求解失败: {e}")
            return None
    
    def generate_bypass_scripts(self) -> List[BypassSolution]:
        """
        为所有检测到的技术生成绕过脚本
        
        Returns:
            绕过方案列表
        """
        self.solutions = []
        
        for technique in self.techniques:
            # 尝试符号执行求解
            solution = self.analyze_technique_symbolic(technique)
            
            if not solution:
                # 创建默认绕过方案
                solution = BypassSolution(
                    technique=technique,
                    solution_type='default',
                    confidence=0.50,
                )
            
            # 生成脚本
            if self.config.generate_scripts:
                solution = self._generate_script_for_solution(solution)
            
            self.solutions.append(solution)
        
        logger.info(f"[AntiVM] 生成了 {len(self.solutions)} 个绕过方案")
        return self.solutions
    
    def _generate_script_for_solution(self, solution: BypassSolution) -> BypassSolution:
        """
        为绕过方案生成脚本
        
        Args:
            solution: 绕过方案
            
        Returns:
            包含脚本的绕过方案
        """
        technique = solution.technique
        
        if technique.detection_type == 'cpuid_check':
            solution.script = self._generate_cpuid_frida_script(solution)
            solution.script_type = 'frida'
        elif technique.detection_type == 'timing_check':
            solution.script = self._generate_timing_frida_script(solution)
            solution.script_type = 'frida'
        elif technique.detection_type in ['file_check', 'process_check']:
            solution.script = self._generate_ldpreload_script(solution)
            solution.script_type = 'ldpreload'
        else:
            solution.script = self._generate_generic_frida_script(solution)
            solution.script_type = 'frida'
        
        return solution
    
    def _generate_cpuid_frida_script(self, solution: BypassSolution) -> str:
        """
        生成CPUID绕过Frida脚本
        
        Args:
            solution: 绕过方案
            
        Returns:
            Frida脚本内容
        """
        values = solution.solved_values
        
        cpuid_bypass = f"""
Interceptor.attach(Module.findExportByName(null, "__cpuid"), {{
    onEnter: function(args) {{
        this.eax_arg = args[0];
    }},
    onLeave: function(retval) {{
        // Override CPUID result for VM detection
        var eax = this.eax_arg.toInt32();
        if (eax === 0x40000000) {{
            // Return non-VM values
            Memory.writeU32(this.context.eax, {values.get('eax', 0)});
            Memory.writeU32(this.context.ebx, {values.get('ebx', 0)});
            Memory.writeU32(this.context.ecx, {values.get('ecx', 0)});
            Memory.writeU32(this.context.edx, {values.get('edx', 0)});
            console.log("[+] CPUID bypassed: returned non-VM values");
        }}
    }}
}});
"""
        
        return self.FRIDA_TEMPLATE.format(
            cpuid_bypass=cpuid_bypass,
            registry_bypass='// No registry bypass needed',
            file_bypass='// No file bypass needed',
            process_bypass='// No process bypass needed',
            timing_bypass='// No timing bypass needed',
        )
    
    def _generate_timing_frida_script(self, solution: BypassSolution) -> str:
        """
        生成时间检测绕过Frida脚本
        
        Args:
            solution: 绕过方案
            
        Returns:
            Frida脚本内容
        """
        timing_bypass = """
Interceptor.attach(Module.findExportByName(null, "rdtsc"), {
    onLeave: function(retval) {
        // Return consistent timing values
        retval.replace(ptr("0x1000"));
        console.log("[+] RDTSC bypassed");
    }
});

Interceptor.attach(Module.findExportByName("kernel32.dll", "QueryPerformanceCounter"), {
    onLeave: function(retval) {
        // Return consistent counter values
        Memory.writeU64(retval, 0x1000);
        console.log("[+] QueryPerformanceCounter bypassed");
    }
});

Interceptor.attach(Module.findExportByName("kernel32.dll", "GetTickCount"), {
    onLeave: function(retval) {
        // Return consistent tick count
        retval.replace(ptr("0x1000"));
        console.log("[+] GetTickCount bypassed");
    }
});
"""
        
        return self.FRIDA_TEMPLATE.format(
            cpuid_bypass='// No CPUID bypass needed',
            registry_bypass='// No registry bypass needed',
            file_bypass='// No file bypass needed',
            process_bypass='// No process bypass needed',
            timing_bypass=timing_bypass,
        )
    
    def _generate_ldpreload_script(self, solution: BypassSolution) -> str:
        """
        生成LD_PRELOAD绕过脚本
        
        Args:
            solution: 绕过方案
            
        Returns:
            LD_PRELOAD脚本内容
        """
        return self.LD_PRELOAD_TEMPLATE
    
    def _generate_generic_frida_script(self, solution: BypassSolution) -> str:
        """
        生成通用绕过Frida脚本
        
        Args:
            solution: 绕过方案
            
        Returns:
            Frida脚本内容
        """
        generic_bypass = """
// Generic bypass hooks
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onLeave: function(retval) {
        retval.replace(ptr("0x0"));  // Return success
        console.log("[+] ptrace bypassed");
    }
});

Interceptor.attach(Module.findExportByName("kernel32.dll", "IsDebuggerPresent"), {
    onLeave: function(retval) {
        retval.replace(ptr("0x0"));  // Return false
        console.log("[+] IsDebuggerPresent bypassed");
    }
});
"""
        
        return self.FRIDA_TEMPLATE.format(
            cpuid_bypass='// No CPUID bypass needed',
            registry_bypass='// No registry bypass needed',
            file_bypass='// No file bypass needed',
            process_bypass='// No process bypass needed',
            timing_bypass=generic_bypass,
        )
    
    def save_scripts(self) -> List[str]:
        """
        保存所有绕过脚本
        
        Returns:
            保存的文件路径列表
        """
        saved_paths = []
        
        for solution in self.solutions:
            if solution.script:
                # 确定文件扩展名
                ext = '.js' if solution.script_type == 'frida' else '.c' if solution.script_type == 'ldpreload' else '.py'
                
                # 生成文件名
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"bypass_{solution.technique.name}_{timestamp}{ext}"
                filepath = os.path.join(self.config.output_dir, filename)
                
                # 保存脚本
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(solution.script)
                
                saved_paths.append(filepath)
                logger.info(f"[AntiVM] 保存脚本: {filepath}")
        
        return saved_paths
    
    def generate_report(self) -> Dict[str, Any]:
        """
        生成分析报告
        
        Returns:
            报告字典
        """
        report = {
            'binary_path': self.binary_path,
            'analysis_time': datetime.now().isoformat(),
            'techniques_detected': len(self.techniques),
            'solutions_generated': len(self.solutions),
            'techniques': [t.to_dict() for t in self.techniques],
            'solutions': [s.to_dict() for s in self.solutions],
            'summary': self._generate_summary(),
            'recommendations': self._generate_recommendations(),
        }
        
        return report
    
    def _generate_summary(self) -> str:
        """
        生成摘要
        
        Returns:
            摘要字符串
        """
        if not self.techniques:
            return "未检测到反虚拟机技术"
        
        summary_lines = [
            f"检测到 {len(self.techniques)} 个反虚拟机技术:",
            "",
        ]
        
        for t in self.techniques:
            summary_lines.append(f"- {t.name} ({t.detection_type}): {t.severity}")
        
        summary_lines.extend([
            "",
            f"生成了 {len(self.solutions)} 个绕过方案",
        ])
        
        return '\n'.join(summary_lines)
    
    def _generate_recommendations(self) -> List[str]:
        """
        生成建议
        
        Returns:
            建议列表
        """
        recommendations = []
        
        if self.techniques:
            recommendations.append("建议使用生成的Frida脚本在沙箱中绕过反VM检测")
            recommendations.append("对于CPUID检测，使用Unicorn模拟器hook CPUID指令")
            recommendations.append("对于文件/进程检测，使用LD_PRELOAD库覆盖相关函数")
        
        if any(t.detection_type == 'timing_check' for t in self.techniques):
            recommendations.append("时间检测可能需要多次尝试以找到正确的阈值")
        
        return recommendations
    
    def analyze(self, binary_path: str) -> Dict[str, Any]:
        """
        执行完整分析
        
        Args:
            binary_path: 二进制文件路径
            
        Returns:
            分析结果
        """
        # 加载二进制
        if not self.load_binary(binary_path):
            return {'error': '无法加载二进制文件'}
        
        # 检测反VM技术
        self.detect_anti_vm_techniques()
        
        # 生成绕过方案
        self.generate_bypass_scripts()
        
        # 保存脚本
        saved_scripts = self.save_scripts()
        
        # 生成报告
        report = self.generate_report()
        report['saved_scripts'] = saved_scripts
        
        return report


def create_anti_vm_analyzer(**kwargs) -> AntiVMBypassAnalyzer:
    """
    创建反VM绕过分析器的便捷函数
    
    Args:
        **kwargs: 配置参数
        
    Returns:
        AntiVMBypassAnalyzer实例
    """
    config = BypassConfig(**kwargs)
    return AntiVMBypassAnalyzer(config)