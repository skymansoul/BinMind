#!/usr/bin/env python3
"""
反调试与反分析检测及自动绕过模块

提供静态分析能力检测二进制文件中使用的反调试技术：
- ptrace检测、时间检测、异常处理、IsDebuggerPresent等
- 反虚拟机技术
- 完整性校验和混淆手法
- 自动生成绕过脚本（Frida/LD_PRELOAD）
"""

import logging
import re
import os
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class AntiAnalysisTechnique:
    """
    检测到的反分析技术
    """
    technique_type: str  # 'debugger_detection', 'vm_detection', 'integrity_check', 'obfuscation', 'timing_check'
    name: str
    location: str
    address: int
    severity: str  # 'Critical', 'High', 'Medium', 'Low'
    description: str
    bypass_status: str = 'pending'  # 'pending', 'possible', 'generated', 'applied'
    bypass_suggestion: str = ''


@dataclass
class BypassScript:
    """
    绕过脚本信息
    """
    script_type: str  # 'frida', 'ld_preload', 'gdb_script'
    name: str
    content: str
    file_path: str = ''
    applicable: bool = True


class AntiAnalysisDetector:
    """
    反分析检测与绕过引擎
    
    核心功能：
    1. 静态检测反调试API调用
    2. 检测反虚拟机技术
    3. 识别完整性校验
    4. 检测时间检测技术
    5. 生成绕过脚本
    """
    
    # 反调试API模式
    DEBUGGER_DETECTION_PATTERNS = {
        'ptrace': [
            r'ptrace\s*\(',
            r'__ptrace\s*\(',
            r'syscall.*ptrace',
            r'SYS_ptrace'
        ],
        'getppid': [
            r'getppid\s*\(',
            r'syscall.*getppid',
            r'SYS_getppid'
        ],
        'IsDebuggerPresent': [
            r'IsDebuggerPresent\s*\(',
            r'GetLastError\s*\(',
            r'CheckRemoteDebuggerPresent\s*\('
        ],
        'NtQueryInformationProcess': [
            r'NtQueryInformationProcess\s*\(',
            r'ZwQueryInformationProcess\s*\('
        ],
        'sysctl': [
            r'sysctl\s*\(',
            r'CTL_KERN',
            r'KERN_PROC'
        ],
        'fork': [
            r'fork\s*\(',
            r'syscall.*fork',
            r'SYS_fork'
        ],
        'vmware_detection': [
            r'VMware',
            r'VMXh',
            r'VirtualBox',
            r'VBox',
            r'QEMU',
            r'Xen',
            r'KVM',
            r'Hyper-V',
            r'Virtual Machine'
        ],
        'debugger_breakpoint': [
            r'int3',
            r'int\s+3',
            r'__debugbreak\s*\(',
            r'DebugBreak\s*\('
        ],
        'hardware_breakpoint': [
            r'Dr0',
            r'Dr1',
            r'Dr2',
            r'Dr3',
            r'Dr6',
            r'Dr7'
        ],
        'exception_handler': [
            r'signal\s*\(',
            r'sigaction\s*\(',
            r'_set_se_translator\s*\(',
            r'setjmp\s*\(',
            r'longjmp\s*\('
        ]
    }
    
    # 完整性校验模式
    INTEGRITY_CHECK_PATTERNS = {
        'crc': [
            r'CRC32',
            r'crc32\s*\(',
            r'__crc32\s*\(',
            r'crc16\s*\(',
            r'CRC16'
        ],
        'md5': [
            r'MD5',
            r'md5sum\s*\(',
            r'__md5\s*\(',
            r'EVP_MD5'
        ],
        'sha': [
            r'SHA1',
            r'SHA256',
            r'SHA512',
            r'sha1\s*\(',
            r'sha256\s*\(',
            r'EVP_SHA'
        ],
        'self_modifying': [
            r'mprotect\s*\(',
            r'VirtualProtect\s*\(',
            r'mmap.*PROT_WRITE',
            r'mmap.*PROT_EXEC'
        ],
        'checksum': [
            r'checksum',
            r'CheckSum',
            r'sum\s*\(',
            r'__sum'
        ]
    }
    
    # 时间检测模式
    TIMING_CHECK_PATTERNS = {
        'rdtsc': [
            r'rdtsc',
            r'__rdtsc\s*\(',
            r'ReadTimeStampCounter\s*\('
        ],
        'gettimeofday': [
            r'gettimeofday\s*\(',
            r'clock_gettime\s*\(',
            r'QueryPerformanceCounter\s*\(',
            r'QueryPerformanceFrequency\s*\('
        ],
        'sleep_check': [
            r'sleep\s*\(',
            r'usleep\s*\(',
            r'nanosleep\s*\(',
            r'Sleep\s*\('
        ]
    }
    
    # 混淆检测模式
    OBFUSCATION_PATTERNS = {
        'garbage_code': [
            r'\b0x[a-fA-F0-9]{4,}\b',
            r'\b[a-fA-F0-9]{8,}\b'
        ],
        'string_obfuscation': [
            r'XOR.*0x',
            r'rol\s*\(',
            r'ror\s*\(',
            r'__rol__',
            r'__ror__'
        ],
        'control_flow_flattening': [
            r'switch.*case.*0x',
            r'goto.*0x',
            r'jmp.*0x'
        ]
    }
    
    def __init__(self, pseudocode: str, binary_info: Dict[str, Any] = None):
        """
        初始化反分析检测器
        
        Args:
            pseudocode: 反编译后的伪代码
            binary_info: 二进制文件信息（包含导入函数等）
        """
        self.pseudocode = pseudocode
        self.binary_info = binary_info or {}
        self.detected_techniques: List[AntiAnalysisTechnique] = []
        self.bypass_scripts: List[BypassScript] = []
        
        self._detect_all()
    
    def _detect_all(self) -> None:
        """
        执行所有检测
        """
        logger.info("[AntiAnalysis] 开始检测反分析技术")
        
        self._detect_debugger_detection()
        self._detect_vm_detection()
        self._detect_integrity_checks()
        self._detect_timing_checks()
        self._detect_obfuscation()
        
        logger.info(f"[AntiAnalysis] 检测完成，发现 {len(self.detected_techniques)} 种反分析技术")
    
    def _detect_debugger_detection(self) -> None:
        """
        检测调试器检测技术
        """
        for technique_name, patterns in self.DEBUGGER_DETECTION_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, self.pseudocode)
                for match in matches:
                    line_num = self._get_line_number(match.start())
                    
                    if technique_name in ['vmware_detection']:
                        technique_type = 'vm_detection'
                        severity = 'Medium'
                    elif technique_name in ['exception_handler']:
                        technique_type = 'debugger_detection'
                        severity = 'Low'
                    else:
                        technique_type = 'debugger_detection'
                        severity = 'High'
                    
                    self.detected_techniques.append(AntiAnalysisTechnique(
                        technique_type=technique_type,
                        name=technique_name,
                        location=f"行 {line_num}",
                        address=line_num,
                        severity=severity,
                        description=f"检测到 {technique_name} 反调试技术"
                    ))
    
    def _detect_vm_detection(self) -> None:
        """
        检测虚拟机检测技术
        """
        vm_strings = [
            'VMware', 'VirtualBox', 'QEMU', 'Xen', 'KVM', 'Hyper-V',
            'VBox', 'VMXh', 'Virtual Machine', 'Parallels'
        ]
        
        for vm_string in vm_strings:
            if vm_string in self.pseudocode:
                line_num = self._get_line_number(self.pseudocode.index(vm_string))
                self.detected_techniques.append(AntiAnalysisTechnique(
                    technique_type='vm_detection',
                    name=f'vm_detection_{vm_string}',
                    location=f"行 {line_num}",
                    address=line_num,
                    severity='Medium',
                    description=f"检测到 {vm_string} 虚拟机检测"
                ))
    
    def _detect_integrity_checks(self) -> None:
        """
        检测完整性校验
        """
        for technique_name, patterns in self.INTEGRITY_CHECK_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, self.pseudocode, re.IGNORECASE)
                if match:
                    line_num = self._get_line_number(match.start())
                    
                    if technique_name in ['self_modifying']:
                        severity = 'Critical'
                    else:
                        severity = 'High'
                    
                    self.detected_techniques.append(AntiAnalysisTechnique(
                        technique_type='integrity_check',
                        name=technique_name,
                        location=f"行 {line_num}",
                        address=line_num,
                        severity=severity,
                        description=f"检测到 {technique_name} 完整性校验"
                    ))
    
    def _detect_timing_checks(self) -> None:
        """
        检测时间检测技术
        """
        for technique_name, patterns in self.TIMING_CHECK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, self.pseudocode):
                    line_num = self._get_line_number(self.pseudocode.index(pattern))
                    self.detected_techniques.append(AntiAnalysisTechnique(
                        technique_type='timing_check',
                        name=technique_name,
                        location=f"行 {line_num}",
                        address=line_num,
                        severity='Medium',
                        description=f"检测到 {technique_name} 时间检测"
                    ))
    
    def _detect_obfuscation(self) -> None:
        """
        检测混淆技术
        """
        for technique_name, patterns in self.OBFUSCATION_PATTERNS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, self.pseudocode)
                match_count = sum(1 for _ in matches)
                
                if match_count >= 5:
                    line_num = self._get_line_number(self.pseudocode.index(pattern))
                    self.detected_techniques.append(AntiAnalysisTechnique(
                        technique_type='obfuscation',
                        name=technique_name,
                        location=f"行 {line_num}",
                        address=line_num,
                        severity='Medium',
                        description=f"检测到 {technique_name} 混淆技术（发现 {match_count} 处）"
                    ))
    
    def _get_line_number(self, position: int) -> int:
        """
        根据位置获取行号
        """
        return self.pseudocode[:position].count('\n') + 1
    
    def generate_bypass_scripts(self, output_dir: str = './bypass') -> List[BypassScript]:
        """
        生成绕过脚本
        
        Args:
            output_dir: 输出目录
        
        Returns:
            生成的绕过脚本列表
        """
        logger.info("[AntiAnalysis] 开始生成绕过脚本")
        
        os.makedirs(output_dir, exist_ok=True)
        self.bypass_scripts = []
        
        debugger_techniques = [t for t in self.detected_techniques 
                              if t.technique_type == 'debugger_detection']
        integrity_techniques = [t for t in self.detected_techniques 
                               if t.technique_type == 'integrity_check']
        
        if debugger_techniques:
            frida_script = self._generate_frida_script(debugger_techniques)
            if frida_script:
                script_path = os.path.join(output_dir, 'bypass_debugger.js')
                with open(script_path, 'w', encoding='utf-8') as f:
                    f.write(frida_script)
                
                self.bypass_scripts.append(BypassScript(
                    script_type='frida',
                    name='bypass_debugger',
                    content=frida_script,
                    file_path=script_path
                ))
                logger.info(f"[AntiAnalysis] 生成 Frida 绕过脚本: {script_path}")
        
        if debugger_techniques or integrity_techniques:
            ld_preload_code = self._generate_ld_preload(debugger_techniques, integrity_techniques)
            if ld_preload_code:
                script_path = os.path.join(output_dir, 'libbypass.c')
                with open(script_path, 'w', encoding='utf-8') as f:
                    f.write(ld_preload_code)
                
                self.bypass_scripts.append(BypassScript(
                    script_type='ld_preload',
                    name='libbypass',
                    content=ld_preload_code,
                    file_path=script_path
                ))
                logger.info(f"[AntiAnalysis] 生成 LD_PRELOAD 绕过源码: {script_path}")
        
        gdb_script = self._generate_gdb_script(debugger_techniques)
        if gdb_script:
            script_path = os.path.join(output_dir, 'bypass.gdb')
            with open(script_path, 'w', encoding='utf-8') as f:
                f.write(gdb_script)
            
            self.bypass_scripts.append(BypassScript(
                script_type='gdb_script',
                name='bypass_gdb',
                content=gdb_script,
                file_path=script_path
            ))
            logger.info(f"[AntiAnalysis] 生成 GDB 绕过脚本: {script_path}")
        
        for technique in self.detected_techniques:
            technique.bypass_status = 'generated'
            technique.bypass_suggestion = self._get_bypass_suggestion(technique)
        
        logger.info(f"[AntiAnalysis] 绕过脚本生成完成，共 {len(self.bypass_scripts)} 个")
        return self.bypass_scripts
    
    def _generate_frida_script(self, techniques: List[AntiAnalysisTechnique]) -> str:
        """
        生成 Frida 绕过脚本
        """
        script_parts = [
            '// Frida bypass script generated by Deemo',
            '// Target: Anti-debugging bypass',
            '',
            'console.log("[+] Loading anti-debug bypass script...");',
            ''
        ]
        
        need_ptrace_hook = any(t.name == 'ptrace' for t in techniques)
        need_getppid_hook = any(t.name == 'getppid' for t in techniques)
        need_isdebugger_hook = any(t.name in ['IsDebuggerPresent', 'NtQueryInformationProcess'] for t in techniques)
        
        if need_ptrace_hook:
            script_parts.extend([
                '// Hook ptrace to prevent debugger detection',
                'Interceptor.attach(Module.findExportByName(null, "ptrace"), {',
                '    onEnter: function(args) {',
                '        console.log("[+] ptrace called");',
                '    },',
                '    onLeave: function(retval) {',
                '        retval.replace(-1); // EPERM',
                '        console.log("[+] ptrace bypassed");',
                '    }',
                '});',
                ''
            ])
        
        if need_getppid_hook:
            script_parts.extend([
                '// Hook getppid to return non-debugger parent',
                'Interceptor.attach(Module.findExportByName(null, "getppid"), {',
                '    onLeave: function(retval) {',
                '        retval.replace(1); // Return init PID',
                '        console.log("[+] getppid bypassed");',
                '    }',
                '});',
                ''
            ])
        
        if need_isdebugger_hook:
            script_parts.extend([
                '// Hook IsDebuggerPresent',
                'Interceptor.attach(Module.findExportByName("kernel32.dll", "IsDebuggerPresent"), {',
                '    onLeave: function(retval) {',
                '        retval.replace(ptr("0x0")); // Return false',
                '        console.log("[+] IsDebuggerPresent bypassed");',
                '    }',
                '});',
                ''
            ])
        
        script_parts.extend([
            '// Hook NtQueryInformationProcess',
            'Interceptor.attach(Module.findExportByName("ntdll.dll", "NtQueryInformationProcess"), {',
            '    onEnter: function(args) {',
            '        var ProcessDebugPort = 0x7;',
            '        if (args[1].toInt32() === ProcessDebugPort) {',
            '            this.hook = true;',
            '        }',
            '    },',
            '    onLeave: function(retval) {',
            '        if (this.hook) {',
            '            retval.replace(0);',
            '            console.log("[+] NtQueryInformationProcess bypassed");',
            '        }',
            '    }',
            '});',
            '',
            'console.log("[+] Anti-debug bypass script loaded successfully!");'
        ])
        
        return '\n'.join(script_parts)
    
    def _generate_ld_preload(self, debugger_techniques: List[AntiAnalysisTechnique], 
                            integrity_techniques: List[AntiAnalysisTechnique]) -> str:
        """
        生成 LD_PRELOAD 绕过库源码
        """
        code_parts = [
            '/* LD_PRELOAD bypass library generated by Deemo */',
            '#define _GNU_SOURCE',
            '#include <dlfcn.h>',
            '#include <sys/ptrace.h>',
            '#include <unistd.h>',
            '#include <stdio.h>',
            '#include <stdint.h>',
            '',
            'static int (*real_ptrace)(int, pid_t, void *, void *);',
            'static pid_t (*real_getppid)(void);',
            '',
            'void _init(void) {',
            '    real_ptrace = dlsym(RTLD_NEXT, "ptrace");',
            '    real_getppid = dlsym(RTLD_NEXT, "getppid");',
            '    fprintf(stderr, "[+] Bypass library loaded\\n");',
            '}',
            '',
            'int ptrace(int request, pid_t pid, void *addr, void *data) {',
            '    fprintf(stderr, "[+] ptrace intercepted: request=%d\\n", request);',
            '    if (request == PTRACE_ATTACH || request == PTRACE_TRACEME) {',
            '        fprintf(stderr, "[+] ptrace bypassed\\n");',
            '        return -1; // EPERM',
            '    }',
            '    return real_ptrace(request, pid, addr, data);',
            '}',
            '',
            'pid_t getppid(void) {',
            '    fprintf(stderr, "[+] getppid intercepted\\n");',
            '    return 1; // Return init PID',
            '}',
            '',
            '/* Compile: gcc -shared -fPIC -o libbypass.so libbypass.c -ldl */'
        ]
        
        return '\n'.join(code_parts)
    
    def _generate_gdb_script(self, techniques: List[AntiAnalysisTechnique]) -> str:
        """
        生成 GDB 绕过脚本
        """
        script_parts = [
            '# GDB bypass script generated by Deemo',
            '# Usage: gdb -x bypass.gdb target_binary',
            '',
            'set disassembly-flavor intel',
            'set print pretty on',
            '',
            '# Bypass ptrace',
            'break ptrace',
            'commands',
            '    silent',
            '    set $rax = -1',
            '    continue',
            'end',
            '',
            '# Bypass getppid',
            'break getppid',
            'commands',
            '    silent',
            '    set $rax = 1',
            '    continue',
            'end',
            '',
            '# Disable breakpoints on int3 instructions',
            'set breakpoint pending on',
            'handle SIGTRAP nostop noprint pass',
            '',
            'echo [+] Bypass script loaded\\n',
            'run'
        ]
        
        return '\n'.join(script_parts)
    
    def _get_bypass_suggestion(self, technique: AntiAnalysisTechnique) -> str:
        """
        获取绕过建议
        """
        suggestions = {
            'ptrace': '使用 Frida 或 LD_PRELOAD 钩取 ptrace 函数返回 -1',
            'getppid': '钩取 getppid 返回 1（init PID）',
            'IsDebuggerPresent': '钩取返回 false',
            'NtQueryInformationProcess': '钩取 ProcessDebugPort 查询返回 0',
            'vm_detection': '使用 VM-aware 调试工具或修改检测代码',
            'integrity_check': '使用 Frida 禁用校验或手动 patch 校验代码',
            'timing_check': '使用调试器忽略时间检查或使用 TSX/NMI 旁路',
            'obfuscation': '使用反混淆工具如 Unicorn, BinaryNinja 等'
        }
        
        return suggestions.get(technique.name, '需要手动分析')
    
    def get_bypass_commands(self) -> List[str]:
        """
        获取绕过命令建议
        """
        commands = []
        
        if any(s.script_type == 'frida' for s in self.bypass_scripts):
            commands.append('frida -U -f ./target_binary -l bypass/bypass_debugger.js')
        
        if any(s.script_type == 'ld_preload' for s in self.bypass_scripts):
            commands.append('LD_PRELOAD=./bypass/libbypass.so ./target_binary')
        
        if any(s.script_type == 'gdb_script' for s in self.bypass_scripts):
            commands.append('gdb -x bypass/bypass.gdb ./target_binary')
        
        if any(t.technique_type == 'timing_check' for t in self.detected_techniques):
            commands.append('strace -o /dev/null ./target_binary  # 伪装系统调用')
        
        return commands
    
    def analyze(self) -> Dict[str, Any]:
        """
        执行完整的反分析检测
        
        Returns:
            包含检测结果的字典
        """
        logger.info("[AntiAnalysis] 执行完整的反分析检测")
        
        result = {
            'detected_techniques': [
                {
                    'technique_type': t.technique_type,
                    'name': t.name,
                    'location': t.location,
                    'address': t.address,
                    'severity': t.severity,
                    'description': t.description,
                    'bypass_status': t.bypass_status,
                    'bypass_suggestion': t.bypass_suggestion
                }
                for t in self.detected_techniques
            ],
            'bypass_scripts': [
                {
                    'script_type': s.script_type,
                    'name': s.name,
                    'file_path': s.file_path,
                    'applicable': s.applicable
                }
                for s in self.bypass_scripts
            ],
            'bypass_commands': self.get_bypass_commands(),
            'summary': {
                'total_techniques': len(self.detected_techniques),
                'debugger_detection_count': len([t for t in self.detected_techniques 
                                               if t.technique_type == 'debugger_detection']),
                'vm_detection_count': len([t for t in self.detected_techniques 
                                          if t.technique_type == 'vm_detection']),
                'integrity_check_count': len([t for t in self.detected_techniques 
                                             if t.technique_type == 'integrity_check']),
                'timing_check_count': len([t for t in self.detected_techniques 
                                           if t.technique_type == 'timing_check']),
                'obfuscation_count': len([t for t in self.detected_techniques 
                                          if t.technique_type == 'obfuscation']),
                'bypass_scripts_generated': len(self.bypass_scripts)
            }
        }
        
        return result


def detect_anti_analysis(pseudocode: str, binary_info: Dict[str, Any] = None, 
                         generate_bypass: bool = False, output_dir: str = './bypass') -> Dict[str, Any]:
    """
    便捷函数：执行反分析检测
    
    Args:
        pseudocode: 反编译后的伪代码
        binary_info: 二进制文件信息
        generate_bypass: 是否生成绕过脚本
        output_dir: 绕过脚本输出目录
    
    Returns:
        检测结果字典
    """
    detector = AntiAnalysisDetector(pseudocode, binary_info)
    
    if generate_bypass:
        detector.generate_bypass_scripts(output_dir)
    
    return detector.analyze()