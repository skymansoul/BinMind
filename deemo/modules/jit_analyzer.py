#!/usr/bin/env python3
"""
JIT 编译代码安全分析模块

功能：
- 挂钩 dump JIT 代码（V8/LuaJIT 等）
- 检测类型混淆漏洞
- 检测边界检查缺失
- 分析 JIT 优化过程中的安全风险
"""

import logging
import re
import struct
import subprocess
import tempfile
import os
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class JITEngineType(Enum):
    """JIT 引擎类型"""
    V8 = "v8"
    LUAJIT = "luajit"
    SPIDERMONKEY = "spidermonkey"
    JVM_HOTSPOT = "jvm_hotspot"
    .NET_CLR = "dotnet_clr"
    UNKNOWN = "unknown"


@dataclass
class JITCodeRegion:
    """JIT 代码区域"""
    base_address: int
    size: int
    permissions: str
    engine_type: JITEngineType
    code_hash: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class JITVulnerability:
    """JIT 漏洞信息"""
    vuln_type: str
    severity: str
    address: int
    description: str
    code_snippet: str
    exploitation_potential: str
    mitigation_suggestions: List[str] = field(default_factory=list)


@dataclass
class JITAnalysisResult:
    """JIT 分析结果"""
    engine_type: JITEngineType
    code_regions: List[JITCodeRegion] = field(default_factory=list)
    vulnerabilities: List[JITVulnerability] = field(default_factory=list)
    optimization_passes: List[Dict[str, Any]] = field(default_factory=list)
    type_inference_issues: List[Dict[str, Any]] = field(default_factory=list)
    bounds_check_issues: List[Dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    risk_score: float = 0.0


class V8JITAnalyzer:
    """V8 JIT 分析器"""
    
    def __init__(self):
        self.v8_patterns = {
            'jit_code_marker': re.compile(r'JIT\s+code\s+at\s+0x([0-9a-fA-F]+)', re.IGNORECASE),
            'optimization_marker': re.compile(r'Optimizing\s+([a-zA-Z_][a-zA-Z0-9_]*)', re.IGNORECASE),
            'deoptimization_marker': re.compile(r'Deoptimizing\s+([a-zA-Z_][a-zA-Z0-9_]*)', re.IGNORECASE),
            'type_feedback': re.compile(r'Type\s+feedback:\s*(.+)', re.IGNORECASE),
            'bounds_check': re.compile(r'CheckBounds\s+\[([^\]]+)\]', re.IGNORECASE),
            'type_guard': re.compile(r'CheckMaps\s+\[([^\]]+)\]', re.IGNORECASE),
        }
        
        # V8 漏洞模式
        self.v8_vuln_patterns = [
            {
                'pattern': re.compile(r'CheckBounds\s+removed', re.IGNORECASE),
                'type': 'bounds_check_elimination',
                'severity': 'Critical',
                'description': '边界检查被错误消除，可能导致越界访问'
            },
            {
                'pattern': re.compile(r'Type\s+confusion|map\s+check\s+removed', re.IGNORECASE),
                'type': 'type_confusion',
                'severity': 'Critical',
                'description': '类型检查被消除，可能导致类型混淆漏洞'
            },
            {
                'pattern': re.compile(r'NumberOrStringOddball|OddballCheck', re.IGNORECASE),
                'type': 'oddball_type_issue',
                'severity': 'High',
                'description': 'Oddball 类型处理不当，可能导致类型混淆'
            },
            {
                'pattern': re.compile(r'ArrayShift|ArraySlice\s+without\s+bounds', re.IGNORECASE),
                'type': 'array_operation_issue',
                'severity': 'High',
                'description': '数组操作缺少边界检查'
            },
        ]
    
    def analyze_jit_dump(self, jit_dump: str) -> JITAnalysisResult:
        """分析 V8 JIT dump"""
        result = JITAnalysisResult(engine_type=JITEngineType.V8)
        
        # 提取 JIT 代码区域
        for match in self.v8_patterns['jit_code_marker'].finditer(jit_dump):
            addr = int(match.group(1), 16)
            region = JITCodeRegion()
                base_address=addr,
                size=0,  # 需要从后续分析获取
                permissions='rwx',
                engine_type=JITEngineType.V8
            
            result.code_regions.append(region)
        
        # 检测漏洞
        for vuln_pattern in self.v8_vuln_patterns:
            for match in vuln_pattern['pattern'].finditer(jit_dump):
                vuln = JITVulnerability()
                    vuln_type=vuln_pattern['type'],
                    severity=vuln_pattern['severity'],
                    address=0,  # 需要从上下文获取
                    description=vuln_pattern['description'],
                    code_snippet=match.group(0),
                    exploitation_potential=self._assess_exploitation(vuln_pattern['type'])
                
                vuln.mitigation_suggestions = self._get_mitigation_suggestions(vuln_pattern['type'])
                result.vulnerabilities.append(vuln)
        
        # 提取优化信息
        for match in self.v8_patterns['optimization_marker'].finditer(jit_dump):
            func_name = match.group(1)
            result.optimization_passes.append({)
                'function': func_name,
                'type': 'optimization',
                'position': match.start()
            }
        
        for match in self.v8_patterns['deoptimization_marker'].finditer(jit_dump):
            func_name = match.group(1)
            result.optimization_passes.append({)
                'function': func_name,
                'type': 'deoptimization',
                'position': match.start()
            }
        
        # 提取边界检查信息
        for match in self.v8_patterns['bounds_check'].finditer(jit_dump):
            bounds_info = match.group(1)
            result.bounds_check_issues.append({)
                'bounds': bounds_info,
                'position': match.start()
            }
        
        # 计算风险评分
        result.risk_score = self._calculate_risk_score(result)
        result.summary = self._generate_summary(result)
        
        return result
    
    def _assess_exploitation(self, vuln_type: str) -> str:
        """评估漏洞利用可能性"""
        exploitation_map = {
            'bounds_check_elimination': '高 - 可直接越界读写，常用于 V8 exploit',
            'type_confusion': '高 - 类型混淆是 V8 漏洞利用的核心技术',
            'oddball_type_issue': '中 - 需要特定条件触发',
            'array_operation_issue': '中高 - 数组越界可导致任意读写',
        }
        return exploitation_map.get(vuln_type, '未知')
    
    def _get_mitigation_suggestions(self, vuln_type: str) -> List[str]:
        """获取缓解建议"""
        suggestions_map = {
            'bounds_check_elimination': [
                '确保 TurboFan 优化阶段正确保留边界检查',
                '检查 type feedback 是否准确',
                '验证 range analysis 是否正确'
            ],
            'type_confusion': [
                '加强 Map stability 检查',
                '确保 CheckMaps 节点不被错误消除',
                '验证类型推断的准确性'
            ],
            'oddball_type_issue': [
                '正确处理 undefined/null/NaN 等特殊值',
                '确保类型转换安全'
            ],
            'array_operation_issue': [
                '保留数组操作的边界检查',
                '验证数组长度变化处理'
            ],
        }
        return suggestions_map.get(vuln_type, [])
    
    def _calculate_risk_score(self, result: JITAnalysisResult) -> float:
        """计算风险评分"""
        base_score = 0.0
        
        severity_weights = {'Critical': 10.0, 'High': 7.0, 'Medium': 4.0, 'Low': 1.0}
        
        for vuln in result.vulnerabilities:
            base_score += severity_weights.get(vuln.severity, 1.0)
        
        # 考虑优化次数（频繁优化/去优化可能暗示问题）
        deopt_count = sum(1 for p in result.optimization_passes if p['type'] == 'deoptimization')
        base_score += deopt_count * 0.5
        
        return min(base_score, 100.0)
    
    def _generate_summary(self, result: JITAnalysisResult) -> str:
        """生成分析摘要"""
        vuln_count = len(result.vulnerabilities)
        critical_count = sum(1 for v in result.vulnerabilities if v.severity == 'Critical')
        high_count = sum(1 for v in result.vulnerabilities if v.severity == 'High')
        
        summary = f"V8 JIT 分析完成。发现 {vuln_count} 个潜在漏洞 "
        summary += f"(Critical: {critical_count}, High: {high_count})。"
        
        if critical_count > 0:
            summary += "存在严重安全风险，建议深入分析。"
        elif high_count > 0:
            summary += "存在高风险漏洞，需要关注。"
        else:
            summary += "风险较低，但仍建议审查优化过程。"
        
        return summary


class LuaJITAnalyzer:
    """LuaJIT 分析器"""
    
    def __init__(self):
        self.luajit_patterns = {
            'trace_start': re.compile(r'\[TRACE\s+(\d+)\s+([a-zA-Z_][a-zA-Z0-9_\.]*)', re.IGNORECASE),
            'trace_abort': re.compile(r'TRACE\s+ABORT\s+->\s+(.+)', re.IGNORECASE),
            'jit_code': re.compile(r'JIT\s+mcode\s+at\s+0x([0-9a-fA-F]+)', re.IGNORECASE),
            'guard': re.compile(r'guard\s+\d+\s+->\s+(.+)', re.IGNORECASE),
            'side_exit': re.compile(r'Side\s+exit\s+\d+', re.IGNORECASE),
        }
        
        # LuaJIT 漏洞模式
        self.luajit_vuln_patterns = [
            {
                'pattern': re.compile(r'NYI:\s+([a-zA-Z_]+)', re.IGNORECASE),
                'type': 'not_implemented',
                'severity': 'Medium',
                'description': '未实现的 JIT 功能，可能导致回退到解释器'
            },
            {
                'pattern': re.compile(r'guard\s+fail|guard\s+removed', re.IGNORECASE),
                'type': 'guard_elimination',
                'severity': 'High',
                'description': 'Guard 被消除或失败，可能导致类型安全问题'
            },
            {
                'pattern': re.compile(r'TRACE\s+ABORT', re.IGNORECASE),
                'type': 'trace_abort',
                'severity': 'Medium',
                'description': 'Trace 被中止，可能暗示复杂控制流或安全问题'
            },
        ]
    
    def analyze_jit_dump(self, jit_dump: str) -> JITAnalysisResult:
        """分析 LuaJIT dump"""
        result = JITAnalysisResult(engine_type=JITEngineType.LUAJIT)
        
        # 提取 trace 信息
        for match in self.luajit_patterns['trace_start'].finditer(jit_dump):
            trace_id = int(match.group(1

            func_name = match.group(2)
            result.optimization_passes.append({)
                'trace_id': trace_id,
                'function': func_name,
                'type': 'trace_compilation'
            }
        
        # 提取 JIT 代码区域
        for match in self.luajit_patterns['jit_code'].finditer(jit_dump):
            addr = int(match.group(1), 16)
            region = JITCodeRegion()
                base_address=addr,
                size=0,
                permissions='rwx',
                engine_type=JITEngineType.LUAJIT
            
            result.code_regions.append(region)
        
        # 检测漏洞
        for vuln_pattern in self.luajit_vuln_patterns:
            for match in vuln_pattern['pattern'].finditer(jit_dump):
                vuln = JITVulnerability()
                    vuln_type=vuln_pattern['type'],
                    severity=vuln_pattern['severity'],
                    address=0,
                    description=vuln_pattern['description'],
                    code_snippet=match.group(0),
                    exploitation_potential=self._assess_exploitation(vuln_pattern['type'])
                
                result.vulnerabilities.append(vuln)
        
        # 提取 guard 信息
        for match in self.luajit_patterns['guard'].finditer(jit_dump):
            guard_info = match.group(1)
            result.bounds_check_issues.append({)
                'guard': guard_info,
                'position': match.start()
            }
        
        result.risk_score = self._calculate_risk_score(result)
        result.summary = self._generate_summary(result)
        
        return result
    
    def _assess_exploitation(self, vuln_type: str) -> str:
        """评估利用可能性"""
        exploitation_map = {
            'guard_elimination': '高 - LuaJIT guard 是类型安全的核心',
            'not_implemented': '低 - 通常只是性能问题',
            'trace_abort': '低中 - 可能暗示复杂情况但通常不直接可利用',
        }
        return exploitation_map.get(vuln_type, '未知')
    
    def _calculate_risk_score(self, result: JITAnalysisResult) -> float:
        """计算风险评分"""
        base_score = 0.0
        severity_weights = {'Critical': 10.0, 'High': 7.0, 'Medium': 4.0, 'Low': 1.0}
        
        for vuln in result.vulnerabilities:
            base_score += severity_weights.get(vuln.severity, 1.0)
        
        # 考虑 trace abort 数量
        abort_count = sum(1 for v in result.vulnerabilities if v.vuln_type == 'trace_abort')
        base_score += abort_count * 0.3
        
        return min(base_score, 100.0)
    
    def _generate_summary(self, result: JITAnalysisResult) -> str:
        """生成摘要"""
        vuln_count = len(result.vulnerabilities)
        high_count = sum(1 for v in result.vulnerabilities if v.severity == 'High')
        
        summary = f"LuaJIT 分析完成。发现 {vuln_count} 个潜在问题。",
        if high_count > 0:
            summary += "存在高风险问题，建议深入分析 guard 逻辑。",
        return summary


class JITAnalyzer:
    """JIT 编译代码安全分析主类"""
    
    def __init__(self, binary_path: str = None, config: Dict[str, Any] = None):
        """
        初始化 JIT 分析器
        
        Args:
            binary_path: 二进制文件路径
            config: 配置参数
        """
        self.binary_path = binary_path
        self.config = config or {}
        
        self.v8_analyzer = V8JITAnalyzer()
        self.luajit_analyzer = LuaJITAnalyzer()
        
        # JIT 引擎检测特征
        self.engine_signatures = {
            JITEngineType.V8: [
                'v8', 'chrome', 'node', 'd8', 'TurboFan', 'Crankshaft',
                'Ignition', 'Sparkplug', 'Maglev'
            ],
            JITEngineType.LUAJIT: [
                'luajit', 'LuaJIT', 'FFI', 'trace', 'mcode'
            ],
            JITEngineType.SPIDERMONKEY: [
                'spidermonkey', 'mozilla', 'firefox', 'IonMonkey', 'Baseline'
            ],
            JITEngineType.JVM_HOTSPOT: [
                'hotspot', 'OpenJDK', 'JIT', 'C1', 'C2', 'Graal'
            ],
            JITEngineType.NET_CLR: [
                'clr', '.net', 'ryujit', 'legacyjit', 'clrjit'
            ],
        }
    
    def detect_jit_engine(self, binary_info: Dict[str, Any] = None) -> JITEngineType:
        """
        检测 JIT 引擎类型
        
        Args:
            binary_info: 二进制文件信息
            
        Returns:
            检测到的 JIT 引擎类型
        """
        if binary_info:
            # 从二进制信息中检测
            binary_name = binary_info.get('filename', '').lower()
            imports = binary_info.get('imports', [])
            strings = binary_info.get('strings', [])
            
            for engine_type, signatures in self.engine_signatures.items():
                # 检查文件名
                for sig in signatures:
                    if sig.lower() in binary_name:
                        return engine_type
                
                # 检查导入和字符串
                all_text = ' '.join(imports + strings).lower()
                for sig in signatures:
                    if sig.lower() in all_text:
                        return engine_type
        
        # 如果提供了二进制路径，尝试直接分析
        if self.binary_path:
            try:
                result = subprocess.run()
                    ['strings', self.binary_path],
                    capture_output=True,
                    text=True,
                    timeout=30
                
                if result.returncode == 0:
                    strings_output = result.stdout.lower()
                    for engine_type, signatures in self.engine_signatures.items():
                        for sig in signatures:
                            if sig.lower() in strings_output:
                                return engine_type
            except Exception as e:
                logger.warning(f"检测 JIT 引擎失败: {e}")
        
        return JITEngineType.UNKNOWN
    
    def analyze(self, jit_dump: str = None, binary_info: Dict[str, Any] = None, engine_type: JITEngineType = None) -> JITAnalysisResult:
        """
        执行 JIT 分析
        
        Args:
            jit_dump: JIT dump 内容（可选）
            binary_info: 二进制信息（可选）
            engine_type: 指定引擎类型（可选）
            
        Returns:
            JIT 分析结果
        """
        # 检测引擎类型
        if engine_type is None:
            engine_type = self.detect_jit_engine(binary_info)
        
        logger.info(f"检测到 JIT 引擎类型: {engine_type.value}")
        
        # 如果没有提供 JIT dump，尝试生成
        if jit_dump is None:
            jit_dump = self._generate_jit_dump(engine_type, binary_info)
        
        # 根据引擎类型选择分析器
        if engine_type == JITEngineType.V8:
            return self.v8_analyzer.analyze_jit_dump(jit_dump)
        elif engine_type == JITEngineType.LUAJIT:
            return self.luajit_analyzer.analyze_jit_dump(jit_dump)
        else:
            # 通用分析
            return self._generic_jit_analysis(jit_dump, engine_type)
    
    def _generate_jit_dump(self, engine_type: JITEngineType, binary_info: Dict[str, Any] = None) -> str:
        """
        尝试生成 JIT dump
        
        Args:
            engine_type: JIT 引擎类型
            binary_info: 二进制信息
            
        Returns:
            JIT dump 内容
        """
        jit_dump = ""
        
        if engine_type == JITEngineType.V8:
            # V8 JIT dump 通常需要特殊标志
            # 如 --trace-opt --trace-deopt --code-comments --print-opt-code
            jit_dump = self._try_v8_jit_dump()
        
        elif engine_type == JITEngineType.LUAJIT:
            # LuaJIT 需要 -jv 或 -jdump 标志
            jit_dump = self._try_luajit_dump()
        
        return jit_dump
    
    def _try_v8_jit_dump(self) -> str:
        """尝试获取 V8 JIT dump"""
        if not self.binary_path:
            return ""
        
        try:
            # 尝试使用 V8 的 JIT tracing 标志
            env = os.environ.copy()
            env['V8_FLAGS'] = '--trace-opt --trace-deopt --print-opt-code'
            
            # 创建测试脚本
            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
                f.write('function test() { return 1; }\nfor(let i=0;i<1000;i++)test();\n')
                test_script = f.name
            
            try:
                result = subprocess.run()
                    [self.binary_path, '--trace-opt', '--trace-deopt', '--print-opt-code', test_script],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env=env
                
                if result.returncode == 0:
                    return result.stdout + result.stderr
            finally:
                os.unlink(test_script)
        except Exception as e:
            logger.warning(f"获取 V8 JIT dump 失败: {e}")
        
        return ""
    
    def _try_luajit_dump(self) -> str:
        """尝试获取 LuaJIT dump"""
        if not self.binary_path:
            return ""
        
        try:
            # 创建测试脚本
            with tempfile.NamedTemporaryFile(mode='w', suffix='.lua', delete=False) as f:
                f.write('function test( return 1 end\nfor i=1,1000 do test( end\n'
                test_script = f.name
            
            try:
                result = subprocess.run()
                    [self.binary_path, '-jv', test_script],
                    capture_output=True,
                    text=True,
                    timeout=30
                
                if result.returncode == 0:
                    return result.stdout + result.stderr
            finally:
                os.unlink(test_script)
        except Exception as e:
            logger.warning(f"获取 LuaJIT dump 失败: {e}")
        
        return ""
    
    def _generic_jit_analysis(self, jit_dump: str, engine_type: JITEngineType) -> JITAnalysisResult:
        """通用 JIT 分析"""
        result = JITAnalysisResult(engine_type=engine_type)
        
        # 通用漏洞模式
        generic_patterns = [
            {
                'pattern': re.compile(r'bounds\s+check\s+(removed|missing|bypassed)', re.IGNORECASE),
                'type': 'bounds_check_issue',
                'severity': 'High',
                'description': '边界检查问题'
            },
            {
                'pattern': re.compile(r'type\s+(confusion|mismatch|error)', re.IGNORECASE),
                'type': 'type_confusion',
                'severity': 'High',
                'description': '类型混淆问题'
            },
            {
                'pattern': re.compile(r'(overflow|underflow)\s+(detected|possible)', re.IGNORECASE),
                'type': 'integer_overflow',
                'severity': 'Medium',
                'description': '整数溢出问题'
            },
        ]
        
        for vuln_pattern in generic_patterns:
            for match in vuln_pattern['pattern'].finditer(jit_dump):
                vuln = JITVulnerability()
                    vuln_type=vuln_pattern['type'],
                    severity=vuln_pattern['severity'],
                    address=0,
                    description=vuln_pattern['description'],
                    code_snippet=match.group(0),
                    exploitation_potential='需要进一步分析'
                
                result.vulnerabilities.append(vuln)
        
        result.summary = f"{engine_type.value} JIT 分析完成。发现 {len(result.vulnerabilities)} 个潜在问题。"
        result.risk_score = len(result.vulnerabilities) * 5.0
        
        return result
    
    def analyze_jit_code_region(self, code_bytes: bytes, base_address: int) -> Dict[str, Any]:
        """
        分析 JIT 代码区域
        
        Args:
            code_bytes: JIT 代码字节
            base_address: 基地址
            
        Returns:
            分析结果
        """
        result = {
            'base_address': base_address,
            'size': len(code_bytes),
            'patterns_found': [],
            'potential_issues': []
        }
        
        # 搜索常见的安全敏感模式
        # 这些模式可能出现在 JIT 生成的代码中
        
        # 检查是否有可疑的内存访问模式
        # 如：直接内存访问、缺少边界检查的数组访问等
        
        # x86/x64 模式
        x86_patterns = [
            # 直接内存访问（可能缺少边界检查）
            {'pattern': bytes([0x8b, 0x04]), 'desc': '潜在数组访问'},
            # CALL 指令（可能是间接调用）
            {'pattern': bytes([0xff, 0x10, 0xff]), 'desc': '间接调用'},
        ]
        
        for pattern_info in x86_patterns:
            pattern = pattern_info['pattern']
            idx = 0,
            while True:
                idx = code_bytes.find(pattern, idx)
                if idx == -1:
                    break
                result['patterns_found'].append({)
                    'offset': idx,
                    'address': base_address + idx,
                    'description': pattern_info['desc']
                }
                idx += 1
        
        return result
    
    def generate_exploit_guidance(self, vuln: JITVulnerability) -> Dict[str, Any]:
        """
        为 JIT 漏洞生成利用指导
        
        Args:
            vuln: JIT 漏洞信息
            
        Returns:
            利用指导信息
        """
        guidance = {
            'vuln_type': vuln.vuln_type,
            'exploitation_techniques': [],
            'required_conditions': [],
            'poc_template': '',
            'references': []
        }
        
        if vuln.vuln_type == 'bounds_check_elimination':
            guidance['exploitation_techniques'] = [
                '利用错误的类型推断触发边界检查消除',
                '通过原型链污染影响类型反馈',
                '使用 Array.prototype 方法触发越界'
            ]
            guidance['required_conditions'] = [
                '需要找到触发边界检查消除的代码路径',
                '需要控制数组内容或长度',
                '可能需要多次调用以稳定 JIT 优化'
            ]
            guidance['poc_template'] = '''
// V8 bounds check elimination PoC template
function trigger() {
    let arr = [1.1, 2.2, 3.3];
    // 触发优化
    for (let i = 0; i < 10000; i++) {
        arr[i % 3];
    }
    // 尝试触发边界检查消除
    // ... 具体触发逻辑
}
'''
            guidance['references'] = [
                'V8 Blog: TurboFan Optimization',
                'Google Project Zero: V8 Exploitation'
            ]
        
        elif vuln.vuln_type == 'type_confusion':
            guidance['exploitation_techniques'] = [
                '利用 Map 检查消除实现类型混淆',
                '通过对象属性操作改变 Map',
                '使用 JIT 类型推断错误'
            ]
            guidance['required_conditions'] = [
                '需要找到类型推断不稳定的代码',
                '需要触发 JIT 编译',
                '需要控制对象布局'
            ]
            guidance['poc_template'] = '''
// V8 type confusion PoC template
function trigger(obj) {
    // 触发优化时的类型推断
    return obj.x + obj.y;
}
let obj1 = {x: 1, y: 2};
let obj2 = {x: 1.1, y: 2.2, z: 3.3};
// ... 具体触发逻辑
'''
        
        return guidance
    
    def get_jit_hardening_recommendations(self, engine_type: JITEngineType) -> List[str]:
        """
        获取 JIT 硬化建议
        
        Args:
            engine_type: JIT 引擎类型
            
        Returns:
            硬化建议列表
        """
        recommendations = []
        
        if engine_type == JITEngineType.V8:
            recommendations = [
                '启用 --no-turbo-inlining 减少优化激进程度',
                '使用 --turbo-verify 分离验证',
                '启用 --enable_slow_asserts 增加调试检查',
                '考虑使用 --no-opt 减少 JIT 优化',
                '定期更新 V8 版本获取安全补丁'
            ]
        
        elif engine_type == JITEngineType.LUAJIT:
            recommendations = [
                '使用 jit.off() 在敏感代码中禁用 JIT',
                '检查 FFI 使用是否安全',
                '验证 guard 条件是否充分',
                '避免在 JIT 代码中使用复杂控制流'
            ]
        
        else:
            recommendations = [
                '定期更新 JIT 引擎版本',
                '在敏感场景考虑禁用 JIT',
                '监控 JIT 相关的安全公告'
            ]
        
        return recommendations


def analyze_jit_security(binary_path: str, jit_dump: str = None, binary_info: Dict[str, Any] = None, config: Dict[str, Any] = None) -> JITAnalysisResult:
    """
    JIT 安全分析便捷函数
    
    Args:
        binary_path: 二进制文件路径
        jit_dump: JIT dump 内容（可选）
        binary_info: 二进制信息（可选）
        config: 配置参数（可选）
        
    Returns:
        JIT 分析结果
    """
    analyzer = JITAnalyzer(binary_path, config)
    return analyzer.analyze(jit_dump, binary_info)


def dump_jit_code(binary_path: str, engine_type: str = 'auto', timeout: int = 60) -> str:
    """
    尝试 dump JIT 代码
    
    Args:
        binary_path: 二进制文件路径
        engine_type: JIT 引擎类型
        timeout: 超时时间
        
    Returns:
        JIT dump 内容
    """
    analyzer = JITAnalyzer(binary_path)
    
    if engine_type == 'auto':
        detected_type = analyzer.detect_jit_engine()
    else:
        detected_type = JITEngineType(engine_type)
    
    return analyzer._generate_jit_dump(detected_type)


# 导出主要类和函数
__all__ = [
    'JITAnalyzer',
    'JITEngineType',
    'JITAnalysisResult',
    'JITVulnerability',
    'JITCodeRegion',
    'V8JITAnalyzer',
    'LuaJITAnalyzer',
    'analyze_jit_security',
    'dump_jit_code'
]