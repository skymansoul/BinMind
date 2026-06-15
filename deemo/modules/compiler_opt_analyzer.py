#!/usr/bin/env python3
"""
编译器优化与安全影响分析模块
"""

import logging
import subprocess
import os
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import json

logger = logging.getLogger(__name__)


class CompilerType(Enum):
    GCC = "GCC"
    CLANG = "Clang"
    MSVC = "MSVC"
    UNKNOWN = "Unknown"


class OptimizationLevel(Enum):
    NONE = "O0"
    O1 = "O1"
    O2 = "O2"
    O3 = "O3"
    OS = "Os"
    OFAST = "Ofast"
    UNKNOWN = "Unknown"


class SecurityRisk(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class OptimizationDetail:
    name: str
    enabled: bool
    security_risk: SecurityRisk
    description: str
    impact: str = ""


@dataclass
class CompilerOptAnalysisResult:
    compiler: CompilerType
    optimization_level: OptimizationLevel
    analysis_success: bool
    error_message: str = ""
    detected_flags: List[str] = field(default_factory=list)
    optimizations: List[OptimizationDetail] = field(default_factory=list)
    security_flags: List[str] = field(default_factory=list)
    missing_security_flags: List[str] = field(default_factory=list)
    overall_risk: SecurityRisk = SecurityRisk.LOW
    summary: str = ""

    def to_dict(self):
        return {
            'compiler': self.compiler.value,
            'optimization_level': self.optimization_level.value,
            'analysis_success': self.analysis_success,
            'error_message': self.error_message,
            'detected_flags': self.detected_flags,
            'optimizations': [{
                'name': opt.name,
                'enabled': opt.enabled,
                'security_risk': opt.security_risk.value,
                'description': opt.description,
                'impact': opt.impact
            } for opt in self.optimizations],
            'security_flags': self.security_flags,
            'missing_security_flags': self.missing_security_flags,
            'overall_risk': self.overall_risk.value,
            'summary': self.summary
        }


class CompilerOptAnalyzer:
    def __init__(self):
        self.gcc_opt_patterns = {
            'O0': r'-O0|\bO0\b',
            'O1': r'-O1|\bO1\b',
            'O2': r'-O2|\bO2\b',
            'O3': r'-O3|\bO3\b',
            'Os': r'-Os|\bOs\b',
            'Ofast': r'-Ofast|\bOfast\b'
        }
        
        self.security_flags = [
            ('-fstack-protector', '栈保护'),
            ('-fstack-protector-all', '全栈保护'),
            ('-fstack-protector-strong', '强化栈保护'),
            ('-Wl,-z,relro', 'RELRO 保护'),
            ('-Wl,-z,now', '立即绑定'),
            ('-fPIE', '位置独立可执行'),
            ('-pie', 'PIE 链接'),
            ('-fPIC', '位置独立代码'),
            ('-D_FORTIFY_SOURCE=2', 'FORTIFY_SOURCE'),
            ('-Wl,-z,noexecstack', '不可执行栈')
        ]
        
        self.optimization_details = [
            OptimizationDetail(
                name='inline',
                enabled=False,
                security_risk=SecurityRisk.LOW,
                description='函数内联优化',
                impact='可能暴露内部函数细节'
            ),
            OptimizationDetail(
                name='loop_unrolling',
                enabled=False,
                security_risk=SecurityRisk.LOW,
                description='循环展开优化',
                impact='增加代码大小，可能影响缓存行为'
            ),
            OptimizationDetail(
                name='dead_code_elimination',
                enabled=False,
                security_risk=SecurityRisk.LOW,
                description='死代码消除',
                impact='可能移除安全检查代码'
            ),
            OptimizationDetail(
                name='constant_propagation',
                enabled=False,
                security_risk=SecurityRisk.LOW,
                description='常量传播',
                impact='可能改变控制流分析结果'
            ),
            OptimizationDetail(
                name='optimize_sibling_calls',
                enabled=False,
                security_risk=SecurityRisk.MEDIUM,
                description='尾调用优化',
                impact='可能改变栈回溯行为'
            ),
            OptimizationDetail(
                name='merge_constants',
                enabled=False,
                security_risk=SecurityRisk.LOW,
                description='常量合并',
                impact='可能影响内存布局'
            ),
            OptimizationDetail(
                name='gcse',
                enabled=False,
                security_risk=SecurityRisk.LOW,
                description='全局公共子表达式消除',
                impact='可能影响调试信息'
            ),
            OptimizationDetail(
                name='lto',
                enabled=False,
                security_risk=SecurityRisk.MEDIUM,
                description='链接时优化',
                impact='可能改变代码布局和符号可见性'
            ),
            OptimizationDetail(
                name='flto',
                enabled=False,
                security_risk=SecurityRisk.MEDIUM,
                description='链接时优化（薄模式）',
                impact='可能影响代码优化程度'
            ),
            OptimizationDetail(
                name='ssp',
                enabled=False,
                security_risk=SecurityRisk.LOW,
                description='栈保护',
                impact='增加栈溢出防护'
            )
        ]

    def detect_compiler(self, binary_path: str) -> CompilerType:
        try:
            result = subprocess.run(
                ['strings', binary_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = result.stdout
            if 'GCC: (' in output:
                return CompilerType.GCC
            elif 'clang' in output.lower():
                return CompilerType.CLANG
            elif 'Microsoft' in output:
                return CompilerType.MSVC
        except Exception as e:
            logger.warning(f"编译器检测失败: {e}")
        
        return CompilerType.UNKNOWN

    def detect_optimization_level(self, binary_path: str) -> OptimizationLevel:
        try:
            result = subprocess.run(
                ['readelf', '-p', '.comment', binary_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = result.stdout
            for level, pattern in self.gcc_opt_patterns.items():
                import re
                if re.search(pattern, output):
                    if level == 'O0':
                        return OptimizationLevel.NONE
                    elif level == 'O1':
                        return OptimizationLevel.O1
                    elif level == 'O2':
                        return OptimizationLevel.O2
                    elif level == 'O3':
                        return OptimizationLevel.O3
                    elif level == 'Os':
                        return OptimizationLevel.OS
                    elif level == 'Ofast':
                        return OptimizationLevel.OFAST
        except Exception as e:
            logger.warning(f"优化级别检测失败: {e}")
        
        return OptimizationLevel.UNKNOWN

    def analyze_security_flags(self, binary_path: str) -> Dict[str, Any]:
        found_flags = []
        missing_flags = []
        
        try:
            result = subprocess.run(
                ['readelf', '-d', binary_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = result.stdout
            
            for flag, desc in self.security_flags:
                if flag in output or ('relro' in output.lower() and 'relro' in flag.lower()):
                    found_flags.append(flag)
                else:
                    missing_flags.append(flag)
        except Exception as e:
            logger.warning(f"安全标志分析失败: {e}")
        
        return {'found': found_flags, 'missing': missing_flags}

    def estimate_optimizations(self, opt_level: OptimizationLevel) -> List[OptimizationDetail]:
        optimizations = []
        
        for opt in self.optimization_details:
            opt_copy = OptimizationDetail(
                name=opt.name,
                enabled=False,
                security_risk=opt.security_risk,
                description=opt.description,
                impact=opt.impact
            )
            
            if opt_level == OptimizationLevel.NONE:
                opt_copy.enabled = False
            elif opt_level == OptimizationLevel.O1:
                if opt.name in ['dead_code_elimination', 'constant_propagation']:
                    opt_copy.enabled = True
            elif opt_level == OptimizationLevel.O2:
                if opt.name in ['inline', 'loop_unrolling', 'dead_code_elimination', 
                               'constant_propagation', 'gcse', 'merge_constants']:
                    opt_copy.enabled = True
            elif opt_level == OptimizationLevel.O3:
                if opt.name not in ['lto', 'flto']:
                    opt_copy.enabled = True
            elif opt_level == OptimizationLevel.OS:
                if opt.name in ['dead_code_elimination', 'merge_constants']:
                    opt_copy.enabled = True
            elif opt_level == OptimizationLevel.OFAST:
                opt_copy.enabled = True
            
            optimizations.append(opt_copy)
        
        return optimizations

    def calculate_overall_risk(self, optimizations: List[OptimizationDetail], 
                               security_flags: Dict[str, Any]) -> SecurityRisk:
        risk_score = 0
        
        for opt in optimizations:
            if opt.enabled:
                if opt.security_risk == SecurityRisk.CRITICAL:
                    risk_score += 4
                elif opt.security_risk == SecurityRisk.HIGH:
                    risk_score += 3
                elif opt.security_risk == SecurityRisk.MEDIUM:
                    risk_score += 2
                elif opt.security_risk == SecurityRisk.LOW:
                    risk_score += 1
        
        missing_count = len(security_flags.get('missing', []))
        risk_score += missing_count * 2
        
        if risk_score >= 15:
            return SecurityRisk.CRITICAL
        elif risk_score >= 10:
            return SecurityRisk.HIGH
        elif risk_score >= 5:
            return SecurityRisk.MEDIUM
        else:
            return SecurityRisk.LOW

    def analyze(self, binary_path: str) -> CompilerOptAnalysisResult:
        if not os.path.exists(binary_path):
            return CompilerOptAnalysisResult(
                compiler=CompilerType.UNKNOWN,
                optimization_level=OptimizationLevel.UNKNOWN,
                analysis_success=False,
                error_message="文件不存在"
            )
        
        try:
            compiler = self.detect_compiler(binary_path)
            opt_level = self.detect_optimization_level(binary_path)
            security_flags = self.analyze_security_flags(binary_path)
            optimizations = self.estimate_optimizations(opt_level)
            overall_risk = self.calculate_overall_risk(optimizations, security_flags)
            
            summary_parts = []
            summary_parts.append(f"编译器: {compiler.value}")
            summary_parts.append(f"优化级别: {opt_level.value}")
            summary_parts.append(f"安全风险: {overall_risk.value}")
            summary_parts.append(f"发现安全标志: {len(security_flags['found'])}")
            summary_parts.append(f"缺失安全标志: {len(security_flags['missing'])}")
            
            return CompilerOptAnalysisResult(
                compiler=compiler,
                optimization_level=opt_level,
                analysis_success=True,
                detected_flags=[opt_level.value],
                optimizations=optimizations,
                security_flags=security_flags['found'],
                missing_security_flags=security_flags['missing'],
                overall_risk=overall_risk,
                summary=" | ".join(summary_parts)
            )
        except Exception as e:
            logger.error(f"分析失败: {e}")
            return CompilerOptAnalysisResult(
                compiler=CompilerType.UNKNOWN,
                optimization_level=OptimizationLevel.UNKNOWN,
                analysis_success=False,
                error_message=str(e)
            )


def analyze_compiler_opt(binary_path: str) -> CompilerOptAnalysisResult:
    """
    分析二进制文件的编译器优化选项及其安全影响
    
    Args:
        binary_path: 二进制文件路径
    
    Returns:
        CompilerOptAnalysisResult: 分析结果
    """
    analyzer = CompilerOptAnalyzer()
    return analyzer.analyze(binary_path)


def format_compiler_opt_report(result: CompilerOptAnalysisResult) -> str:
    """
    格式化编译器优化分析报告
    
    Args:
        result: 分析结果
    
    Returns:
        格式化的报告字符串
    """
    if not result.analysis_success:
        return f"分析失败: {result.error_message}"
    
    parts = [
        "# 编译器优化与安全影响分析报告",
        "",
        "## 基本信息",
        f"- 编译器: {result.compiler.value}",
        f"- 优化级别: {result.optimization_level.value}",
        f"- 整体安全风险: {result.overall_risk.value}",
        "",
        "## 安全标志状态",
        "### 已启用",
    ]
    
    if result.security_flags:
        parts.extend([f"- {flag}" for flag in result.security_flags])
    else:
        parts.append("无")
    
    parts.append("")
    parts.append("### 缺失")
    
    if result.missing_security_flags:
        parts.extend([f"- {flag}" for flag in result.missing_security_flags])
    else:
        parts.append("无")
    
    parts.append("")
    parts.append("## 优化选项详情")
    
    for opt in result.optimizations:
        status = "✓" if opt.enabled else "✗"
        parts.append(f"- [{status}] {opt.name}: {opt.description}")
        if opt.enabled:
            parts.append(f"  - 安全风险: {opt.security_risk.value}")
            parts.append(f"  - 影响: {opt.impact}")
    
    parts.append("")
    parts.append("## 总结")
    parts.append(result.summary)
    
    return "\n".join(parts)


def export_compiler_opt_report(result: CompilerOptAnalysisResult, file_path: str) -> bool:
    """
    导出编译器优化分析报告
    
    Args:
        result: 分析结果
        file_path: 输出文件路径
    
    Returns:
        是否成功
    """
    try:
        if file_path.endswith('.json'):
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(result.to_dict(), f, ensure_ascii=False, indent=2)
        else:
            report_content = format_compiler_opt_report(result)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
        return True
    except Exception as e:
        logger.error(f"导出报告失败: {e}")
        return False
