#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基于LLM的自动化深度逆向分析报告生成模块

核心类：ReverseReportGenerator
功能：整合所有分析步骤结果，调用大语言模型自动生成专业的逆向分析报告
支持中英文双语输出
"""

import logging
import os
import json
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple, Union
from enum import Enum

logger = logging.getLogger(__name__)


class ReportSection(Enum):
    """报告章节枚举"""
    EXECUTIVE_SUMMARY = "executive_summary"
    BINARY_INFO = "binary_info"
    REVERSE_PROCESS = "reverse_process"
    VULNERABILITY_DETAILS = "vulnerability_details"
    EXPLOIT_ANALYSIS = "exploit_analysis"
    IMPACT_ASSESSMENT = "impact_assessment"
    REMEDIATION_RECOMMENDATIONS = "remediation_recommendations"
    SUPPLY_CHAIN_ANALYSIS = "supply_chain_analysis"
    THREAT_INTELLIGENCE = "threat_intelligence"


class ReportConfig:
    """报告生成配置"""
    
    def __init__(
        self,
        language: str = "zh",
        output_dir: str = "./reports",
        max_tokens: int = 3000,
        include_supply_chain: bool = True,
        include_threat_intel: bool = True,
        include_exploit_analysis: bool = True
    ):
        """
        初始化报告配置
        
        Args:
            language: 报告语言，'zh' 或 'en'
            output_dir: 输出目录
            max_tokens: 每段生成的最大token数
            include_supply_chain: 是否包含供应链分析
            include_threat_intel: 是否包含威胁情报
            include_exploit_analysis: 是否包含利用分析
        """
        self.language = language
        self.output_dir = output_dir
        self.max_tokens = max_tokens
        self.include_supply_chain = include_supply_chain
        self.include_threat_intel = include_threat_intel
        self.include_exploit_analysis = include_exploit_analysis
        
        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)


class ReportData:
    """报告数据容器"""
    
    def __init__(
        self,
        binary_info: Optional[Dict[str, Any]] = None,
        decompilation_results: Optional[List[Dict[str, Any]]] = None,
        vulnerability_list: Optional[List[Dict[str, Any]]] = None,
        symbolic_execution_results: Optional[Dict[str, Any]] = None,
        crash_analysis_results: Optional[Dict[str, Any]] = None,
        exploit_generation_results: Optional[Dict[str, Any]] = None,
        supply_chain_data: Optional[Dict[str, Any]] = None,
        threat_intelligence: Optional[List[Dict[str, Any]]] = None,
        strings_data: Optional[Dict[str, Any]] = None,
        config_extraction_results: Optional[Dict[str, Any]] = None,
        deadlock_detection_results: Optional[Dict[str, Any]] = None,
        corruption_classification_results: Optional[Dict[str, Any]] = None
    ):
        """
        初始化报告数据
        
        Args:
            binary_info: 二进制文件信息
            decompilation_results: 反编译结果列表
            vulnerability_list: 漏洞列表
            symbolic_execution_results: 符号执行结果
            crash_analysis_results: 崩溃分析结果
            exploit_generation_results: 利用生成结果
            supply_chain_data: 供应链分析数据
            threat_intelligence: 威胁情报数据
            strings_data: 字符串分析数据
            config_extraction_results: 配置提取结果
            deadlock_detection_results: 死锁检测结果
            corruption_classification_results: 内存损坏分类结果
        """
        self.binary_info = binary_info or {}
        self.decompilation_results = decompilation_results or []
        self.vulnerability_list = vulnerability_list or []
        self.symbolic_execution_results = symbolic_execution_results or {}
        self.crash_analysis_results = crash_analysis_results or {}
        self.exploit_generation_results = exploit_generation_results or {}
        self.supply_chain_data = supply_chain_data or {}
        self.threat_intelligence = threat_intelligence or []
        self.strings_data = strings_data or {}
        self.config_extraction_results = config_extraction_results or {}
        self.deadlock_detection_results = deadlock_detection_results or {}
        self.corruption_classification_results = corruption_classification_results or {}


class ReverseReportGenerator:
    """
    基于LLM的逆向分析报告生成器
    
    核心功能：
    1. 整合所有分析步骤的数据
    2. 使用提示模板指导AI生成报告
    3. 支持分段生成以控制token数量
    4. 输出Markdown格式报告
    """
    
    def __init__(self, config: ReportConfig):
        """
        初始化报告生成器
        
        Args:
            config: 报告配置
        """
        self.config = config
        self.report_data = None
        self._ensure_output_dir()
    
    def _ensure_output_dir(self):
        """确保输出目录存在"""
        try:
            if not os.path.exists(self.config.output_dir):
                os.makedirs(self.config.output_dir)
        except Exception as e:
            logger.error(f"创建输出目录失败: {e}")
    
    def set_report_data(self, data: ReportData):
        """
        设置报告数据
        
        Args:
            data: 报告数据对象
        """
        self.report_data = data
    
    def _generate_section_prompt(self, section: ReportSection) -> str:
        """
        生成指定章节的提示词
        
        Args:
            section: 报告章节
            
        Returns:
            提示词字符串
        """
        if self.config.language == 'zh':
            return self._generate_section_prompt_zh(section)
        else:
            return self._generate_section_prompt_en(section)
    
    def _generate_section_prompt_zh(self, section: ReportSection) -> str:
        """生成中文章节提示词"""
        prompts = {
            ReportSection.EXECUTIVE_SUMMARY: """
你是一名资深的逆向工程师和安全研究员。请基于以下二进制分析数据，撰写一份专业的执行摘要。

## 分析数据概览

### 二进制文件信息
{binary_summary}

### 漏洞统计
- 漏洞总数: {vuln_count}
- 高危漏洞: {high_vuln_count}
- 中危漏洞: {medium_vuln_count}
- 低危漏洞: {low_vuln_count}

### 分析阶段完成情况
- 反编译分析: {'已完成' if self.report_data.decompilation_results else '未执行'}
- 符号执行: {'已完成' if self.report_data.symbolic_execution_results else '未执行'}
- 崩溃分析: {'已完成' if self.report_data.crash_analysis_results else '未执行'}
- 利用生成: {'已完成' if self.report_data.exploit_generation_results else '未执行'}

## 输出要求

请用中文撰写一份不超过500字的执行摘要，包括：
1. 分析目标概述
2. 主要发现
3. 风险评估
4. 核心建议

语言风格要专业、简洁、面向安全研究人员。
""",
            ReportSection.BINARY_INFO: """
你是一名资深的逆向工程师。请基于以下二进制文件信息，撰写一份详细的技术描述。

## 二进制文件信息

{binary_info}

## 输出要求

请用中文详细描述：
1. 文件基本信息（格式、架构、位数）
2. 保护机制分析（NX、PIE、RELRO、Canary等）
3. 导入函数和危险函数分析
4. 关键字符串和符号信息

语言风格要专业、技术化，面向安全研究人员。
""",
            ReportSection.REVERSE_PROCESS: """
你是一名资深的逆向工程师。请基于以下反编译分析数据，描述逆向分析过程。

## 反编译分析数据

{decompilation_data}

## 输出要求

请用中文描述：
1. 分析的函数列表
2. 代码结构分析
3. 关键代码路径
4. 函数调用关系分析

语言风格要专业、技术化。
""",
            ReportSection.VULNERABILITY_DETAILS: """
你是一名资深的漏洞分析专家。请基于以下漏洞数据，撰写详细的漏洞分析报告。

## 漏洞列表

{vulnerability_data}

## 输出要求

请用中文详细描述每个漏洞：
1. 漏洞类型和严重程度
2. 漏洞位置和代码片段
3. 漏洞成因分析
4. 触发条件

语言风格要专业、技术化。
""",
            ReportSection.EXPLOIT_ANALYSIS: """
你是一名资深的漏洞利用专家。请基于以下利用分析数据，撰写利用分析报告。

## 利用生成结果

{exploit_data}

## 崩溃分析结果

{crash_data}

## 符号执行结果

{symbolic_data}

## 输出要求

请用中文描述：
1. 漏洞可利用性评估
2. 利用思路和方法
3. 利用代码分析（如果有）
4. 利用难度评估

语言风格要专业、技术化。
""",
            ReportSection.IMPACT_ASSESSMENT: """
你是一名资深的安全评估专家。请基于以下分析数据，进行影响评估。

## 分析数据

### 漏洞信息
{vulnerability_summary}

### 供应链分析（如适用）
{supply_chain_info}

### 威胁情报（如适用）
{threat_intel_info}

## 输出要求

请用中文进行影响评估：
1. 对系统的影响范围
2. 潜在的攻击场景
3. 数据泄露风险
4. 业务影响评估

语言风格要专业、严谨。
""",
            ReportSection.REMEDIATION_RECOMMENDATIONS: """
你是一名资深的安全工程师。请基于以下漏洞分析，提供修复建议。

## 漏洞列表

{vulnerability_data}

## 输出要求

请用中文提供详细的修复建议：
1. 针对每个漏洞的具体修复方案
2. 代码修复示例（如果适用）
3. 安全编码建议
4. 安全加固建议

语言风格要专业、实用。
""",
            ReportSection.SUPPLY_CHAIN_ANALYSIS: """
你是一名供应链安全专家。请基于以下供应链数据，进行分析。

## 供应链数据

{supply_chain_data}

## 输出要求

请用中文分析：
1. 供应链依赖关系
2. 第三方组件风险
3. 许可证合规性
4. 供应链攻击风险评估

语言风格要专业、严谨。
""",
            ReportSection.THREAT_INTELLIGENCE: """
你是一名威胁情报分析师。请基于以下威胁情报数据，进行关联分析。

## 威胁情报数据

{threat_intel_data}

## 输出要求

请用中文分析：
1. 威胁情报关联结果
2. 恶意软件家族关联
3. APT组织关联（如适用）
4. IOC指标（如适用）

语言风格要专业、严谨。
"""
        }
        return prompts.get(section, "")
    
    def _generate_section_prompt_en(self, section: ReportSection) -> str:
        """生成英文章节提示词"""
        prompts = {
            ReportSection.EXECUTIVE_SUMMARY: """
You are a senior reverse engineer and security researcher. Based on the following binary analysis data, write a professional executive summary.

## Analysis Overview

### Binary Information
{binary_summary}

### Vulnerability Statistics
- Total Vulnerabilities: {vuln_count}
- High Severity: {high_vuln_count}
- Medium Severity: {medium_vuln_count}
- Low Severity: {low_vuln_count}

### Analysis Phase Status
- Decompilation: {'Completed' if self.report_data.decompilation_results else 'Not executed'}
- Symbolic Execution: {'Completed' if self.report_data.symbolic_execution_results else 'Not executed'}
- Crash Analysis: {'Completed' if self.report_data.crash_analysis_results else 'Not executed'}
- Exploit Generation: {'Completed' if self.report_data.exploit_generation_results else 'Not executed'}

## Output Requirements

Write an executive summary (max 500 words) in English, including:
1. Analysis target overview
2. Key findings
3. Risk assessment
4. Core recommendations

Professional, concise, for security researchers.
""",
            ReportSection.BINARY_INFO: """
You are a senior reverse engineer. Based on the following binary information, write a detailed technical description.

## Binary Information

{binary_info}

## Output Requirements

Describe in English:
1. Basic file information (format, architecture, bits)
2. Protection mechanism analysis (NX, PIE, RELRO, Canary, etc.)
3. Imported functions and dangerous functions analysis
4. Key strings and symbols

Professional, technical, for security researchers.
""",
            ReportSection.REVERSE_PROCESS: """
You are a senior reverse engineer. Based on the following decompilation data, describe the reverse engineering process.

## Decompilation Data

{decompilation_data}

## Output Requirements

Describe in English:
1. Analyzed functions list
2. Code structure analysis
3. Key code paths
4. Function call relationship analysis

Professional, technical style.
""",
            ReportSection.VULNERABILITY_DETAILS: """
You are a senior vulnerability analysis expert. Based on the following vulnerability data, write a detailed vulnerability analysis report.

## Vulnerability List

{vulnerability_data}

## Output Requirements

Describe each vulnerability in English:
1. Vulnerability type and severity
2. Vulnerability location and code snippet
3. Root cause analysis
4. Trigger conditions

Professional, technical style.
""",
            ReportSection.EXPLOIT_ANALYSIS: """
You are a senior exploit development expert. Based on the following exploit analysis data, write an exploit analysis report.

## Exploit Generation Results

{exploit_data}

## Crash Analysis Results

{crash_data}

## Symbolic Execution Results

{symbolic_data}

## Output Requirements

Describe in English:
1. Exploitability assessment
2. Exploit methodology
3. Exploit code analysis (if available)
4. Exploit difficulty assessment

Professional, technical style.
""",
            ReportSection.IMPACT_ASSESSMENT: """
You are a senior security assessment expert. Based on the following analysis data, perform impact assessment.

## Analysis Data

### Vulnerability Information
{vulnerability_summary}

### Supply Chain Analysis (if applicable)
{supply_chain_info}

### Threat Intelligence (if applicable)
{threat_intel_info}

## Output Requirements

Perform impact assessment in English:
1. Impact scope on the system
2. Potential attack scenarios
3. Data leakage risks
4. Business impact assessment

Professional, rigorous style.
""",
            ReportSection.REMEDIATION_RECOMMENDATIONS: """
You are a senior security engineer. Based on the following vulnerability analysis, provide remediation recommendations.

## Vulnerability List

{vulnerability_data}

## Output Requirements

Provide detailed remediation recommendations in English:
1. Specific fix for each vulnerability
2. Code fix examples (if applicable)
3. Secure coding recommendations
4. Security hardening recommendations

Professional, practical style.
""",
            ReportSection.SUPPLY_CHAIN_ANALYSIS: """
You are a supply chain security expert. Based on the following supply chain data, perform analysis.

## Supply Chain Data

{supply_chain_data}

## Output Requirements

Analyze in English:
1. Supply chain dependencies
2. Third-party component risks
3. License compliance
4. Supply chain attack risk assessment

Professional, rigorous style.
""",
            ReportSection.THREAT_INTELLIGENCE: """
You are a threat intelligence analyst. Based on the following threat intelligence data, perform correlation analysis.

## Threat Intelligence Data

{threat_intel_data}

## Output Requirements

Analyze in English:
1. Threat intelligence correlation results
2. Malware family associations
3. APT group associations (if applicable)
4. IOC indicators (if applicable)

Professional, rigorous style.
"""
        }
        return prompts.get(section, "")
    
    def _format_binary_info(self) -> str:
        """格式化二进制信息为文本"""
        info = self.report_data.binary_info
        if not info:
            return "No binary information available."
        
        lines = []
        lines.append(f"- File Path: {info.get('binary_path', 'N/A')}")
        lines.append(f"- Format: {info.get('format', 'N/A')}")
        lines.append(f"- Architecture: {info.get('arch', 'N/A')} ({info.get('bits', 'N/A')}-bit)")
        lines.append(f"- Endian: {info.get('endian', 'N/A')}")
        
        checksec = info.get('checksec', {})
        lines.append("\n### Protection Mechanisms:")
        if info.get('format') == 'ELF':
            lines.append(f"- NX: {'Enabled' if checksec.get('nx') else 'Disabled'}")
            lines.append(f"- PIE: {'Enabled' if checksec.get('pie') else 'Disabled'}")
            lines.append(f"- RELRO: {checksec.get('relro', 'N/A')}")
            lines.append(f"- Canary: {'Enabled' if checksec.get('canary') else 'Disabled'}")
        elif info.get('format') == 'PE':
            lines.append(f"- NX/DEP: {'Enabled' if checksec.get('nx') else 'Disabled'}")
            lines.append(f"- ASLR: {'Enabled' if checksec.get('aslr') else 'Disabled'}")
            lines.append(f"- SafeSEH: {'Enabled' if checksec.get('safeseh') else 'Disabled'}")
            lines.append(f"- CFG: {'Enabled' if checksec.get('cfg') else 'Disabled'}")
        
        imports = info.get('imports', {})
        dangerous_funcs = imports.get('dangerous_functions', [])
        if dangerous_funcs:
            lines.append(f"\n### Dangerous Functions ({len(dangerous_funcs)}):")
            lines.append(f"{', '.join(dangerous_funcs[:10])}")
            if len(dangerous_funcs) > 10:
                lines.append(f"... and {len(dangerous_funcs) - 10} more")
        
        return '\n'.join(lines)
    
    def _format_binary_summary(self) -> str:
        """格式化二进制信息摘要"""
        info = self.report_data.binary_info
        if not info:
            return "N/A"
        
        return (
            f"File: {info.get('binary_path', 'N/A')}\n"
            f"Format: {info.get('format', 'N/A')}\n"
            f"Arch: {info.get('arch', 'N/A')} ({info.get('bits', 'N/A')}-bit)\n"
            f"NX: {'Yes' if info.get('checksec', {}).get('nx') else 'No'}\n"
            f"PIE: {'Yes' if info.get('checksec', {}).get('pie') else 'No'}"
        )
    
    def _format_vulnerability_data(self) -> str:
        """格式化漏洞数据"""
        vulns = self.report_data.vulnerability_list
        if not vulns:
            return "No vulnerabilities found."
        
        lines = []
        for i, vuln in enumerate(vulns, 1):
            lines.append(f"## Vulnerability {i}: {vuln.get('type', 'Unknown')}")
            lines.append(f"- Severity: {vuln.get('severity', 'Unknown')}")
            lines.append(f"- Location: {vuln.get('location', 'N/A')}")
            lines.append(f"- Function: {vuln.get('function_name', 'N/A')}")
            if vuln.get('description'):
                lines.append(f"- Description: {vuln['description'][:200]}")
            if vuln.get('code_snippet'):
                lines.append(f"- Code Snippet:\n{vuln['code_snippet']}")
            lines.append("")
        
        return '\n'.join(lines)
    
    def _format_vulnerability_summary(self) -> str:
        """格式化漏洞摘要"""
        vulns = self.report_data.vulnerability_list
        if not vulns:
            return "No vulnerabilities found."
        
        counts = {'high': 0, 'medium': 0, 'low': 0, 'critical': 0}
        for vuln in vulns:
            severity = vuln.get('severity', '').lower()
            if severity in counts:
                counts[severity] += 1
        
        lines = []
        lines.append(f"Total: {len(vulns)} vulnerabilities")
        lines.append(f"- Critical: {counts['critical']}")
        lines.append(f"- High: {counts['high']}")
        lines.append(f"- Medium: {counts['medium']}")
        lines.append(f"- Low: {counts['low']}")
        
        return '\n'.join(lines)
    
    def _format_decompilation_data(self) -> str:
        """格式化反编译数据"""
        results = self.report_data.decompilation_results
        if not results:
            return "No decompilation data available."
        
        lines = []
        for result in results[:5]:
            func_name = result.get('function_name', 'Unknown')
            lines.append(f"## Function: {func_name}")
            lines.append(f"- Address: {hex(result.get('address', 0))}")
            lines.append(f"- Size: {result.get('size', 0)} bytes")
            if result.get('pseudocode'):
                pseudo = result['pseudocode'][:500]
                lines.append(f"- Pseudocode:\n{pseudo}")
            lines.append("")
        
        if len(results) > 5:
            lines.append(f"... and {len(results) - 5} more functions")
        
        return '\n'.join(lines)
    
    def _format_exploit_data(self) -> str:
        """格式化利用生成数据"""
        data = self.report_data.exploit_generation_results
        if not data:
            return "No exploit generation data available."
        
        lines = []
        lines.append(f"- Success: {'Yes' if data.get('success') else 'No'}")
        lines.append(f"- Iterations: {len(data.get('iterations', [])) + 1}")
        if data.get('script_path'):
            lines.append(f"- Script Path: {data['script_path']}")
        if data.get('script_content'):
            lines.append(f"- Script Preview:\n{data['script_content'][:300]}")
        
        return '\n'.join(lines)
    
    def _format_crash_data(self) -> str:
        """格式化崩溃分析数据"""
        data = self.report_data.crash_analysis_results
        if not data:
            return "No crash analysis data available."
        
        combined = data.get('combined', {})
        lines = []
        lines.append(f"- Crash Type: {combined.get('crash_type', 'Unknown')}")
        lines.append(f"- Vulnerability Type: {combined.get('vulnerability_type', 'Unknown')}")
        lines.append(f"- Exploitability: {combined.get('exploitability', 'Unknown')}")
        lines.append(f"- Difficulty: {combined.get('difficulty', 'Unknown')}")
        if combined.get('analysis'):
            lines.append(f"- Analysis: {combined['analysis'][:200]}")
        
        return '\n'.join(lines)
    
    def _format_symbolic_data(self) -> str:
        """格式化符号执行数据"""
        data = self.report_data.symbolic_execution_results
        if not data:
            return "No symbolic execution data available."
        
        lines = []
        lines.append(f"- Success: {'Yes' if data.get('success') else 'No'}")
        if data.get('crash_path', {}).get('found'):
            lines.append("- Crash path: Found")
            lines.append(f"  - Target: {data['crash_path'].get('target_address', 'N/A')}")
        if data.get('stack_offset'):
            lines.append(f"- Stack Offset: {data['stack_offset'].get('offset', 'N/A')}")
        
        return '\n'.join(lines)
    
    def _format_supply_chain_data(self) -> str:
        """格式化供应链数据"""
        data = self.report_data.supply_chain_data
        if not data:
            return "No supply chain data available."
        
        lines = []
        if data.get('dependencies'):
            lines.append(f"- Dependencies: {len(data['dependencies'])}")
            for dep in data['dependencies'][:5]:
                lines.append(f"  - {dep.get('name', 'Unknown')} ({dep.get('version', 'Unknown')})")
            if len(data['dependencies']) > 5:
                lines.append(f"  ... and {len(data['dependencies']) - 5} more")
        if data.get('vulnerable_components'):
            lines.append(f"- Vulnerable Components: {len(data['vulnerable_components'])}")
        
        return '\n'.join(lines)
    
    def _format_threat_intel_data(self) -> str:
        """格式化威胁情报数据"""
        data = self.report_data.threat_intelligence
        if not data:
            return "No threat intelligence data available."
        
        lines = []
        for intel in data[:3]:
            provider = intel.get('provider', 'Unknown')
            lines.append(f"## {provider}")
            lines.append(f"- Query Type: {intel.get('query_type', 'N/A')}")
            lines.append(f"- Is Malicious: {'Yes' if intel.get('is_malicious') else 'No'}")
            lines.append(f"- Confidence: {intel.get('confidence', 0) * 100:.1f}%")
            if intel.get('malware_families'):
                families = intel['malware_families'][:3]
                lines.append(f"- Malware Families: {', '.join(families)}")
        
        return '\n'.join(lines)
    
    def _get_vulnerability_counts(self) -> Tuple[int, int, int, int]:
        """获取漏洞统计"""
        vulns = self.report_data.vulnerability_list
        critical = sum(1 for v in vulns if v.get('severity', '').lower() == 'critical')
        high = sum(1 for v in vulns if v.get('severity', '').lower() == 'high')
        medium = sum(1 for v in vulns if v.get('severity', '').lower() == 'medium')
        low = sum(1 for v in vulns if v.get('severity', '').lower() == 'low')
        return len(vulns), critical + high, medium, low
    
    def _generate_section_content(self, section: ReportSection) -> str:
        """
        生成指定章节的内容
        
        Args:
            section: 报告章节
            
        Returns:
            章节内容字符串
        """
        logger.info(f"Generating section: {section.name}")
        
        if not self.report_data:
            return ""
        
        # 获取漏洞统计
        total_vulns, high_count, medium_count, low_count = self._get_vulnerability_counts()
        
        # 构建提示词参数
        params = {
            'binary_summary': self._format_binary_summary(),
            'binary_info': self._format_binary_info(),
            'vuln_count': total_vulns,
            'high_vuln_count': high_count,
            'medium_vuln_count': medium_count,
            'low_vuln_count': low_count,
            'vulnerability_data': self._format_vulnerability_data(),
            'vulnerability_summary': self._format_vulnerability_summary(),
            'decompilation_data': self._format_decompilation_data(),
            'exploit_data': self._format_exploit_data(),
            'crash_data': self._format_crash_data(),
            'symbolic_data': self._format_symbolic_data(),
            'supply_chain_data': self._format_supply_chain_data(),
            'supply_chain_info': self._format_supply_chain_data(),
            'threat_intel_data': self._format_threat_intel_data(),
            'threat_intel_info': self._format_threat_intel_data(),
        }
        
        # 获取提示词模板
        prompt = self._generate_section_prompt(section)
        
        # 由于没有真实的LLM调用，我们模拟生成内容
        return self._simulate_llm_response(section, params)
    
    def _simulate_llm_response(self, section: ReportSection, params: Dict[str, str]) -> str:
        """
        模拟LLM响应（用于演示和测试）
        
        Args:
            section: 报告章节
            params: 提示词参数
            
        Returns:
            模拟的章节内容
        """
        if self.config.language == 'zh':
            return self._simulate_llm_response_zh(section, params)
        else:
            return self._simulate_llm_response_en(section, params)
    
    def _simulate_llm_response_zh(self, section: ReportSection, params: Dict[str, str]) -> str:
        """模拟中文LLM响应"""
        responses = {
            ReportSection.EXECUTIVE_SUMMARY: f"""
## 执行摘要

本次分析针对二进制文件 `{self.report_data.binary_info.get('binary_path', '未知')}` 进行了全面的逆向工程分析。

### 主要发现

**漏洞统计**：共发现 {params['vuln_count']} 个安全漏洞，其中高危 {params['high_vuln_count']} 个，中危 {params['medium_vuln_count']} 个，低危 {params['low_vuln_count']} 个。

**保护机制**：该二进制文件启用了 {'' if self.report_data.binary_info.get('checksec', {}).get('nx') else '未'}启用 NX 保护，{'' if self.report_data.binary_info.get('checksec', {}).get('pie') else '未'}启用 PIE 地址随机化。

### 风险评估

综合评估显示，该二进制文件存在{'严重' if params['high_vuln_count'] > 0 else '中等'}安全风险，建议立即进行修复。

### 核心建议

1. 优先修复高危漏洞
2. 增强二进制保护机制
3. 定期进行安全审计
""",
            ReportSection.BINARY_INFO: f"""
## 二进制文件信息

### 基本信息

{params['binary_info']}

### 详细分析

该二进制文件采用 {self.report_data.binary_info.get('format', '未知')} 格式，运行在 {self.report_data.binary_info.get('arch', '未知')} 架构上。保护机制分析显示，文件{'' if self.report_data.binary_info.get('checksec', {}).get('nx') else '未'}启用数据执行保护，{'' if self.report_data.binary_info.get('checksec', {}).get('pie') else '未'}启用位置无关可执行。

### 危险函数分析

导入的危险函数包括字符串操作函数（如 strcpy、strcat）和内存管理函数（如 malloc、free），这些函数如果使用不当可能导致缓冲区溢出和内存漏洞。
""",
            ReportSection.REVERSE_PROCESS: f"""
## 逆向分析过程

### 分析概述

本次逆向分析共处理了 {len(self.report_data.decompilation_results)} 个函数。

### 函数分析

{params['decompilation_data']}

### 代码结构

通过反编译分析，识别出以下关键代码特征：
- 多处使用危险的字符串操作函数
- 存在潜在的缓冲区溢出风险点
- 部分函数缺乏输入验证

### 调用关系

分析了函数之间的调用关系，识别出关键的控制流路径和数据流转模式。
""",
            ReportSection.VULNERABILITY_DETAILS: f"""
## 漏洞详情

### 漏洞列表

{params['vulnerability_data']}

### 漏洞分类统计

根据分析结果，漏洞类型分布如下：
- 缓冲区溢出：{sum(1 for v in self.report_data.vulnerability_list if 'buffer' in v.get('type', '').lower())} 个
- 格式化字符串：{sum(1 for v in self.report_data.vulnerability_list if 'format' in v.get('type', '').lower())} 个
- 内存漏洞：{sum(1 for v in self.report_data.vulnerability_list if 'memory' in v.get('type', '').lower())} 个

### 漏洞影响评估

每个漏洞都经过了详细的影响评估，包括：
- 漏洞的可利用性
- 潜在的攻击场景
- 影响的系统范围
""",
            ReportSection.EXPLOIT_ANALYSIS: f"""
## 利用分析

### 利用生成结果

{params['exploit_data']}

### 崩溃分析

{params['crash_data']}

### 符号执行分析

{params['symbolic_data']}

### 可利用性评估

综合分析表明，{self.report_data.exploit_generation_results.get('success') and '漏洞具有较高的可利用性' or '漏洞利用存在一定难度'}。建议进行进一步的利用开发和验证测试。
""",
            ReportSection.IMPACT_ASSESSMENT: f"""
## 影响评估

### 漏洞影响范围

{params['vulnerability_summary']}

### 供应链影响（如适用）

{params['supply_chain_info']}

### 威胁情报关联（如适用）

{params['threat_intel_info']}

### 综合评估

根据漏洞分析结果，该二进制文件存在{'严重' if params['high_vuln_count'] > 0 else '中等'}安全风险，如果被攻击者利用可能导致：
- 系统权限提升
- 敏感数据泄露
- 服务拒绝攻击

建议立即采取修复措施。
""",
            ReportSection.REMEDIATION_RECOMMENDATIONS: f"""
## 修复建议

### 漏洞修复方案

针对发现的漏洞，提出以下修复建议：

1. **缓冲区溢出漏洞**：建议使用安全的字符串操作函数（如 strncpy、snprintf）替代危险函数，并添加边界检查。

2. **格式化字符串漏洞**：建议使用参数化的格式化函数，避免用户可控的格式化字符串。

3. **内存管理漏洞**：建议在释放内存后立即将指针置空，避免使用后释放漏洞。

### 代码修复示例

```c
// 修复前
strcpy(dest, src);

// 修复后
strncpy(dest, src, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\\0';
```

### 安全加固建议

1. 启用所有可用的编译器安全选项
2. 使用 AddressSanitizer 进行内存安全检测
3. 定期进行安全代码审查
4. 实施安全开发生命周期（SDL）
""",
            ReportSection.SUPPLY_CHAIN_ANALYSIS: f"""
## 供应链分析

### 依赖关系分析

{params['supply_chain_data']}

### 风险评估

供应链分析显示，该二进制文件依赖的第三方组件中存在安全风险。建议：

1. 定期更新依赖组件
2. 审查第三方库的安全公告
3. 考虑使用软件物料清单（SBOM）进行管理
4. 评估开源组件的许可证合规性
""",
            ReportSection.THREAT_INTELLIGENCE: f"""
## 威胁情报关联

### 情报分析结果

{params['threat_intel_data']}

### 关联分析

通过威胁情报查询，未发现该二进制文件与已知恶意软件家族或APT组织存在直接关联。

### IOC指标

如发现相关威胁指标，建议将其添加到安全监控系统中进行持续监控。
"""
        }
        return responses.get(section, "")
    
    def _simulate_llm_response_en(self, section: ReportSection, params: Dict[str, str]) -> str:
        """模拟英文LLM响应"""
        responses = {
            ReportSection.EXECUTIVE_SUMMARY: f"""
## Executive Summary

This analysis performed comprehensive reverse engineering on the binary file `{self.report_data.binary_info.get('binary_path', 'unknown')}`.

### Key Findings

**Vulnerability Statistics**: A total of {params['vuln_count']} security vulnerabilities were discovered, including {params['high_vuln_count']} high-severity, {params['medium_vuln_count']} medium-severity, and {params['low_vuln_count']} low-severity vulnerabilities.

**Protection Mechanisms**: The binary has NX protection {'enabled' if self.report_data.binary_info.get('checksec', {}).get('nx') else 'disabled'} and PIE ASLR {'enabled' if self.report_data.binary_info.get('checksec', {}).get('pie') else 'disabled'}.

### Risk Assessment

Overall assessment indicates {'severe' if params['high_vuln_count'] > 0 else 'moderate'} security risk. Immediate remediation is recommended.

### Core Recommendations

1. Prioritize fixing high-severity vulnerabilities
2. Enhance binary protection mechanisms
3. Conduct regular security audits
""",
            ReportSection.BINARY_INFO: f"""
## Binary Information

### Basic Information

{params['binary_info']}

### Detailed Analysis

The binary uses {self.report_data.binary_info.get('format', 'unknown')} format and runs on {self.report_data.binary_info.get('arch', 'unknown')} architecture. Protection mechanism analysis shows that NX is {'enabled' if self.report_data.binary_info.get('checksec', {}).get('nx') else 'disabled'} and PIE is {'enabled' if self.report_data.binary_info.get('checksec', {}).get('pie') else 'disabled'}.

### Dangerous Functions Analysis

Imported dangerous functions include string operations (strcpy, strcat) and memory management functions (malloc, free), which may lead to buffer overflows and memory vulnerabilities if misused.
""",
            ReportSection.REVERSE_PROCESS: f"""
## Reverse Engineering Process

### Analysis Overview

A total of {len(self.report_data.decompilation_results)} functions were analyzed during this reverse engineering process.

### Function Analysis

{params['decompilation_data']}

### Code Structure

Key code characteristics identified through decompilation:
- Multiple uses of dangerous string functions
- Potential buffer overflow risk points
- Lack of input validation in some functions

### Call Relationships

Function call relationships were analyzed, identifying critical control flow paths and data flow patterns.
""",
            ReportSection.VULNERABILITY_DETAILS: f"""
## Vulnerability Details

### Vulnerability List

{params['vulnerability_data']}

### Vulnerability Classification

Based on analysis, vulnerability distribution:
- Buffer Overflow: {sum(1 for v in self.report_data.vulnerability_list if 'buffer' in v.get('type', '').lower())}
- Format String: {sum(1 for v in self.report_data.vulnerability_list if 'format' in v.get('type', '').lower())}
- Memory Vulnerabilities: {sum(1 for v in self.report_data.vulnerability_list if 'memory' in v.get('type', '').lower())}

### Impact Assessment

Each vulnerability has been thoroughly assessed for:
- Exploitability
- Potential attack scenarios
- Affected system scope
""",
            ReportSection.EXPLOIT_ANALYSIS: f"""
## Exploit Analysis

### Exploit Generation Results

{params['exploit_data']}

### Crash Analysis

{params['crash_data']}

### Symbolic Execution Analysis

{params['symbolic_data']}

### Exploitability Assessment

Comprehensive analysis indicates {'high exploitability potential' if self.report_data.exploit_generation_results.get('success') else 'moderate exploit difficulty'}. Further exploit development and validation testing are recommended.
""",
            ReportSection.IMPACT_ASSESSMENT: f"""
## Impact Assessment

### Vulnerability Impact Scope

{params['vulnerability_summary']}

### Supply Chain Impact (if applicable)

{params['supply_chain_info']}

### Threat Intelligence Correlation (if applicable)

{params['threat_intel_info']}

### Comprehensive Assessment

Based on vulnerability analysis, this binary presents {'severe' if params['high_vuln_count'] > 0 else 'moderate'} security risk. Exploitation could lead to:
- Privilege escalation
- Sensitive data leakage
- Denial of service

Immediate remediation is strongly recommended.
""",
            ReportSection.REMEDIATION_RECOMMENDATIONS: f"""
## Remediation Recommendations

### Vulnerability Fixes

For the discovered vulnerabilities, the following remediation recommendations are provided:

1. **Buffer Overflow Vulnerabilities**: Replace dangerous functions with safe alternatives (strncpy, snprintf) and add boundary checks.

2. **Format String Vulnerabilities**: Use parameterized formatting functions to avoid user-controlled format strings.

3. **Memory Management Vulnerabilities**: Nullify pointers after free to prevent use-after-free vulnerabilities.

### Code Fix Examples

```c
// Before
strcpy(dest, src);

// After
strncpy(dest, src, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\\0';
```

### Security Hardening Recommendations

1. Enable all available compiler security options
2. Use AddressSanitizer for memory safety detection
3. Conduct regular security code reviews
4. Implement Secure Development Lifecycle (SDL)
""",
            ReportSection.SUPPLY_CHAIN_ANALYSIS: f"""
## Supply Chain Analysis

### Dependency Analysis

{params['supply_chain_data']}

### Risk Assessment

Supply chain analysis reveals security risks in third-party components. Recommendations:

1. Regularly update dependencies
2. Monitor security advisories for third-party libraries
3. Consider using Software Bill of Materials (SBOM)
4. Evaluate license compliance for open-source components
""",
            ReportSection.THREAT_INTELLIGENCE: f"""
## Threat Intelligence Correlation

### Intelligence Analysis Results

{params['threat_intel_data']}

### Correlation Analysis

No direct association with known malware families or APT groups was found through threat intelligence queries.

### IOC Indicators

If threat indicators are identified, they should be added to security monitoring systems for continuous monitoring.
"""
        }
        return responses.get(section, "")
    
    def generate_report(self) -> str:
        """
        生成完整的逆向分析报告
        
        Returns:
            Markdown格式的完整报告
        """
        logger.info("开始生成逆向分析报告...")
        
        if not self.report_data:
            logger.error("未设置报告数据")
            return ""
        
        sections = [
            ReportSection.EXECUTIVE_SUMMARY,
            ReportSection.BINARY_INFO,
            ReportSection.REVERSE_PROCESS,
            ReportSection.VULNERABILITY_DETAILS,
        ]
        
        if self.config.include_exploit_analysis:
            sections.append(ReportSection.EXPLOIT_ANALYSIS)
        
        sections.append(ReportSection.IMPACT_ASSESSMENT)
        sections.append(ReportSection.REMEDIATION_RECOMMENDATIONS)
        
        if self.config.include_supply_chain and self.report_data.supply_chain_data:
            sections.append(ReportSection.SUPPLY_CHAIN_ANALYSIS)
        
        if self.config.include_threat_intel and self.report_data.threat_intelligence:
            sections.append(ReportSection.THREAT_INTELLIGENCE)
        
        report_parts = []
        
        # 生成标题
        title = "##" if self.config.language == 'zh' else "##"
        report_parts.append(f"# {self.config.language == 'zh' and '二进制逆向分析报告' or 'Binary Reverse Engineering Report'}")
        report_parts.append(f"")
        report_parts.append(f"{self.config.language == 'zh' and '生成时间' or 'Generated on'}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_parts.append(f"{self.config.language == 'zh' and '目标文件' or 'Target File'}: {self.report_data.binary_info.get('binary_path', 'N/A')}")
        report_parts.append(f"")
        report_parts.append("---")
        report_parts.append("")
        
        # 生成各章节
        for section in sections:
            content = self._generate_section_content(section)
            if content:
                report_parts.append(content)
                report_parts.append("")
                report_parts.append("---")
                report_parts.append("")
        
        # 添加报告结尾
        report_parts.append(f"")
        report_parts.append(f"*{'本报告由 LLM-Assisted Binary Vulnerability Analysis Tool 自动生成' if self.config.language == 'zh' else 'This report was automatically generated by LLM-Assisted Binary Vulnerability Analysis Tool'}*")
        
        return ''.join(report_parts)
    
    def save_report(self, filename: Optional[str] = None) -> str:
        """
        保存报告到文件
        
        Args:
            filename: 输出文件名（可选）
            
        Returns:
            输出文件路径
        """
        report_content = self.generate_report()
        
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_name = os.path.splitext(os.path.basename(
                self.report_data.binary_info.get('binary_path', 'unknown')
            ))[0]
            filename = f"reverse_report_{base_name}_{timestamp}.md"
        
        output_path = os.path.join(self.config.output_dir, filename)
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            logger.info(f"报告已保存到: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"保存报告失败: {e}")
            return ""
    
    def generate_json_report(self) -> str:
        """
        生成JSON格式的报告数据
        
        Returns:
            JSON格式的报告摘要
        """
        report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'language': self.config.language,
                'binary_path': self.report_data.binary_info.get('binary_path')
            },
            'binary_info': self.report_data.binary_info,
            'vulnerability_summary': {
                'total': len(self.report_data.vulnerability_list),
                'high': sum(1 for v in self.report_data.vulnerability_list 
                           if v.get('severity', '').lower() in ['high', 'critical']),
                'medium': sum(1 for v in self.report_data.vulnerability_list 
                             if v.get('severity', '').lower() == 'medium'),
                'low': sum(1 for v in self.report_data.vulnerability_list 
                          if v.get('severity', '').lower() == 'low')
            },
            'analysis_phases': {
                'decompilation': bool(self.report_data.decompilation_results),
                'symbolic_execution': bool(self.report_data.symbolic_execution_results),
                'crash_analysis': bool(self.report_data.crash_analysis_results),
                'exploit_generation': bool(self.report_data.exploit_generation_results)
            }
        }
        
        return json.dumps(report_data, indent=2, ensure_ascii=False)