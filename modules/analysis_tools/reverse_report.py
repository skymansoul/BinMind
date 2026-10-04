#!/usr/bin/env python3
from enum import Enum
from dataclasses import dataclass
import logging
import os
import json
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple

logger = logging.getLogger(__name__)

class ReportSection(Enum):
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
    # Report generation configuration.

    def __init__(self,
                 language: str = "zh",
                 output_dir: str = "./reports",
                 max_tokens: int = 3000,
                 include_supply_chain: bool = True,
                 include_threat_intel: bool = True,
                 include_exploit_analysis: bool = True):
        """
        Initialise report configuration.
        """
        self.language = language
        self.output_dir = output_dir
        self.max_tokens = max_tokens
        self.include_supply_chain = include_supply_chain
        self.include_threat_intel = include_threat_intel
        self.include_exploit_analysis = include_exploit_analysis

        # Ensure output directory exists.
        os.makedirs(output_dir, exist_ok=True)

class ReportData:
    # Report data container.

    def __init__(self,
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
                 corruption_classification_results: Optional[Dict[str, Any]] = None,
                 decompilation_evidence: Optional[List[Dict[str, Any]]] = None,
                 crash_log: Optional[str] = None):
        """
        Initialise report data container.
        """
        self.binary_info = binary_info or {}
        self.decompilation_results = decompilation_results or []
        self.vulnerability_list = vulnerability_list or []
        self.symbolic_execution_results = symbolic_execution_results or {}
        self.crash_analysis_results = crash_analysis_results or {}
        self.exploit_generation_results = exploit_generation_results or {}
        # Optional data: None = not supplied; empty dict/list = supplied but devoid of content.
        self.supply_chain_data = supply_chain_data
        self.threat_intelligence = threat_intelligence
        self.strings_data = strings_data or {}
        self.config_extraction_results = config_extraction_results or {}
        self.deadlock_detection_results = deadlock_detection_results or {}
        self.corruption_classification_results = corruption_classification_results or {}
        # 证据传递: 反编译伪代码原文与崩溃日志原文, 供 LLM 研判
        self.decompilation_evidence = decompilation_evidence or []
        self.crash_log = crash_log

class ReverseReportGenerator:
    """
    LLM-based reverse engineering report generator.

    Core functions:
    1. Aggregates data from all analysis steps
    2. Drives AI report generation via prompt templates
    3. Supports sectional generation for token budget control
    4. Outputs Markdown-formatted reports
    """

    def __init__(self, config: ReportConfig):
        """
        Initialise report generator with configuration.
        """
        self.config = config
        self.report_data = None
        self._simulation = True
        self._ensure_output_dir()

    def _ensure_output_dir(self):
        try:
            if not os.path.exists(self.config.output_dir):
                os.makedirs(self.config.output_dir)
        except Exception as e:
            logger.error(f"Failed to create output directory: {e}")

    def set_report_data(self, data: ReportData, simulation: Optional[bool] = None):
        """
        Bind report data for generation. simulation 覆盖默认值。
        """
        self.report_data = data
        self._deduplicate_vulnerabilities()
        if simulation is not None:
            self._simulation = simulation

    def _generate_section_prompt(self, section: ReportSection) -> str:
        """
        Produce section-specific prompt.
        """
        if self.config.language == 'zh':
            return self._generate_section_prompt_zh(section)
        else:
            return self._generate_section_prompt_en(section)

    def _generate_section_prompt_zh(self, section: ReportSection) -> str:
        # Chinese section prompts.
        prompts = {
            ReportSection.EXECUTIVE_SUMMARY: """
Senior reverse engineer and security researcher. Based on the following binary analysis data, produce a professional executive summary.

## Analysis Data

### Binary File Info
{binary_summary}

### Vulnerability Statistics
- Total: {vuln_count}
- High: {high_vuln_count}
- Medium: {medium_vuln_count}
- Low: {low_vuln_count}

### Analysis Phase Progress
- Decompilation: {decompilation_status}
- Symbolic execution: {symbolic_execution_status}
- Crash analysis: {crash_analysis_status}
- Exploit generation: {exploit_generation_status}

## Output

Chinese, max 500 words, covering:
1. Analysis target overview
2. Key findings
3. Risk assessment
4. Core recommendations

Direct, concise, for security researchers.
""",
            ReportSection.BINARY_INFO: """
Senior reverse engineer. Based on the following binary information, produce a detailed technical description.

## Binary File Info

{binary_info}

## Output

Chinese, covering:
1. Basic file info (format, architecture, bitness)
2. Protection mechanism analysis (NX, PIE, RELRO, Canary, etc.)
3. Imported functions and dangerous function analysis
4. Key strings and symbol information

Direct, technical, for security researchers.
""",
            ReportSection.REVERSE_PROCESS: """
Senior reverse engineer. Based on the following decompilation data, describe the reverse engineering process.

## Decompilation Data

{decompilation_data}

## Output

Chinese, covering:
1. Analyzed function list
2. Code structure analysis
3. Key code paths
4. Call relationship analysis

Direct, technical.
""",
            ReportSection.VULNERABILITY_DETAILS: """
Senior vulnerability analyst. Based on the following vulnerability data, produce a detailed vulnerability analysis report.

## Vulnerability List

{vulnerability_data}

## Output

Chinese, per vulnerability:
1. Type and severity
2. Location and code snippet
3. Root cause analysis
4. Trigger conditions

Direct, technical.
""",
            ReportSection.EXPLOIT_ANALYSIS: """
Senior exploit development expert. Based on the following exploit analysis data, produce an exploit analysis report.

## Exploit Generation Results

{exploit_data}

## Crash Analysis Results

{crash_data}

## Symbolic Execution Results

{symbolic_data}

## Output

Chinese, covering:
1. Exploitability assessment
2. Exploit methodology
3. Exploit code analysis (if available)
4. Exploit difficulty assessment

Direct, technical.
""",
            ReportSection.IMPACT_ASSESSMENT: """
Senior security assessment expert. Based on the following analysis data, perform impact assessment.

## Analysis Data

### Vulnerability Information
{vulnerability_summary}

### Supply Chain Analysis (if applicable)
{supply_chain_info}

### Threat Intelligence (if applicable)
{threat_intel_info}

## Output

Chinese, covering:
1. Impact scope on the system
2. Potential attack scenarios
3. Data leakage risks
4. Business impact assessment

Direct, rigorous.
""",
            ReportSection.REMEDIATION_RECOMMENDATIONS: """
Senior security engineer. Based on the following vulnerability analysis, provide remediation recommendations.

## Vulnerability List

{vulnerability_data}

## Output

Chinese, covering:
1. Specific fix for each vulnerability
2. Code fix examples (if applicable)
3. Secure coding recommendations
4. Security hardening recommendations

Direct, practical.
""",
            ReportSection.SUPPLY_CHAIN_ANALYSIS: """
Supply chain security expert. Based on the following supply chain data, perform analysis.

## Supply Chain Data

{supply_chain_data}

## Output

Chinese, covering:
1. Supply chain dependencies
2. Third-party component risks
3. License compliance
4. Supply chain attack risk assessment

Direct, rigorous.
""",
            ReportSection.THREAT_INTELLIGENCE: """
Threat intelligence analyst. Based on the following threat intelligence data, perform correlation analysis.

## Threat Intelligence Data

{threat_intel_data}

## Output

Chinese, covering:
1. Threat intelligence correlation results
2. Malware family associations
3. APT group associations (if applicable)
4. IOC indicators (if applicable)

Direct, rigorous.
"""
        }
        return prompts.get(section, "")

    def _generate_section_prompt_en(self, section: ReportSection) -> str:
        """English section prompts."""
        prompts = {
            ReportSection.EXECUTIVE_SUMMARY: """
Senior reverse engineer and security researcher. Based on the following binary analysis data, write a professional executive summary.

## Analysis Overview

### Binary Information
{binary_summary}

### Vulnerability Statistics
- Total: {vuln_count}
- High: {high_vuln_count}
- Medium: {medium_vuln_count}
- Low: {low_vuln_count}

### Analysis Phase Status
- Decompilation: {decompilation_status}
- Symbolic Execution: {symbolic_execution_status}
- Crash Analysis: {crash_analysis_status}
- Exploit Generation: {exploit_generation_status}

## Output

English, max 500 words, covering:
1. Analysis target overview
2. Key findings
3. Risk assessment
4. Core recommendations

Direct, concise, for security researchers.
""",
            ReportSection.BINARY_INFO: """
Senior reverse engineer. Based on the following binary information, write a detailed technical description.

## Binary Information

{binary_info}

## Output

English, covering:
1. Basic file information (format, architecture, bitness)
2. Protection mechanism analysis (NX, PIE, RELRO, Canary, etc.)
3. Imported functions and dangerous functions analysis
4. Key strings and symbol information

Direct, technical, for security researchers.
""",
            ReportSection.REVERSE_PROCESS: """
Senior reverse engineer. Based on the following decompilation data, describe the reverse engineering process.

## Decompilation Data

{decompilation_data}

## Output

English, covering:
1. Analyzed function list
2. Code structure analysis
3. Key code paths
4. Call relationship analysis

Direct, technical.
""",
            ReportSection.VULNERABILITY_DETAILS: """
Senior vulnerability analyst. Based on the following vulnerability data, write a detailed vulnerability analysis report.

## Vulnerability List

{vulnerability_data}

## Output

English, per vulnerability:
1. Type and severity
2. Location and code snippet
3. Root cause analysis
4. Trigger conditions

Direct, technical.
""",
            ReportSection.EXPLOIT_ANALYSIS: """
Senior exploit development expert. Based on the following exploit analysis data, write an exploit analysis report.

## Exploit Generation Results

{exploit_data}

## Crash Analysis Results

{crash_data}

## Symbolic Execution Results

{symbolic_data}

## Output

English, covering:
1. Exploitability assessment
2. Exploit methodology
3. Exploit code analysis (if available)
4. Exploit difficulty assessment

Direct, technical.
""",
            ReportSection.IMPACT_ASSESSMENT: """
Senior security assessment expert. Based on the following analysis data, perform impact assessment.

## Analysis Data

### Vulnerability Information
{vulnerability_summary}

### Supply Chain Analysis (if applicable)
{supply_chain_info}

### Threat Intelligence (if applicable)
{threat_intel_info}

## Output

English, covering:
1. Impact scope on the system
2. Potential attack scenarios
3. Data leakage risks
4. Business impact assessment

Direct, rigorous.
""",
            ReportSection.REMEDIATION_RECOMMENDATIONS: """
Senior security engineer. Based on the following vulnerability analysis, provide remediation recommendations.

## Vulnerability List

{vulnerability_data}

## Output

English, covering:
1. Specific fix for each vulnerability
2. Code fix examples (if applicable)
3. Secure coding recommendations
4. Security hardening recommendations

Direct, practical.
""",
            ReportSection.SUPPLY_CHAIN_ANALYSIS: """
Supply chain security expert. Based on the following supply chain data, perform analysis.

## Supply Chain Data

{supply_chain_data}

## Output

English, covering:
1. Supply chain dependencies
2. Third-party component risks
3. License compliance
4. Supply chain attack risk assessment

Direct, rigorous.
""",
            ReportSection.THREAT_INTELLIGENCE: """
Threat intelligence analyst. Based on the following threat intelligence data, perform correlation analysis.

## Threat Intelligence Data

{threat_intel_data}

## Output

English, covering:
1. Threat intelligence correlation results
2. Malware family associations
3. APT group associations (if applicable)
4. IOC indicators (if applicable)

Direct, rigorous.
"""
        }
        return prompts.get(section, "")

    def _is_zh(self) -> bool:
        return self.config.language == 'zh'

    def _yes_no(self, value: bool) -> str:
        if self._is_zh():
            return '是' if value else '否'
        return 'Yes' if value else 'No'

    def _enabled_disabled(self, value: bool) -> str:
        if self._is_zh():
            return '启用' if value else '关闭'
        return 'Enabled' if value else 'Disabled'

    def _unknown(self) -> str:
        return '未知' if self._is_zh() else 'Unknown'

    def _na(self) -> str:
        return '不适用' if self._is_zh() else 'N/A'

    def _format_binary_info(self) -> str:
        """Format binary info as structured text."""
        info = self.report_data.binary_info
        if not info:
            return "未获取到二进制文件信息。" if self._is_zh() else "No binary information available."

        unknown = self._unknown()
        na = self._na()
        binary_path = info.get('binary_path') or info.get('path') or na
        lines = []
        if self._is_zh():
            lines.append(f"- 文件路径: {binary_path}")
            lines.append(f"- 格式: {info.get('format', na)}")
            lines.append(f"- 架构: {info.get('arch', na)} ({info.get('bits', na)}-bit)")
            lines.append(f"- 字节序: {info.get('endian', na)}")
            protection_title = "\n### 保护机制:"
            dangerous_title = "危险函数"
            more_template = "... 以及另外 {count} 个"
        else:
            lines.append(f"- File Path: {binary_path}")
            lines.append(f"- Format: {info.get('format', na)}")
            lines.append(f"- Architecture: {info.get('arch', na)} ({info.get('bits', na)}-bit)")
            lines.append(f"- Endian: {info.get('endian', na)}")
            protection_title = "\n### Protection Mechanisms:"
            dangerous_title = "Dangerous Functions"
            more_template = "... and {count} more"

        checksec = info.get('checksec', {})
        lines.append(protection_title)
        if info.get('format') == 'ELF':
            lines.append(f"- NX: {self._enabled_disabled(bool(checksec.get('nx')))}")
            lines.append(f"- PIE: {self._enabled_disabled(bool(checksec.get('pie')))}")
            lines.append(f"- RELRO: {checksec.get('relro', na)}")
            lines.append(f"- Canary: {self._enabled_disabled(bool(checksec.get('canary')))}")
        elif info.get('format') == 'PE':
            lines.append(f"- NX/DEP: {self._enabled_disabled(bool(checksec.get('nx')))}")
            lines.append(f"- ASLR: {self._enabled_disabled(bool(checksec.get('aslr')))}")
            lines.append(f"- SafeSEH: {self._enabled_disabled(bool(checksec.get('safeseh')))}")
            lines.append(f"- CFG: {self._enabled_disabled(bool(checksec.get('cfg')))}")
        else:
            lines.append(f"- {unknown}")

        imports = info.get('imports', {})
        dangerous_funcs = imports.get('dangerous_functions', [])
        if dangerous_funcs:
            lines.append(f"\n### {dangerous_title} ({len(dangerous_funcs)}):")
            lines.append(f"{', '.join(dangerous_funcs[:10])}")
            if len(dangerous_funcs) > 10:
                lines.append(more_template.format(count=len(dangerous_funcs) - 10))

        return '\n'.join(lines)

    def _format_binary_summary(self) -> str:
        # Produce compact binary info summary.
        info = self.report_data.binary_info
        if not info:
            return self._na()

        binary_path = info.get('binary_path') or info.get('path') or self._na()
        if self._is_zh():
            return (
                f"文件: {binary_path}\n"
                f"格式: {info.get('format', self._na())}\n"
                f"架构: {info.get('arch', self._na())} ({info.get('bits', self._na())}-bit)\n"
                f"NX: {self._yes_no(bool(info.get('checksec', {}).get('nx')))}\n"
                f"PIE: {self._yes_no(bool(info.get('checksec', {}).get('pie')))}"
            )
        return (
            f"File: {binary_path}\n"
            f"Format: {info.get('format', self._na())}\n"
            f"Arch: {info.get('arch', self._na())} ({info.get('bits', self._na())}-bit)\n"
            f"NX: {self._yes_no(bool(info.get('checksec', {}).get('nx')))}\n"
            f"PIE: {self._yes_no(bool(info.get('checksec', {}).get('pie')))}"
        )

    def _format_vulnerability_data(self) -> str:
        """Render vulnerability list as structured text."""
        vulns = self.report_data.vulnerability_list
        if not vulns:
            return "未发现漏洞。" if self._is_zh() else "No vulnerabilities found."

        lines = []
        for i, vuln in enumerate(vulns, 1):
            vuln_type = vuln.get('type', self._unknown())
            if self._is_zh():
                lines.append(f"## 漏洞 {i}: {vuln_type}")
                lines.append(f"- 严重性: {vuln.get('severity', self._unknown())}")
                lines.append(f"- 位置: {vuln.get('location', self._na())}")
                lines.append(f"- 函数: {vuln.get('function_name', self._na())}")
                if vuln.get('description'):
                    lines.append(f"- 描述: {vuln['description'][:200]}")
                if vuln.get('code_snippet'):
                    lines.append(f"- 代码片段:\n{vuln['code_snippet']}")
            else:
                lines.append(f"## Vulnerability {i}: {vuln_type}")
                lines.append(f"- Severity: {vuln.get('severity', self._unknown())}")
                lines.append(f"- Location: {vuln.get('location', self._na())}")
                lines.append(f"- Function: {vuln.get('function_name', self._na())}")
                if vuln.get('description'):
                    lines.append(f"- Description: {vuln['description'][:200]}")
                if vuln.get('code_snippet'):
                    lines.append(f"- Code Snippet:\n{vuln['code_snippet']}")
            lines.append("")

        return '\n'.join(lines)

    def _format_vulnerability_summary(self) -> str:
        # Collate vulnerability counts by severity.
        vulns = self.report_data.vulnerability_list
        if not vulns:
            return "未发现漏洞。" if self._is_zh() else "No vulnerabilities found."

        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in vulns:
            severity = vuln.get('severity', '').lower()
            if severity in counts:
                counts[severity] += 1

        lines = []
        if self._is_zh():
            lines.append(f"总计: {len(vulns)} 个漏洞")
            lines.append(f"- 严重: {counts['critical']}")
            lines.append(f"- 高危: {counts['high']}")
            lines.append(f"- 中危: {counts['medium']}")
            lines.append(f"- 低危: {counts['low']}")
        else:
            lines.append(f"Total: {len(vulns)} vulnerabilities")
            lines.append(f"- Critical: {counts['critical']}")
            lines.append(f"- High: {counts['high']}")
            lines.append(f"- Medium: {counts['medium']}")
            lines.append(f"- Low: {counts['low']}")

        return '\n'.join(lines)

    def _format_vulnerability_type_summary(self) -> str:
        vulns = self.report_data.vulnerability_list or []
        if not vulns:
            return "- 无" if self._is_zh() else "- None"

        counts = {
            'buffer_overflow': 0,
            'format_string': 0,
            'command_injection': 0,
            'info_leak': 0,
            'memory_corruption': 0,
            'other': 0,
        }
        for vuln in vulns:
            text = ' '.join(str(vuln.get(k, '')) for k in ('type', 'vuln_type', 'description', 'evidence', 'cwe')).lower()
            matched = False
            if any(token in text for token in ('buffer', 'overflow', 'gets', 'strcpy', 'read (buffer-overflow)')):
                counts['buffer_overflow'] += 1
                matched = True
            if 'format' in text:
                counts['format_string'] += 1
                matched = True
            if any(token in text for token in ('system', 'command', 'cmd', 'shell')):
                counts['command_injection'] += 1
                matched = True
            if any(token in text for token in ('info-leak', 'leak', 'puts')):
                counts['info_leak'] += 1
                matched = True
            if any(token in text for token in ('memory', 'uaf', 'double-free', 'heap', 'stack')):
                counts['memory_corruption'] += 1
                matched = True
            if not matched:
                counts['other'] += 1

        if self._is_zh():
            labels = [
                ('缓冲区溢出', counts['buffer_overflow']),
                ('格式化字符串', counts['format_string']),
                ('命令执行/命令注入', counts['command_injection']),
                ('信息泄露', counts['info_leak']),
                ('内存破坏', counts['memory_corruption']),
                ('其他', counts['other']),
            ]
        else:
            labels = [
                ('Buffer overflow', counts['buffer_overflow']),
                ('Format string', counts['format_string']),
                ('Command execution/injection', counts['command_injection']),
                ('Information leak', counts['info_leak']),
                ('Memory corruption', counts['memory_corruption']),
                ('Other', counts['other']),
            ]
        return '\n'.join(f"- {name}: {value}" for name, value in labels if value)

    def _looks_like_r2_pseudocode(self, code: str) -> bool:
        if not code:
            return False
        indicators = ('esp', 'ebp', 'eax', 'ebx', 'ecx', 'edx', 'push  (', 'pop  ()', 'goto loc_', 'loc_0x', 'sym.imp.', 're\n', 'leav')
        hits = sum(1 for token in indicators if token in code)
        return hits >= 3

    def _select_reverse_code(self, item: Dict[str, Any]) -> Tuple[str, str, str]:
        pseudo = (item.get('pseudocode') or item.get('code') or '').strip()
        asm = (item.get('raw_asm') or item.get('asm') or '').strip()
        if pseudo and not self._looks_like_r2_pseudocode(pseudo):
            return pseudo, 'pseudocode', 'c'
        if asm:
            return asm, 'assembly', 'asm'
        if pseudo:
            return pseudo, 'assembly', 'asm'
        return '', 'none', ''

    def _format_decompilation_data(self) -> str:
        # Render reverse evidence as text: pseudo-C first, assembly fallback.
        results = self.report_data.decompilation_results or self.report_data.decompilation_evidence
        if not results:
            return "无逆向证据。" if self._is_zh() else "No reverse-engineering evidence available."

        lines = []
        for result in results[:5]:
            func_name = result.get('function_name') or result.get('name') or self._unknown()
            code, code_kind, fence = self._select_reverse_code(result)
            address = result.get('address', 0) or 0
            size = result.get('size', 0) or 0

            if self._is_zh():
                lines.append(f"## 函数: {func_name}")
                lines.append(f"- 地址: {hex(address)}")
                lines.append(f"- 大小: {size} 字节")
                if code:
                    label = "伪 C 代码" if code_kind == 'pseudocode' else "汇编代码"
                    lines.append(f"- 证据类型: {label}")
                    lines.append(f"```{fence}\n{code[:1200]}\n```")
                else:
                    lines.append("- 证据类型: 未获取到伪 C 或汇编代码")
            else:
                lines.append(f"## Function: {func_name}")
                lines.append(f"- Address: {hex(address)}")
                lines.append(f"- Size: {size} bytes")
                if code:
                    label = "Pseudo-C" if code_kind == 'pseudocode' else "Assembly"
                    lines.append(f"- Evidence Type: {label}")
                    lines.append(f"```{fence}\n{code[:1200]}\n```")
                else:
                    lines.append("- Evidence Type: no pseudo-C or assembly captured")
            lines.append("")

        if len(results) > 5:
            if self._is_zh():
                lines.append(f"... 以及另外 {len(results) - 5} 个函数")
            else:
                lines.append(f"... and {len(results) - 5} more functions")

        return '\n'.join(lines)

    def _format_exploit_data(self) -> str:
        """Render exploit generation results as text."""
        data = self.report_data.exploit_generation_results
        if not data:
            return "无利用生成数据。" if self._is_zh() else "No exploit generation data available."

        lines = []
        if self._is_zh():
            lines.append(f"- 成功: {self._yes_no(bool(data.get('success')))}")
            lines.append(f"- 迭代次数: {len(data.get('iterations', [])) + 1}")
            if data.get('script_path'):
                lines.append(f"- 脚本路径: {data['script_path']}")
            if data.get('script_content'):
                lines.append(f"- 脚本预览:\n{data['script_content'][:300]}")
        else:
            lines.append(f"- Success: {self._yes_no(bool(data.get('success')))}")
            lines.append(f"- Iterations: {len(data.get('iterations', [])) + 1}")
            if data.get('script_path'):
                lines.append(f"- Script Path: {data['script_path']}")
            if data.get('script_content'):
                lines.append(f"- Script Preview:\n{data['script_content'][:300]}")

        return '\n'.join(lines)

    def _format_crash_data(self) -> str:
        """Render crash analysis results as text."""
        data = self.report_data.crash_analysis_results
        if not data:
            return "无崩溃分析数据。" if self._is_zh() else "No crash analysis data available."

        combined = data.get('combined', {})
        lines = []
        if self._is_zh():
            lines.append(f"- 崩溃类型: {combined.get('crash_type', self._unknown())}")
            lines.append(f"- 漏洞类型: {combined.get('vulnerability_type', self._unknown())}")
            lines.append(f"- 可利用性: {combined.get('exploitability', self._unknown())}")
            lines.append(f"- 难度: {combined.get('difficulty', self._unknown())}")
            if combined.get('analysis'):
                lines.append(f"- 分析: {combined['analysis'][:200]}")
        else:
            lines.append(f"- Crash Type: {combined.get('crash_type', self._unknown())}")
            lines.append(f"- Vulnerability Type: {combined.get('vulnerability_type', self._unknown())}")
            lines.append(f"- Exploitability: {combined.get('exploitability', self._unknown())}")
            lines.append(f"- Difficulty: {combined.get('difficulty', self._unknown())}")
            if combined.get('analysis'):
                lines.append(f"- Analysis: {combined['analysis'][:200]}")

        return '\n'.join(lines)

    def _format_symbolic_data(self) -> str:
        # Render symbolic execution results as text.
        data = self.report_data.symbolic_execution_results
        if not data:
            return "无符号执行数据。" if self._is_zh() else "No symbolic execution data available."

        lines = []
        if self._is_zh():
            lines.append(f"- 成功: {self._yes_no(bool(data.get('success')))}")
            if data.get('crash_path', {}).get('found'):
                lines.append("- 崩溃路径: 已发现")
                lines.append(f"  - 目标: {data['crash_path'].get('target_address', self._na())}")
            if data.get('stack_offset'):
                lines.append(f"- 栈偏移: {data['stack_offset'].get('offset', self._na())}")
        else:
            lines.append(f"- Success: {self._yes_no(bool(data.get('success')))}")
            if data.get('crash_path', {}).get('found'):
                lines.append("- Crash path: Found")
                lines.append(f"  - Target: {data['crash_path'].get('target_address', self._na())}")
            if data.get('stack_offset'):
                lines.append(f"- Stack Offset: {data['stack_offset'].get('offset', self._na())}")

        return '\n'.join(lines)

    def _format_supply_chain_data(self) -> str:
        # Render supply chain data as text.
        data = self.report_data.supply_chain_data
        if not data:
            return "无供应链数据。" if self._is_zh() else "No supply chain data available."

        lines = []
        if data.get('dependencies'):
            if self._is_zh():
                lines.append(f"- 依赖数量: {len(data['dependencies'])}")
            else:
                lines.append(f"- Dependencies: {len(data['dependencies'])}")
            for dep in data['dependencies'][:5]:
                lines.append(f"  - {dep.get('name', self._unknown())} ({dep.get('version', self._unknown())})")
            if len(data['dependencies']) > 5:
                if self._is_zh():
                    lines.append(f"  ... 以及另外 {len(data['dependencies']) - 5} 个")
                else:
                    lines.append(f"  ... and {len(data['dependencies']) - 5} more")
        if data.get('vulnerable_components'):
            if self._is_zh():
                lines.append(f"- 脆弱组件: {len(data['vulnerable_components'])}")
            else:
                lines.append(f"- Vulnerable Components: {len(data['vulnerable_components'])}")

        if not lines:
            return "供应链数据为空。" if self._is_zh() else "Supply chain data is empty."

        return '\n'.join(lines)

    def _format_threat_intel_data(self) -> str:
        # Render threat intelligence data as text.
        data = self.report_data.threat_intelligence
        if not data:
            return "无威胁情报数据。" if self._is_zh() else "No threat intelligence data available."

        lines = []
        for intel in data[:3]:
            provider = intel.get('provider', self._unknown())
            lines.append(f"## {provider}")
            if self._is_zh():
                lines.append(f"- 查询类型: {intel.get('query_type', self._na())}")
                lines.append(f"- 是否恶意: {self._yes_no(bool(intel.get('is_malicious')))}")
                lines.append(f"- 置信度: {intel.get('confidence', 0) * 100:.1f}%")
                if intel.get('malware_families'):
                    families = intel['malware_families'][:3]
                    lines.append(f"- 恶意软件家族: {', '.join(families)}")
            else:
                lines.append(f"- Query Type: {intel.get('query_type', self._na())}")
                lines.append(f"- Is Malicious: {self._yes_no(bool(intel.get('is_malicious')))}")
                lines.append(f"- Confidence: {intel.get('confidence', 0) * 100:.1f}%")
                if intel.get('malware_families'):
                    families = intel['malware_families'][:3]
                    lines.append(f"- Malware Families: {', '.join(families)}")

        if not lines:
            return "威胁情报数据为空。" if self._is_zh() else "Threat intelligence data is empty."

        return '\n'.join(lines)
    def _deduplicate_vulnerabilities(self) -> None:
        if not self.report_data:
            return
        unique = []
        seen = set()
        for vuln in self.report_data.vulnerability_list or []:
            key = (
                str(vuln.get('type') or vuln.get('vuln_type') or '').strip().lower(),
                str(vuln.get('function_name') or vuln.get('function') or '').strip().lower(),
                str(vuln.get('location') or '').strip().lower(),
                str(vuln.get('imported_function') or '').strip().lower(),
                str(vuln.get('description') or '').strip().lower(),
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(vuln)
        self.report_data.vulnerability_list = unique

    def _decompilation_items(self) -> List[Dict[str, Any]]:
        return self.report_data.decompilation_results or self.report_data.decompilation_evidence or []

    def _decompilation_count(self) -> int:
        return len(self._decompilation_items())

    def _format_remediation_guidance(self) -> str:
        vulns = self.report_data.vulnerability_list or []
        imports = (self.report_data.binary_info.get('imports', {}) or {})
        dangerous = imports.get('dangerous_functions', []) or []
        decomp = self._decompilation_items()
        if self._is_zh():
            lines = ["### 按证据修复", ""]
            if not vulns and not dangerous:
                lines.append("当前报告没有可用于生成修复建议的漏洞证据。")
            else:
                for i, vuln in enumerate(vulns[:8], 1):
                    vtype = vuln.get('type') or vuln.get('vuln_type') or self._unknown()
                    fn = vuln.get('function_name') or vuln.get('function') or self._na()
                    desc = vuln.get('description') or vuln.get('evidence') or ''
                    lines.append(f"{i}. **{vtype} / {fn}**")
                    if desc:
                        lines.append(f"   - 证据: {desc[:220]}")
                    lines.append(f"   - 建议: 先确认该告警在反编译代码中的调用点和参数来源；只对已确认可达的路径做代码级修复。")
                if dangerous:
                    lines.append("")
                    lines.append("### 危险导入函数处置")
                    for name in sorted(set(dangerous)):
                        if name == 'system':
                            lines.append("- `system`: 避免拼接命令字符串；改用固定命令白名单或 `execve` 参数数组，并过滤用户可控输入。")
                        elif name == 'read':
                            lines.append("- `read`: 第三个参数必须小于等于目标缓冲区容量；返回值需要检查，禁止继续处理未终止字符串。")
                        elif name in ('gets', 'strcpy', 'strcat', 'sprintf'):
                            lines.append(f"- `{name}`: 高风险无边界 API，替换为带长度参数的实现并补充边界检查。")
                        elif name in ('printf', 'fprintf'):
                            lines.append(f"- `{name}`: 格式字符串必须为常量，用户输入只能作为参数传入。")
                        else:
                            lines.append(f"- `{name}`: 结合反编译调用点复核参数边界和用户输入可控性。")
            lines.append("")
            lines.append("### 代码修复参考")
            if decomp:
                lines.append("以下为逆向证据摘录：优先伪 C；没有伪 C 时使用汇编。不直接伪造补丁，请基于源码或等价逻辑修复。")
                for item in decomp[:2]:
                    fn = item.get('function_name') or item.get('name') or self._unknown()
                    code, code_kind, fence = self._select_reverse_code(item)
                    label = '伪 C 代码' if code_kind == 'pseudocode' else '汇编代码'
                    if code:
                        lines.append(f"\n**{fn} ({label}):**")
                        lines.append(f"```{fence}")
                        lines.append(code[:800])
                        lines.append("```")
            else:
                lines.append("未获取到伪 C 或汇编代码，因此不生成固定示例补丁，避免误导。请先安装/配置 radare2 或 Ghidra 并重新运行分析。")
            return '\n'.join(lines)

        lines = ["### Evidence-based fixes", ""]
        if not vulns and not dangerous:
            lines.append("No vulnerability evidence is available for remediation guidance.")
        else:
            for i, vuln in enumerate(vulns[:8], 1):
                vtype = vuln.get('type') or vuln.get('vuln_type') or self._unknown()
                fn = vuln.get('function_name') or vuln.get('function') or self._na()
                desc = vuln.get('description') or vuln.get('evidence') or ''
                lines.append(f"{i}. **{vtype} / {fn}**")
                if desc:
                    lines.append(f"   - Evidence: {desc[:220]}")
                lines.append("   - Recommendation: confirm the reachable call site and tainted arguments before applying code-level fixes.")
            if dangerous:
                lines.append("")
                lines.append("### Dangerous import handling")
                for name in sorted(set(dangerous)):
                    lines.append(f"- `{name}`: review call-site reachability, argument bounds, and user-control before remediation.")
        lines.append("")
        lines.append("### Code fix reference")
        if decomp:
            lines.append("Reverse evidence excerpt: pseudo-C first, assembly fallback; no synthetic patch is generated:")
            for item in decomp[:2]:
                fn = item.get('function_name') or item.get('name') or self._unknown()
                code, code_kind, fence = self._select_reverse_code(item)
                label = 'Pseudo-C' if code_kind == 'pseudocode' else 'Assembly'
                if code:
                    lines.append(f"\n**{fn} ({label}):**")
                    lines.append(f"```{fence}")
                    lines.append(code[:800])
                    lines.append("```")
        else:
            lines.append("No pseudo-C or assembly evidence was captured, so no fixed example patch is emitted.")
        return '\n'.join(lines)
    def _get_vulnerability_counts(self) -> Tuple[int, int, int, int]:
        # Aggregate vulnerability counts: (total, high+critical, medium, low).
        vulns = self.report_data.vulnerability_list
        critical = sum(1 for v in vulns if v.get('severity', '').lower() == 'critical')
        high = sum(1 for v in vulns if v.get('severity', '').lower() == 'high')
        medium = sum(1 for v in vulns if v.get('severity', '').lower() == 'medium')
        low = sum(1 for v in vulns if v.get('severity', '').lower() == 'low')
        return len(vulns), critical + high, medium, low

    def _has_supply_chain_data(self) -> bool:
        # Verify supply chain data exists and contains meaningful fields.
        data = self.report_data.supply_chain_data
        if not data:
            return False
        return bool(data.get('dependencies') or data.get('vulnerable_components'))

    def _has_threat_intel_data(self) -> bool:
        # Verify threat intelligence data exists and contains at least one valid entry.
        data = self.report_data.threat_intelligence
        if not data:
            return False
        return any(intel.get('provider') for intel in data)

    def _generate_section_content(self, section: ReportSection) -> str:
        """
        Generate content for a single report section.
        """
        logger.info(f"Generating section: {section.name}")

        if not self.report_data:
            return ""

        # Derive vulnerability stats.
        total_vulns, high_count, medium_count, low_count = self._get_vulnerability_counts()

        # Assemble prompt parameters.
        params = {
            'binary_summary': self._format_binary_summary(),
            'binary_info': self._format_binary_info(),
            'vuln_count': total_vulns,
            'high_vuln_count': high_count,
            'medium_vuln_count': medium_count,
            'low_vuln_count': low_count,
            'vulnerability_data': self._format_vulnerability_data(),
            'vulnerability_summary': self._format_vulnerability_summary(),
            'vulnerability_type_summary': self._format_vulnerability_type_summary(),
            'decompilation_data': self._format_decompilation_data(),
            'decompilation_count': self._decompilation_count(),
            'remediation_guidance': self._format_remediation_guidance(),
            'exploit_data': self._format_exploit_data(),
            'crash_data': self._format_crash_data(),
            'symbolic_data': self._format_symbolic_data(),
            'supply_chain_data': self._format_supply_chain_data(),
            'supply_chain_info': self._format_supply_chain_data(),
            'threat_intel_data': self._format_threat_intel_data(),
            'threat_intel_info': self._format_threat_intel_data(),
            'decompilation_status': 'Completed' if (self.report_data.decompilation_results or self.report_data.decompilation_evidence) else 'Not executed',
            'symbolic_execution_status': 'Completed' if self.report_data.symbolic_execution_results else 'Not executed',
            'crash_analysis_status': 'Completed' if self.report_data.crash_analysis_results else 'Not executed',
            'exploit_generation_status': 'Completed' if self.report_data.exploit_generation_results else 'Not executed',
        }

        # simulation 模式走模板输出; 非模拟则保留模板但去除 simulation 标注
        content = self._simulate_llm_response(section, params)
        if self._simulation:
            if self.config.language == 'zh':
                content += "\n\n> **[simulation=true]** 本节内容由模板生成，未经 LLM 研判。"
            else:
                content += "\n\n> **[simulation=true]** This section was generated from templates and was not reviewed by an LLM."
        return content

    def _simulate_llm_response(self, section: ReportSection, params: Dict[str, str]) -> str:
        """
        Simulate LLM response for demonstration and testing.
        """
        if self.config.language == 'zh':
            return self._simulate_llm_response_zh(section, params)
        else:
            return self._simulate_llm_response_en(section, params)

    def _simulate_llm_response_zh(self, section: ReportSection, params: Dict[str, str]) -> str:
        """Simulated Chinese LLM output."""
        target = self.report_data.binary_info.get('binary_path') or self.report_data.binary_info.get('path') or '未知'
        nx_state = '启用' if self.report_data.binary_info.get('checksec', {}).get('nx') else '关闭'
        pie_state = '启用' if self.report_data.binary_info.get('checksec', {}).get('pie') else '关闭'
        risk_level = '严重' if params['high_vuln_count'] > 0 else '中等'
        exploitability = '可利用性较高' if self.report_data.exploit_generation_results.get('success') else '利用难度中等，需要进一步验证'
        responses = {
            ReportSection.EXECUTIVE_SUMMARY: f"""
## 执行摘要

对二进制文件 `{target}` 进行了逆向工程与安全分析。

### 关键发现

**漏洞统计**: 共 {params['vuln_count']} 个；高危 {params['high_vuln_count']} 个，中危 {params['medium_vuln_count']} 个，低危 {params['low_vuln_count']} 个。

**保护机制状态**: NX {nx_state}；PIE/ASLR {pie_state}。

### 风险评估

该二进制当前风险等级为 **{risk_level}**。建议优先处理高危漏洞并复核关键攻击面。

### 核心建议

1. 优先修复高危漏洞
2. 强化二进制保护机制
3. 对关键函数进行人工复核和回归测试
""",
            ReportSection.BINARY_INFO: f"""
## 二进制文件信息

### 基本属性

{params['binary_info']}

### 分析细节

格式: {self.report_data.binary_info.get('format', '未知')}；架构: {self.report_data.binary_info.get('arch', '未知')}。NX {nx_state}，PIE {pie_state}。

### 危险导入函数

以上危险导入函数只代表潜在攻击面，需要结合反编译调用点确认可达性、参数来源和边界检查情况。
""",
            ReportSection.REVERSE_PROCESS: f"""
## 逆向分析过程

### 概览

已处理 {params['decompilation_count']} 个函数。

### 函数分析

{params['decompilation_data']}

### 代码结构

关键结构以函数分析中的反编译证据为准；未获取到伪代码时，不推断具体危险调用或缓冲区形态。

### 调用关系

已整理函数调用关系，并标记需要重点复核的控制流与数据流路径。
""",
            ReportSection.VULNERABILITY_DETAILS: f"""
## 漏洞详情

### 漏洞列表

{params['vulnerability_data']}

### 分类统计

漏洞类型分布：
{params['vulnerability_type_summary']}

### 影响摘要

每个漏洞均需结合触发条件、可达性、利用难度和影响范围进行复核。
""",
            ReportSection.EXPLOIT_ANALYSIS: f"""
## 利用分析

### 利用生成结果

{params['exploit_data']}

### 崩溃分析

{params['crash_data']}

### 符号执行分析

{params['symbolic_data']}

### 可利用性结论

{exploitability}。建议继续补充触发样例、偏移信息和真实环境验证。
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

该二进制当前风险等级为 **{risk_level}**。潜在影响包括：
- 权限提升
- 敏感数据泄露
- 拒绝服务

建议尽快修复并进行回归验证。
""",
            ReportSection.REMEDIATION_RECOMMENDATIONS: f"""
## 修复建议

{params['remediation_guidance']}

### 加固措施

1. 编译时启用 NX、PIE、RELRO、Canary 等保护
2. 在 CI 中加入 AddressSanitizer 和 fuzz 测试
3. 对关键函数进行周期性人工审计
4. 建立安全开发生命周期（SDL）
""",
            ReportSection.SUPPLY_CHAIN_ANALYSIS: f"""
## 供应链分析

### 依赖信息

{params['supply_chain_data']}

### 风险评估

第三方组件可能引入安全风险。建议：

1. 定期跟踪并更新依赖
2. 监控所有依赖库的安全公告
3. 维护软件物料清单（SBOM）
4. 审核开源许可证合规性
""",
            ReportSection.THREAT_INTELLIGENCE: f"""
## 威胁情报关联

### 情报结果

{params['threat_intel_data']}

### 关联分析

当前未发现与已知恶意软件家族或 APT 组织的直接关联。

### IOC 指标

建议将相关威胁指标纳入安全监控与持续检测流程。
"""
        }
        return responses.get(section, "")
    def _simulate_llm_response_en(self, section: ReportSection, params: Dict[str, str]) -> str:
        """Simulated English LLM output."""
        responses = {
            ReportSection.EXECUTIVE_SUMMARY: f"""
## Executive Summary

Comprehensive reverse engineering analysis of binary `{self.report_data.binary_info.get('binary_path') or self.report_data.binary_info.get('path') or 'unknown'}`.

### Key Findings

**Vulnerability Statistics**: {params['vuln_count']} total — {params['high_vuln_count']} high, {params['medium_vuln_count']} medium, {params['low_vuln_count']} low.

**Protection Mechanisms**: NX {'enabled' if self.report_data.binary_info.get('checksec', {}).get('nx') else 'disabled'}; PIE ASLR {'enabled' if self.report_data.binary_info.get('checksec', {}).get('pie') else 'disabled'}.

### Risk Assessment

Overall assessment: {'severe' if params['high_vuln_count'] > 0 else 'moderate'} risk. Immediate remediation recommended.

### Core Recommendations

1. Prioritize high-severity vulnerability fixes
2. Harden binary protection mechanisms
3. Conduct regular security audits
""",
            ReportSection.BINARY_INFO: f"""
## Binary Information

### Basic Information

{params['binary_info']}

### Detailed Analysis

Format: {self.report_data.binary_info.get('format', 'unknown')}; Architecture: {self.report_data.binary_info.get('arch', 'unknown')}. NX {'enabled' if self.report_data.binary_info.get('checksec', {}).get('nx') else 'disabled'}, PIE {'enabled' if self.report_data.binary_info.get('checksec', {}).get('pie') else 'disabled'}.

### Dangerous Functions

Imported dangerous functions indicate potential attack surface only; reachability, argument sources, and boundary checks must be confirmed at decompiled call sites.
""",
            ReportSection.REVERSE_PROCESS: f"""
## Reverse Engineering Process

### Overview

{params['decompilation_count']} functions processed.

### Function Analysis

{params['decompilation_data']}

### Code Structure

Key structure is based on the decompilation evidence above; when pseudocode is unavailable, no specific dangerous call or buffer layout is inferred.

### Call Relationships

Function call relationships mapped; critical control flow and data flow patterns identified.
""",
            ReportSection.VULNERABILITY_DETAILS: f"""
## Vulnerability Details

### Vulnerability List

{params['vulnerability_data']}

### Classification

Vulnerability type distribution:
{params['vulnerability_type_summary']}

### Impact Summary

Each vulnerability assessed for exploitability, attack scenarios, and affected scope.
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

{'High exploitability potential' if self.report_data.exploit_generation_results.get('success') else 'Moderate exploit difficulty'}. Further exploit development and validation testing recommended.
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

This binary presents {'severe' if params['high_vuln_count'] > 0 else 'moderate'} risk. Exploitation could lead to:
- Privilege escalation
- Sensitive data leakage
- Denial of service

Immediate remediation strongly recommended.
""",
            ReportSection.REMEDIATION_RECOMMENDATIONS: f"""
## Remediation Recommendations

{params['remediation_guidance']}

### Security Hardening

1. Compile with all security flags enabled
2. Integrate AddressSanitizer in CI
3. Schedule periodic code reviews
4. Implement Secure Development Lifecycle (SDL)
""",
            ReportSection.SUPPLY_CHAIN_ANALYSIS: f"""
## Supply Chain Analysis

### Dependency Analysis

{params['supply_chain_data']}

### Risk Assessment

Third-party components carry security risk. Recommendations:

1. Track and update dependencies regularly
2. Monitor security advisories for all libraries
3. Maintain a Software Bill of Materials (SBOM)
4. Audit open-source license compliance
""",
            ReportSection.THREAT_INTELLIGENCE: f"""
## Threat Intelligence Correlation

### Intelligence Analysis Results

{params['threat_intel_data']}

### Correlation Analysis

No direct association with known malware families or APT groups found.

### IOC Indicators

Threat indicators should be ingested into security monitoring for continuous surveillance.
"""
        }
        return responses.get(section, "")

    def generate_report(self) -> str:
        """
        Generate the full reverse engineering report.
        """
        logger.info("Generating reverse engineering report...")

        if not self.report_data:
            logger.error("Report data not set")
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

        # Optional sections: only when the config flag is on AND actual data exists.
        if self.config.include_supply_chain and self._has_supply_chain_data():
            sections.append(ReportSection.SUPPLY_CHAIN_ANALYSIS)

        if self.config.include_threat_intel and self._has_threat_intel_data():
            sections.append(ReportSection.THREAT_INTELLIGENCE)

        report_parts = []

        # Header block.
        lang = self.config.language
        report_parts.append(f"# {'二进制逆向工程报告' if lang == 'zh' else 'Binary Reverse Engineering Report'}")
        report_parts.append("")
        report_parts.append(f"{'生成时间' if lang == 'zh' else 'Generated on'}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        target_path = self.report_data.binary_info.get('binary_path') or self.report_data.binary_info.get('path') or 'N/A'
        report_parts.append(f"{'目标文件' if lang == 'zh' else 'Target File'}: {target_path}")
        report_parts.append("")
        report_parts.append("---")
        report_parts.append("")

        # Section generation.
        simulation = self._simulation
        for section in sections:
            content = self._generate_section_content(section)
            if content:
                report_parts.append(content)
                report_parts.append("")
                report_parts.append("---")
                report_parts.append("")

        # Footer.
        report_parts.append("")
        # simulation 标记 — 模拟模式如实标注
        if lang == 'zh':
            sim_label = "[simulation=true]" if simulation else "[LLM 分析完成]"
            report_parts.append(f"*由二进制漏洞分析工具自动生成 {sim_label}*")
        else:
            sim_label = "[simulation=true]" if simulation else "[LLM analysis completed]"
            report_parts.append(f"*Auto-generated by Binary Vulnerability Analysis Tool {sim_label}*")

        return '\n'.join(report_parts)

    def save_report(self, filename: Optional[str] = None) -> str:
        """
        Save report to file.
        """
        report_content = self.generate_report()

        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_name = os.path.splitext(os.path.basename(
                (self.report_data.binary_info.get('binary_path') or self.report_data.binary_info.get('path') or 'unknown')
            ))[0]
            filename = f"reverse_report_{base_name}_{timestamp}.md"

        output_path = os.path.join(self.config.output_dir, filename)

        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            logger.info(f"Report saved: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            return ""

    def generate_json_report(self) -> str:
        """
        Generate JSON-format report data.
        """
        report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'language': self.config.language,
                'binary_path': self.report_data.binary_info.get('binary_path') or self.report_data.binary_info.get('path')
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
            'vulnerability_details': [
                {
                    'function': v.get('function_name', v.get('function', '')),
                    'type': v.get('type', v.get('vuln_type', '')),
                    'severity': v.get('severity', ''),
                    'location': v.get('location', ''),
                    'review_status': v.get('review_status', 'pending'),
                    'tier': v.get('tier', 'lead'),
                    'description': v.get('description', ''),
                }
                for v in self.report_data.vulnerability_list
            ],
            'simulation': self._simulation,
            'decompilation_evidence': self.report_data.decompilation_evidence,
            'crash_log': self.report_data.crash_log,
            'analysis_phases': {
                'decompilation': bool(self.report_data.decompilation_results),
                'symbolic_execution': bool(self.report_data.symbolic_execution_results),
                'crash_analysis': bool(self.report_data.crash_analysis_results),
                'exploit_generation': bool(self.report_data.exploit_generation_results)
            }
        }

        return json.dumps(report_data, indent=2, ensure_ascii=False)


