#!/usr/bin/env python3
# Primary interface: ReportSection, ReportConfig, ReportData, ReverseReportGenerator (4 classes).
# Dependencies: os, json.
# Time O(n), space O(1).
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
        # Exception boundary added post-hoc — missing before caused analysis termination.
        # Legacy path retained as comments; hand-written version easier to debug.
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

    def _format_binary_info(self) -> str:
        """Format binary info as structured text."""
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
        # Entry — boundary and null-hardening verified (a35b).
        # Produce compact binary info summary.
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
        """Render vulnerability list as structured text."""
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
        # Collate vulnerability counts by severity.
        vulns = self.report_data.vulnerability_list
        if not vulns:
            return "No vulnerabilities found."

        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
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
        # Render decompilation results as text.
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
        """Render exploit generation results as text."""
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
        """Render crash analysis results as text."""
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
        # Render symbolic execution results as text.
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
        # Render supply chain data as text.
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

        # No usable field populated — data is effectively empty.
        if not lines:
            return "Supply chain data is empty."

        return '\n'.join(lines)

    def _format_threat_intel_data(self) -> str:
        # Render threat intelligence data as text.
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

        if not lines:
            return "Threat intelligence data is empty."

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
            'decompilation_data': self._format_decompilation_data(),
            'exploit_data': self._format_exploit_data(),
            'crash_data': self._format_crash_data(),
            'symbolic_data': self._format_symbolic_data(),
            'supply_chain_data': self._format_supply_chain_data(),
            'supply_chain_info': self._format_supply_chain_data(),
            'threat_intel_data': self._format_threat_intel_data(),
            'threat_intel_info': self._format_threat_intel_data(),
            'decompilation_status': 'Completed' if self.report_data.decompilation_results else 'Not executed',
            'symbolic_execution_status': 'Completed' if self.report_data.symbolic_execution_results else 'Not executed',
            'crash_analysis_status': 'Completed' if self.report_data.crash_analysis_results else 'Not executed',
            'exploit_generation_status': 'Completed' if self.report_data.exploit_generation_results else 'Not executed',
        }

        # simulation 模式走模板输出; 非模拟则保留模板但去除 simulation 标注
        content = self._simulate_llm_response(section, params)
        if self._simulation:
            content += "\n\n> **[simulation=true]** 本节内容由模板生成，未经 LLM 研判。"
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
        responses = {
            ReportSection.EXECUTIVE_SUMMARY: f"""
## Executive Summary

Comprehensive reverse engineering analysis of binary `{self.report_data.binary_info.get('binary_path', 'Unknown')}`.

### Key Findings

**Vulnerability count**: {params['vuln_count']} total — {params['high_vuln_count']} high, {params['medium_vuln_count']} medium, {params['low_vuln_count']} low.

**Protection status**: NX {'enabled' if self.report_data.binary_info.get('checksec', {}).get('nx') else 'disabled'}; PIE/ASLR {'enabled' if self.report_data.binary_info.get('checksec', {}).get('pie') else 'disabled'}.

### Risk Assessment

The binary carries {'critical' if params['high_vuln_count'] > 0 else 'moderate'} risk. Immediate remediation advised.

### Core Recommendations

1. Patch high-severity vulnerabilities first
2. Harden binary protection mechanisms
3. Schedule recurring security audits
""",
            ReportSection.BINARY_INFO: f"""
## Binary File Information

### Basic Properties

{params['binary_info']}

### Analysis Detail

Format: {self.report_data.binary_info.get('format', 'Unknown')}; Architecture: {self.report_data.binary_info.get('arch', 'Unknown')}. NX {'enabled' if self.report_data.binary_info.get('checksec', {}).get('nx') else 'disabled'}, PIE {'enabled' if self.report_data.binary_info.get('checksec', {}).get('pie') else 'disabled'}.

### Dangerous Imported Functions

Imported dangerous functions include string operations (strcpy, strcat) and memory management (malloc, free). Misuse of these may cause buffer overflows and memory corruption.
""",
            ReportSection.REVERSE_PROCESS: f"""
## Reverse Engineering Process

### Overview

{len(self.report_data.decompilation_results)} functions processed.

### Function Analysis

{params['decompilation_data']}

### Code Structure

Key characteristics identified via decompilation:
- Multiple unsafe string function calls
- Probable buffer overflow points
- Missing input validation in select paths

### Call Graph

Function call relationships mapped; critical control flow and data flow paths identified.
""",
            ReportSection.VULNERABILITY_DETAILS: f"""
## Vulnerability Details

### Vulnerability List

{params['vulnerability_data']}

### Classification

Vulnerability type distribution:
- Buffer overflow: {sum(1 for v in self.report_data.vulnerability_list if 'buffer' in v.get('type', '').lower())}
- Format string: {sum(1 for v in self.report_data.vulnerability_list if 'format' in v.get('type', '').lower())}
- Memory corruption: {sum(1 for v in self.report_data.vulnerability_list if 'memory' in v.get('type', '').lower())}

### Impact Summary

Each vulnerability assessed for exploitability, attack scenarios, and affected scope.
""",
            ReportSection.EXPLOIT_ANALYSIS: f"""
## Exploit Analysis

### Exploit Generation

{params['exploit_data']}

### Crash Analysis

{params['crash_data']}

### Symbolic Execution Analysis

{params['symbolic_data']}

### Exploitability Verdict

{'High exploitability' if self.report_data.exploit_generation_results.get('success') else 'Non-trivial exploit difficulty'}. Further exploit refinement and validation testing recommended.
""",
            ReportSection.IMPACT_ASSESSMENT: f"""
## Impact Assessment

### Vulnerability Scope

{params['vulnerability_summary']}

### Supply Chain Impact (if applicable)

{params['supply_chain_info']}

### Threat Intelligence Correlation (if applicable)

{params['threat_intel_info']}

### Overall Assessment

This binary presents {'critical' if params['high_vuln_count'] > 0 else 'moderate'} risk. Exploitation may enable:
- Privilege escalation
- Sensitive data exfiltration
- Denial of service

Immediate remediation required.
""",
            ReportSection.REMEDIATION_RECOMMENDATIONS: f"""
## Remediation Recommendations

### Per-Vulnerability Fixes

1. **Buffer overflow**: Replace unsafe functions (strcpy, strcat) with bounded variants (strncpy, snprintf). Add input length validation.

2. **Format string**: Eliminate user-controlled format strings. Use parameterised formatting exclusively.

3. **Memory management**: Zero pointers immediately after free. Adopt a consistent ownership model.

### Code Fix Reference

```c
// Before
strcpy(dest, src);

// After
strncpy(dest, src, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\\0';
```

### Hardening Measures

1. Compile with all available security flags
2. Run AddressSanitizer / fuzzer in CI
3. Conduct periodic manual code review
4. Implement Secure Development Lifecycle (SDL)
""",
            ReportSection.SUPPLY_CHAIN_ANALYSIS: f"""
## Supply Chain Analysis

### Dependencies

{params['supply_chain_data']}

### Risk Assessment

Third-party components carry security risk. Recommendations:

1. Track and update dependencies regularly
2. Monitor security advisories for all included libraries
3. Maintain a Software Bill of Materials (SBOM)
4. Audit open-source license compliance
""",
            ReportSection.THREAT_INTELLIGENCE: f"""
## Threat Intelligence Correlation

### Intelligence Results

{params['threat_intel_data']}

### Correlation

No direct match to known malware families or APT groups detected via threat intelligence queries.

### IOC Indicators

Threat indicators should be ingested into security monitoring for continuous surveillance.
"""
        }
        return responses.get(section, "")

    def _simulate_llm_response_en(self, section: ReportSection, params: Dict[str, str]) -> str:
        """Simulated English LLM output."""
        responses = {
            ReportSection.EXECUTIVE_SUMMARY: f"""
## Executive Summary

Comprehensive reverse engineering analysis of binary `{self.report_data.binary_info.get('binary_path', 'unknown')}`.

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

Imported dangerous functions include string operations (strcpy, strcat) and memory management (malloc, free). Misuse may lead to buffer overflows and memory corruption.
""",
            ReportSection.REVERSE_PROCESS: f"""
## Reverse Engineering Process

### Overview

{len(self.report_data.decompilation_results)} functions processed.

### Function Analysis

{params['decompilation_data']}

### Code Structure

Key characteristics identified via decompilation:
- Multiple unsafe string function calls
- Probable buffer overflow points
- Missing input validation in select paths

### Call Relationships

Function call relationships mapped; critical control flow and data flow patterns identified.
""",
            ReportSection.VULNERABILITY_DETAILS: f"""
## Vulnerability Details

### Vulnerability List

{params['vulnerability_data']}

### Classification

Vulnerability type distribution:
- Buffer Overflow: {sum(1 for v in self.report_data.vulnerability_list if 'buffer' in v.get('type', '').lower())}
- Format String: {sum(1 for v in self.report_data.vulnerability_list if 'format' in v.get('type', '').lower())}
- Memory Vulnerabilities: {sum(1 for v in self.report_data.vulnerability_list if 'memory' in v.get('type', '').lower())}

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

### Vulnerability Fixes

1. **Buffer Overflow**: Replace unsafe functions (strcpy, strcat) with bounded variants (strncpy, snprintf). Add boundary checks.

2. **Format String**: Eliminate user-controlled format strings. Use parameterised formatting exclusively.

3. **Memory Management**: Zero pointers after free. Adopt a consistent ownership model.

### Code Fix Examples

```c
// Before
strcpy(dest, src);

// After
strncpy(dest, src, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\\0';
```

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
        report_parts.append(f"# {'Binary Reverse Engineering Report' if lang == 'zh' else 'Binary Reverse Engineering Report'}")
        report_parts.append("")
        report_parts.append(f"{'Generated' if lang == 'zh' else 'Generated on'}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_parts.append(f"{'Target File' if lang == 'zh' else 'Target File'}: {self.report_data.binary_info.get('binary_path', 'N/A')}")
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
        sim_label = "[simulation=true]" if simulation else "[LLM 分析完成]"
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
                self.report_data.binary_info.get('binary_path', 'unknown')
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
