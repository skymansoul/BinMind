#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动化漏洞根因解释模块

功能：
1. 检测到漏洞后，结合上下文与CWE生成CVE级根因分析报告
2. 分析漏洞的根本原因、攻击向量、影响范围
3. 提供修复建议和缓解措施

数据流：
1. 输入：漏洞检测结果（类型、位置、上下文代码、内存状态）
2. 处理：LLM分析漏洞上下文，匹配CWE，生成根因报告
3. 输出：结构化的根因分析报告

与其他模块的交互：
- 接收漏洞检测模块的结果
- 查询CWE数据库获取标准漏洞分类
- 输出报告供报告生成模块使用
"""

import logging
import os
import json
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

# 尝试导入可选依赖
OPENAI_AVAILABLE = False

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    logger.warning("OpenAI SDK未安装，将使用模拟模式")


class VulnerabilitySeverity(Enum):
    """漏洞严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Exploitability(Enum):
    """可利用性"""
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    UNKNOWN = "unknown"


@dataclass
class VulnerabilityContext:
    """漏洞上下文信息"""
    vulnerability_type: str
    function_name: str
    function_address: int
    binary_path: str
    pseudocode: str
    assembly: str
    crash_address: Optional[int] = None
    stack_trace: Optional[List[str]] = None
    memory_state: Optional[Dict[str, Any]] = None
    registers: Optional[Dict[str, int]] = None
    user_input: Optional[str] = None


@dataclass
class CWEMapping:
    """CWE映射"""
    cwe_id: str
    cwe_name: str
    description: str
    likelihood: float
    related_cwes: List[str] = field(default_factory=list)


@dataclass
class RootCauseAnalysis:
    """根因分析结果"""
    vulnerability_id: str
    vulnerability_type: str
    cwe_mappings: List[CWEMapping]
    root_cause: str
    attack_vector: str
    impact: str
    exploitability: Exploitability
    severity: VulnerabilitySeverity
    affected_components: List[str]
    reproduction_steps: List[str]
    mitigation: List[str]
    references: List[str]
    confidence: float


@dataclass
class AnalysisReport:
    """分析报告"""
    generated_at: float
    target_binary: str
    analysis_id: str
    vulnerabilities: List[RootCauseAnalysis]
    summary: Dict[str, Any] = field(default_factory=dict)


class CWEDatabase:
    """CWE数据库"""
    
    def __init__(self):
        self.cwe_database = self._load_cwe_database()
    
    def _load_cwe_database(self) -> Dict[str, Dict[str, Any]]:
        """加载CWE数据库"""
        return {
            'CWE-119': {
                'name': 'Buffer Overflow',
                'description': 'The software writes data past the end, or before the beginning, of the intended buffer.',
                'keywords': ['buffer', 'overflow', 'strcpy', 'strcat', 'memcpy', 'gets', 'sprintf']
            },
            'CWE-120': {
                'name': 'Buffer Copy without Checking Size of Input',
                'description': 'The program copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.',
                'keywords': ['buffer', 'copy', 'memcpy', 'strcpy', 'size', 'length']
            },
            'CWE-415': {
                'name': 'Double Free',
                'description': 'The software calls free() twice on the same memory address, potentially leading to memory corruption or execution of arbitrary code.',
                'keywords': ['free', 'double', 'memory', 'heap']
            },
            'CWE-416': {
                'name': 'Use After Free',
                'description': 'Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute arbitrary code.',
                'keywords': ['use after free', 'dangling', 'pointer', 'free']
            },
            'CWE-78': {
                'name': 'Command Injection',
                'description': 'The software constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command when it is sent to a downstream component.',
                'keywords': ['system', 'exec', 'command', 'shell', 'popen']
            },
            'CWE-89': {
                'name': 'SQL Injection',
                'description': 'The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.',
                'keywords': ['sql', 'query', 'database', 'select', 'insert']
            },
            'CWE-190': {
                'name': 'Integer Overflow or Wraparound',
                'description': 'The software performs a calculation that can produce an integer overflow or wraparound, when the logic assumes that the resulting value will always be larger than the original value.',
                'keywords': ['integer', 'overflow', 'underflow', 'arithmetic', 'calculation']
            },
            'CWE-20': {
                'name': 'Improper Input Validation',
                'description': 'The software receives input or data, but it does not validate or incorrectly validates that the input has the properties required to process the data safely and correctly.',
                'keywords': ['input', 'validation', 'check', 'sanitize']
            },
            'CWE-362': {
                'name': 'Concurrent Execution using Shared Resource with Improper Synchronization',
                'description': 'A race condition occurs when multiple threads access and manipulate the same data concurrently, and the outcome of the execution depends on the order in which the threads execute.',
                'keywords': ['race', 'condition', 'thread', 'mutex', 'lock', 'concurrent']
            },
            'CWE-327': {
                'name': 'Use of a Broken or Risky Cryptographic Algorithm',
                'description': 'The software uses a broken or risky cryptographic algorithm or protocol.',
                'keywords': ['crypto', 'encryption', 'hash', 'algorithm', 'security']
            },
            'CWE-476': {
                'name': 'NULL Pointer Dereference',
                'description': 'A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL.',
                'keywords': ['null', 'pointer', 'dereference', 'crash']
            },
            'CWE-502': {
                'name': 'Deserialization of Untrusted Data',
                'description': 'The software deserializes untrusted data without sufficiently verifying that the resulting data will be valid.',
                'keywords': ['deserialize', 'serialization', 'object', 'data']
            }
        }
    
    def search_cwe(self, keywords: List[str]) -> List[Dict[str, Any]]:
        """
        根据关键词搜索CWE
        
        Args:
            keywords: 关键词列表
        
        Returns:
            CWE匹配列表
        """
        results = []
        
        for cwe_id, info in self.cwe_database.items():
            score = 0
            matched_keywords = []
            
            for kw in keywords:
                kw_lower = kw.lower()
                if kw_lower in info['name'].lower():
                    score += 3
                    matched_keywords.append(kw)
                if kw_lower in info['description'].lower():
                    score += 2
                    matched_keywords.append(kw)
                if any(kw_lower in k.lower() for k in info['keywords']):
                    score += 1
                    matched_keywords.append(kw)
            
            if score > 0:
                results.append({
                    'cwe_id': cwe_id,
                    'cwe_name': info['name'],
                    'description': info['description'],
                    'score': score,
                    'matched_keywords': list(set(matched_keywords))
                })
        
        # 按分数排序
        results.sort(key=lambda x: x['score'], reverse=True)
        
        return results


class RootCauseAnalyzer(ABC):
    """根因分析器抽象基类"""

    @abstractmethod
    def analyze(self, context: VulnerabilityContext) -> RootCauseAnalysis:
        """
        分析漏洞根因
        
        Args:
            context: 漏洞上下文信息
        
        Returns:
            根因分析结果
        """
        pass


class LLMRootCauseAnalyzer(RootCauseAnalyzer):
    """基于LLM的根因分析器"""

    def __init__(self, api_key: str = None, model: str = "gpt-4o-mini"):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.model = model
        self.cwe_database = CWEDatabase()
        self._validate_api_key()

    def _validate_api_key(self):
        """验证API密钥"""
        if not self.api_key:
            logger.warning("OpenAI API密钥未设置，将使用模拟模式")
            self.use_mock = True
        else:
            self.use_mock = False
            openai.api_key = self.api_key

    def analyze(self, context: VulnerabilityContext) -> RootCauseAnalysis:
        """分析漏洞根因"""
        if self.use_mock:
            return self._mock_analyze(context)

        try:
            # 提取关键词
            keywords = self._extract_keywords(context)
            
            # 搜索CWE
            cwe_matches = self.cwe_database.search_cwe(keywords)
            
            # 构建提示
            prompt = self._build_analysis_prompt(context, cwe_matches)
            
            response = openai.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是一名资深的漏洞分析专家，擅长进行CVE级别的根因分析。"},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.2
            )

            result = json.loads(response.choices[0].message.content.strip())
            
            # 转换为RootCauseAnalysis对象
            return RootCauseAnalysis(
                vulnerability_id=result.get('vulnerability_id', f"VULN_{int(time.time())}"),
                vulnerability_type=result.get('vulnerability_type', context.vulnerability_type),
                cwe_mappings=[
                    CWEMapping(
                        cwe_id=cwe.get('cwe_id', ''),
                        cwe_name=cwe.get('cwe_name', ''),
                        description=cwe.get('description', ''),
                        likelihood=cwe.get('likelihood', 0.5),
                        related_cwes=cwe.get('related_cwes', [])
                    ) for cwe in result.get('cwe_mappings', [])
                ],
                root_cause=result.get('root_cause', ''),
                attack_vector=result.get('attack_vector', ''),
                impact=result.get('impact', ''),
                exploitability=Exploitability(result.get('exploitability', 'unknown')),
                severity=VulnerabilitySeverity(result.get('severity', 'medium')),
                affected_components=result.get('affected_components', []),
                reproduction_steps=result.get('reproduction_steps', []),
                mitigation=result.get('mitigation', []),
                references=result.get('references', []),
                confidence=result.get('confidence', 0.8)
            )

        except Exception as e:
            logger.error(f"LLM根因分析失败: {e}")
            return self._mock_analyze(context)

    def _extract_keywords(self, context: VulnerabilityContext) -> List[str]:
        """提取关键词"""
        text = f"{context.pseudocode} {context.assembly} {context.vulnerability_type}"
        keywords = []
        
        # 提取常见漏洞相关关键词
        vuln_keywords = {
            'buffer', 'overflow', 'strcpy', 'strcat', 'memcpy', 'gets', 'sprintf',
            'free', 'malloc', 'double', 'use after free', 'dangling', 'pointer',
            'system', 'exec', 'command', 'shell', 'popen',
            'sql', 'query', 'database',
            'integer', 'underflow', 'arithmetic',
            'input', 'validation', 'sanitize',
            'race', 'condition', 'thread', 'mutex', 'lock',
            'crypto', 'encryption', 'hash',
            'null', 'dereference',
            'deserialize', 'serialization'
        }
        
        for kw in vuln_keywords:
            if kw in text.lower():
                keywords.append(kw)
        
        return keywords

    def _build_analysis_prompt(self, context: VulnerabilityContext, cwe_matches: List[Dict[str, Any]]) -> str:
        """构建分析提示"""
        cwe_info = "\n".join([
            f"{cwe['cwe_id']}: {cwe['cwe_name']} - {cwe['description']}"
            for cwe in cwe_matches[:5]
        ])
        
        prompt = f"""
        请对以下漏洞进行CVE级别的根因分析：
        
        漏洞类型: {context.vulnerability_type}
        函数名: {context.function_name}
        函数地址: {hex(context.function_address)}
        二进制文件: {context.binary_path}
        
        伪代码:
        {context.pseudocode}
        
        汇编代码:
        {context.assembly}
        
        崩溃地址: {hex(context.crash_address) if context.crash_address else 'N/A'}
        
        寄存器状态: {json.dumps(context.registers, indent=2) if context.registers else 'N/A'}
        
        候选CWE分类:
        {cwe_info}
        
        请提供以下分析结果（JSON格式）：
        {{
            "vulnerability_id": "唯一漏洞标识",
            "vulnerability_type": "漏洞类型",
            "cwe_mappings": [
                {{
                    "cwe_id": "CWE编号",
                    "cwe_name": "CWE名称",
                    "description": "描述",
                    "likelihood": 匹配概率(0-1),
                    "related_cwes": ["相关CWE列表"]
                }}
            ],
            "root_cause": "根本原因描述",
            "attack_vector": "攻击向量",
            "impact": "影响范围",
            "exploitability": "easy/medium/hard/unknown",
            "severity": "critical/high/medium/low/info",
            "affected_components": ["受影响组件列表"],
            "reproduction_steps": ["复现步骤"],
            "mitigation": ["修复建议"],
            "references": ["参考链接或文档"],
            "confidence": 分析置信度(0-1)
        }}
        """
        
        return prompt

    def _mock_analyze(self, context: VulnerabilityContext) -> RootCauseAnalysis:
        """模拟根因分析"""
        # 提取关键词
        keywords = self._extract_keywords(context)
        
        # 搜索CWE
        cwe_matches = self.cwe_database.search_cwe(keywords)
        
        # 构建CWE映射
        cwe_mappings = []
        for cwe in cwe_matches[:3]:
            cwe_mappings.append(CWEMapping(
                cwe_id=cwe['cwe_id'],
                cwe_name=cwe['cwe_name'],
                description=cwe['description'],
                likelihood=min(1.0, cwe['score'] / 10),
                related_cwes=[]
            ))
        
        # 确定严重程度和可利用性
        severity = VulnerabilitySeverity.MEDIUM
        exploitability = Exploitability.MEDIUM
        root_cause = "需要进一步分析"
        
        if 'buffer' in keywords or 'overflow' in keywords:
            severity = VulnerabilitySeverity.CRITICAL
            exploitability = Exploitability.EASY
            root_cause = "程序在复制数据时未正确验证缓冲区边界，导致缓冲区溢出漏洞"
        elif 'free' in keywords:
            severity = VulnerabilitySeverity.HIGH
            exploitability = Exploitability.MEDIUM
            root_cause = "程序存在内存使用后释放或重复释放的问题"
        elif 'system' in keywords or 'exec' in keywords:
            severity = VulnerabilitySeverity.CRITICAL
            exploitability = Exploitability.EASY
            root_cause = "程序直接执行用户可控的命令，存在命令注入漏洞"
        
        return RootCauseAnalysis(
            vulnerability_id=f"VULN_{int(time.time())}",
            vulnerability_type=context.vulnerability_type,
            cwe_mappings=cwe_mappings,
            root_cause=root_cause,
            attack_vector="攻击者通过构造恶意输入触发漏洞",
            impact="可能导致远程代码执行、拒绝服务或信息泄露",
            exploitability=exploitability,
            severity=severity,
            affected_components=[context.function_name],
            reproduction_steps=[
                "1. 构造恶意输入数据",
                "2. 将输入传递给受影响函数",
                "3. 观察程序行为或崩溃"
            ],
            mitigation=[
                "1. 对所有用户输入进行严格验证",
                "2. 使用安全的字符串处理函数",
                "3. 启用编译器安全选项（如ASLR、DEP）"
            ],
            references=[
                "https://cwe.mitre.org/",
                "https://owasp.org/www-community/attacks/"
            ],
            confidence=0.75
        )


class AutoRootCauseAnalyzer:
    """
    自动化漏洞根因分析器
    
    功能：
    1. 接收漏洞检测结果
    2. 结合上下文分析漏洞根因
    3. 匹配CWE分类
    4. 生成结构化的根因分析报告
    """

    def __init__(self, analyzer_type: str = "llm"):
        """
        初始化根因分析器
        
        Args:
            analyzer_type: 分析器类型 ("llm" 或 "heuristic")
        """
        self.analyzer_type = analyzer_type
        self.llm_analyzer = LLMRootCauseAnalyzer()
        self.analyses: Dict[str, RootCauseAnalysis] = {}
        
        logger.info(f"使用根因分析器类型: {analyzer_type}")

    def analyze_vulnerability(self, context: VulnerabilityContext) -> RootCauseAnalysis:
        """
        分析单个漏洞
        
        Args:
            context: 漏洞上下文信息
        
        Returns:
            根因分析结果
        """
        logger.info(f"开始分析漏洞: {context.vulnerability_type} @ {hex(context.function_address)}")
        
        if self.analyzer_type == "llm":
            result = self.llm_analyzer.analyze(context)
        else:
            result = self.llm_analyzer._mock_analyze(context)
        
        # 保存分析结果
        self.analyses[result.vulnerability_id] = result
        
        logger.info(f"漏洞分析完成: {result.vulnerability_id}, 严重程度: {result.severity.value}")
        
        return result

    def batch_analyze(self, contexts: List[VulnerabilityContext]) -> List[RootCauseAnalysis]:
        """
        批量分析漏洞
        
        Args:
            contexts: 漏洞上下文列表
        
        Returns:
            根因分析结果列表
        """
        results = []
        
        for context in contexts:
            result = self.analyze_vulnerability(context)
            results.append(result)
        
        return results

    def generate_report(self, output_path: Optional[str] = None) -> AnalysisReport:
        """
        生成分析报告
        
        Args:
            output_path: 输出路径（可选）
        
        Returns:
            分析报告
        """
        report = AnalysisReport(
            generated_at=time.time(),
            target_binary="",
            analysis_id=f"ANALYSIS_{int(time.time())}",
            vulnerabilities=list(self.analyses.values()),
            summary=self._generate_summary()
        )
        
        # 设置目标二进制
        if self.analyses:
            first_vuln = next(iter(self.analyses.values()))
            report.target_binary = first_vuln.affected_components[0] if first_vuln.affected_components else "Unknown"
        
        # 保存报告
        if output_path:
            self._save_report(report, output_path)
        
        return report

    def _generate_summary(self) -> Dict[str, Any]:
        """生成摘要"""
        severity_counts = defaultdict(int)
        total_vulnerabilities = len(self.analyses)
        critical_count = 0
        high_count = 0
        
        for analysis in self.analyses.values():
            severity_counts[analysis.severity.value] += 1
            if analysis.severity == VulnerabilitySeverity.CRITICAL:
                critical_count += 1
            elif analysis.severity == VulnerabilitySeverity.HIGH:
                high_count += 1
        
        return {
            'total_vulnerabilities': total_vulnerabilities,
            'critical_count': critical_count,
            'high_count': high_count,
            'severity_distribution': dict(severity_counts)
        }

    def _save_report(self, report: AnalysisReport, output_path: str):
        """保存报告到文件"""
        report_data = {
            'generated_at': report.generated_at,
            'target_binary': report.target_binary,
            'analysis_id': report.analysis_id,
            'summary': report.summary,
            'vulnerabilities': []
        }
        
        for vuln in report.vulnerabilities:
            report_data['vulnerabilities'].append({
                'vulnerability_id': vuln.vulnerability_id,
                'vulnerability_type': vuln.vulnerability_type,
                'cwe_mappings': [
                    {
                        'cwe_id': cwe.cwe_id,
                        'cwe_name': cwe.cwe_name,
                        'description': cwe.description,
                        'likelihood': cwe.likelihood,
                        'related_cwes': cwe.related_cwes
                    } for cwe in vuln.cwe_mappings
                ],
                'root_cause': vuln.root_cause,
                'attack_vector': vuln.attack_vector,
                'impact': vuln.impact,
                'exploitability': vuln.exploitability.value,
                'severity': vuln.severity.value,
                'affected_components': vuln.affected_components,
                'reproduction_steps': vuln.reproduction_steps,
                'mitigation': vuln.mitigation,
                'references': vuln.references,
                'confidence': vuln.confidence
            })
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, ensure_ascii=False, indent=2)
            logger.info(f"分析报告已保存到: {output_path}")
        except Exception as e:
            logger.error(f"保存报告失败: {e}")


def analyze_root_cause(vulnerability_type: str, function_name: str, pseudocode: str,
                       assembly: str = "", function_address: int = 0,
                       binary_path: str = "", **kwargs) -> RootCauseAnalysis:
    """
    便捷的根因分析函数
    
    Args:
        vulnerability_type: 漏洞类型
        function_name: 函数名
        pseudocode: 伪代码
        assembly: 汇编代码
        function_address: 函数地址
        binary_path: 二进制路径
        **kwargs: 其他上下文信息
    
    Returns:
        RootCauseAnalysis
    """
    context = VulnerabilityContext(
        vulnerability_type=vulnerability_type,
        function_name=function_name,
        function_address=function_address,
        binary_path=binary_path,
        pseudocode=pseudocode,
        assembly=assembly,
        crash_address=kwargs.get('crash_address'),
        stack_trace=kwargs.get('stack_trace'),
        memory_state=kwargs.get('memory_state'),
        registers=kwargs.get('registers'),
        user_input=kwargs.get('user_input')
    )
    
    analyzer = AutoRootCauseAnalyzer()
    return analyzer.analyze_vulnerability(context)


def format_root_cause_report(report: AnalysisReport) -> str:
    """
    格式化根因分析报告
    
    Args:
        report: AnalysisReport
    
    Returns:
        格式化的报告字符串
    """
    parts = [
        "# 自动化漏洞根因分析报告",
        "",
        f"报告ID: {report.analysis_id}",
        f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.generated_at))}",
        f"目标二进制: {report.target_binary}",
        ""
    ]
    
    if report.summary:
        parts.append("## 摘要")
        parts.append(f"- 检测到漏洞数: {report.summary.get('total_vulnerabilities', 0)}")
        parts.append(f"- 严重漏洞数: {report.summary.get('critical_count', 0)}")
        parts.append(f"- 高危漏洞数: {report.summary.get('high_count', 0)}")
        
        dist = report.summary.get('severity_distribution', {})
        if dist:
            parts.append(f"- 严重程度分布: {', '.join([f'{k}: {v}' for k, v in dist.items()])}")
    
    if report.vulnerabilities:
        parts.append("")
        parts.append("## 漏洞详情")
        
        for vuln in report.vulnerabilities:
            parts.extend([
                f"\n### {vuln.vulnerability_id}",
                f"**类型**: {vuln.vulnerability_type}",
                f"**严重程度**: {vuln.severity.value}",
                f"**可利用性**: {vuln.exploitability.value}",
                f"**置信度**: {vuln.confidence:.1%}",
                ""
            ])
            
            if vuln.cwe_mappings:
                parts.append("**CWE分类**:")
                for cwe in vuln.cwe_mappings:
                    parts.append(f"- {cwe.cwe_id}: {cwe.cwe_name} (匹配度: {cwe.likelihood:.1%})")
            
            parts.extend([
                "",
                "**根本原因**:",
                vuln.root_cause,
                "",
                "**攻击向量**:",
                vuln.attack_vector,
                "",
                "**影响范围**:",
                vuln.impact,
                ""
            ])
            
            if vuln.affected_components:
                parts.append(f"**受影响组件**: {', '.join(vuln.affected_components)}")
            
            if vuln.reproduction_steps:
                parts.append("**复现步骤**:")
                for i, step in enumerate(vuln.reproduction_steps, 1):
                    parts.append(f"{i}. {step}")
            
            if vuln.mitigation:
                parts.append("")
                parts.append("**修复建议**:")
                for i, mit in enumerate(vuln.mitigation, 1):
                    parts.append(f"{i}. {mit}")
            
            if vuln.references:
                parts.append("")
                parts.append("**参考资料**:")
                for ref in vuln.references:
                    parts.append(f"- {ref}")
    
    return "\n".join(parts)