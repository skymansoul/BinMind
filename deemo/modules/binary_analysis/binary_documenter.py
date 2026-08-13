#!/usr/bin/env python3
"""
Automated binary documentation and function annotation module.

Leverages decompilation and AI analysis results to automatically generate
reverse-engineering-oriented documentation (Markdown format) for key functions
in a binary, describing function purpose, parameters, return values, internal
logic and potential risks — akin to automated "reverse engineering notes."

Author: BinMind Security Team
Version: 1.0.0
"""

import os
import json
import logging
import re
from typing import List, Dict, Optional, Any
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger('binmind.binary_documenter')


@dataclass
class FunctionDoc:
    """Function documentation data structure.

    Each field corresponds to one dimension of function metadata.

    Attributes:
        name: Function name
        address: Function address
        description: Functional description
        parameters: Parameter list
        return_value: Return value description
        calling_convention: Calling convention
        side_effects: Side effect list
        risk_level: Risk level
        dependencies: Dependency function list
        pseudocode: Pseudocode snippet
        notes: Remarks
    """
    name: str
    address: str = ''
    description: str = ''
    parameters: list = field(default_factory=list)
    return_value: str = ''
    calling_convention: str = ''
    side_effects: list = field(default_factory=list)
    risk_level: str = 'Low'
    dependencies: list = field(default_factory=list)
    pseudocode: str = ''
    notes: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'address': self.address,
            'description': self.description,
            'parameters': self.parameters,
            'return_value': self.return_value,
            'calling_convention': self.calling_convention,
            'side_effects': self.side_effects,
            'risk_level': self.risk_level,
            'dependencies': self.dependencies,
            'pseudocode': self.pseudocode,
            'notes': self.notes
        }

    def to_markdown(self) -> str:
        """Convert to Markdown format.

        Returns:
            Markdown string
        """
        md_lines = [
            f"## {self.name}",
            "",
            f"**地址**: `{self.address}`",
            f"**调用约定**: {self.calling_convention}",
            f"**风险等级**: {self.risk_level}",
            "",
            "### 功能描述",
            "",
            self.description if self.description else "暂无描述",
            "",
            "### 参数",
            "",
        ]

        if self.parameters:
            for param in self.parameters:
                md_lines.append(f"- `{param.get('name', 'unknown')}` ({param.get('type', 'unknown')}): {param.get('description', '')}")
        else:
            md_lines.append("无参数")

        md_lines.extend([
            "",
            "### 返回值",
            "",
            self.return_value if self.return_value else "无返回值",
            "",
            "### 副作用",
            "",
        ])

        if self.side_effects:
            for effect in self.side_effects:
                md_lines.append(f"- {effect}")
        else:
            md_lines.append("无明显副作用")

        md_lines.extend([
            "",
            "### 依赖函数",
            "",
        ])

        if self.dependencies:
            for dep in self.dependencies:
                md_lines.append(f"- `{dep}`")
        else:
            md_lines.append("无依赖")

        md_lines.extend([
            "",
            "### 伪代码",
            "",
            "```c",
            self.pseudocode if self.pseudocode else "// 无伪代码",
            "```",
            "",
            "### 备注",
            "",
            self.notes if self.notes else "无备注",
            "",
        ])

        return '\n'.join(md_lines)


@dataclass
class DocumenterConfig:
    """Document generator configuration.

    Configuration object responsible for all output and behavior switches.

    Attributes:
        output_dir: Output directory
        output_format: Output format (markdown/json/pdf)
        include_pseudocode: Whether to include pseudocode
        include_risk_analysis: Whether to include risk analysis
        language: Document language
        project_name: Project name
    """
    output_dir: str = './reports/docs'
    format: str = 'markdown'
    include_pseudocode: bool = True
    include_risk_analysis: bool = True
    language: str = 'zh-CN'
    project_name: str = 'unknown'

    def validate(self) -> bool:
        """Validate configuration."""
        if self.format not in ['markdown', 'json', 'pdf']:
            logger.error(f"[DocGen] 不支持的格式: {self.format}")
            return False
        return True


class BinaryDocumenter:
    """Binary document generator.

    Leverages decompilation and AI analysis results to automatically generate
    reverse-engineering-oriented documentation for key functions in a binary,
    describing function purpose, parameters, return values, internal logic
    and potential risks.

    Core pipeline: extract -> analyze -> document -> save

    Attributes:
        config: Document generator configuration
        functions: Function document list
        pseudocode: Decompiled pseudocode
        ai_analysis_results: AI analysis results
    """

    # Calling convention recognition patterns, matching symbol decorations
    # produced by different compilers.
    CALLING_CONVENTIONS = {
        '__stdcall': 'stdcall',
        '__cdecl': 'cdecl',
        '__fastcall': 'fastcall',
        '__thiscall': 'thiscall',
        'syscall': 'syscall',
    }

    # Risk level keywords stratified by severity, used to assess function threat potential.
    RISK_KEYWORDS = {
        'Critical': ['exec', 'system', 'shell', 'cmd', 'fork', 'ptrace', 'mprotect'],
        'High': ['malloc', 'free', 'strcpy', 'sprintf', 'gets', 'scanf', 'memcpy'],
        'Medium': ['read', 'write', 'open', 'close', 'connect', 'socket'],
        'Low': ['printf', 'strlen', 'strcmp', 'atoi', 'itoa'],
    }

    def __init__(self, config: DocumenterConfig):
        """Initialize the document generator.

        Args:
            config: Document generator configuration
        """
        self.config = config
        self.functions: List[FunctionDoc] = []
        self.pseudocode: str = ''
        self.ai_analysis_results: Dict[str, Any] = {}
        self.global_analysis: Dict[str, Any] = {}

        # Create output directory.
        self._setup_output_dir()

        logger.info(f"[DocGen] Document generator initialized, output dir: {config.output_dir}")

    def _setup_output_dir(self) -> None:
        """Set up output directory."""
        output_path = Path(self.config.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

    def load_pseudocode(self, pseudocode_text: str) -> None:
        """Load decompiled pseudocode.

        Args:
            pseudocode_text: Pseudocode text
        """
        self.pseudocode = pseudocode_text
        logger.info(f"[DocGen] Pseudocode loaded, length: {len(pseudocode_text)} chars")

    def load_ai_analysis(self, analysis_results: Dict[str, Any]) -> None:
        """Load AI analysis results.

        Args:
            analysis_results: AI analysis results dictionary
        """
        self.ai_analysis_results = analysis_results
        logger.info(f"[DocGen] AI analysis results loaded")

    def extract_functions(self) -> List[Dict[str, Any]]:
        """Extract functions from pseudocode.

        Returns:
            List of function info dictionaries
        """
        if not self.pseudocode:
            logger.warning("[DocGen] No pseudocode loaded")
            return []

        functions = []

        # Support multiple decompiler output formats (C-style, IDA, Ghidra),
        # matched by priority.
        patterns = [
            # C-style function definition
            r'(?P<return_type>\w+)\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)\s*\{(?P<body>.*?)\n\}',
            # IDA pseudo-code style
            r'(?P<return_type>\w+)\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)\s*//\s*(?P<address>0x[0-9a-fA-F]+)',
            # Ghidra style
            r'(undefined|void|int|char|long|ulong|uint)\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)',
        ]

        for pattern in patterns:
            matches = re.finditer(pattern, self.pseudocode, re.MULTILINE | re.DOTALL)
            for match in matches:
                func_info = {
                    'name': match.group('name'),
                    'return_type': match.group('return_type') if 'return_type' in match.groupdict() else 'void',
                    'params': match.group('params') if 'params' in match.groupdict() else '',
                    'address': match.group('address') if 'address' in match.groupdict() else '',
                    'body': match.group('body') if 'body' in match.groupdict() else '',
                }

                # Deduplicate: multiple regexes may match the same function.
                if not any(f['name'] == func_info['name'] for f in functions):
                    functions.append(func_info)

        logger.info(f"[DocGen] Extracted {len(functions)} functions")
        return functions

    def analyze_function(self, func_info: Dict[str, Any]) -> FunctionDoc:
        """Analyze a single function.

        Args:
            func_info: Function info dictionary

        Returns:
            FunctionDoc instance
        """
        func_name = func_info.get('name', 'unknown')
        func_body = func_info.get('body', '')
        func_params = func_info.get('params', '')

        # Create function document.
        func_doc = FunctionDoc(
            name=func_name,
            address=func_info.get('address', ''),
            pseudocode=func_body if self.config.include_pseudocode else '')

        # Analyze parameters.
        func_doc.parameters = self._parse_parameters(func_params)

        # Analyze calling convention, risk level, side effects, and dependencies
        # in priority order. Each analysis dimension is independent.
        func_doc.calling_convention = self._detect_calling_convention(func_body)
        func_doc.risk_level = self._assess_risk_level(func_name, func_body)
        func_doc.side_effects = self._detect_side_effects(func_body)
        func_doc.dependencies = self._detect_dependencies(func_body)

        # Get description from AI analysis results.
        if self.ai_analysis_results:
            func_doc.description = self._get_ai_description(func_name)
            func_doc.return_value = self._get_ai_return_value(func_name)

        # Fall back to heuristic description if no AI result available.
        if not func_doc.description:
            func_doc.description = self._generate_basic_description(func_name, func_body)

        return func_doc

    def _parse_parameters(self, params_str: str) -> List[Dict[str, str]]:
        """Parse parameter string.

        Args:
            params_str: Parameter string

        Returns:
            Parameter list
        """
        parameters = []

        # 'void' means no-arg function, return empty list.
        if not params_str or params_str.strip() == 'void':
            return parameters

        param_parts = params_str.split(',')

        for part in param_parts:
            part = part.strip()
            if not part:
                continue

            tokens = part.split()
            if len(tokens) >= 2:
                param_type = tokens[0]
                param_name = tokens[-1].replace('*', '')

                # Pointer types append * to the type name.
                if '*' in part:
                    param_type += '*'

                parameters.append({
                    'name': param_name,
                    'type': param_type,
                    'description': ''
                })

        return parameters

    def _detect_calling_convention(self, func_body: str) -> str:
        """Detect calling convention.

        Args:
            func_body: Function body

        Returns:
            Calling convention name
        """
        for convention, name in self.CALLING_CONVENTIONS.items():
            if convention in func_body:
                return name

        # Default to cdecl when unable to identify.
        return 'cdecl'

    def _assess_risk_level(self, func_name: str, func_body: str) -> str:
        """Assess function risk level.

        Args:
            func_name: Function name
            func_body: Function body

        Returns:
            Risk level
        """
        # Merge function name and body into search text, match from highest to lowest risk.
        combined_text = func_name + ' ' + func_body

        for level, keywords in self.RISK_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in combined_text.lower():
                    return level

        return 'Low'

    def _detect_side_effects(self, func_body: str) -> List[str]:
        """Detect side effects.

        Args:
            func_body: Function body

        Returns:
            Side effect list
        """
        side_effects = []

        # Detect side effects by category. Each category uses an independent
        # regex check and multiple categories may be hit simultaneously.
        if re.search(r'malloc|calloc|realloc|free', func_body, re.IGNORECASE):
            side_effects.append('动态内存分配/释放')

        if re.search(r'open|fopen|read|write|close', func_body, re.IGNORECASE):
            side_effects.append('文件I/O操作')

        if re.search(r'socket|connect|send|recv|bind', func_body, re.IGNORECASE):
            side_effects.append('网络通信')

        if re.search(r'fork|exec|system|popen', func_body, re.IGNORECASE):
            side_effects.append('进程创建/执行')

        if re.search(r'global|static|extern', func_body, re.IGNORECASE):
            side_effects.append('可能修改全局状态')

        return side_effects

    def _detect_dependencies(self, func_body: str) -> List[str]:
        """Detect dependency functions.

        Args:
            func_body: Function body

        Returns:
            Dependency function list
        """
        dependencies = []

        # Match function call syntax name(...) to extract all called functions.
        call_pattern = r'(\w+)\s*\([^)]*\)'
        matches = re.findall(call_pattern, func_body)

        # Filter out control flow keywords, keep only actual function calls.
        keywords = ['if', 'while', 'for', 'switch', 'return', 'sizeof', 'typeof']

        for match in matches:
            if match not in keywords and match not in dependencies:
                dependencies.append(match)

        return dependencies

    def _get_ai_description(self, func_name: str) -> str:
        """Get function description from AI analysis results.

        Args:
            func_name: Function name

        Returns:
            Function description
        """
        # Check functions list first, then vulnerabilities list.
        # Vulnerability descriptions take higher priority.
        if 'functions' in self.ai_analysis_results:
            for func in self.ai_analysis_results['functions']:
                if func.get('name') == func_name:
                    return func.get('description', '')

        if 'vulnerabilities' in self.ai_analysis_results:
            for vuln in self.ai_analysis_results['vulnerabilities']:
                if vuln.get('function') == func_name:
                    return f"Vulnerability found: {vuln.get('type', '')} - {vuln.get('description', '')}"

        return ''

    def _get_ai_return_value(self, func_name: str) -> str:
        """Get return value description from AI analysis results.

        Args:
            func_name: Function name

        Returns:
            Return value description
        """
        if 'functions' in self.ai_analysis_results:
            for func in self.ai_analysis_results['functions']:
                if func.get('name') == func_name:
                    return func.get('return_value', '')

        return ''

    def _generate_basic_description(self, func_name: str, func_body: str) -> str:
        """Generate basic description.

        Args:
            func_name: Function name
            func_body: Function body

        Returns:
            Basic description
        """
        # Infer function purpose from naming conventions.
        # Accuracy depends on whether function names are semantically meaningful.
        name_lower = func_name.lower()

        if 'init' in name_lower:
            return '初始化函数，用于设置初始状态或配置'
        elif 'main' in name_lower:
            return '程序入口函数，执行主要逻辑'
        elif 'check' in name_lower or 'verify' in name_lower:
            return '检查/验证函数，用于验证条件或数据'
        elif 'parse' in name_lower or 'process' in name_lower:
            return '解析/处理函数，用于处理输入数据'
        elif 'encrypt' in name_lower or 'decrypt' in name_lower:
            return '加密/解密函数，涉及密码学操作'
        elif 'alloc' in name_lower or 'malloc' in name_lower:
            return '内存分配函数，管理动态内存'
        elif 'free' in name_lower or 'dealloc' in name_lower:
            return '内存释放函数，清理动态内存'
        elif 'read' in name_lower or 'write' in name_lower:
            return '读写函数，涉及I/O操作'
        elif 'send' in name_lower or 'recv' in name_lower:
            return '网络通信函数，发送或接收数据'
        elif 'handler' in name_lower or 'callback' in name_lower:
            return '回调处理函数，响应特定事件'
        else:
            return f'函数 {func_name}，需要进一步分析'

    def generate_all_docs(self) -> List[FunctionDoc]:
        """Generate documentation for all functions.

        Returns:
            Function document list
        """
        func_infos = self.extract_functions()

        self.functions = []
        for func_info in func_infos:
            func_doc = self.analyze_function(func_info)
            self.functions.append(func_doc)

        logger.info(f"[DocGen] Generated {len(self.functions)} function documents")
        return self.functions

    def generate_document(self) -> str:
        """Generate complete document.

        Returns:
            Complete Markdown document
        """
        if not self.functions:
            self.generate_all_docs()

        doc_lines = [
            f"# {self.config.project_name} 逆向分析文档",
            "",
            f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**函数数量**: {len(self.functions)}",
            "",
            "---",
            "",
            "## 目录",
            "",
        ]

        # Generate TOC anchors. Anchor names use lowercase function names
        # and must match Markdown heading anchor generation rules.
        for func in self.functions:
            doc_lines.append(f"- [{func.name}](#{func.name.lower()})")

        doc_lines.extend([
            "",
            "---",
            "",
        ])

        for func in self.functions:
            doc_lines.append(func.to_markdown())

        # Append risk summary if risk analysis is enabled.
        # Risk summary aggregates risk level distribution across all functions
        # and highlights high-risk items.
        if self.config.include_risk_analysis:
            doc_lines.extend([
                "---",
                "",
                "## 风险分析摘要",
                "",
                self._generate_risk_summary(),
                "",
            ])

        return '\n'.join(doc_lines)

    def _generate_risk_summary(self) -> str:
        """Generate risk summary.

        Returns:
            Risk summary Markdown
        """
        risk_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
        }

        for func in self.functions:
            risk_counts[func.risk_level] = risk_counts.get(func.risk_level, 0) + 1

        summary_lines = [
            "| 风险等级 | 函数数量 |",
            "|----------|----------|",
        ]

        for level, count in risk_counts.items():
            summary_lines.append(f"| {level} | {count} |")

        summary_lines.extend([
            "",
            "### 高风险函数列表",
            "",
        ])

        # Only list Critical and High level functions in the summary.
        high_risk_funcs = [f for f in self.functions if f.risk_level in ['Critical', 'High']]
        if high_risk_funcs:
            for func in high_risk_funcs:
                summary_lines.append(f"- `{func.name}` ({func.risk_level}): {func.description[:50]}...")
        else:
            summary_lines.append("无高风险函数")

        return '\n'.join(summary_lines)

    def save_document(self, output_path: Optional[str] = None) -> str:
        """Save document.

        Args:
            output_path: Output path

        Returns:
            Saved file path
        """
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{self.config.project_name}_analysis_{timestamp}.md"
            output_path = os.path.join(self.config.output_dir, filename)

        # Path safety check to prevent directory traversal attacks.
        output_path = os.path.abspath(output_path)
        if not output_path.startswith(os.path.abspath(self.config.output_dir)):
            raise ValueError("Output path is outside the allowed directory scope")

        document = self.generate_document()

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(document)

        logger.info(f"[DocGen] Document saved: {output_path}")
        return output_path

    def save_json(self, output_path: Optional[str] = None) -> str:
        """Save JSON format document.

        Args:
            output_path: Output path

        Returns:
            Saved file path
        """
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{self.config.project_name}_analysis_{timestamp}.json"
            output_path = os.path.join(self.config.output_dir, filename)

        # Path safety check to prevent directory traversal attacks.
        output_path = os.path.abspath(output_path)
        if not output_path.startswith(os.path.abspath(self.config.output_dir)):
            raise ValueError("Output path is outside the allowed directory scope")

        data = {
            'project_name': self.config.project_name,
            'generation_time': datetime.now().isoformat(),
            'functions': [f.to_dict() for f in self.functions],
            'summary': {
                'total_functions': len(self.functions),
                'risk_distribution': {},
            }
        }

        # Compute risk distribution dynamically for chart generation.
        for func in self.functions:
            level = func.risk_level
            data['summary']['risk_distribution'][level] = data['summary']['risk_distribution'].get(level, 0) + 1

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(f"[DocGen] JSON document saved: {output_path}")
        return output_path

    def get_function_doc(self, func_name: str) -> Optional[FunctionDoc]:
        """Get documentation for a specific function.

        Args:
            func_name: Function name

        Returns:
            FunctionDoc or None
        """
        for func in self.functions:
            if func.name == func_name:
                return func
        return None

    def search_functions(self, keyword: str) -> List[FunctionDoc]:
        """Search for functions containing a keyword.

        Args:
            keyword: Search keyword

        Returns:
            Matching function document list
        """
        results = []
        keyword_lower = keyword.lower()

        # Case-insensitive search in function name and description.
        for func in self.functions:
            if keyword_lower in func.name.lower() or keyword_lower in func.description.lower():
                results.append(func)

        return results

    def analyze(self, pseudocode_text: str, ai_results: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute full document generation analysis.

        Args:
            pseudocode_text: Pseudocode
            ai_results: AI analysis results

        Returns:
            Analysis result dictionary
        """
        # One-stop entry point: load -> generate -> save pipeline.
        self.load_pseudocode(pseudocode_text)
        if ai_results:
            self.load_ai_analysis(ai_results)

        self.generate_all_docs()

        md_path = self.save_document()
        json_path = self.save_json()

        return {
            'status': 'success',
            'functions_count': len(self.functions),
            'markdown_path': md_path,
            'json_path': json_path,
            'summary': self._generate_risk_summary(),
        }


def create_documenter(project_name: str, **kwargs) -> BinaryDocumenter:
    """Convenience function to create a document generator.

    Args:
        project_name: Project name

    Returns:
        BinaryDocumenter instance
    """
    # Factory function: merges default config with caller-supplied overrides.
    config = DocumenterConfig(project_name=project_name, **kwargs)
    return BinaryDocumenter(config)
