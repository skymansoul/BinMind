#!/usr/bin/env python3
"""二进制自动化文档与函数注解模块。

结合反编译与 AI 分析结果, 为二进制关键函数自动生成逆向导向的
Markdown 文档: 函数用途/参数/返回值/内部逻辑/潜在风险,
相当于自动化的"逆向工程笔记"。
"""

import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger('binmind.binary_documenter')


@dataclass
class FunctionDoc:
    """函数文档结构: 名称/地址/描述/参数/返回值/调用约定/副作用/风险/依赖/伪代码/备注。"""
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
        """转换为 Markdown 格式。"""
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
    """文档生成配置: 输出目录/格式(markdown|json|pdf)/是否含伪代码/是否含风险分析/语言/项目名。"""
    output_dir: str = './reports/docs'
    format: str = 'markdown'
    include_pseudocode: bool = True
    include_risk_analysis: bool = True
    language: str = 'zh-CN'
    project_name: str = 'unknown'

    def validate(self) -> bool:
        """配置校验。"""
        if self.format not in ['markdown', 'json', 'pdf']:
            logger.error(f"[DocGen] 不支持的格式: {self.format}")
            return False
        return True


class BinaryDocumenter:
    """二进制文档生成器。

    结合反编译与 AI 分析结果, 为二进制关键函数自动生成逆向导向
    文档。主链路: extract -> analyze -> document -> save。
    字段: config 配置, functions 函数文档列表, pseudocode 伪代码,
    ai_analysis_results AI 分析结果。
    """

    # 调用约定识别模式, 匹配不同编译器的符号修饰
    CALLING_CONVENTIONS = {
        '__stdcall': 'stdcall',
        '__cdecl': 'cdecl',
        '__fastcall': 'fastcall',
        '__thiscall': 'thiscall',
        'syscall': 'syscall',
    }

    # 风险等级关键词按严重度分层, 用于评估函数威胁潜力
    RISK_KEYWORDS = {
        'Critical': ['exec', 'system', 'shell', 'cmd', 'fork', 'ptrace', 'mprotect'],
        'High': ['malloc', 'free', 'strcpy', 'sprintf', 'gets', 'scanf', 'memcpy'],
        'Medium': ['read', 'write', 'open', 'close', 'connect', 'socket'],
        'Low': ['printf', 'strlen', 'strcmp', 'atoi', 'itoa'],
    }

    def __init__(self, config: DocumenterConfig):
        """初始化文档生成器。"""
        self.config = config
        self.functions: List[FunctionDoc] = []
        self.pseudocode: str = ''
        self.ai_analysis_results: Dict[str, Any] = {}
        self.global_analysis: Dict[str, Any] = {}

        # 创建输出目录
        self._setup_output_dir()

        logger.info(f"[DocGen] Document generator initialized, output dir: {config.output_dir}")

    def _setup_output_dir(self) -> None:
        """创建输出目录。"""
        output_path = Path(self.config.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

    def load_pseudocode(self, pseudocode_text: str) -> None:
        """载入反编译伪代码。"""
        self.pseudocode = pseudocode_text
        logger.info(f"[DocGen] Pseudocode loaded, length: {len(pseudocode_text)} chars")

    def load_ai_analysis(self, analysis_results: Dict[str, Any]) -> None:
        """载入 AI 分析结果。"""
        self.ai_analysis_results = analysis_results
        logger.info(f"[DocGen] AI analysis results loaded")

    def extract_functions(self) -> List[Dict[str, Any]]:
        """从伪代码提取函数信息列表。"""
        if not self.pseudocode:
            logger.warning("[DocGen] No pseudocode loaded")
            return []

        functions = []

        # 支持多种反编译器输出格式 (C 风格 / IDA / Ghidra), 按优先级匹配
        patterns = [
            # C 风格函数定义
            r'(?P<return_type>\w+)\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)\s*\{(?P<body>.*?)\n\}',
            # IDA 伪代码风格
            r'(?P<return_type>\w+)\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)\s*//\s*(?P<address>0x[0-9a-fA-F]+)',
            # Ghidra 风格
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

                # 去重: 多个正则可能命中同一函数
                if not any(f['name'] == func_info['name'] for f in functions):
                    functions.append(func_info)

        logger.info(f"[DocGen] Extracted {len(functions)} functions")
        return functions

    def analyze_function(self, func_info: Dict[str, Any]) -> FunctionDoc:
        """分析单个函数, 产出 FunctionDoc。"""
        func_name = func_info.get('name', 'unknown')
        func_body = func_info.get('body', '')
        func_params = func_info.get('params', '')

        # 构造函数文档
        func_doc = FunctionDoc(
            name=func_name,
            address=func_info.get('address', ''),
            pseudocode=func_body if self.config.include_pseudocode else '')

        # 解析参数
        func_doc.parameters = self._parse_parameters(func_params)

        # 各分析维度独立: 调用约定/风险/副作用/依赖
        func_doc.calling_convention = self._detect_calling_convention(func_body)
        func_doc.risk_level = self._assess_risk_level(func_name, func_body)
        func_doc.side_effects = self._detect_side_effects(func_body)
        func_doc.dependencies = self._detect_dependencies(func_body)

        # 优先取 AI 分析结果中的描述
        if self.ai_analysis_results:
            func_doc.description = self._get_ai_description(func_name)
            func_doc.return_value = self._get_ai_return_value(func_name)

        # 无 AI 结果时回退启发式描述
        if not func_doc.description:
            func_doc.description = self._generate_basic_description(func_name, func_body)

        return func_doc

    def _parse_parameters(self, params_str: str) -> List[Dict[str, str]]:
        """解析参数字符串为参数列表。"""
        parameters = []

        # 'void' 表示无参函数
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

                # 指针类型在类型名后追加 *
                if '*' in part:
                    param_type += '*'

                parameters.append({
                    'name': param_name,
                    'type': param_type,
                    'description': ''
                })

        return parameters

    def _detect_calling_convention(self, func_body: str) -> str:
        """检测调用约定。"""
        for convention, name in self.CALLING_CONVENTIONS.items():
            if convention in func_body:
                return name

        # 无法识别时默认 cdecl
        return 'cdecl'

    def _assess_risk_level(self, func_name: str, func_body: str) -> str:
        """评估函数风险等级。"""
        # 函数名与函数体合并为搜索文本, 按风险从高到低匹配
        combined_text = func_name + ' ' + func_body

        for level, keywords in self.RISK_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in combined_text.lower():
                    return level

        return 'Low'

    def _detect_side_effects(self, func_body: str) -> List[str]:
        """检测副作用列表。"""
        side_effects = []

        # 按类别独立检测, 可同时命中多个类别
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
        """检测依赖函数列表。"""
        dependencies = []

        # 匹配 name(...) 调用语法, 提取所有被调函数
        call_pattern = r'(\w+)\s*\([^)]*\)'
        matches = re.findall(call_pattern, func_body)

        # 过滤控制流关键字, 只保留真实函数调用
        keywords = ['if', 'while', 'for', 'switch', 'return', 'sizeof', 'typeof']

        for match in matches:
            if match not in keywords and match not in dependencies:
                dependencies.append(match)

        return dependencies

    def _get_ai_description(self, func_name: str) -> str:
        """从 AI 分析结果取函数描述。"""
        # 先查 functions 列表, 再查 vulnerabilities 列表, 漏洞描述优先
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
        """从 AI 分析结果取返回值描述。"""
        if 'functions' in self.ai_analysis_results:
            for func in self.ai_analysis_results['functions']:
                if func.get('name') == func_name:
                    return func.get('return_value', '')

        return ''

    def _generate_basic_description(self, func_name: str, func_body: str) -> str:
        """按命名约定生成基础描述, 精度取决于函数名是否有语义。"""
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
        """为全部函数生成文档。"""
        func_infos = self.extract_functions()

        self.functions = []
        for func_info in func_infos:
            func_doc = self.analyze_function(func_info)
            self.functions.append(func_doc)

        logger.info(f"[DocGen] Generated {len(self.functions)} function documents")
        return self.functions

    def generate_document(self) -> str:
        """生成完整 Markdown 文档。"""
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

        # TOC 锚点用小写函数名, 需与 Markdown 标题锚点生成规则一致
        for func in self.functions:
            doc_lines.append(f"- [{func.name}](#{func.name.lower()})")

        doc_lines.extend([
            "",
            "---",
            "",
        ])

        for func in self.functions:
            doc_lines.append(func.to_markdown())

        # 启用风险分析时追加风险摘要 (各等级分布 + 高风险项)
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
        """生成风险摘要 Markdown。"""
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

        # 摘要只列 Critical 与 High 级函数
        high_risk_funcs = [f for f in self.functions if f.risk_level in ['Critical', 'High']]
        if high_risk_funcs:
            for func in high_risk_funcs:
                summary_lines.append(f"- `{func.name}` ({func.risk_level}): {func.description[:50]}...")
        else:
            summary_lines.append("无高风险函数")

        return '\n'.join(summary_lines)

    def save_document(self, output_path: Optional[str] = None) -> str:
        """保存 Markdown 文档, 返回路径。"""
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{self.config.project_name}_analysis_{timestamp}.md"
            output_path = os.path.join(self.config.output_dir, filename)

        # 路径安全检查, 防目录穿越
        output_path = os.path.abspath(output_path)
        if not output_path.startswith(os.path.abspath(self.config.output_dir)):
            raise ValueError("Output path is outside the allowed directory scope")

        document = self.generate_document()

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(document)

        logger.info(f"[DocGen] Document saved: {output_path}")
        return output_path

    def save_json(self, output_path: Optional[str] = None) -> str:
        """保存 JSON 格式文档, 返回路径。"""
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{self.config.project_name}_analysis_{timestamp}.json"
            output_path = os.path.join(self.config.output_dir, filename)

        # 路径安全检查, 防目录穿越
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

        # 动态统计风险分布, 供图表生成使用
        for func in self.functions:
            level = func.risk_level
            data['summary']['risk_distribution'][level] = data['summary']['risk_distribution'].get(level, 0) + 1

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(f"[DocGen] JSON document saved: {output_path}")
        return output_path

    def get_function_doc(self, func_name: str) -> Optional[FunctionDoc]:
        """按名取函数文档, 未命中返回 None。"""
        for func in self.functions:
            if func.name == func_name:
                return func
        return None

    def search_functions(self, keyword: str) -> List[FunctionDoc]:
        """按关键词在函数名与描述中大小写不敏感搜索。"""
        results = []
        keyword_lower = keyword.lower()

        # 函数名与描述中大小写不敏感匹配
        for func in self.functions:
            if keyword_lower in func.name.lower() or keyword_lower in func.description.lower():
                results.append(func)

        return results

    def analyze(self, pseudocode_text: str, ai_results: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """完整文档生成分析: load → generate → save。"""
        # 一站式入口
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
    """便捷工厂: 默认配置与调用方覆盖合并后创建文档生成器。"""
    config = DocumenterConfig(project_name=project_name, **kwargs)
    return BinaryDocumenter(config)
