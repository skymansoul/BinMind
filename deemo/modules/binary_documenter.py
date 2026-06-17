#!/usr/bin/env python3
"""
自动生成二进制文档与函数注释模块

利用反编译和AI分析结果，自动为二进制中的关键函数生成面向逆向工程师的文档（Markdown格式），
描述函数功能、参数、返回值、内部逻辑和潜在风险，类似自动化"逆向笔记"。

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

from config import Config

logger = logging.getLogger('deemo.binary_documenter')


@dataclass
class FunctionDoc:
    """
    函数文档数据结构
    
    Attributes:
        name: 函数名称
        address: 函数地址
        description: 功能描述
        parameters: 参数列表
        return_value: 返回值描述
        calling_convention: 调用约定
        side_effects: 副作用列表
        risk_level: 风险等级
        dependencies: 依赖函数列表
        pseudocode: 伪代码片段
        notes: 备注
    """
    name: str
    address: str = ''
    description: str = ''
    parameters: List[Dict[str, str]] = field(default_factory=list)
    return_value: str = ''
    calling_convention: str = ''
    side_effects: List[str] = field(default_factory=list)
    risk_level: str = 'Low'
    dependencies: List[str] = field(default_factory=list)
    pseudocode: str = ''
    notes: str = ''
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
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
        """
        转换为Markdown格式
        
        Returns:
            Markdown文档字符串
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
        
        md_lines.extend([)
            "",
            "### 返回值",
            "",
            self.return_value if self.return_value else "无返回值",
            "",
            "### 副作用",
            "",
        ]
        
        if self.side_effects:
            for effect in self.side_effects:
                md_lines.append(f"- {effect}")
        else:
            md_lines.append("无明显副作用")
        
        md_lines.extend([)
            "",
            "### 依赖函数",
            "",
        ]
        
        if self.dependencies:
            for dep in self.dependencies:
                md_lines.append(f"- `{dep}`")
        else:
            md_lines.append("无依赖")
        
        md_lines.extend([)
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
        ]
        
        return '\n'.join(md_lines)


@dataclass
class DocumenterConfig:
    """
    文档生成器配置
    
    Attributes:
        output_dir: 输出目录
        format: 输出格式（markdown/json/pdf）
        include_pseudocode: 是否包含伪代码
        include_risk_analysis: 是否包含风险分析
        language: 文档语言
        project_name: 项目名称
    """
    output_dir: str = './reports/docs'
    format: str = 'markdown'
    include_pseudocode: bool = True
    include_risk_analysis: bool = True
    language: str = 'zh-CN'
    project_name: str = 'unknown'
    
    def validate(self) -> bool:
        """验证配置"""
        if self.format not in ['markdown', 'json', 'pdf']:
            logger.error(f"[DocGen] 不支持的格式: {self.format}")
            return False
        return True


class BinaryDocumenter:
    """
    二进制文档生成器
    
    利用反编译和AI分析结果，自动为二进制中的关键函数生成面向逆向工程师的文档，
    描述函数功能、参数、返回值、内部逻辑和潜在风险。
    
    Attributes:
        config: 文档生成器配置
        functions: 函数文档列表
        pseudocode: 反编译伪代码
        ai_analysis_results: AI分析结果
    """
    
    # 调用约定识别模式
    CALLING_CONVENTIONS = {
        '__stdcall': 'stdcall',
        '__cdecl': 'cdecl',
        '__fastcall': 'fastcall',
        '__thiscall': 'thiscall',
        'syscall': 'syscall',
    }
    
    # 风险等级关键词
    RISK_KEYWORDS = {
        'Critical': ['exec', 'system', 'shell', 'cmd', 'fork', 'ptrace', 'mprotect'],
        'High': ['malloc', 'free', 'strcpy', 'sprintf', 'gets', 'scanf', 'memcpy'],
        'Medium': ['read', 'write', 'open', 'close', 'connect', 'socket'],
        'Low': ['printf', 'strlen', 'strcmp', 'atoi', 'itoa'],
    }
    
    def __init__(self, config: DocumenterConfig):
        """
        初始化文档生成器
        
        Args:
            config: 文档生成器配置
        """
        self.config = config
        self.functions: List[FunctionDoc] = []
        self.pseudocode: str = ''
        self.ai_analysis_results: Dict[str, Any] = {}
        self.global_analysis: Dict[str, Any] = {}
        
        # 创建输出目录
        self._setup_output_dir()
        
        logger.info(f"[DocGen] 初始化文档生成器，输出目录: {config.output_dir}")
    
    def _setup_output_dir(self) -> None:
        """设置输出目录"""
        output_path = Path(self.config.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
    
    def load_pseudocode(self, pseudocode: str) -> None:
        """
        加载反编译伪代码
        
        Args:
            pseudocode: 反编译伪代码字符串
        """
        self.pseudocode = pseudocode
        logger.info(f"[DocGen] 加载伪代码，长度: {len(pseudocode)} 字符")
    
    def load_ai_analysis(self, analysis_results: Dict[str, Any]) -> None:
        """
        加载AI分析结果
        
        Args:
            analysis_results: AI分析结果字典
        """
        self.ai_analysis_results = analysis_results
        logger.info(f"[DocGen] 加载AI分析结果")
    
    def extract_functions(self) -> List[Dict[str, Any]]:
        """
        从伪代码中提取函数
        
        Returns:
            函数信息列表
        """
        if not self.pseudocode:
            logger.warning("[DocGen] 未加载伪代码")
            return []
        
        functions = []
        
        # 函数定义模式（支持多种格式）
        patterns = [
            # C风格函数定义
            r'(?P<return_type>\w+)\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)\s*\{(?P<body>.*?)\n\}',
            # IDA伪代码风格
            r'(?P<return_type>\w+)\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)\s*//\s*(?P<address>0x[0-9a-fA-F]+)',
            # Ghidra风格
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
                
                # 避免重复添加
                if not any(f['name'] == func_info['name'] for f in functions):
                    functions.append(func_info)
        
        logger.info(f"[DocGen] 提取到 {len(functions)} 个函数")
        return functions
    
    def analyze_function(self, func_info: Dict[str, Any]) -> FunctionDoc:
        """
        分析单个函数
        
        Args:
            func_info: 函数信息字典
            
        Returns:
            函数文档对象
        """
        func_name = func_info.get('name', 'unknown')
        func_body = func_info.get('body', '')
        func_params = func_info.get('params', '')
        
        # 创建函数文档
        func_doc = FunctionDoc()
            name=func_name,
            address=func_info.get('address', ''),
            pseudocode=func_body if self.config.include_pseudocode else '',
        
        
        # 分析参数
        func_doc.parameters = self._parse_parameters(func_params)
        
        # 分析调用约定
        func_doc.calling_convention = self._detect_calling_convention(func_body)
        
        # 分析风险等级
        func_doc.risk_level = self._assess_risk_level(func_name, func_body)
        
        # 分析副作用
        func_doc.side_effects = self._detect_side_effects(func_body)
        
        # 分析依赖
        func_doc.dependencies = self._detect_dependencies(func_body)
        
        # 从AI分析结果中获取描述
        if self.ai_analysis_results:
            func_doc.description = self._get_ai_description(func_name)
            func_doc.return_value = self._get_ai_return_value(func_name)
        
        # 如果没有AI结果，生成基本描述
        if not func_doc.description:
            func_doc.description = self._generate_basic_description(func_name, func_body)
        
        return func_doc
    
    def _parse_parameters(self, params_str: str) -> List[Dict[str, str]]:
        """
        解析参数字符串
        
        Args:
            params_str: 参数字符串
            
        Returns:
            参数列表
        """
        parameters = []
        
        if not params_str or params_str.strip() == 'void':
            return parameters
        
        # 分割参数
        param_parts = params_str.split(',')
        
        for part in param_parts:
            part = part.strip()
            if not part:
                continue
            
            # 解析类型和名称
            tokens = part.split()
            if len(tokens) >= 2:
                param_type = tokens[0]
                param_name = tokens[-1].replace('*', '')
                
                # 处理指针
                if '*' in part:
                    param_type += '*'
                
                parameters.append({)
                    'name': param_name,
                    'type': param_type,
                    'description': ''
                }
        
        return parameters
    
    def _detect_calling_convention(self, func_body: str) -> str:
        """
        检测调用约定
        
        Args:
            func_body: 函数体
            
        Returns:
            调用约定类型
        """
        for convention, name in self.CALLING_CONVENTIONS.items():
            if convention in func_body:
                return name
        
        # 默认根据平台判断
        return 'cdecl'
    
    def _assess_risk_level(self, func_name: str, func_body: str) -> str:
        """
        评估函数风险等级
        
        Args:
            func_name: 函数名称
            func_body: 函数体
            
        Returns:
            风险等级
        """
        # 检查函数名和函数体中的关键词
        combined_text = func_name + ' ' + func_body
        
        for level, keywords in self.RISK_KEYWORDS.items():
            for keyword in keywords:
                if keyword.lower() in combined_text.lower():
                    return level
        
        return 'Low'
    
    def _detect_side_effects(self, func_body: str) -> List[str]:
        """
        检测副作用
        
        Args:
            func_body: 函数体
            
        Returns:
            副作用列表
        """
        side_effects = []
        
        # 检测内存操作
        if re.search(r'malloc|calloc|realloc|free', func_body, re.IGNORECASE):
            side_effects.append('动态内存分配/释放')
        
        # 检测文件操作
        if re.search(r'open|fopen|read|write|close', func_body, re.IGNORECASE):
            side_effects.append('文件I/O操作')
        
        # 检测网络操作
        if re.search(r'socket|connect|send|recv|bind', func_body, re.IGNORECASE):
            side_effects.append('网络通信')
        
        # 检测进程操作
        if re.search(r'fork|exec|system|popen', func_body, re.IGNORECASE):
            side_effects.append('进程创建/执行')
        
        # 检测全局变量修改
        if re.search(r'global|static|extern', func_body, re.IGNORECASE):
            side_effects.append('可能修改全局状态')
        
        return side_effects
    
    def _detect_dependencies(self, func_body: str) -> List[str]:
        """
        检测依赖函数
        
        Args:
            func_body: 函数体
            
        Returns:
            依赖函数列表
        """
        dependencies = []
        
        # 检测函数调用
        call_pattern = r'(\w+)\s*\([^)]*\)'
        matches = re.findall(call_pattern, func_body)
        
        # 过滤掉常见关键字和当前函数
        keywords = ['if', 'while', 'for', 'switch', 'return', 'sizeof', 'typeof']
        
        for match in matches:
            if match not in keywords and match not in dependencies:
                dependencies.append(match)
        
        return dependencies
    
    def _get_ai_description(self, func_name: str) -> str:
        """
        从AI分析结果获取函数描述
        
        Args:
            func_name: 函数名称
            
        Returns:
            函数描述
        """
        if 'functions' in self.ai_analysis_results:
            for func in self.ai_analysis_results['functions']:
                if func.get('name') == func_name:
                    return func.get('description', '')
        
        if 'vulnerabilities' in self.ai_analysis_results:
            for vuln in self.ai_analysis_results['vulnerabilities']:
                if vuln.get('function') == func_name:
                    return f"存在漏洞: {vuln.get('type', '')} - {vuln.get('description', '')}"
        
        return ''
    
    def _get_ai_return_value(self, func_name: str) -> str:
        """
        从AI分析结果获取返回值描述
        
        Args:
            func_name: 函数名称
            
        Returns:
            返回值描述
        """
        if 'functions' in self.ai_analysis_results:
            for func in self.ai_analysis_results['functions']:
                if func.get('name') == func_name:
                    return func.get('return_value', '')

        
        return ''
    
    def _generate_basic_description(self, func_name: str, func_body: str) -> str:
        """
        生成基本描述
        
        Args:
            func_name: 函数名称
            func_body: 函数体
            
        Returns:
            基本描述
        """
        # 根据函数名推断功能
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
            return '处理回调函数，响应特定事件'
        else:
            return f'函数 {func_name}，具体功能需进一步分析'
    
    def generate_all_docs(self) -> List[FunctionDoc]:
        """
        生成所有函数文档
        
        Returns:
            函数文档列表
        """
        # 提取函数
        func_infos = self.extract_functions()
        
        # 分析每个函数
        self.functions = []
        for func_info in func_infos:
            func_doc = self.analyze_function(func_info)
            self.functions.append(func_doc)
        
        logger.info(f"[DocGen] 生成了 {len(self.functions)} 个函数文档")
        return self.functions
    
    def generate_document(self) -> str:
        """
        生成完整文档
        
        Returns:
            文档内容字符串
        """
        if not self.functions:
            self.generate_all_docs()
        
        # 生成Markdown文档
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
        
        # 生成目录
        for func in self.functions:
            doc_lines.append(f"- [{func.name}](#{func.name.lower()})")
        
        doc_lines.extend([)
            "",
            "---",
            "",
        ]
        
        # 添加每个函数的文档
        for func in self.functions:
            doc_lines.append(func.to_markdown(

        
        # 添加全局分析摘要
        if self.config.include_risk_analysis:
            doc_lines.extend([)
                "---",
                "",
                "## 风险分析摘要",
                "",
                self._generate_risk_summary(),
                "",
            ]
        
        return '\n'.join(doc_lines)
    
    def _generate_risk_summary(self) -> str:
        """
        生成风险摘要
        
        Returns:
            风险摘要字符串
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
        
        summary_lines.extend([)
            "",
            "### 高风险函数列表",
            "",
        ]
        
        high_risk_funcs = [f for f in self.functions if f.risk_level in ['Critical', 'High']]
        if high_risk_funcs:
            for func in high_risk_funcs:
                summary_lines.append(f"- `{func.name}` ({func.risk_level}): {func.description[:50]}...")
        else:
            summary_lines.append("无高风险函数")
        
        return '\n'.join(summary_lines)
    
    def save_document(self, output_path: Optional[str] = None) -> str:
        """
        保存文档
        
        Args:
            output_path: 输出路径
            
        Returns:
            保存的文件路径
        """
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{self.config.project_name}_analysis_{timestamp}.md"
            output_path = os.path.join(self.config.output_dir, filename)
        
        # 路径安全校验
        output_path = os.path.abspath(output_path)
        if not output_path.startswith(os.path.abspath(self.config.output_dir)):
            raise ValueError("输出路径不在允许的目录范围内")
        
        document = self.generate_document()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(document)
        
        logger.info(f"[DocGen] 文档已保存: {output_path}")
        return output_path
    
    def save_json(self, output_path: Optional[str] = None) -> str:
        """
        保存JSON格式文档
        
        Args:
            output_path: 输出路径
            
        Returns:
            保存的文件路径
        """
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{self.config.project_name}_analysis_{timestamp}.json"
            output_path = os.path.join(self.config.output_dir, filename)
        
        # 路径安全校验
        output_path = os.path.abspath(output_path)
        if not output_path.startswith(os.path.abspath(self.config.output_dir)):
            raise ValueError("输出路径不在允许的目录范围内")
        
        data = {
            'project_name': self.config.project_name,
            'generation_time': datetime.now().isoformat(),
            'functions': [f.to_dict() for f in self.functions],
            'summary': {
                'total_functions': len(self.functions),
                'risk_distribution': {},
            }
        }
        
        # 计算风险分布
        for func in self.functions:
            level = func.risk_level
            data['summary']['risk_distribution'][level] = data['summary']['risk_distribution'].get(level, 0) + 1
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"[DocGen] JSON文档已保存: {output_path}")
        return output_path
    
    def get_function_doc(self, func_name: str) -> Optional[FunctionDoc]:
        """
        获取指定函数的文档
        
        Args:
            func_name: 函数名称
            
        Returns:
            函数文档对象，未找到返回None
        """
        for func in self.functions:
            if func.name == func_name:
                return func
        return None
    
    def search_functions(self, keyword: str) -> List[FunctionDoc]:
        """
        搜索包含关键词的函数
        
        Args:
            keyword: 搜索关键词
            
        Returns:
            匹配的函数文档列表
        """
        results = []
        keyword_lower = keyword.lower()
        
        for func in self.functions:
            if keyword_lower in func.name.lower() or keyword_lower in func.description.lower():
                results.append(func)
        
        return results
    
    def analyze(self, pseudocode: str, ai_results: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        执行完整文档生成分析
        
        Args:
            pseudocode: 反编译伪代码
            ai_results: AI分析结果
            
        Returns:
            分析结果
        """
        # 加载输入
        self.load_pseudocode(pseudocode)
        if ai_results:
            self.load_ai_analysis(ai_results)
        
        # 生成文档
        self.generate_all_docs()
        
        # 保存文档
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
    """
    创建文档生成器的便捷函数
    
    Args:
        project_name: 项目名称
        **kwargs: 其他配置参数
        
    Returns:
        BinaryDocumenter实例
    """
    config = DocumenterConfig(project_name=project_name, **kwargs)
    return BinaryDocumenter(config