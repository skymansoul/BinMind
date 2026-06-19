"""
基于AI的伪代码自然语言解释与注释增强模块

该模块利用LLM对反编译生成的伪代码进行自然语言解释，
生成易于理解的注释，帮助非专业人员理解代码逻辑和安全风险。

Author: LLM-Assisted Binary Vulnerability Analysis Tool
Version: 1.3.1
"""

import logging
import os
import re
import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ExplanationLevel(Enum):
    """
    解释详细程度级别
    """
    BASIC = 'basic'      # 基础解释，适合非技术人员
    TECHNICAL = 'technical'  # 技术解释，适合开发者
    SECURITY = 'security'    # 安全视角解释，适合安全研究员
    FULL = 'full'        # 完整解释，包含所有视角


@dataclass
class CodeExplanation:
    """
    代码解释结果
    
    Attributes:
        original_code: 原始伪代码
        explained_code: 带注释的代码
        summary: 整体摘要
        function_explanations: 函数解释列表
        variable_explanations: 变量解释列表
        security_notes: 安全相关说明
        risk_indicators: 风险指标
        confidence: 解释置信度
    """
    original_code: str
    explained_code: str = ''
    summary: str = ''
    function_explanations: List[Dict[str, str]] = field(default_factory=list)
    variable_explanations: List[Dict[str, str]] = field(default_factory=list)
    security_notes: List[str] = field(default_factory=list)
    risk_indicators: List[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class FunctionAnalysis:
    """
    函数分析结果
    
    Attributes:
        function_name: 函数名
        address: 函数地址
        parameters: 参数列表
        return_type: 返回类型
        purpose: 功能描述
        logic_flow: 逻辑流程
        security_risks: 安全风险
        suggested_fixes: 建议修复
    """
    function_name: str
    address: str = ''
    parameters: List[Dict[str, str]] = field(default_factory=list)
    return_type: str = ''
    purpose: str = ''
    logic_flow: str = ''
    security_risks: List[str] = field(default_factory=list)
    suggested_fixes: List[str] = field(default_factory=list)


# 伪代码解释提示词模板
PSEUDOCODE_EXPLANATION_TEMPLATE = """
你是一名资深的逆向工程和代码安全分析专家，擅长将反编译生成的伪代码转换为易于理解的自然语言解释。

## 任务
对以下伪代码进行详细解释，生成带有中文注释的代码，并提供安全分析。

## 伪代码
```c
{pseudocode}
```

## 上下文信息
- 文件名: {filename}
- 函数名: {function_name}
- 架构: {architecture}

## 解释要求

### 1. 代码注释
请为代码添加详细的中文注释，包括：
- 每个变量的用途说明
- 每个条件判断的逻辑解释
- 每个循环的目的说明
- 关键操作的详细解释

### 2. 函数整体分析
请提供：
- 函数的主要功能描述（一句话概括）
- 输入参数的含义
- 返回值的含义
- 函数的调用场景推测

### 3. 安全风险分析
请识别以下安全问题：
- 输入验证是否充分
- 是否存在缓冲区溢出风险
- 是否存在整数溢出风险
- 是否使用了危险函数（strcpy、sprintf等）
- 是否存在内存泄漏风险
- 是否存在逻辑漏洞

### 4. 风险等级评估
请评估函数的安全风险等级：
- Critical: 存在可被利用的严重漏洞
- High: 存在明显的安全问题
- Medium: 存在潜在风险
- Low: 代码相对安全

## 输出格式
请以JSON格式输出结果：

```json
{
    "explained_code": "带注释的代码",
    "summary": "函数整体摘要",
    "purpose": "函数主要功能",
    "parameters": [
        {"name": "参数名", "type": "类型", "description": "描述"}
    ],
    "return_value": {"type": "类型", "description": "描述"},
    "logic_flow": "逻辑流程描述",
    "security_notes": ["安全说明1", "安全说明2"],
    "risk_indicators": ["风险指标1", "风险指标2"],
    "risk_level": "风险等级",
    "suggested_fixes": ["修复建议1", "修复建议2"],
    "confidence": 0.85
}
```

请确保输出是有效的JSON格式。
"""

# 变量解释提示词模板
VARIABLE_EXPLANATION_TEMPLATE = """
你是一名逆向工程专家，请解释以下伪代码中的变量用途。

## 变量列表
{variables}

## 上下文代码片段
```c
{code_context}
```

## 输出要求
请以JSON格式输出每个变量的解释：

```json
{
    "variables": [
        {"name": "变量名", "type": "类型", "purpose": "用途", "sensitivity": "是否敏感数据"}
    ]
}
```
"""

# 安全风险解释提示词模板
SECURITY_EXPLANATION_TEMPLATE = """
你是一名安全研究员，请从安全角度分析以下伪代码。

## 伪代码
```c
{pseudocode}
```

## 分析要求
请识别以下安全风险：
1. 输入验证问题
2. 内存安全问题（缓冲区溢出、内存泄漏）
3. 整数溢出风险
4. 危险函数使用
5. 逻辑漏洞
6. 信息泄露风险
7. 权限问题

## 输出格式
请以JSON格式输出：

```json
{
    "vulnerabilities": [
        {
            "type": "漏洞类型",
            "location": "代码位置",
            "description": "漏洞描述",
            "severity": "严重程度",
            "exploitation": "利用方式",
            "fix": "修复建议"
        }
    ],
    "overall_risk": "整体风险评估",
    "attack_vectors": ["攻击向量1", "攻击向量2"]
}
```
"""


class PseudocodeExplainer:
    """
    基于AI的伪代码自然语言解释与注释增强器
    
    利用LLM对反编译伪代码进行解释，生成易于理解的注释。
    """
    
    def __init__(self, llm_client: Optional[Any] = None):
        """
        初始化解释器
        
        Args:
            llm_client: LLM客户端实例（如OpenAI）
        """
        from config import Config
        
        self.llm_client = llm_client
        
        # 尝试初始化LLM客户端
        if not self.llm_client:
            self._init_llm_client()
            
        self.explanation_cache: Dict[str, CodeExplanation] = {}
        
    def _init_llm_client(self) -> None:
        """初始化LLM客户端"""
        try:
            from openai import OpenAI
            from config import Config
            
            if hasattr(Config, 'OPENAI_API_KEY') and Config.OPENAI_API_KEY:
                self.llm_client = OpenAI()
                    api_key=Config.OPENAI_API_KEY,
                    base_url=Config.OPENAI_BASE_URL if hasattr(Config, 'OPENAI_BASE_URL') else None
                
                logger.info("LLM客户端初始化成功")
            else:
                logger.warning("未配置OpenAI API密钥，AI解释功能受限")
                
        except ImportError:
            logger.warning("openai库未安装，AI解释功能不可用")
        except Exception as e:
            logger.error(f"初始化LLM客户端失败: {e}")
            
    def explain_code(, self, pseudocode: str, filename: str = '', function_name: str = '', architecture: str = '', level: ExplanationLevel = ExplanationLevel.TECHNICAL) -> CodeExplanation:
        """
        解释伪代码
        
        Args:
            pseudocode: 伪代码文本
            filename: 文件名
            function_name: 函数名
            architecture: 架构
            level: 解释详细程度
            
        Returns:
            CodeExplanation: 解释结果
        """
        # 检查缓存
        cache_key = f"{filename}:{function_name}:{hash(pseudocode)}",
        if cache_key in self.explanation_cache:
            logger.debug(f"使用缓存的解释结果: {cache_key}")
            return self.explanation_cache[cache_key]
            
        result = CodeExplanation(original_code=pseudocode)
        
        if not pseudocode or len(pseudocode.strip()) < 10:
            result.summary = "代码太短，无法进行有效解释",
            return result
            
        try:
            # 使用LLM进行解释
            if self.llm_client:
                explanation = self._explain_with_llm()
                    pseudocode, filename, function_name, architecture, level
                
                
                if explanation:
                    result = self._parse_explanation(explanation, pseudocode)
                    
            else:
                # 使用规则基础的解释
                result = self._explain_with_rules(pseudocode)
                
            # 缓存结果
            self.explanation_cache[cache_key] = result
            
        except Exception as e:
            logger.error(f"解释伪代码失败: {e}")
            result.summary = f"解释失败: {str(e)}"
            
        return result
        
    def _explain_with_llm(, self, pseudocode: str, filename: str, function_name: str, architecture: str, level: ExplanationLevel) -> Optional[str]:
        """
        使用LLM解释伪代码
        
        Args:
            pseudocode: 伪代码
            filename: 文件名
            function_name: 函数名
            architecture: 架构
            level: 解释级别
            
        Returns:
            LLM响应或None
        """
        try:
            from config import Config
            
            # 构建提示词
            prompt = PSEUDOCODE_EXPLANATION_TEMPLATE.format()
                pseudocode=pseudocode,
                filename=filename or 'unknown',
                function_name=function_name or 'unknown',
                architecture=architecture or 'unknown'
            
            
            # 根据解释级别调整提示词
            if level == ExplanationLevel.BASIC:
                prompt += "\n\n请使用通俗易懂的语言，避免专业术语。"
            elif level == ExplanationLevel.SECURITY:
                prompt += "\n\n请重点关注安全风险分析，提供详细的漏洞描述和修复建议。"
                
            model = getattr(Config, 'LLM_MODEL', 'gpt-4')
            
            response = self.llm_client.chat.completions.create()
                model=model,
                messages=[
                    {"role": "system", "content": "你是一名资深的逆向工程和安全分析专家。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=4000
            
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"LLM调用失败: {e}")
            return None
            
    def _parse_explanation(, self, explanation: str, original_code: str) -> CodeExplanation:
        """
        解析LLM返回的解释
        
        Args:
            explanation: LLM响应
            original_code: 原始代码
            
        Returns:
            CodeExplanation: 解析后的解释结果
        """
        result = CodeExplanation(original_code=original_code)
        
        try:
            # 提取JSON部分
            json_match = re.search(r'```json\s*([\s\S]*?)\s*```', explanation)
            if json_match:
                json_str = json_match.group(1)
            else:
                # 尝试直接解析
                json_start = explanation.find('{')
                json_end = explanation.rfind('}') + 1,
                if json_start != -1 and json_end > json_start:
                    json_str = explanation[json_start:json_end]
                else:
                    json_str = explanation
                    
            data = json.loads(json_str)
            
            result.explained_code = data.get('explained_code', '')
            result.summary = data.get('summary', '')
            result.function_explanations = [{
                'name': data.get('function_name', ''),
                'purpose': data.get('purpose', ''),
                'logic_flow': data.get('logic_flow', ''),
                'parameters': data.get('parameters', []),
                'return_value': data.get('return_value', {})
            }]
            result.security_notes = data.get('security_notes', [])
            result.risk_indicators = data.get('risk_indicators', [])
            result.confidence = data.get('confidence', 0.5)
            
        except json.JSONDecodeError as e:
            logger.warning(f"解析JSON失败: {e}")
            # 使用文本解析
            result.summary = explanation[:500]
            result.confidence = 0.3
            
        return result
        
    def _explain_with_rules(self, pseudocode: str) -> CodeExplanation:
        """
        使用规则基础的解释（无LLM时使用）
        
        Args:
            pseudocode: 伪代码
            
        Returns:
            CodeExplanation: 解释结果
        """
        result = CodeExplanation(original_code=pseudocode)
        
        # 提取函数名
        func_pattern = r'(?:void|int|char|bool|size_t|unsigned|long)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')
        func_match = re.search(func_pattern, pseudocode)
        if func_match:
            func_name = func_match.group(1)
            result.function_explanations.append({)
                'name': func_name,
                'purpose': self._infer_function_purpose(func_name, pseudocode)
            }
            
        # 提取变量
        var_pattern = r'(?:int|char|bool|size_t|void\s*\*|unsigned|long)\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        variables = re.findall(var_pattern, pseudocode)
        
        for var in variables:
            purpose = self._infer_variable_purpose(var)
            result.variable_explanations.append({)
                'name': var,
                'purpose': purpose
            }
            
        # 检测危险函数
        dangerous_funcs = ['strcpy', 'strcat', 'sprintf', 'gets', 'scanf', 'memcpy', 'malloc', 'free']
        for func in dangerous_funcs:
            if func in pseudocode:
                result.security_notes.append(f"使用了危险函数: {func}")
                result.risk_indicators.append(f"potential_{func}_issue")
                
        # 检测循环和条件
        if 'while' in pseudocode or 'for' in pseudocode:
            result.summary += "包含循环结构。",
        if 'if' in pseudocode:
            result.summary += "包含条件判断。"
            
        result.confidence = 0.5
        result.summary = f"基于规则的分析结果。函数可能执行: {result.function_explanations[0]['purpose'] if result.function_explanations else '未知操作'}"
        
        return result
        
    def _infer_function_purpose(self, func_name: str, code: str) -> str:
        """
        推断函数用途
        
        Args:
            func_name: 函数名
            code: 代码
            
        Returns:
            用途描述
        """
        # 根据函数名推断
        name_lower = func_name.lower()
        
        if 'init' in name_lower:
            return "初始化函数，用于设置初始状态"
        if 'free' in name_lower or 'clean' in name_lower or 'destroy' in name_lower:
            return "清理函数，用于释放资源"
        if 'read' in name_lower or 'get' in name_lower:
            return "读取函数，用于获取数据"
        if 'write' in name_lower or 'set' in name_lower or 'put' in name_lower:
            return "写入函数，用于设置数据"
        if 'process' in name_lower or 'handle' in name_lower:
            return "处理函数，用于处理数据或事件"
        if 'check' in name_lower or 'verify' in name_lower or 'validate' in name_lower:
            return "验证函数，用于检查数据有效性"
        if 'parse' in name_lower:
            return "解析函数，用于解析数据格式"
        if 'encrypt' in name_lower or 'decrypt' in name_lower:
            return "加密/解密函数，用于数据处理"
        if 'connect' in name_lower or 'send' in name_lower or 'recv' in name_lower:
            return "网络通信函数，用于数据传输"
        if 'main' in name_lower:
            return "主函数，程序入口点"
            
        return "执行特定操作"
        
    def _infer_variable_purpose(self, var_name: str) -> str:
        """
        推断变量用途
        
        Args:
            var_name: 变量名
            
        Returns:
            用途描述
        """
        name_lower = var_name.lower()
        
        if 'size' in name_lower or 'len' in name_lower or 'count' in name_lower:
            return "表示大小或数量"
        if 'buf' in name_lower or 'buffer' in name_lower:
            return "数据缓冲区"
        if 'ptr' in name_lower or 'pointer' in name_lower:
            return "指针变量"
        if 'result' in name_lower or 'ret' in name_lower or 'status' in name_lower:
            return "返回值或状态"
        if 'index' in name_lower or 'idx' in name_lower or 'i' in name_lower:
            return "索引或计数器"
        if 'key' in name_lower or 'secret' in name_lower or 'password' in name_lower:
            return "密钥或敏感数据"
        if 'addr' in name_lower or 'address' in name_lower:
            return "地址信息"
        if 'data' in name_lower:
            return "数据存储"
        if 'flag' in name_lower:
            return "标志位"
        if 'tmp' in name_lower or 'temp' in name_lower:
            return "临时变量"
            
        return "通用变量"
        
    def analyze_function(, self, pseudocode: str, function_name: str, address: str = '') -> FunctionAnalysis:
        """
        分析单个函数
        
        Args:
            pseudocode: 函数伪代码
            function_name: 函数名
            address: 函数地址
            
        Returns:
            FunctionAnalysis: 函数分析结果
        """
        analysis = FunctionAnalysis()
            function_name=function_name,
            address=address
        
        
        # 提取参数
        param_pattern = r'\(([^)]*)\)'
        param_match = re.search(param_pattern, pseudocode.split('\n')[0] if pseudocode else '')
        if param_match:
            params_str = param_match.group(1)
            params = [p.strip() for p in params_str.split(',') if p.strip()]
            
            for param in params:
                parts = param.split()
                if len(parts) >= 2:
                    analysis.parameters.append({)
                        'type': parts[0],
                        'name': parts[-1]
                    }
                    
        # 提取返回类型
        return_pattern = r'^([a-zA-Z_][a-zA-Z0-9_]*\s*\*?)\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(')
        return_match = re.match(return_pattern, pseudocode.strip() if pseudocode else '')
        if return_match:
            analysis.return_type = return_match.group(1).strip()
            
        # 推断功能
        analysis.purpose = self._infer_function_purpose(function_name, pseudocode)
        
        # 检测安全风险
        dangerous_patterns = [
            ('strcpy', '缓冲区溢出风险'),
            ('strcat', '缓冲区溢出风险'),
            ('sprintf', '格式化字符串风险'),
            ('gets', '缓冲区溢出风险'),
            ('scanf', '输入验证不足'),
            ('malloc', '内存泄漏风险'),
            ('free', '双重释放风险'),
            ('memcpy', '缓冲区溢出风险'),
        ]
        
        for pattern, risk in dangerous_patterns:
            if pattern in pseudocode:
                analysis.security_risks.append(risk)
                
        # 检测整数溢出
        if re.search(r'\+\s*\d+|\-\s*\d+|\*\s*\d+', pseudocode):
            if 'size' in pseudocode.lower() or 'len' in pseudocode.lower():
                analysis.security_risks.append('整数溢出风险')
                
        return analysis
        
    def batch_explain(, self, code_blocks: List[Dict[str, str]], level: ExplanationLevel = ExplanationLevel.TECHNICAL) -> List[CodeExplanation]:
        """
        批量解释多个代码块
        
        Args:
            code_blocks: 代码块列表，每个包含 pseudocode, filename, function_name
            level: 解释级别
            
        Returns:
            解释结果列表
        """
        results = []
        
        for block in code_blocks:
            result = self.explain_code()
                pseudocode=block.get('pseudocode', ''),
                filename=block.get('filename', ''),
                function_name=block.get('function_name', ''),
                architecture=block.get('architecture', ''),
                level=level
            
            results.append(result)
            
        return results
        
    def generate_commented_code(, self, pseudocode: str, comments: Dict[int, str]) -> str:
        """
        生成带注释的代码
        
        Args:
            pseudocode: 原始伪代码
            comments: 行号到注释的映射
            
        Returns:
            带注释的代码
        """
        lines = pseudocode.split('\n')
        result_lines = []
        
        for i, line in enumerate(lines):
            result_lines.append(line)
            
            if i + 1 in comments:
                comment = comments[i + 1]
                # 添加注释
                if '//' in line:
                    result_lines.append(f"    // {comment}")
                else:
                    result_lines.append(f"    // {comment}")
                    
        return '\n'.join(result_lines)
        
    def security_analysis(self, pseudocode: str) -> Dict[str, Any]:
        """
        安全视角分析伪代码
        
        Args:
            pseudocode: 伪代码
            
        Returns:
            安全分析结果
        """
        result = {
            'vulnerabilities': [],
            'overall_risk': 'unknown',
            'attack_vectors': []
        }
        
        try:
            if self.llm_client:
                prompt = SECURITY_EXPLANATION_TEMPLATE.format(pseudocode=pseudocode)
                
                response = self.llm_client.chat.completions.create()
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": "你是一名资深的安全研究员。"},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3,
                    max_tokens=2000
                
                
                content = response.choices[0].message.content
                
                # 解析JSON
                json_match = re.search(r'```json\s*([\s\S]*?)\s*```', content)
                if json_match:
                    result = json.loads(json_match.group(1

                    
            else:
                # 使用规则分析
                result = self._security_analysis_rules(pseudocode)
                
        except Exception as e:
            logger.error(f"安全分析失败: {e}")
            
        return result
        
    def _security_analysis_rules(self, pseudocode: str) -> Dict[str, Any]:
        """
        基于规则的安全分析
        
        Args:
            pseudocode: 伪代码
            
        Returns:
            分析结果
        """
        vulnerabilities = []
        attack_vectors = []
        
        # 检测危险函数
        dangerous_funcs = {
            'strcpy': ('缓冲区溢出', 'high', '通过超长输入覆盖缓冲区'),
            'strcat': ('缓冲区溢出', 'high', '通过超长输入覆盖缓冲区'),
            'sprintf': ('格式化字符串', 'high', '通过格式化字符串泄露信息'),
            'gets': ('缓冲区溢出', 'critical', '通过超长输入覆盖缓冲区'),
            'scanf': ('输入验证不足', 'medium', '通过恶意输入触发漏洞'),
            'malloc': ('内存管理问题', 'medium', '可能导致内存泄漏'),
            'free': ('内存管理问题', 'medium', '可能导致双重释放'),
            'memcpy': ('缓冲区溢出', 'high', '通过超长输入覆盖缓冲区'),
        }
        
        for func, (vuln_type, severity, attack) in dangerous_funcs.items():
            if func in pseudocode:
                vulnerabilities.append({)
                    'type': vuln_type,
                    'location': f"函数调用: {func}",
                    'severity': severity,
                    'fix': f"建议使用安全替代函数"
                }
                attack_vectors.append(attack)
                
        # 检测整数溢出
        if re.search(r'\+\s*\d+|\-\s*\d+|\*\s*\d+', pseudocode):
            if 'size' in pseudocode.lower() or 'len' in pseudocode.lower():
                vulnerabilities.append({)
                    'type': '整数溢出',
                    'location': '算术运算',
                    'severity': 'medium',
                    'fix': '添加边界检查'
                }
                
        # 评估整体风险
        severities = [v['severity'] for v in vulnerabilities]
        if 'critical' in severities:
            overall_risk = 'critical'
        elif 'high' in severities:
            overall_risk = 'high'
        elif 'medium' in severities:
            overall_risk = 'medium'
        else:
            overall_risk = 'low'
            
        return {
            'vulnerabilities': vulnerabilities,
            'overall_risk': overall_risk,
            'attack_vectors': attack_vectors
        }
        
    def generate_report(self, explanation: CodeExplanation) -> str:
        """
        生成解释报告
        
        Args:
            explanation: 解释结果
            
        Returns:
            Markdown格式报告
        """
        report = []
        report.append("## 伪代码解释报告\n")
        
        report.append("### 整体摘要")
        report.append(explanation.summary)
        report.append("")
        
        if explanation.function_explanations:
            report.append("### 函数分析")
            for func in explanation.function_explanations:
                report.append(f"\n#### 函数 `{func.get('name', 'unknown')}`")
                if func.get('purpose'):
                    report.append(f"- **功能**: {func['purpose']}")
                if func.get('logic_flow'):
                    report.append(f"- **逻辑流程**: {func['logic_flow']}")
                    
                params = func.get('parameters', [])
                if params:
                    report.append("\n**参数**:")
                    for param in params:
                        report.append(f"- `{param.get('name', '')}` ({param.get('type', '')}): {param.get('description', '')}")
                        
        if explanation.variable_explanations:
            report.append("\n### 变量说明")
            for var in explanation.variable_explanations:
                report.append(f"- `{var.get('name', '')}`: {var.get('purpose', '')}")
                
        if explanation.security_notes:
            report.append("\n### 安全说明")
            for note in explanation.security_notes:
                report.append(f"- ⚠️ {note}")
                
        if explanation.risk_indicators:
            report.append("\n### 风险指标")
            for indicator in explanation.risk_indicators:
                report.append(f"- 🔴 {indicator}")
                
        if explanation.explained_code:
            report.append("\n### 带注释的代码")
            report.append("```c")
            report.append(explanation.explained_code)
            report.append("```")
            
        report.append(f"\n### 置信度")
        report.append(f"- {explanation.confidence:.2f}")
        
        return '\n'.join(report)


def explain_pseudocode(, pseudocode: str, filename: str = '', function_name: str = '', architecture: str = '', level: ExplanationLevel = ExplanationLevel.TECHNICAL) -> CodeExplanation:
    """
    解释伪代码
    
    Args:
        pseudocode: 伪代码文本
        filename: 文件名
        function_name: 函数名
        architecture: 架构
        level: 解释级别
        
    Returns:
        CodeExplanation: 解释结果
    """
    explainer = PseudocodeExplainer()
    return explainer.explain_code(pseudocode, filename, function_name, architecture, level