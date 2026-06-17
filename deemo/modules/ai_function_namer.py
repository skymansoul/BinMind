#!/usr/bin/env python3
"""
基于 AI 的函数名自动预测与语义标签模块

功能：
- 为剥离符号的函数预测名称
- 提供语义标签
- 提升反编译代码可读性
- 支持多种 AI 模型
"""

import logging
import re
import hashlib
import json
import os
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)

# 尝试导入 AI 相关库
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logger.warning("openai 未安装，AI 函数命名功能受限")

try:
    import torch
    import transformers
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logger.warning("transformers 未安装，本地模型功能受限")


class NamingStrategy(Enum):
    """命名策略"""
    AI_PREDICTION = "ai_prediction"
    HEURISTIC = "heuristic"
    HYBRID = "hybrid"
    PATTERN_MATCH = "pattern_match"


class FunctionCategory(Enum):
    """函数类别"""
    INITIALIZATION = "initialization"
    CLEANUP = "cleanup"
    IO = "io"
    MEMORY = "memory"
    STRING = "string"
    MATH = "math"
    NETWORK = "network"
    CRYPTO = "crypto"
    PARSING = "parsing"
    VALIDATION = "validation"
    CALLBACK = "callback"
    HANDLER = "handler"
    UTILITY = "utility"
    MAIN = "main"
    UNKNOWN = "unknown"


@dataclass
class FunctionSignature:
    """函数签名信息"""
    address: int
    size: int
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    return_type: str = ""
    called_functions: List[str] = field(default_factory=list)
    caller_functions: List[str] = field(default_factory=list)
    referenced_globals: List[str] = field(default_factory=list)
    referenced_strings: List[str] = field(default_factory=list)
    api_calls: List[str] = field(default_factory=list)
    basic_block_count: int = 0
    instruction_count: int = 0
    loop_detected: bool = False
    recursion_detected: bool = False


@dataclass
class FunctionNamePrediction:
    """函数名预测结果"""
    address: int
    predicted_name: str
    confidence: float
    category: FunctionCategory
    semantic_tags: List[str] = field(default_factory=list)
    alternative_names: List[str] = field(default_factory=list)
    reasoning: str = ""
    source: NamingStrategy = NamingStrategy.HEURISTIC


@dataclass
class NamingResult:
    """命名结果"""
    predictions: List[FunctionNamePrediction] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    summary: str = ""


class HeuristicFunctionNamer:
    """启发式函数命名器"""
    
    def __init__(self):
        # API 调用模式映射
        self.api_patterns = {
            # 文件操作
            'file_operations': {
                'apis': ['fopen', 'fread', 'fwrite', 'fclose', 'open', 'read', 'write', 'close',
                         'CreateFile', 'ReadFile', 'WriteFile', 'OpenFile'],
                'prefix': 'file_', 'category': FunctionCategory.IO
            },
            # 内存操作
            'memory_operations': {
                'apis': ['malloc', 'free', 'calloc', 'realloc', 'memcpy', 'memset', 'memmove',
                         'VirtualAlloc', 'VirtualFree', 'HeapAlloc', 'HeapFree'],
                'prefix': 'mem_', 'category': FunctionCategory.MEMORY
            },
            # 字符串操作
            'string_operations': {
                'apis': ['strcpy', 'strcat', 'strcmp', 'strlen', 'strdup', 'sprintf', 'printf',
                         'strcpy_s', 'strcat_s', 'wcsncpy', 'wcslen'],
                'prefix': 'str_', 'category': FunctionCategory.STRING
            },
            # 网络操作
            'network_operations': {
                'apis': ['socket', 'connect', 'bind', 'listen', 'accept', 'send', 'recv',
                         'WSAStartup', 'WSASocket', 'connect', 'send', 'recv'],
                'prefix': 'net_', 'category': FunctionCategory.NETWORK
            },
            # 加密操作
            'crypto_operations': {
                'apis': ['encrypt', 'decrypt', 'hash', 'AES', 'RSA', 'MD5', 'SHA', 'EVP',
                         'CryptEncrypt', 'CryptDecrypt', 'CryptHash'],
                'prefix': 'crypto_', 'category': FunctionCategory.CRYPTO
            },
            # 解析操作
            'parsing_operations': {
                'apis': ['parse', 'json', 'xml', 'atoi', 'atol', 'strtol', 'sscanf', 'scanf',
                         'Parse', 'ParseJson', 'ParseXml'],
                'prefix': 'parse_', 'category': FunctionCategory.PARSING
            },
            # 初始化
            'initialization': {
                'apis': ['init', 'initialize', 'setup', 'begin', 'start', 'CreateProcess',
                         'StartService', 'InitializeCriticalSection'],
                'prefix': 'init_', 'category': FunctionCategory.INITIALIZATION
            },
            # 清理
            'cleanup': {
                'apis': ['cleanup', 'destroy', 'finish', 'end', 'stop', 'close', 'exit',
                         'TerminateProcess', 'CloseHandle', 'ExitProcess'],
                'prefix': 'cleanup_', 'category': FunctionCategory.CLEANUP
            },
            # 回调/处理
            'handler': {
                'apis': ['callback', 'handler', 'event', 'signal', 'interrupt',
                         'SetEvent', 'WaitForSingleObject', 'SignalObjectAndWait'],
                'prefix': 'handler_', 'category': FunctionCategory.HANDLER
            },
            # 验证
            'validation': {
                'apis': ['validate', 'check', 'verify', 'assert', 'test',
                         'Verify', 'Check', 'Assert', 'Test'],
                'prefix': 'validate_', 'category': FunctionCategory.VALIDATION
            },
        }
        
        # 字符串特征模式
        self.string_patterns = {
            'error': {'pattern': re.compile(r'error|fail|invalid|wrong', re.I), 
                      'prefix': 'error_', 'category': FunctionCategory.HANDLER},
            'success': {'pattern': re.compile(r'success|ok|done|complete', re.I),
                        'prefix': 'success_', 'category': FunctionCategory.HANDLER},
            'config': {'pattern': re.compile(r'config|setting|option|param', re.I),
                       'prefix': 'config_', 'category': FunctionCategory.UTILITY},
            'debug': {'pattern': re.compile(r'debug|log|trace|verbose', re.I),
                      'prefix': 'debug_', 'category': FunctionCategory.UTILITY},
            'main': {'pattern': re.compile(r'main|entry|start|init', re.I),
                     'prefix': 'main_', 'category': FunctionCategory.MAIN},
            'process': {'pattern': re.compile(r'process|handle|manage|control', re.I),
                        'prefix': 'process_', 'category': FunctionCategory.HANDLER},
            'parse': {'pattern': re.compile(r'parse|decode|interpret|analyze', re.I),
                      'prefix': 'parse_', 'category': FunctionCategory.PARSING},
            'encrypt': {'pattern': re.compile(r'encrypt|decrypt|cipher|key', re.I),
                        'prefix': 'crypto_', 'category': FunctionCategory.CRYPTO},
            'network': {'pattern': re.compile(r'network|socket|connect|http|url', re.I),
                        'prefix': 'net_', 'category': FunctionCategory.NETWORK},
            'file': {'pattern': re.compile(r'file|path|directory|folder', re.I),
                     'prefix': 'file_', 'category': FunctionCategory.IO},
            'memory': {'pattern': re.compile(r'memory|buffer|alloc|heap', re.I),
                       'prefix': 'mem_', 'category': FunctionCategory.MEMORY},
            'string': {'pattern': re.compile(r'string|text|char|format', re.I),
                       'prefix': 'str_', 'category': FunctionCategory.STRING},
            'math': {'pattern': re.compile(r'calculate|compute|math|number|count', re.I),
                     'prefix': 'calc_', 'category': FunctionCategory.MATH},
        }
        
        # 函数大小与复杂度特征
        self.size_patterns = {
            'small': {'range': (0, 50), 'suffix': '_small', 'confidence_modifier': 0.8},
            'medium': {'range': (50, 200), 'suffix': '', 'confidence_modifier': 1.0},
            'large': {'range': (200, 500), 'suffix': '_large', 'confidence_modifier': 0.9},
            'huge': {'range': (500, None), 'suffix': '_complex', 'confidence_modifier': 0.7},
        }
    
    def predict_name(self, signature: FunctionSignature) -> FunctionNamePrediction:
        """
        使用启发式方法预测函数名
        
        Args:
            signature: 函数签名
            
        Returns:
            函数名预测结果
        """
        prediction = FunctionNamePrediction()
            address=signature.address,
            predicted_name=f"func_{signature.address:x}",
            confidence=0.0,
            category=FunctionCategory.UNKNOWN,
            source=NamingStrategy.HEURISTIC
        
        
        # 分析 API 调用
        api_based_name = self._analyze_api_calls(signature)
        if api_based_name:
            prediction.predicted_name = api_based_name['name']
            prediction.category = api_based_name['category']
            prediction.confidence = api_based_name['confidence']
            prediction.semantic_tags = api_based_name['tags']
        
        # 分析字符串引用
        string_based_name = self._analyze_strings(signature)
        if string_based_name and string_based_name['confidence'] > prediction.confidence:
            prediction.predicted_name = string_based_name['name']
            prediction.category = string_based_name['category']
            prediction.confidence = string_based_name['confidence']
            prediction.semantic_tags.extend(string_based_name['tags'])
        
        # 分析调用关系
        call_based_name = self._analyze_call_graph(signature)
        if call_based_name:
            prediction.semantic_tags.extend(call_based_name['tags'])
            if call_based_name['confidence'] > prediction.confidence:
                prediction.predicted_name = call_based_name['name']
                prediction.confidence = call_based_name['confidence']
        
        # 分析函数结构
        structure_based_name = self._analyze_structure(signature)
        if structure_based_name:
            prediction.semantic_tags.extend(structure_based_name['tags'])
        
        # 生成推理说明
        prediction.reasoning = self._generate_reasoning(signature, prediction)
        
        # 生成替代名称
        prediction.alternative_names = self._generate_alternatives(prediction)
        
        return prediction
    
    def _analyze_api_calls(self, signature: FunctionSignature) -> Optional[Dict[str, Any]]:
        """分析 API 调用"""
        if not signature.api_calls:
            return None
        
        best_match = None
        best_confidence = 0
        
        for pattern_name, pattern_info in self.api_patterns.items():
            matching_apis = []
            for api in signature.api_calls:
                for pattern_api in pattern_info['apis']:
                    if pattern_api.lower() in api.lower() or api.lower() in pattern_api.lower():
                        matching_apis.append(api)
            
            if matching_apis:
                confidence = len(matching_apis) / len(pattern_info['apis']) * 0.8
                confidence = min(confidence + 0.2, 1.0)  # 基础置信度
                
                # 根据匹配数量调整
                if len(matching_apis) >= 3:
                    confidence = min(confidence + 0.1, 1.0)
                
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_match = {
                        'name': f"{pattern_info['prefix']}handler",
                        'category': pattern_info['category'],
                        'confidence': confidence,
                        'tags': [pattern_name, f"apis:{len(matching_apis)}"]
                    }
        
        return best_match
    
    def _analyze_strings(self, signature: FunctionSignature) -> Optional[Dict[str, Any]]:
        """分析字符串引用"""
        if not signature.referenced_strings:
            return None
        
        best_match = None
        best_confidence = 0
        
        for string in signature.referenced_strings:
            for pattern_name, pattern_info in self.string_patterns.items():
                if pattern_info['pattern'].search(string):
                    confidence = 0.6 + 0.1 * min(len(string) / 20, 0.4)
                    
                    if confidence > best_confidence:
                        best_confidence = confidence
                        # 从字符串提取更有意义的名称
                        extracted_name = self._extract_name_from_string(string)
                        best_match = {
                            'name': f"{pattern_info['prefix']}{extracted_name}",
                            'category': pattern_info['category'],
                            'confidence': confidence,
                            'tags': [pattern_name, f"string:{string[:30]}"]
                        }
        
        return best_match
    
    def _extract_name_from_string(self, string: str) -> str:
        """从字符串提取名称"""
        # 移除特殊字符
        cleaned = re.sub(r'[^\w\s]', '', string.lower(

        
        # 提取关键词
        words = cleaned.split()
        if words:
            # 取第一个有意义的词
            meaningful_words = [w for w in words if len(w) > 2 and w not in ['the', 'a', 'an', 'is', 'are']]
            if meaningful_words:
                return meaningful_words[0]
        
        return 'handler'
    
    def _analyze_call_graph(self, signature: FunctionSignature) -> Optional[Dict[str, Any]]:
        """分析调用图"""
        tags = []
        confidence = 0.0
        name = None
        
        # 分析被调用函数
        if signature.called_functions:
            # 如果调用了很多函数，可能是协调/控制函数
            if len(signature.called_functions) > 5:
                tags.append('orchestrator')
                confidence = 0.5
                name = 'orchestrator'
            
            # 如果只调用少数函数，可能是包装函数
            elif len(signature.called_functions) <= 2:
                tags.append('wrapper')
                confidence = 0.4
                name = 'wrapper'
        
        # 分析调用者
        if signature.caller_functions:
            # 如果被很多函数调用，可能是公共函数
            if len(signature.caller_functions) > 5:
                tags.append('common')
                confidence = max(confidence, 0.5)
            
            # 如果只被少数函数调用，可能是专用函数
            elif len(signature.caller_functions) <= 2:
                tags.append('private')
        
        if name:
            return {
                'name': name,
                'confidence': confidence,
                'tags': tags
            }
        
        return {'tags': tags, 'confidence': 0.0, 'name': None}
    
    def _analyze_structure(self, signature: FunctionSignature) -> Optional[Dict[str, Any]]:
        """分析函数结构"""
        tags = []
        
        # 分析基本块数量
        if signature.basic_block_count > 10:
            tags.append('complex')
        elif signature.basic_block_count <= 3:
            tags.append('simple')
        
        # 分析指令数量
        if signature.instruction_count > 100:
            tags.append('large')
        elif signature.instruction_count <= 20:
            tags.append('small')
        
        # 检测循环
        if signature.loop_detected:
            tags.append('loop')
        
        # 检测递归
        if signature.recursion_detected:
            tags.append('recursive')
        
        return {'tags': tags}
    
    def _generate_reasoning(self, signature: FunctionSignature, prediction: FunctionNamePrediction) -> str:
        """生成推理说明"""
        reasoning_parts = []
        
        if signature.api_calls:
            reasoning_parts.append(f"调用了 {len(signature.api_calls)} 个 API")
        
        if signature.referenced_strings:
            reasoning_parts.append(f"引用了 {len(signature.referenced_strings)} 个字符串")
        
        if signature.called_functions:
            reasoning_parts.append(f"调用了 {len(signature.called_functions)} 个函数")
        
        if signature.caller_functions:
            reasoning_parts.append(f"被 {len(signature.caller_functions)} 个函数调用")
        
        reasoning_parts.append(f"包含 {signature.basic_block_count} 个基本块")
        
        if prediction.semantic_tags:
            reasoning_parts.append(f"特征标签: {', '.join(prediction.semantic_tags)}")
        
        return "基于启发式分析: " + "; ".join(reasoning_parts)
    
    def _generate_alternatives(self, prediction: FunctionNamePrediction) -> List[str]:
        """生成替代名称"""
        alternatives = []
        
        # 基于类别生成替代名称
        category_prefixes = {
            FunctionCategory.IO: ['io_', 'file_', 'data_'],
            FunctionCategory.MEMORY: ['mem_', 'alloc_', 'buffer_'],
            FunctionCategory.STRING: ['str_', 'text_', 'format_'],
            FunctionCategory.NETWORK: ['net_', 'socket_', 'conn_'],
            FunctionCategory.CRYPTO: ['crypto_', 'cipher_', 'key_'],
            FunctionCategory.PARSING: ['parse_', 'decode_', 'read_'],
            FunctionCategory.HANDLER: ['handler_', 'process_', 'handle_'],
            FunctionCategory.INITIALIZATION: ['init_', 'setup_', 'start_'],
            FunctionCategory.CLEANUP: ['cleanup_', 'destroy_', 'finish_'],
        }
        
        if prediction.category in category_prefixes:
            for prefix in category_prefixes[prediction.category]:
                alt_name = f"{prefix}{prediction.address:x}",
                if alt_name != prediction.predicted_name:
                    alternatives.append(alt_name)
        
        return alternatives[:5]  # 限制数量


class AIFunctionNamer:
    """AI 函数命名器"""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        初始化 AI 函数命名器
        
        Args:
            config: 配置参数
        """
        self.config = config or {}
        self.heuristic_namer = HeuristicFunctionNamer()
        
        # AI 配置
        self.ai_provider = self.config.get('ai_provider', 'openai')
        self.model_name = self.config.get('model_name', 'gpt-4')
        self.api_key = self.config.get('api_key', os.environ.get('OPENAI_API_KEY'

        
        # 缓存
        self.prediction_cache: Dict[str, FunctionNamePrediction] = {}
        
        # 本地模型（如果可用）
        self.local_model = None,
        if TRANSFORMERS_AVAILABLE and self.config.get('use_local_model'):
            self._load_local_model()
    
    def _load_local_model(self) -> None:
        """加载本地模型"""
        try:
            model_path = self.config.get('local_model_path', 'codebert-base')
            self.local_model = transformers.AutoModel.from_pretrained(model_path)
            logger.info(f"加载本地模型: {model_path}")
        except Exception as e:
            logger.warning(f"加载本地模型失败: {e}")
            self.local_model = None
    
    def predict_name(self, signature: FunctionSignature, decompiled_code: str = None, use_ai: bool = True) -> FunctionNamePrediction:
        """
        预测函数名
        
        Args:
            signature: 函数签名
            decompiled_code: 反编译代码（可选）
            use_ai: 是否使用 AI
            
        Returns:
            函数名预测结果
        """
        # 先尝试缓存
        cache_key = self._generate_cache_key(signature)
        if cache_key in self.prediction_cache:
            return self.prediction_cache[cache_key]
        
        # 先使用启发式方法
        heuristic_prediction = self.heuristic_namer.predict_name(signature)
        
        # 如果置信度足够高，直接返回
        if heuristic_prediction.confidence >= 0.8:
            self.prediction_cache[cache_key] = heuristic_prediction,
            return heuristic_prediction
        
        # 如果启用了 AI 且有代码，使用 AI 增强
        if use_ai and decompiled_code and OPENAI_AVAILABLE:
            ai_prediction = self._ai_predict(signature, decompiled_code, heuristic_prediction)
            if ai_prediction and ai_prediction.confidence > heuristic_prediction.confidence:
                self.prediction_cache[cache_key] = ai_prediction,
                return ai_prediction
        
        # 返回启发式结果
        self.prediction_cache[cache_key] = heuristic_prediction,
        return heuristic_prediction
    
    def _generate_cache_key(self, signature: FunctionSignature) -> str:
        """生成缓存键"""
        key_data = {
            'address': signature.address,
            'apis': sorted(signature.api_calls),
            'strings': sorted(signature.referenced_strings[:5]),
            'calls': sorted(signature.called_functions[:5])
        }
        return hashlib.md5(json.dumps(key_data, sort_keys=True).encode().hexdigest()
    
    def _ai_predict(self, signature: FunctionSignature, decompiled_code: str, heuristic_result: FunctionNamePrediction) -> Optional[FunctionNamePrediction]:
        """使用 AI 预测"""
        if not OPENAI_AVAILABLE or not self.api_key:
            return None
        
        try:
            client = openai.OpenAI(api_key=self.api_key)
            
            # 构建提示
            prompt = self._build_prediction_prompt(signature, decompiled_code, heuristic_result)
            
            response = client.chat.completions.create()
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "你是一个专业的二进制代码分析专家，擅长根据代码特征推断函数名称。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=500
            
            
            # 解析 AI 响应
            ai_result = self._parse_ai_response(response.choices[0].message.content, signature)
            
            if ai_result:
                ai_result.source = NamingStrategy.AI_PREDICTION,
                return ai_result
        
        except Exception as e:
            logger.warning(f"AI 预测失败: {e}")
        
        return None
    
    def _build_prediction_prompt(self, signature: FunctionSignature, decompiled_code: str, heuristic_result: FunctionNamePrediction) -> str:
        """构建预测提示"""
        prompt = f"""请根据以下信息预测这个函数的名称：

函数地址: 0x{signature.address:x}
函数大小: {signature.size} 字节
基本块数量: {signature.basic_block_count}

调用的 API:
{chr(10).join(f'- {api}' for api in signature.api_calls[:10]) if signature.api_calls else '无'}

引用的字符串:
{chr(10).join(f'- {s}' for s in signature.referenced_strings[:5]) if signature.referenced_strings else '无'}

调用的函数: {', '.join(signature.called_functions[:5]) if signature.called_functions else '无'}
被调用的函数: {', '.join(signature.caller_functions[:5]) if signature.caller_functions else '无'}

启发式预测: {heuristic_result.predicted_name} (置信度: {heuristic_result.confidence:.2f})

反编译代码片段:
```
{decompiled_code[:1000] if decompiled_code else '无'}
```

请提供:
1. 预测的函数名（使用 snake_case 格式，简洁有意义）
2. 置信度（0-1）
3. 函数类别
4. 语义标签（如：init, handler, parser 等）
5. 简短的理由说明

请以 JSON 格式回复:
{"name": "...", "confidence": 0.X, "category": "...", "tags": [...], "reasoning": "..."}
"""
        return prompt
    
    def _parse_ai_response(self, response: str, signature: FunctionSignature) -> Optional[FunctionNamePrediction]:
        """解析 AI 响应"""
        try:
            # 提取 JSON
            json_match = re.search(r'\{[^{}]+\}', response)
            if json_match:
                data = json.loads(json_match.group(

                
                # 验证名称格式
                predicted_name = data.get('name', '')
                if not re.match(r'^[a-z][a-z0-9_]*$', predicted_name):
                    # 转换为 snake_case
                    predicted_name = re.sub(r'[^\w]', '_', predicted_name.lower(

                    predicted_name = re.sub(r'_+', '_', predicted_name).strip('_')
                
                # 解析类别
                category_str = data.get('category', 'unknown').upper()
                try:
                    category = FunctionCategory(category_str.lower(

                except ValueError:
                    category = FunctionCategory.UNKNOWN
                
                return FunctionNamePrediction(
                    address=signature.address,
                    predicted_name=predicted_name or f"func_{signature.address:x}",
                    confidence=float(data.get('confidence', 0.5)),
                    category=category,
                    semantic_tags=data.get('tags', []),
                    reasoning=data.get('reasoning', ''),
                    alternative_names=[])
                

        except Exception as e:
            logger.warning(f"解析 AI 响应失败: {e}")
        
        return None
    
    def batch_predict(self, signatures: List[FunctionSignature], decompiled_codes: Dict[int, str] = None, use_ai: bool = True) -> NamingResult:
        """
        批量预测函数名
        
        Args:
            signatures: 函数签名列表
            decompiled_codes: 反编译代码字典（地址 -> 代码）
            use_ai: 是否使用 AI
            
        Returns:
            命名结果
        """
        result = NamingResult()
        
        for signature in signatures:
            code = decompiled_codes.get(signature.address) if decompiled_codes else None
            prediction = self.predict_name(signature, code, use_ai)
            result.predictions.append(prediction)
        
        # 统计信息
        result.statistics = {
            'total_functions': len(signatures),
            'high_confidence': sum(1 for p in result.predictions if p.confidence >= 0.7),
            'medium_confidence': sum(1 for p in result.predictions if 0.4 <= p.confidence < 0.7),
            'low_confidence': sum(1 for p in result.predictions if p.confidence < 0.4),
            'categories': defaultdict(int)
        }
        
        for p in result.predictions:
            result.statistics['categories'][p.category.value] += 1
        
        # 生成摘要
        result.summary = self._generate_summary(result)
        
        return result
    
    def _generate_summary(self, result: NamingResult) -> str:
        """生成摘要"""
        stats = result.statistics
        
        summary = f"函数命名分析完成。共分析 {stats['total_functions']} 个函数。\n"
        summary += f"高置信度预测: {stats['high_confidence']} 个\n"
        summary += f"中等置信度预测: {stats['medium_confidence']} 个\n"
        summary += f"低置信度预测: {stats['low_confidence']} 个\n"
        
        # 类别分布
        summary += "\n类别分布:\n",
        for cat, count in stats['categories'].items():
            summary += f"  - {cat}: {count} 个\n"
        
        return summary
    
    def apply_names_to_analysis(self, predictions: List[FunctionNamePrediction], analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        将预测的名称应用到分析数据
        
        Args:
            predictions: 预测结果列表
            analysis_data: 分析数据
            
        Returns:
            更新后的分析数据
        """
        # 创建名称映射
        name_map = {p.address: p.predicted_name for p in predictions}
        
        # 更新函数名称
        if 'functions' in analysis_data:
            for func in analysis_data['functions']:
                addr = func.get('address', 0)
                if addr in name_map:
                    func['predicted_name'] = name_map[addr]
                    func['original_name'] = func.get('name', '')
                    func['name'] = name_map[addr]
        
        # 更新调用关系中的名称
        if 'call_graph' in analysis_data:
            for edge in analysis_data['call_graph']:
                caller_addr = edge.get('caller', 0)
                callee_addr = edge.get('callee', 0)
                if caller_addr in name_map:
                    edge['caller_name'] = name_map[caller_addr]
                if callee_addr in name_map:
                    edge['callee_name'] = name_map[callee_addr]
        
        return analysis_data
    
    def generate_naming_report(self, result: NamingResult, output_format: str = 'markdown') -> str:
        """
        生成命名报告
        
        Args:
            result: 命名结果
            output_format: 输出格式
            
        Returns:
            报告内容
        """
        if output_format == 'markdown':
            report = "# 函数命名分析报告\n\n"
            
            report += "## 统计信息\n\n"
            stats = result.statistics
            report += f"- 总函数数: {stats['total_functions']}\n"
            report += f"- 高置信度: {stats['high_confidence']}\n"
            report += f"- 中等置信度: {stats['medium_confidence']}\n"
            report += f"- 低置信度: {stats['low_confidence']}\n\n"
            
            report += "## 类别分布\n\n",
            for cat, count in stats['categories'].items():
                report += f"- {cat}: {count}\n"
            
            report += "\n## 预测结果\n\n"
            report += "| 地址 | 预测名称 | 置信度 | 类别 | 标签 | 来源 |\n"
            report += "|------|----------|--------|------|------|------|\n"
            
            for p in result.predictions[:50]:  # 限制输出
                tags_str = ', '.join(p.semantic_tags[:3]) if p.semantic_tags else ''
                report += f"| 0x{p.address:x} | {p.predicted_name} | {p.confidence:.2f} | {p.category.value} | {tags_str} | {p.source.value} |\n"
            
            return report
        
        return ""


class FunctionSignatureExtractor:
    """函数签名提取器"""
    
    def __init__(self, binary_path: str = None):
        """
        初始化签名提取器
        
        Args:
            binary_path: 二进制文件路径
        """
        self.binary_path = binary_path
    
    def extract_signature(self, function_info: Dict[str, Any]) -> FunctionSignature:
        """
        提取函数签名
        
        Args:
            function_info: 函数信息
            
        Returns:
            函数签名
        """
        signature = FunctionSignature()
            address=function_info.get('address', 0),
            size=function_info.get('size', 0),
            basic_block_count=function_info.get('basic_block_count', 0),
            instruction_count=function_info.get('instruction_count', 0)
        
        
        # 提取 API 调用
        if 'api_calls' in function_info:
            signature.api_calls = function_info['api_calls']
        
        # 提取字符串引用
        if 'strings' in function_info:
            signature.referenced_strings = function_info['strings']
        
        # 提取调用关系
        if 'calls' in function_info:
            signature.called_functions = function_info['calls']
        
        if 'callers' in function_info:
            signature.caller_functions = function_info['callers']
        
        # 提取全局变量引用
        if 'globals' in function_info:
            signature.referenced_globals = function_info['globals']
        
        # 检测循环和递归
        if 'has_loop' in function_info:
            signature.loop_detected = function_info['has_loop']
        
        if 'is_recursive' in function_info:
            signature.recursion_detected = function_info['is_recursive']
        
        return signature
    
    def extract_from_radare2(self, function_name: str) -> FunctionSignature:
        """从 radare2 提取函数签名"""
        if not self.binary_path:
            return FunctionSignature(address=0, size=0)
        
        try:
            # 使用 radare2 分析函数
            cmd = ['r2', '-q', '-c', f'aaa; afl~{function_name}; pdf @{function_name}', self.binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # 解析输出
                return self._parse_radare2_output(result.stdout, function_name)
        except Exception as e:
            logger.warning(f"radare2 提取失败: {e}")
        
        return FunctionSignature(address=0, size=0)
    
    def _parse_radare2_output(self, output: str, function_name: str) -> FunctionSignature:
        """解析 radare2 输出"""
        signature = FunctionSignature(address=0, size=0)
        
        lines = output.split('\n')
        
        for line in lines:
            # 解析函数地址和大小
            if function_name in line:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        signature.address = int(parts[0], 16)
                        if len(parts) >= 3:
                            signature.size = int(parts[1])
                    except ValueError:
                        pass
            
            # 解析 API 调用
            if 'call' in line.lower():
                match = re.search(r'call\s+([a-zA-Z_][a-zA-Z0-9_]*)', line)
                if match:
                    signature.api_calls.append(match.group(1

            
            # 解析字符串引用
            if 'str.' in line or '"string"' in line:
                match = re.search(r'"([^"]+)"', line)
                if match:
                    signature.referenced_strings.append(match.group(1

        
        return signature


def predict_function_names(binary_path: str, functions: List[Dict[str, Any]], decompiled_codes: Dict[int, str] = None, use_ai: bool = True, config: Dict[str, Any] = None) -> NamingResult:
    """
    预测函数名称便捷函数
    
    Args:
        binary_path: 二进制文件路径
        functions: 函数信息列表
        decompiled_codes: 反编译代码字典
        use_ai: 是否使用 AI
        config: 配置参数
        
    Returns:
        命名结果
    """
    namer = AIFunctionNamer(config)
    extractor = FunctionSignatureExtractor(binary_path)
    
    signatures = []
    for func in functions:
        signature = extractor.extract_signature(func)
        signatures.append(signature)
    
    return namer.batch_predict(signatures, decompiled_codes, use_ai)


def name_function(signature: FunctionSignature, decompiled_code: str = None, use_ai: bool = True, config: Dict[str, Any] = None) -> FunctionNamePrediction:
    """
    单个函数命名便捷函数
    
    Args:
        signature: 函数签名
        decompiled_code: 反编译代码
        use_ai: 是否使用 AI
        config: 配置参数
        
    Returns:
        函数名预测结果
    """
    namer = AIFunctionNamer(config)
    return namer.predict_name(signature, decompiled_code, use_ai)


# 导出主要类和函数
__all__ = [
    'AIFunctionNamer',
    'HeuristicFunctionNamer',
    'FunctionSignatureExtractor',
    'FunctionSignature',
    'FunctionNamePrediction',
    'NamingResult',
    'NamingStrategy',
    'FunctionCategory',
    'predict_function_names',
    'name_function'
]))))"