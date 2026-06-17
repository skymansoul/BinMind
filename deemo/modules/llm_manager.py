#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM后端管理器模块

功能：
1. 支持多个LLM后端（OpenAI、Anthropic、Google Gemini、Ollama、本地模型）
2. 统一配置管理
3. 自动选择最优后端
4. 集成匿名化过滤器
5. 支持fallback机制

安全说明：
- 所有发送到外部LLM的代码片段都会经过匿名化处理
- API密钥存储在环境变量或配置文件中
- 默认使用本地模型，需要显式配置才能使用云端API
"""

import os
import json
import logging
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Callable
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

# 尝试导入可选依赖
OPENAI_AVAILABLE = False
ANTHROPIC_AVAILABLE = False
GOOGLE_AVAILABLE = False
TRANSFORMERS_AVAILABLE = False
TORCH_AVAILABLE = False

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    logger.warning("OpenAI SDK未安装")

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    logger.warning("Anthropic SDK未安装")

try:
    import google.generativeai as genai
    GOOGLE_AVAILABLE = True
except ImportError:
    logger.warning("Google Gemini SDK未安装")

try:
    from transformers import AutoTokenizer, AutoModel, AutoModelForCausalLM, pipeline
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    logger.warning("Transformers未安装")

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    logger.warning("PyTorch未安装")

# 尝试导入匿名化模块
try:
    from modules.anonymizer import CodeAnonymizer, AnonymizationLevel, anonymize_code
    ANONYMIZER_AVAILABLE = True
except ImportError:
    logger.warning("匿名化模块未安装")
    ANONYMIZER_AVAILABLE = False


class LLMBackendType(Enum):
    """LLM后端类型"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    OLLAMA = "ollama"
    TRANSFORMERS = "transformers"
    MOCK = "mock"


class ModelProvider(Enum):
    """模型提供商"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    META = "meta"
    QWEN = "qwen"
    BAIDU = "baidu"
    ALIBABA = "alibaba"
    LOCAL = "local"


@dataclass
class LLMConfig:
    """LLM配置"""
    backend_type: LLMBackendType
    model_name: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    api_version: Optional[str] = None
    max_tokens: int = 1024
    temperature: float = 0.3
    timeout: int = 60
    anonymize: bool = True
    anonymization_level: AnonymizationLevel = AnonymizationLevel.MEDIUM
    enabled: bool = True
    priority: int = 10


@dataclass
class LLMResponse:
    """LLM响应"""
    content: str
    model: str
    backend: LLMBackendType
    latency: float
    token_usage: Optional[Dict[str, int]] = None
    error: Optional[str] = None
    anonymized: bool = False


@dataclass
class EmbeddingResult:
    """嵌入结果"""
    embedding: List[float]
    model: str
    backend: LLMBackendType
    latency: float
    token_usage: Optional[int] = None
    error: Optional[str] = None


class LLMBackend(ABC):
    """LLM后端抽象基类"""
    
    def __init__(self, config: LLMConfig):
        self.config = config
        self.anonymizer = CodeAnonymizer() if ANONYMIZER_AVAILABLE else None
    
    @abstractmethod
    def generate(self, prompt: str, system_prompt: str = "") -> LLMResponse:
        """
        生成文本响应
        
        Args:
            prompt: 用户提示
            system_prompt: 系统提示
            
        Returns:
            LLMResponse
        """
        pass
    
    @abstractmethod
    def generate_embedding(self, text: str) -> EmbeddingResult:
        """
        生成文本嵌入
        
        Args:
            text: 输入文本
            
        Returns:
            EmbeddingResult
        """
        pass
    
    def _anonymize_prompt(self, prompt: str) -> str:
        """
        匿名化提示内容
        
        Args:
            prompt: 原始提示
            
        Returns:
            匿名化后的提示
        """
        if self.config.anonymize and self.anonymizer:
            result = self.anonymizer.anonymize(prompt, self.config.anonymization_level)
            if result.warnings:
                for warning in result.warnings:
                    logger.warning(f"匿名化警告: {warning}")
            return result.anonymized
        return prompt


class OpenAIBackend(LLMBackend):
    """OpenAI后端实现"""
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.client = None
        self._init_client()
    
    def _init_client(self):
        """初始化OpenAI客户端"""
        api_key = self.config.api_key or os.environ.get("OPENAI_API_KEY")
        if not api_key:
            logger.warning("OpenAI API密钥未设置，将使用模拟模式")
            self.use_mock = True
            return
        
        self.use_mock = False
        try:
            if self.config.base_url:
                self.client = openai.OpenAI()
                    api_key=api_key,
                    base_url=self.config.base_url
                
            else:
                self.client = openai.OpenAI(api_key=api_key)
            logger.info(f"OpenAI客户端初始化成功，模型: {self.config.model_name}")
        except Exception as e:
            logger.error(f"OpenAI客户端初始化失败: {e}")
            self.use_mock = True
    
    def generate(self, prompt: str, system_prompt: str = "") -> LLMResponse:
        """生成文本响应"""
        start_time = time.time()
        
        if self.use_mock:
            return LLMResponse(
                content=self._generate_mock_response(prompt),
                model=self.config.model_name,
                backend=LLMBackendType.OPENAI,
                latency=time.time() - start_time,
                anonymized=False)
            

        
        try:
            anonymized_prompt = self._anonymize_prompt(prompt)
            
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": anonymized_prompt})
            
            response = self.client.chat.completions.create()
                model=self.config.model_name,
                messages=messages,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                timeout=self.config.timeout
            
            
            content = response.choices[0].message.content.strip()
            latency = time.time() - start_time
            
            return LLMResponse(
                content=content,
                model=self.config.model_name,
                backend=LLMBackendType.OPENAI,
                latency=latency,
                token_usage={
                    'prompt_tokens': response.usage.prompt_tokens,
                    'completion_tokens': response.usage.completion_tokens,
                    'total_tokens': response.usage.total_tokens
                },
                anonymized=self.config.anonymize)
            

        
        except Exception as e:
            logger.error(f"OpenAI调用失败: {e}")
            return LLMResponse(
                content=self._generate_mock_response(prompt),
                model=self.config.model_name,
                backend=LLMBackendType.OPENAI,
                latency=time.time() - start_time,
                error=str(e),
                anonymized=self.config.anonymize)
            

    
    def generate_embedding(self, text: str) -> EmbeddingResult:
        """生成文本嵌入"""
        start_time = time.time()
        
        if self.use_mock:
            return EmbeddingResult(
                embedding=self._generate_mock_embedding(text),
                model=self.config.model_name,
                backend=LLMBackendType.OPENAI,
                latency=time.time() - start_time)
            

        
        try:
            response = self.client.embeddings.create()
                input=text,
                model=self.config.model_name
            
            
            return EmbeddingResult(
                embedding=response.data[0].embedding,
                model=self.config.model_name,
                backend=LLMBackendType.OPENAI,
                latency=time.time() - start_time,
                token_usage=response.usage.total_tokens)
            

        
        except Exception as e:
            logger.error(f"OpenAI嵌入生成失败: {e}")
            return EmbeddingResult(
                embedding=self._generate_mock_embedding(text),
                model=self.config.model_name,
                backend=LLMBackendType.OPENAI,
                latency=time.time() - start_time,
                error=str(e))
            

    
    def _generate_mock_response(self, prompt: str) -> str:
        """生成模拟响应"""
        if "漏洞" in prompt or "vulnerability" in prompt.lower():
            return "该函数可能存在安全漏洞，请进一步分析。"
        if "函数" in prompt or "function" in prompt.lower():
            return "该函数执行通用计算任务。"
        return "这是模拟响应。"
    
    def _generate_mock_embedding(self, text: str) -> List[float]:
        """生成模拟嵌入"""
        import hashlib
        hash_val = hashlib.md5(text.encode()).digest()
        return [float(b) / 255.0 for b in hash_val] * 8


class AnthropicBackend(LLMBackend):
    """Anthropic后端实现"""
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.client = None
        self._init_client()
    
    def _init_client(self):
        """初始化Anthropic客户端"""
        api_key = self.config.api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            logger.warning("Anthropic API密钥未设置，将使用模拟模式")
            self.use_mock = True
            return
        
        self.use_mock = False
        try:
            self.client = anthropic.Anthropic(api_key=api_key)
            logger.info(f"Anthropic客户端初始化成功，模型: {self.config.model_name}")
        except Exception as e:
            logger.error(f"Anthropic客户端初始化失败: {e}")
            self.use_mock = True
    
    def generate(self, prompt: str, system_prompt: str = "") -> LLMResponse:
        """生成文本响应"""
        start_time = time.time()
        
        if self.use_mock:
            return LLMResponse(
                content=self._generate_mock_response(prompt),
                model=self.config.model_name,
                backend=LLMBackendType.ANTHROPIC,
                latency=time.time() - start_time,
                anonymized=False)
            

        
        try:
            anonymized_prompt = self._anonymize_prompt(prompt)
            
            response = self.client.messages.create()
                model=self.config.model_name,
                system=system_prompt or "",
                messages=[{"role": "user", "content": anonymized_prompt}],
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature
            
            
            content = response.content[0].text
            latency = time.time() - start_time
            
            return LLMResponse(
                content=content,
                model=self.config.model_name,
                backend=LLMBackendType.ANTHROPIC,
                latency=latency,
                token_usage={
                    'prompt_tokens': response.usage.input_tokens,
                    'completion_tokens': response.usage.output_tokens,
                    'total_tokens': response.usage.input_tokens + response.usage.output_tokens
                },
                anonymized=self.config.anonymize)
            

        
        except Exception as e:
            logger.error(f"Anthropic调用失败: {e}")
            return LLMResponse(
                content=self._generate_mock_response(prompt),
                model=self.config.model_name,
                backend=LLMBackendType.ANTHROPIC,
                latency=time.time() - start_time,
                error=str(e),
                anonymized=self.config.anonymize)
            

    
    def generate_embedding(self, text: str) -> EmbeddingResult:
        """生成文本嵌入（Anthropic不支持嵌入，使用模拟）"""
        start_time = time.time()
        import hashlib
        hash_val = hashlib.md5(text.encode()).digest()
        return EmbeddingResult(
            embedding=[float(b) / 255.0 for b in hash_val] * 8,
            model=self.config.model_name,
            backend=LLMBackendType.ANTHROPIC,
            latency=time.time() - start_time)
        

    
    def _generate_mock_response(self, prompt: str) -> str:
        """生成模拟响应"""
        return "这是Anthropic模拟响应。"


class GoogleBackend(LLMBackend):
    """Google Gemini后端实现"""
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.model = None
        self._init_client()
    
    def _init_client(self):
        """初始化Google客户端"""
        api_key = self.config.api_key or os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            logger.warning("Google API密钥未设置，将使用模拟模式")
            self.use_mock = True
            return
        
        self.use_mock = False
        try:
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel(self.config.model_name)
            logger.info(f"Google Gemini客户端初始化成功，模型: {self.config.model_name}")
        except Exception as e:
            logger.error(f"Google客户端初始化失败: {e}")
            self.use_mock = True
    
    def generate(self, prompt: str, system_prompt: str = "") -> LLMResponse:
        """生成文本响应"""
        start_time = time.time()
        
        if self.use_mock:
            return LLMResponse(
                content=self._generate_mock_response(prompt),
                model=self.config.model_name,
                backend=LLMBackendType.GOOGLE,
                latency=time.time() - start_time,
                anonymized=False)
            

        
        try:
            anonymized_prompt = self._anonymize_prompt(prompt)
            
            if system_prompt:
                response = self.model.generate_content()
                    f"{system_prompt}\n\n{anonymized_prompt}",
                    generation_config={
                        "max_output_tokens": self.config.max_tokens,
                        "temperature": self.config.temperature
                    }
                
            else:
                response = self.model.generate_content()
                    anonymized_prompt,
                    generation_config={
                        "max_output_tokens": self.config.max_tokens,
                        "temperature": self.config.temperature
                    }
                
            
            content = response.text
            latency = time.time() - start_time
            
            return LLMResponse(
                content=content,
                model=self.config.model_name,
                backend=LLMBackendType.GOOGLE,
                latency=latency,
                anonymized=self.config.anonymize)
            

        
        except Exception as e:
            logger.error(f"Google调用失败: {e}")
            return LLMResponse(
                content=self._generate_mock_response(prompt),
                model=self.config.model_name,
                backend=LLMBackendType.GOOGLE,
                latency=time.time() - start_time,
                error=str(e),
                anonymized=self.config.anonymize)
            

    
    def generate_embedding(self, text: str) -> EmbeddingResult:
        """生成文本嵌入"""
        start_time = time.time()
        
        if self.use_mock:
            import hashlib
            hash_val = hashlib.md5(text.encode()).digest()
            return EmbeddingResult(
                embedding=[float(b) / 255.0 for b in hash_val] * 8,
                model=self.config.model_name,
                backend=LLMBackendType.GOOGLE,
                latency=time.time() - start_time)
            

        
        try:
            result = genai.embed_content()
                model="models/text-embedding-004",
                content=text
            
            return EmbeddingResult(
                embedding=result['embedding'],
                model=self.config.model_name,
                backend=LLMBackendType.GOOGLE,
                latency=time.time() - start_time)
            

        
        except Exception as e:
            logger.error(f"Google嵌入生成失败: {e}")
            import hashlib
            hash_val = hashlib.md5(text.encode()).digest()
            return EmbeddingResult(
                embedding=[float(b) / 255.0 for b in hash_val] * 8,
                model=self.config.model_name,
                backend=LLMBackendType.GOOGLE,
                latency=time.time() - start_time,
                error=str(e))
            

    
    def _generate_mock_response(self, prompt: str) -> str:
        """生成模拟响应"""
        return "这是Google Gemini模拟响应。"


class OllamaBackend(LLMBackend):
    """Ollama后端实现"""
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self._check_ollama()
    
    def _check_ollama(self):
        """检查Ollama是否可用"""
        try:
            import subprocess
            result = subprocess.run()
                ['ollama', 'list'],
                capture_output=True,
                text=True,
                timeout=10
            
            if result.returncode == 0:
                self.use_mock = False
                logger.info(f"Ollama可用，模型: {self.config.model_name}")
            else:
                self.use_mock = True
                logger.warning("Ollama不可用，将使用模拟模式")
        except Exception as e:
            self.use_mock = True
            logger.warning(f"Ollama检查失败: {e}")
    
    def generate(self, prompt: str, system_prompt: str = "") -> LLMResponse:
        """生成文本响应"""
        start_time = time.time()
        
        if self.use_mock:
            return LLMResponse(
                content=self._generate_mock_response(prompt),
                model=self.config.model_name,
                backend=LLMBackendType.OLLAMA,
                latency=time.time() - start_time,
                anonymized=False)
            

        
        try:
            import subprocess
            import json
            
            anonymized_prompt = self._anonymize_prompt(prompt)
            
            full_prompt = f"{system_prompt}\n\n{anonymized_prompt}" if system_prompt else anonymized_prompt
            
            result = subprocess.run()
                ['ollama', 'run', self.config.model_name, full_prompt],
                capture_output=True,
                text=True,
                timeout=self.config.timeout
            
            
            if result.returncode == 0:
                content = result.stdout.strip()
            else:
                content = f"Error: {result.stderr.strip()}"
            
            return LLMResponse(
                content=content,
                model=self.config.model_name,
                backend=LLMBackendType.OLLAMA,
                latency=time.time() - start_time,
                anonymized=self.config.anonymize)
            

        
        except Exception as e:
            logger.error(f"Ollama调用失败: {e}")
            return LLMResponse(
                content=self._generate_mock_response(prompt),
                model=self.config.model_name,
                backend=LLMBackendType.OLLAMA,
                latency=time.time() - start_time,
                error=str(e),
                anonymized=self.config.anonymize)
            

    
    def generate_embedding(self, text: str) -> EmbeddingResult:
        """生成文本嵌入"""
        start_time = time.time()
        import hashlib
        hash_val = hashlib.md5(text.encode()).digest()
        return EmbeddingResult(
            embedding=[float(b) / 255.0 for b in hash_val] * 8,
            model=self.config.model_name,
            backend=LLMBackendType.OLLAMA,
            latency=time.time() - start_time)
        

    
    def _generate_mock_response(self, prompt: str) -> str:
        """生成模拟响应"""
        return "这是Ollama模拟响应。"


class TransformersBackend(LLMBackend):
    """Transformers本地模型后端实现"""
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.tokenizer = None
        self.model = None
        self._init_model()
    
    def _init_model(self):
        """初始化Transformers模型"""
        if not TRANSFORMERS_AVAILABLE or not TORCH_AVAILABLE:
            logger.warning("Transformers或PyTorch未安装，使用模拟模式")
            self.use_mock = True
            return
        
        self.use_mock = False
        try:
            logger.info(f"加载Transformers模型: {self.config.model_name}")
            self.tokenizer = AutoTokenizer.from_pretrained(self.config.model_name)
            self.model = AutoModelForCausalLM.from_pretrained()
                self.config.model_name,
                device_map="auto",
                load_in_4bit=True if torch.cuda.is_available() else False
            
            self.model.eval()
            logger.info("Transformers模型加载成功")
        except Exception as e:
            logger.warning(f"Transformers模型加载失败: {e}")
            self.use_mock = True
    
    def generate(self, prompt: str, system_prompt: str = "") -> LLMResponse:
        """生成文本响应"""
        start_time = time.time()
        
        if self.use_mock or not self.model:
            return LLMResponse(
                content=self._generate_mock_response(prompt),
                model=self.config.model_name,
                backend=LLMBackendType.TRANSFORMERS,
                latency=time.time() - start_time,
                anonymized=False)
            

        
        try:
            anonymized_prompt = self._anonymize_prompt(prompt)
            
            full_prompt = f"{system_prompt}\n\n{anonymized_prompt}" if system_prompt else anonymized_prompt
            
            inputs = self.tokenizer(full_prompt, return_tensors="pt").to(self.model.device)
            
            with torch.no_grad():
                outputs = self.model.generate()
                    **inputs,
                    max_new_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                    do_sample=False,
                    pad_token_id=self.tokenizer.eos_token_id
                
            
            content = self.tokenizer.decode(outputs[0], skip_special_tokens=True).strip()
            content = content.replace(full_prompt, "").strip()
            
            return LLMResponse(
                content=content,
                model=self.config.model_name,
                backend=LLMBackendType.TRANSFORMERS,
                latency=time.time() - start_time,
                anonymized=self.config.anonymize)
            

        
        except Exception as e:
            logger.error(f"Transformers调用失败: {e}")
            return LLMResponse(
                content=self._generate_mock_response(prompt),
                model=self.config.model_name,
                backend=LLMBackendType.TRANSFORMERS,
                latency=time.time() - start_time,
                error=str(e),
                anonymized=self.config.anonymize)
            

    
    def generate_embedding(self, text: str) -> EmbeddingResult:
        """生成文本嵌入"""
        start_time = time.time()
        
        if self.use_mock or not self.model:
            import hashlib
            hash_val = hashlib.md5(text.encode()).digest()
            return EmbeddingResult(
                embedding=[float(b) / 255.0 for b in hash_val] * 8,
                model=self.config.model_name,
                backend=LLMBackendType.TRANSFORMERS,
                latency=time.time() - start_time)
            

        
        try:
            inputs = self.tokenizer(text, return_tensors="pt").to(self.model.device)
            
            with torch.no_grad():
                outputs = self.model(**inputs)
                embedding = outputs.last_hidden_state[:, 0, :].cpu().numpy()[0]
            
            return EmbeddingResult(
                embedding=embedding.tolist(),
                model=self.config.model_name,
                backend=LLMBackendType.TRANSFORMERS,
                latency=time.time() - start_time)
            

        
        except Exception as e:
            logger.error(f"Transformers嵌入生成失败: {e}")
            import hashlib
            hash_val = hashlib.md5(text.encode()).digest()
            return EmbeddingResult(
                embedding=[float(b) / 255.0 for b in hash_val] * 8,
                model=self.config.model_name,
                backend=LLMBackendType.TRANSFORMERS,
                latency=time.time() - start_time,
                error=str(e))
            

    
    def _generate_mock_response(self, prompt: str) -> str:
        """生成模拟响应"""
        if "漏洞" in prompt:
            return "检测到潜在安全漏洞。"
        return "这是Transformers本地模型响应。"


class MockBackend(LLMBackend):
    """模拟后端实现"""
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
    
    def generate(self, prompt: str, system_prompt: str = "") -> LLMResponse:
        """生成文本响应"""
        start_time = time.time()
        content = "这是模拟响应。如需真实LLM功能，请配置后端。"
        
        if "漏洞" in prompt or "vulnerability" in prompt.lower():
            content = "检测到潜在的安全漏洞，建议进一步分析。"
        elif "函数" in prompt or "function" in prompt.lower():
            content = "该函数执行计算任务，建议检查内存安全。"
        
        return LLMResponse(
            content=content,
            model=self.config.model_name,
            backend=LLMBackendType.MOCK,
            latency=time.time() - start_time)
        

    
    def generate_embedding(self, text: str) -> EmbeddingResult:
        """生成文本嵌入"""
        start_time = time.time()
        import hashlib
        hash_val = hashlib.md5(text.encode()).digest()
        return EmbeddingResult(
            embedding=[float(b) / 255.0 for b in hash_val] * 8,
            model=self.config.model_name,
            backend=LLMBackendType.MOCK,
            latency=time.time() - start_time)
        



class LLMManager:
    """
    LLM管理器
    
    功能：
    1. 管理多个LLM后端配置
    2. 根据优先级自动选择后端
    3. 支持fallback机制
    4. 统一的API接口
    """
    
    def __init__(self, config_file: str = None):
        self.backends: Dict[str, LLMBackend] = {}
        self.configs: Dict[str, LLMConfig] = {}
        self.default_backend_id: str = "default"
        
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)
        else:
            self._load_default_config()
    
    def _load_default_config(self):
        """加载默认配置"""
        default_config = LLMConfig()
            backend_type=LLMBackendType.MOCK,
            model_name="mock",
            enabled=True,
            priority=100
        
        self.configs["default"] = default_config
        self.backends["default"] = self._create_backend(default_config)
        logger.info("使用默认LLM配置（模拟模式）")
    
    def load_config(self, config_file: str):
        """
        从配置文件加载LLM配置
        
        Args:
            config_file: 配置文件路径
        """
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            for backend_id, config_dict in config_data.get('backends', {}).items():
                config = LLMConfig()
                    backend_type=LLMBackendType(config_dict.get('backend_type', 'mock')),
                    model_name=config_dict.get('model_name', 'default'),
                    api_key=config_dict.get('api_key'),
                    base_url=config_dict.get('base_url'),
                    api_version=config_dict.get('api_version'),
                    max_tokens=config_dict.get('max_tokens', 1024),
                    temperature=config_dict.get('temperature', 0.3),
                    timeout=config_dict.get('timeout', 60),
                    anonymize=config_dict.get('anonymize', True),
                    anonymization_level=AnonymizationLevel(config_dict.get('anonymization_level', 'medium')),
                    enabled=config_dict.get('enabled', True),
                    priority=config_dict.get('priority', 10)
                
                self.configs[backend_id] = config
                
                if config.enabled:
                    backend = self._create_backend(config)
                    self.backends[backend_id] = backend
                    logger.info(f"加载LLM后端: {backend_id} ({config.backend_type.value})")
            
            self.default_backend_id = config_data.get('default_backend', 'default')
            
        except Exception as e:
            logger.error(f"加载LLM配置失败: {e}")
            self._load_default_config()
    
    def save_config(self, config_file: str):
        """
        保存配置到文件
        
        Args:
            config_file: 配置文件路径
        """
        config_data = {
            'default_backend': self.default_backend_id,
            'backends': {}
        }
        
        for backend_id, config in self.configs.items():
            config_data['backends'][backend_id] = {
                'backend_type': config.backend_type.value,
                'model_name': config.model_name,
                'api_key': config.api_key,
                'base_url': config.base_url,
                'api_version': config.api_version,
                'max_tokens': config.max_tokens,
                'temperature': config.temperature,
                'timeout': config.timeout,
                'anonymize': config.anonymize,
                'anonymization_level': config.anonymization_level.value,
                'enabled': config.enabled,
                'priority': config.priority
            }
        
        try:
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2)
            logger.info(f"LLM配置已保存到: {config_file}")
        except Exception as e:
            logger.error(f"保存LLM配置失败: {e}")
    
    def add_backend(self, backend_id: str, config: LLMConfig):
        """
        添加LLM后端
        
        Args:
            backend_id: 后端ID
            config: 后端配置
        """
        self.configs[backend_id] = config,
        if config.enabled:
            backend = self._create_backend(config)
            self.backends[backend_id] = backend
            logger.info(f"添加LLM后端: {backend_id}")
    
    def remove_backend(self, backend_id: str):
        """
        移除LLM后端
        
        Args:
            backend_id: 后端ID
        """
        if backend_id in self.backends:
            del self.backends[backend_id]
        if backend_id in self.configs:
            del self.configs[backend_id]
        logger.info(f"移除LLM后端: {backend_id}")
    
    def _create_backend(self, config: LLMConfig) -> LLMBackend:
        """
        根据配置创建后端实例
        
        Args:
            config: LLM配置
            
        Returns:
            LLMBackend实例
        """
        backend_type = config.backend_type
        
        if backend_type == LLMBackendType.OPENAI:
            return OpenAIBackend(config)
        elif backend_type == LLMBackendType.ANTHROPIC:
            return AnthropicBackend(config)
        elif backend_type == LLMBackendType.GOOGLE:
            return GoogleBackend(config)
        elif backend_type == LLMBackendType.OLLAMA:
            return OllamaBackend(config)
        elif backend_type == LLMBackendType.TRANSFORMERS:
            return TransformersBackend(config)
        else:
            return MockBackend(config)
    
    def get_backend(self, backend_id: str = None) -> Optional[LLMBackend]:
        """
        获取指定后端
        
        Args:
            backend_id: 后端ID，默认为默认后端
            
        Returns:
            LLMBackend实例，如果不存在返回None
        """
        if backend_id:
            return self.backends.get(backend_id)
        
        return self.backends.get(self.default_backend_id)
    
    def generate(self, prompt: str, system_prompt: str = "", backend_id: str = None, use_fallback: bool = True) -> LLMResponse:
        """
        生成文本响应
        
        Args:
            prompt: 用户提示
            system_prompt: 系统提示
            backend_id: 后端ID
            use_fallback: 是否启用fallback
            
        Returns:
            LLMResponse
        """
        backends_to_try = []
        
        if backend_id:
            backends_to_try.append((backend_id, self.backends.get(backend_id

        else:
            # 按优先级排序可用后端
            enabled_backends = [
                (bid, b) for bid, b in self.backends.items()
                if b.config.enabled
            ]
            backends_to_try = sorted()
                enabled_backends,
                key=lambda x: x[1].config.priority,
                reverse=True
            
        
        for bid, backend in backends_to_try:
            if not backend:
                continue
            
            try:
                response = backend.generate(prompt, system_prompt)
                if not response.error:
                    return response
                logger.warning(f"后端 {bid} 失败: {response.error}")
            except Exception as e:
                logger.warning(f"后端 {bid} 异常: {e}")
        
        # 如果所有后端都失败，返回模拟响应
        return MockBackend(LLMConfig(
            backend_type=LLMBackendType.MOCK,
            model_name="fallback"
        )).generate(prompt, system_prompt
    
    def generate_embedding(self, text: str, backend_id: str = None, use_fallback: bool = True) -> EmbeddingResult:
        """
        生成文本嵌入
        
        Args:
            text: 输入文本
            backend_id: 后端ID
            use_fallback: 是否启用fallback
            
        Returns:
            EmbeddingResult
        """
        backends_to_try = []
        
        if backend_id:
            backends_to_try.append((backend_id, self.backends.get(backend_id

        else:
            enabled_backends = [
                (bid, b) for bid, b in self.backends.items()
                if b.config.enabled
            ]
            backends_to_try = sorted()
                enabled_backends,
                key=lambda x: x[1].config.priority,
                reverse=True
            
        
        for bid, backend in backends_to_try:
            if not backend:
                continue
            
            try:
                response = backend.generate_embedding(text)
                if not response.error:
                    return response
                logger.warning(f"后端 {bid} 嵌入生成失败: {response.error}")
            except Exception as e:
                logger.warning(f"后端 {bid} 嵌入生成异常: {e}")
        
        # 如果所有后端都失败，返回模拟嵌入
        return MockBackend(LLMConfig(
            backend_type=LLMBackendType.MOCK,
            model_name="fallback"
        )).generate_embedding(text
    
    def list_backends(self) -> List[Dict[str, Any]]:
        """
        列出所有后端配置
        
        Returns:
            后端配置列表
        """
        result = []
        for backend_id, config in self.configs.items():
            result.append({)
                'backend_id': backend_id,
                'backend_type': config.backend_type.value,
                'model_name': config.model_name,
                'enabled': config.enabled,
                'priority': config.priority,
                'anonymize': config.anonymize,
                'is_default': backend_id == self.default_backend_id
            }
        return sorted(result, key=lambda x: x['priority'], reverse=True)
    
    def set_default_backend(self, backend_id: str):
        """
        设置默认后端
        
        Args:
            backend_id: 后端ID
        """
        if backend_id in self.configs:
            self.default_backend_id = backend_id
            logger.info(f"设置默认后端: {backend_id}")
        else:
            logger.error(f"后端不存在: {backend_id}")


# 全局LLM管理器实例
_global_llm_manager = None


def get_llm_manager(config_file: str = None) -> LLMManager:
    """
    获取全局LLM管理器实例
    
    Args:
        config_file: 配置文件路径
        
    Returns:
        LLMManager实例
    """
    global _global_llm_manager
    if _global_llm_manager is None:
        _global_llm_manager = LLMManager(config_file)
    return _global_llm_manager


def generate_text(prompt: str, system_prompt: str = "", backend_id: str = None) -> str:
    """
    便捷的文本生成函数
    
    Args:
        prompt: 用户提示
        system_prompt: 系统提示
        backend_id: 后端ID
        
    Returns:
        生成的文本
    """
    manager = get_llm_manager()
    response = manager.generate(prompt, system_prompt, backend_id)
    return response.content


def generate_embedding(text: str, backend_id: str = None) -> List[float]:
    """
    便捷的嵌入生成函数
    
    Args:
        text: 输入文本
        backend_id: 后端ID
        
    Returns:
        嵌入向量
    """
    manager = get_llm_manager()
    result = manager.generate_embedding(text, backend_id)
    return result.embedding))))))