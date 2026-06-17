"""
基于 LLM 的伪代码反混淆推理模块

功能:
    1. 直接使用大语言模型对混淆后的伪代码进行理解
    2. 尝试翻译为更清晰的高级语言逻辑
    3. 结合去混淆算法, 提供"可读性增强"版伪代码

核心技术:
    - LLM 提示工程 (多轮对话)
    - 局部上下文 + 全局变量
    - 函数注释自动生成
    - 重命名建议
"""

import logging
import os
import json
import re
import time
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class LLMProvider(Enum):
    OPENAI = "openai"
    OLLAMA = "ollama"
    ANTHROPIC = "anthropic"
    CUSTOM = "custom"


@dataclass
class DeobfContext:
    """反混淆上下文"""
    func_name: str
    decomp_code: str
    arch: str = "x86_64"
    language: str = "c"
    symbol_table: Dict[str, str] = field(default_factory=dict)
    string_table: List[str] = field(default_factory=list)
    call_graph: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class LLMDeobfResult:
    """LLM 反混淆结果"""
    func_name: str
    enhanced_code: str
    summary: str
    renamed_symbols: Dict[str, str] = field(default_factory=dict)
    inference: str = ""
    confidence: float = 0.5
    raw_response: str = ""


class LLMClientBase:
    """LLM 客户端基类"""

    def __init__(self, provider: LLMProvider, model: str):
        self.provider = provider
        self.model = model

    def chat(self, system: str, user: str,
             temperature: float = 0.0) -> str:
        raise NotImplementedError


class OpenAIClient(LLMClientBase):
    """OpenAI 客户端"""

    def __init__(self, model: str = "gpt-4o-mini",
                 api_key: Optional[str] = None,
                 base_url: Optional[str] = None):
        super().__init__(LLMProvider.OPENAI, model)
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.base_url = base_url

    def chat(self, system: str, user: str,
             temperature: float = 0.0) -> str:
        try:
            import openai
            client = openai.OpenAI(api_key=self.api_key, base_url=self.base_url)
            resp = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user}
                ],
                temperature=temperature
            )
            return resp.choices[0].message.content
        except Exception as e:
            logger.warning(f"OpenAI 调用失败: {e}")
            return ""


class OllamaClient(LLMClientBase):
    """Ollama 客户端"""

    def __init__(self, model: str = "qwen2.5-coder:7b",
                 host: str = "http://localhost:11434"):
        super().__init__(LLMProvider.OLLAMA, model)
        self.host = host.rstrip("/")

    def chat(self, system: str, user: str,
             temperature: float = 0.0) -> str:
        try:
            import requests
            r = requests.post(
                f"{self.host}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user}
                    ],
                    "stream": False,
                    "options": {"temperature": temperature}
                },
                timeout=180
            )
            r.raise_for_status()
            return r.json()["message"]["content"]
        except Exception as e:
            logger.warning(f"Ollama 调用失败: {e}")
            return ""


class PromptTemplates:
    """提示词模板"""

    SYSTEM = """你是一名资深的二进制安全逆向工程师, 擅长阅读和分析混淆后的反编译代码。
你的任务:
1. 分析给定函数的高级逻辑
2. 重命名通用变量 (v1, v2, var_xxx) 为有意义的名称
3. 解释每个基本块的目的
4. 输出更易读的高级语言伪代码

请始终以严格 JSON 格式输出, 包含:
{
  "summary": "函数功能一句话总结",
  "enhanced_code": "可读性增强的伪代码",
  "renamed_symbols": {"原名": "建议名"},
  "inference": "你的分析推理过程"
}"""

    USER_TEMPLATE = """请分析以下反编译代码 (可能经过混淆):

函数名: {func_name}
架构: {arch}
语言: {language}

符号表:
{symbol_table}

字符串表:
{string_table}

调用图 (caller -> [callees]):
{call_graph}

反编译代码:
```
{decomp_code}
```

请输出 JSON 格式分析结果。"""


class LLMDeobfuscator:
    """LLM 反混淆器"""

    def __init__(self, client: Optional[LLMClientBase] = None):
        self.client = client

    def _build_prompt(self, ctx: DeobfContext) -> Tuple[str, str]:
        sys_prompt = PromptTemplates.SYSTEM
        user_prompt = PromptTemplates.USER_TEMPLATE.format(
            func_name=ctx.func_name,
            arch=ctx.arch,
            language=ctx.language,
            symbol_table=json.dumps(ctx.symbol_table, ensure_ascii=False, indent=2),
            string_table=json.dumps(ctx.string_table, ensure_ascii=False, indent=2)[:2000],
            call_graph=json.dumps(ctx.call_graph, ensure_ascii=False, indent=2)[:2000],
            decomp_code=ctx.decomp_code[:8000]
        )
        return sys_prompt, user_prompt

    def _parse_response(self, response: str) -> Dict[str, Any]:
        # 尝试提取 JSON
        m = re.search(r"\{.*\}", response, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception as e:
                logger.warning(f"JSON 解析失败: {e}")
        return {
            "summary": "解析失败",
            "enhanced_code": response,
            "renamed_symbols": {},
            "inference": ""
        }

    def deobfuscate(self, ctx: DeobfContext) -> LLMDeobfResult:
        if self.client is None:
            return LLMDeobfResult(
                func_name=ctx.func_name,
                enhanced_code=ctx.decomp_code,
                summary="无 LLM 客户端, 返回原代码",
                confidence=0.0
            )
        sys_p, user_p = self._build_prompt(ctx)
        try:
            raw = self.client.chat(sys_p, user_p, temperature=0.0)
        except Exception as e:
            logger.warning(f"LLM 调用失败: {e}")
            return LLMDeobfResult(
                func_name=ctx.func_name,
                enhanced_code=ctx.decomp_code,
                summary="LLM 调用失败",
                confidence=0.0
            )
        parsed = self._parse_response(raw)
        return LLMDeobfResult(
            func_name=ctx.func_name,
            enhanced_code=parsed.get('enhanced_code', ctx.decomp_code),
            summary=parsed.get('summary', ''),
            renamed_symbols=parsed.get('renamed_symbols', {}),
            inference=parsed.get('inference', ''),
            confidence=0.8 if parsed else 0.2,
            raw_response=raw
        )


class ReadabilityEnhancer:
    """可读性增强器 (LLM + 启发式)"""

    def __init__(self, llm_client: Optional[LLMClientBase] = None):
        self.llm = LLMDeobfuscator(llm_client)

    def enhance(self, decomp_code: str, func_name: str,
                symbol_table: Optional[Dict[str, str]] = None,
                string_table: Optional[List[str]] = None) -> LLMDeobfResult:
        ctx = DeobfContext(
            func_name=func_name,
            decomp_code=decomp_code,
            symbol_table=symbol_table or {},
            string_table=string_table or []
        )
        return self.llm.deobfuscate(ctx)


def llm_deobfuscate(
    decomp_code: str,
    func_name: str,
    use_ollama: bool = False,
    ollama_model: str = "qwen2.5-coder:7b",
    openai_model: str = "gpt-4o-mini"
) -> Dict[str, Any]:
    """便捷入口"""
    if use_ollama:
        client = OllamaClient(model=ollama_model)
    else:
        client = OpenAIClient(model=openai_model)
    enhancer = ReadabilityEnhancer(client)
    res = enhancer.enhance(decomp_code, func_name)
    return {
        'success': True,
        'func_name': res.func_name,
        'summary': res.summary,
        'enhanced_code': res.enhanced_code,
        'renamed_symbols': res.renamed_symbols,
        'inference': res.inference,
        'confidence': res.confidence
    }
