#!/usr/bin/env python3
# 基于LLM的反混淆器——支持OpenAI/Ollama后端，提示模板，可读性增强，结构化输出
# HTTP重试与指数退避，token用量追踪，防御性JSON解析

import logging as _logging
import json as _json
import re as _re
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set, Callable

__dbg = _logging.getLogger(__name__)


# 枚举

class LLMProvider(Enum):
    OPENAI = "openai"
    OLLAMA = "ollama"
    MOCK = "mock"
    CUSTOM = "custom"


# 数据类

@dataclass
class DeobfContext:
    """反混淆上下文: 混淆代码及元数据。"""
    obfuscated_code: str = ""
    source_language: str = "c"
    obfuscation_type: str = ""  # ollvm/tigress/movfuscator/custom等
    function_name: str = ""
    architecture: str = "x86_64"
    compiler_hints: List[str] = field(default_factory=list)
    known_patterns: List[Dict[str, str]] = field(default_factory=list)
    additional_context: str = ""
    max_tokens: int = 4096

    def summary(self) -> str:
        parts = [
            f"Language: {self.source_language}",
            f"Architecture: {self.architecture}",
        ]
        if self.obfuscation_type:
            parts.append(f"Obfuscation: {self.obfuscation_type}")
        if self.function_name:
            parts.append(f"Function: {self.function_name}")
        return ", ".join(parts)


@dataclass
class LLMDeobfResult:
    """结构化反混淆结果。"""
    original_code: str = ""
    deobfuscated_code: str = ""
    readability_score: float = 0.0
    confidence: float = 0.0
    identified_patterns: List[str] = field(default_factory=list)
    transformations_applied: List[str] = field(default_factory=list)
    variable_renames: Dict[str, str] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    raw_llm_response: str = ""
    token_count: int = 0
    elapsed_ms: float = 0.0

    def is_successful(self) -> bool:
        return self.confidence >= 0.3 and len(self.deobfuscated_code) > 0

    def summary(self) -> str:
        return (
            f"Deobfuscation: confidence={self.confidence:.2f}, "
            f"readability={self.readability_score:.2f}, "
            f"patterns={len(self.identified_patterns)}, "
            f"transformations={len(self.transformations_applied)}"
        )


# 指数退避重试辅助——瞬时故障不应阻断去混淆流水线

def _retry_http_call(request_fn, max_retries: int = 3, backoff_base: float = 2.0):
    """可降级重试包装器: 429/5xx和连接错误触发指数退避。
    非重试性错误直接向上抛出，由调用方处理。"""
    import time as _time
    import urllib.error as _ue

    last_exc = None
    attempt = 0
    while attempt < max_retries:
        try:
            return request_fn()
        except _ue.HTTPError as e:
            # 仅瞬时性状态码重试: 速率限制和服务端错误
            if e.code in (429, 500, 502, 503, 504) and attempt < max_retries - 1:
                delay = backoff_base ** attempt
                __dbg.warning("HTTP %d 可重试，%.1fs后退避 (%d/%d): %s",
                              e.code, delay, attempt + 1, max_retries, e.reason)
                _time.sleep(delay)
                attempt += 1
                continue
            raise
        except (OSError, TimeoutError, _ue.URLError) as e:
            if attempt < max_retries - 1:
                delay = backoff_base ** attempt
                __dbg.warning("网络层错误，%.1fs后退避 (%d/%d): %s",
                              delay, attempt + 1, max_retries, e)
                _time.sleep(delay)
                attempt += 1
                continue
            raise
        except Exception:
            # 非预期异常不重试，直接传播
            raise
        attempt += 1

    if last_exc is not None:
        raise last_exc
    return None


# LLM客户端基类与实现

class LLMClientBase:
    """LLM API通信抽象基类。"""

    def complete(self, prompt: str, system_prompt: str = "", max_tokens: int = 4096,
                 temperature: float = 0.3) -> str:
        raise NotImplementedError

    def get_provider(self) -> LLMProvider:
        raise NotImplementedError


class OpenAIClient(LLMClientBase):
    """OpenAI API兼容客户端(支持任意OpenAI兼容端点)。"""

    __slots__ = ('m_api_key', 'm_model', 'm_base_url', 'm_timeout', 'm_last_token_count')

    def __init__(self, api_key: str = "", model: str = "gpt-4", base_url: str = "", timeout: int = 120):
        self.m_api_key = api_key
        self.m_model = model
        self.m_base_url = base_url
        self.m_timeout = timeout
        # 追踪最近一次请求的token消耗，供上层成本核算
        self.m_last_token_count: int = 0

    def complete(self, prompt: str, system_prompt: str = "", max_tokens: int = 4096,
                 temperature: float = 0.3) -> str:
        import urllib.request as _ur
        import urllib.error as _ue

        url = self.m_base_url or "https://api.openai.com/v1/chat/completions"

        messages: List[Dict] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        body = _json.dumps({
            "model": self.m_model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }).encode('utf-8')

        req = _ur.Request(url, data=body, headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.m_api_key}",
        })

        # 内部闭包: 将单次HTTP调用封装为可重试单元
        def _do_request():
            with _ur.urlopen(req, timeout=self.m_timeout) as resp:
                raw = resp.read().decode('utf-8')
                # 防御性解析: 上游返回畸形JSON不应导致整个去混淆任务崩溃
                try:
                    data = _json.loads(raw)
                except _json.JSONDecodeError as je:
                    __dbg.error("OpenAI响应JSON解析失败: %s", je)
                    return ""
                # 提取token用量——用于模型选型和成本基准测试
                if isinstance(data, dict) and 'usage' in data:
                    usage = data['usage']
                    self.m_last_token_count = usage.get('total_tokens', 0)
                return data["choices"][0]["message"]["content"]

        try:
            return _retry_http_call(_do_request, max_retries=3, backoff_base=2.0)
        except _ue.HTTPError as e:
            __dbg.error("OpenAI HTTP error: %s %s", e.code, e.reason)
            return ""
        except (OSError, TimeoutError, _ue.URLError) as e:
            __dbg.error("OpenAI request error: %s", e)
            return ""
        except Exception as e:
            __dbg.error("OpenAI request error: %s", e)
            return ""

    def get_provider(self) -> LLMProvider:
        return LLMProvider.OPENAI


class OllamaClient(LLMClientBase):
    """Ollama本地LLM客户端。"""

    __slots__ = ('m_model', 'm_base_url', 'm_timeout', 'm_last_token_count')

    def __init__(self, model: str = "llama3", base_url: str = "http://localhost:11434", timeout: int = 300):
        self.m_model = model
        self.m_base_url = base_url
        self.m_timeout = timeout
        # Ollama在/api/generate响应中返回eval_count，记录供分析
        self.m_last_token_count: int = 0

    def complete(self, prompt: str, system_prompt: str = "", max_tokens: int = 4096,
                 temperature: float = 0.3) -> str:
        import urllib.request as _ur
        import urllib.error as _ue

        url = f"{self.m_base_url}/api/generate"

        full_prompt = prompt
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"

        body = _json.dumps({
            "model": self.m_model,
            "prompt": full_prompt,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": temperature,
            },
        }).encode('utf-8')

        req = _ur.Request(url, data=body, headers={"Content-Type": "application/json"})

        def _do_request():
            with _ur.urlopen(req, timeout=self.m_timeout) as resp:
                raw = resp.read().decode('utf-8')
                try:
                    data = _json.loads(raw)
                except _json.JSONDecodeError as je:
                    __dbg.error("Ollama响应JSON解析失败: %s", je)
                    return ""
                # Ollama返回eval_count作为生成token数
                if isinstance(data, dict):
                    self.m_last_token_count = data.get('eval_count', 0)
                return data.get("response", "")

        try:
            return _retry_http_call(_do_request, max_retries=3, backoff_base=2.0)
        except _ue.HTTPError as e:
            __dbg.error("Ollama HTTP error: %s %s", e.code, e.reason)
            return ""
        except (OSError, TimeoutError, _ue.URLError) as e:
            __dbg.error("Ollama request error: %s", e)
            return ""
        except Exception as e:
            __dbg.error("Ollama request error: %s", e)
            return ""

    def get_provider(self) -> LLMProvider:
        return LLMProvider.OLLAMA


class MockDeobfClient(LLMClientBase):
    """测试用mock客户端——返回基于规则的反混淆响应。"""

    def complete(self, prompt: str, system_prompt: str = "", max_tokens: int = 4096,
                 temperature: float = 0.3) -> str:
        return self._mock_deobfuscate(prompt)

    def get_provider(self) -> LLMProvider:
        return LLMProvider.MOCK

    def _mock_deobfuscate(self, prompt: str) -> str:
        """应用简单正则反混淆模式。"""
        code = prompt

        # 提取代码块(如有)
        code_match = _re.search(r'```(?:c|cpp|asm)?\s*\n(.*?)```', prompt, _re.DOTALL)
        if code_match:
            code = code_match.group(1)

        # XOR字符串混淆模式
        code = _re.sub(
            r'(\w+)\s*=\s*(\w+)\s*\^\s*(0x[0-9a-fA-F]+|\d+);',
            r'\1 = \2 ^ \3; /* 反混淆: XOR常量 */',
            code,
        )

        # 不透明谓词模式
        code = _re.sub(
            r'if\s*\(\s*\([^)]+\*\s*[^)]+\)\s*%\s*2\s*==\s*0\s*\)',
            r'if (1) /* 反混淆: 恒真不透明谓词 */',
            code,
        )

        # 控制流平坦化模式(简单情况)
        code = _re.sub(
            r'while\s*\(\s*1\s*\)\s*\{[^}]*switch\s*\(\s*(\w+)\s*\)',
            r'/* 反混淆: 控制流平坦化，调度变量 \1 */\n\g<0>',
            code,
        )

        # 死代码模式
        if 'dead_code' in prompt.lower():
            code = _re.sub(
                r'if\s*\(\s*0\s*\)\s*\{[^}]*\}',
                r'/* 反混淆: 已移除死代码 */',
                code,
            )

        # 变量重命名提示
        code = _re.sub(r'\b(var_\d+)\b', r'renamed_\1', code)

        return f"```c\n// 反混淆代码(mock)\n{code}\n```"


# 提示模板

class PromptTemplates:
    """反混淆提示模板集合。"""

    SYSTEM_PROMPT = (
        "You are an expert reverse engineer specializing in code deobfuscation. "
        "Your task is to analyze obfuscated code and produce clean, readable, semantically equivalent code. "
        "Identify and reverse obfuscation techniques including: control-flow flattening, opaque predicates, "
        "string encryption, dead code insertion, instruction substitution, constant unfolding, "
        "virtualization-based obfuscation, and MBA (Mixed Boolean-Arithmetic) expressions. "
        "Rename variables to meaningful names. Add explanatory comments. "
        "Output ONLY the deobfuscated code in a markdown code block."
    )

    @staticmethod
    def general_deobfuscation(ctx: DeobfContext) -> str:
        return f"""Deobfuscate the following {ctx.source_language} code.

Context:
- Obfuscation type: {ctx.obfuscation_type or 'unknown'}
- Architecture: {ctx.architecture}
- Function: {ctx.function_name or 'unknown'}
{'- Compiler hints: ' + ', '.join(ctx.compiler_hints) if ctx.compiler_hints else ''}
{'- Additional context: ' + ctx.additional_context if ctx.additional_context else ''}

Obfuscated code:
```{ctx.source_language}
{ctx.obfuscated_code}
```

Provide the fully deobfuscated, readable code."""

    @staticmethod
    def ollvm_deobfuscation(ctx: DeobfContext) -> str:
        return f"""Reverse OLLVM (Obfuscator-LLVM) obfuscation for the following code.

OLLVM techniques to identify and reverse:
1. Control-flow flattening (state variable + dispatcher block)
2. Bogus control flow (opaque predicates)
3. Instruction substitution (complex arithmetic replacements)
4. String obfuscation
5. Split basic blocks

Code:
```{ctx.source_language}
{ctx.obfuscated_code}
```

Output: clean, deobfuscated code with original control flow restored."""

    @staticmethod
    def movfuscator_deobfuscation(ctx: DeobfContext) -> str:
        return f"""Reverse Movfuscator obfuscation.

Movfuscator converts all instructions to MOV operations.
Identify the lookup table structure and recover the original logic.

Code (x86 assembly):
```asm
{ctx.obfuscated_code}
```

Output: equivalent C code recovering the original logic."""

    @staticmethod
    def string_decryption(ctx: DeobfContext) -> str:
        return f"""Decrypt obfuscated string literals in the following code.
Identify XOR-based, RC4-based, or custom string decryption routines.
Replace encrypted string references with their decrypted values.

Code:
```{ctx.source_language}
{ctx.obfuscated_code}
```

Output code with all strings decrypted and decryption functions annotated."""

    @staticmethod
    def variable_recovery(ctx: DeobfContext) -> str:
        return f"""Analyze the following obfuscated code and infer meaningful variable names.
Replace generic names (v1, v2, a1, loc_xxx) with descriptive names based on usage context.

Code:
```{ctx.source_language}
{ctx.obfuscated_code}
```

Output code with all variables renamed meaningfully."""

    @staticmethod
    def control_flow_recovery(ctx: DeobfContext) -> str:
        return f"""Recover the original control flow from flattened/obfuscated code.

1. Identify the state variable and dispatcher
2. Reconstruct the original block ordering
3. Remove bogus control flow (always-true/false conditions)
4. Restructure loops and conditionals naturally

Code:
```{ctx.source_language}
{ctx.obfuscated_code}
```

Output code with natural control flow restored."""


# 可读性增强器

class ReadabilityEnhancer:
    """LLM反混淆后的可读性后处理。"""

    __slots__ = ()

    @staticmethod
    def enhance(code: str, language: str = "c") -> str:
        enhanced = code

        # 提取代码块(如有包裹)
        code_match = _re.search(r'```(?:\w+)?\s*\n(.*?)```', enhanced, _re.DOTALL)
        if code_match:
            enhanced = code_match.group(1)

        # 去除首尾空白
        enhanced = enhanced.strip()

        # 缩进归一为4空格
        lines = enhanced.split('\n')
        normalized: List[str] = []
        for line in lines:
            stripped = line.lstrip('\t')
            if line.startswith('\t'):
                stripped = '    ' + stripped
            normalized.append(stripped)
        enhanced = '\n'.join(normalized)

        # 函数定义前插入空行
        enhanced = _re.sub(r'\n(?!\n)(\w[\w\s*]+)\s+(\w+)\s*\([^)]*\)\s*\{', r'\n\n\1 \2(...) {', enhanced)

        # 合并多余空行
        enhanced = _re.sub(r'\n{3,}', '\n\n', enhanced)

        return enhanced

    @staticmethod
    def score_readability(code: str) -> float:
        """基于启发式计算0-1可读性评分。"""
        score = 0.5
        lines = code.split('\n')
        if len(lines) == 0:
            return 0.0

        # 惩罚单字母变量名
        single_letter_count = len(_re.findall(r'\b[a-zA-Z]\b', code))
        score -= min(0.2, single_letter_count * 0.005)

        # 惩罚过长行
        long_line_count = sum(1 for l in lines if len(l) > 120)
        score -= min(0.15, long_line_count * 0.01)

        # 奖励注释
        comment_count = sum(1 for l in lines if l.strip().startswith('//') or l.strip().startswith('/*'))
        score += min(0.2, comment_count * 0.01)

        # 奖励空行分隔
        blank_count = sum(1 for l in lines if l.strip() == '')
        if len(lines) > 10:
            ratio = blank_count / len(lines)
            score += min(0.1, ratio * 0.5)

        # 惩罚魔法数字(无上下文的十六进制常量)
        hex_count = len(_re.findall(r'0x[0-9a-fA-F]{3,}', code))
        score -= min(0.1, hex_count * 0.01)

        return max(0.0, min(1.0, score))


# LLM反混淆器

class LLMDeobfuscator:
    """LLM驱动的主反混淆器，支持可配置策略。
    系统架构原则: 策略模式解耦LLM后端与去混淆逻辑，使任一环节可独立演进。"""

    __slots__ = ('m_client', 'm_templates', 'm_enhancer', 'm_history',
                 'm_default_temperature')

    def __init__(self, llm_client: Optional[LLMClientBase] = None, temperature: float = 0.3):
        self.m_client = llm_client if llm_client is not None else MockDeobfClient()
        self.m_templates = PromptTemplates()
        self.m_enhancer = ReadabilityEnhancer()
        self.m_default_temperature = temperature
        self.m_history: List[Dict[str, Any]] = []

    def deobfuscate(self, ctx: DeobfContext, strategy: str = "general",
                    temperature: float = 0.0) -> LLMDeobfResult:
        import time as _time
        start = _time.time()
        result = LLMDeobfResult()
        result.original_code = ctx.obfuscated_code

        if temperature <= 0:
            temperature = self.m_default_temperature

        # 选择提示框架
        strategy_map = {
            "general": self.m_templates.general_deobfuscation,
            "ollvm": self.m_templates.ollvm_deobfuscation,
            "movfuscator": self.m_templates.movfuscator_deobfuscation,
            "string_decrypt": self.m_templates.string_decryption,
            "variable_recovery": self.m_templates.variable_recovery,
            "control_flow_recovery": self.m_templates.control_flow_recovery,
        }

        prompt_fn = strategy_map.get(strategy, self.m_templates.general_deobfuscation)
        prompt = prompt_fn(ctx)

        # 调用LLM
        response = self.m_client.complete(
            prompt,
            system_prompt=self.m_templates.SYSTEM_PROMPT,
            max_tokens=ctx.max_tokens,
            temperature=temperature,
        )

        result.raw_llm_response = response
        result.elapsed_ms = (_time.time() - start) * 1000

        # 从LLM客户端提取token用量——支撑成本建模与模型对比
        client_tokens = getattr(self.m_client, 'm_last_token_count', 0)
        if client_tokens > 0:
            result.token_count = client_tokens

        if not response:
            result.errors.append("LLM返回空响应")
            return result

        # 从响应提取代码
        code_match = _re.search(r'```(?:\w+)?\s*\n(.*?)```', response, _re.DOTALL)
        if code_match:
            result.deobfuscated_code = code_match.group(1).strip()
        else:
            result.deobfuscated_code = response.strip()

        # 增强可读性
        result.deobfuscated_code = self.m_enhancer.enhance(result.deobfuscated_code, ctx.source_language)

        # 计算可读性评分
        result.readability_score = self.m_enhancer.score_readability(result.deobfuscated_code)

        # 识别混淆模式
        result.identified_patterns = self._identify_patterns(result.deobfuscated_code, response)

        # 检测变换
        result.transformations_applied = self._detect_transformations(ctx.obfuscated_code, result.deobfuscated_code)

        # 计算置信度
        result.confidence = self._compute_confidence(result)

        # 提取变量重命名
        result.variable_renames = self._extract_renames(ctx.obfuscated_code, result.deobfuscated_code)

        self.m_history.append({
            "strategy": strategy,
            "confidence": result.confidence,
            "elapsed_ms": result.elapsed_ms,
            "obfuscation_type": ctx.obfuscation_type,
        })

        return result

    def deobfuscate_multi_pass(self, ctx: DeobfContext, strategies: Optional[List[str]] = None) -> LLMDeobfResult:
        """多轮策略级联: 前一轮输出作为后一轮输入，逐步精炼。
        保持最优结果，即使后续轮次置信度下降也不丢失进展。"""
        if strategies is None:
            strategies = ["general", "string_decrypt", "control_flow_recovery", "variable_recovery"]

        current_ctx = DeobfContext(
            obfuscated_code=ctx.obfuscated_code,
            source_language=ctx.source_language,
            obfuscation_type=ctx.obfuscation_type,
            function_name=ctx.function_name,
            architecture=ctx.architecture,
            compiler_hints=list(ctx.compiler_hints),
            additional_context=ctx.additional_context,
            max_tokens=ctx.max_tokens,
        )

        best_result: Optional[LLMDeobfResult] = None

        si = 0
        while si < len(strategies):
            strategy = strategies[si]
            result = self.deobfuscate(current_ctx, strategy=strategy)

            if result.is_successful():
                current_ctx.obfuscated_code = result.deobfuscated_code
                if best_result is None or result.confidence > best_result.confidence:
                    best_result = result

            si += 1

        if best_result is None:
            return LLMDeobfResult(
                original_code=ctx.obfuscated_code,
                errors=["所有策略均失败"],
            )

        return best_result

    def deobfuscate_with_validation(self, ctx: DeobfContext,
                                    validator: Callable[[str], bool],
                                    max_attempts: int = 3) -> LLMDeobfResult:
        """带校验的重试循环: 温度逐步升高以探索更大解空间，上限1.0防止输出退化。"""
        best_result: Optional[LLMDeobfResult] = None

        attempt = 0
        while attempt < max_attempts:
            temp = self.m_default_temperature + (attempt * 0.15)
            result = self.deobfuscate(ctx, temperature=min(temp, 1.0))

            if validator(result.deobfuscated_code):
                return result

            if best_result is None or result.confidence > best_result.confidence:
                best_result = result

            result.warnings.append(f"第{attempt + 1}次尝试校验失败")
            attempt += 1

        if best_result:
            best_result.warnings.append("所有校验尝试均失败，返回最佳结果")
        return best_result if best_result else LLMDeobfResult(errors=["所有尝试均失败"])

    def _identify_patterns(self, code: str, llm_response: str) -> List[str]:
        patterns: List[str] = []
        pattern_checks = [
            ("control_flow_flattening", r'(?:state|dispatcher|switch.*state)', "控制流平坦化"),
            ("opaque_predicate", r'(?:always.?true|opaque.*pred)', "不透明谓词"),
            ("string_encryption", r'(?:string.*(?:encrypt|decrypt|xor))', "字符串加密"),
            ("dead_code", r'(?:dead.*code|unreachable)', "死代码插入"),
            ("instruction_substitution", r'(?:instruction.*(?:substitut|replac))', "指令替换"),
            ("constant_folding", r'(?:constant.*(?:fold|obfuscat))', "常量混淆"),
            ("mba_expression", r'(?:MBA|mixed.*boolean.*arithmetic)', "MBA表达式"),
            ("virtualization", r'(?:VM|virtual.*machine|bytecode)', "虚拟化混淆"),
            ("anti_debug", r'(?:anti.*debug|ptrace|isDebugger)', "反调试"),
            ("anti_analysis", r'(?:anti.*(?:analysis|disassem))', "反分析"),
            ("bogus_control_flow", r'(?:bogus.*(?:control|flow|block))', "虚假控制流"),
            ("code_splicing", r'(?:code.*(?:splic|split))', "代码拼接"),
        ]

        combined = f"{code}\n{llm_response}".lower()
        pi = 0
        while pi < len(pattern_checks):
            pkey, pregex, plabel = pattern_checks[pi]
            if _re.search(pregex, combined):
                patterns.append(plabel)
            pi += 1

        return patterns

    def _detect_transformations(self, original: str, deobfuscated: str) -> List[str]:
        trans: List[str] = []
        orig_lines = original.split('\n')
        deob_lines = deobfuscated.split('\n')

        if len(deob_lines) < len(orig_lines):
            trans.append("代码缩减")
        if _re.search(r'0x[0-9a-fA-F]+', original) and not _re.search(r'0x[0-9a-fA-F]+', deobfuscated):
            trans.append("常量展开")
        if _re.search(r'(?:var_|loc_|v\d)', original) and not _re.search(r'(?:var_|loc_|v\d)', deobfuscated):
            trans.append("变量重命名")
        if _re.search(r'switch\s*\(', original) and not _re.search(r'switch\s*\(', deobfuscated):
            trans.append("控制流反平坦化")
        if '/*' in deobfuscated or '//' in deobfuscated:
            trans.append("注释标注")

        return trans

    def _compute_confidence(self, result: LLMDeobfResult) -> float:
        conf = 0.3
        if result.deobfuscated_code:
            conf += 0.3
        if result.readability_score > 0.5:
            conf += 0.15
        if len(result.identified_patterns) > 0:
            conf += min(0.15, len(result.identified_patterns) * 0.03)
        if len(result.transformations_applied) > 0:
            conf += min(0.1, len(result.transformations_applied) * 0.02)
        if result.deobfuscated_code and len(result.deobfuscated_code) < len(result.original_code) * 2:
            conf += 0.1
        return min(1.0, conf)

    def _extract_renames(self, original: str, deobfuscated: str) -> Dict[str, str]:
        r"""推断变量重命名映射。启发式: 原始混淆名与目标可读名的集合差。
        注意\w+确保至少匹配一个字符，避免空串污染结果集。"""
        renames: Dict[str, str] = {}
        orig_vars = set(_re.findall(r'\b((?:var_|loc_|v)\w+)\b', original))
        deob_vars = set(_re.findall(r'\b([a-zA-Z_]\w*)\b', deobfuscated))

        if len(orig_vars) <= len(deob_vars):
            orig_list = sorted(orig_vars)
            deob_list = sorted(deob_vars - orig_vars)
            vi = 0
            while vi < min(len(orig_list), len(deob_list)):
                renames[orig_list[vi]] = deob_list[vi]
                vi += 1

        return renames

    def reset(self):
        self.m_history.clear()


# 便捷函数

def llm_deobfuscate(obfuscated_code: str,
                    llm_client: Optional[LLMClientBase] = None,
                    obfuscation_type: str = "",
                    source_language: str = "c",
                    strategy: str = "general") -> LLMDeobfResult:
    ctx = DeobfContext(
        obfuscated_code=obfuscated_code,
        source_language=source_language,
        obfuscation_type=obfuscation_type,
    )
    deobf = LLMDeobfuscator(llm_client=llm_client)
    return deobf.deobfuscate(ctx, strategy=strategy)
