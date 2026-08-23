from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# 可选依赖 - 真正的LLM后端不会空转，但不强制安装
try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    httpx = None  # type: ignore
    _HTTPX_AVAILABLE = False


class ExplanationLevel(Enum):
    BRIEF = "brief"
    STANDARD = "standard"
    DETAILED = "detailed"
    SECURITY_FOCUSED = "security_focused"
    BEGINNER_FRIENDLY = "beginner_friendly"
    # 逆向工程专用 — 关注反编译器产物中常见的模式
    DECOMPILER_AWARE = "decompiler_aware"
    # 恶意代码分析专用 — 关注C2、进程注入、反调试等行为
    MALWARE_TRIAGE = "malware_triage"
    # 兼容别名 — 简化的四级粒度
    BASIC = "basic"
    TECHNICAL = "technical"
    SECURITY = "security"
    FULL = "full"


@dataclass
class CodeExplanation:
    original_code: str = ""
    natural_language_explanation: str = ""
    line_annotations: Dict[str, str] = field(default_factory=dict)
    security_notes: List[str] = field(default_factory=list)
    complexity: str = "medium"
    confidence: float = 0.0
    # 兼容字段 — 由启发式分析填充
    summary: str = ""
    purpose: str = ""
    logic_flow: str = ""
    key_variables: Dict[str, str] = field(default_factory=dict)
    security_concerns: List[str] = field(default_factory=list)
    complexity_notes: str = ""
    suggestions: List[str] = field(default_factory=list)
    raw_response: str = ""
    simulation: bool = False
    findings: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'original_code': self.original_code,
            'natural_language_explanation': self.natural_language_explanation,
            'line_annotations': self.line_annotations,
            'security_notes': self.security_notes,
            'complexity': self.complexity,
            'confidence': self.confidence,
            'summary': self.summary,
            'purpose': self.purpose,
            'logic_flow': self.logic_flow,
            'key_variables': self.key_variables,
            'security_concerns': self.security_concerns,
            'suggestions': self.suggestions,
            'simulation': self.simulation,
            'findings': self.findings,
        }


@dataclass
class FunctionAnalysis:
    function_name: str = ""
    signature: str = ""
    purpose: str = ""
    parameters: Dict[str, str] = field(default_factory=dict)
    return_value: str = ""
    side_effects: List[str] = field(default_factory=list)
    security_risks: List[str] = field(default_factory=list)
    suggested_fixes: List[str] = field(default_factory=list)
    # 兼容字段
    name: str = ""
    summary: str = ""
    return_description: str = ""
    security_issues: List[Dict[str, str]] = field(default_factory=list)
    complexity: str = "unknown"
    calls: List[str] = field(default_factory=list)
    called_by: List[str] = field(default_factory=list)
    data_flow: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'function_name': self.function_name or self.name,
            'signature': self.signature,
            'purpose': self.purpose or self.summary,
            'parameters': self.parameters,
            'return_value': self.return_value,
            'side_effects': self.side_effects,
            'security_risks': self.security_risks,
            'suggested_fixes': self.suggested_fixes,
            'security_issues': self.security_issues,
            'complexity': self.complexity,
            'calls': self.calls,
        }


@dataclass
class DiffSummary:
    added_lines: List[str] = field(default_factory=list)
    removed_lines: List[str] = field(default_factory=list)
    modified_blocks: List[Dict[str, str]] = field(default_factory=list)
    new_calls: List[str] = field(default_factory=list)
    removed_calls: List[str] = field(default_factory=list)
    risk_delta: str = "unchanged"  # elevated | reduced | unchanged
    summary: str = ""


EXPLANATION_TEMPLATES = {
    ExplanationLevel.BRIEF: (
        "Explain this pseudocode briefly. Cover: (1) What it does in one sentence, "
        "(2) Key inputs/outputs.\n\nCode:\n{code}"
    ),
    ExplanationLevel.STANDARD: (
        "Explain this pseudocode. Cover: (1) Purpose and context, "
        "(2) Logic flow step-by-step, (3) Key variables and their roles.\n\nCode:\n{code}"
    ),
    ExplanationLevel.DETAILED: (
        "Provide a detailed explanation of this pseudocode. Cover: "
        "(1) Purpose and high-level context, "
        "(2) Step-by-step logic flow with branching analysis, "
        "(3) All variables and their roles, "
        "(4) Data flow and dependencies, "
        "(5) Algorithmic complexity, "
        "(6) Potential edge cases.\n\nCode:\n{code}"
    ),
    ExplanationLevel.SECURITY_FOCUSED: (
        "Analyze this pseudocode for security issues. Cover: "
        "(1) What the code does, "
        "(2) All potential vulnerabilities (buffer overflow, use-after-free, "
        "integer overflow, format string, race conditions, etc.), "
        "(3) Unsafe API usage, "
        "(4) Missing input validation, "
        "(5) Severity assessment for each finding, "
        "(6) Recommended fixes.\n\nCode:\n{code}"
    ),
    ExplanationLevel.BEGINNER_FRIENDLY: (
        "Explain this pseudocode in simple terms for someone learning programming. "
        "Cover: (1) What problem it solves, (2) How it works (avoid jargon), "
        "(3) Simple analogies if helpful, (4) What each variable stores.\n\nCode:\n{code}"
    ),
    # 反编译器产物专属 — IDA/Ghidra 输出的伪代码充满 __readfsdword、LOBYTE 等噪音
    ExplanationLevel.DECOMPILER_AWARE: (
        "Analyze this decompiled pseudocode. Note that it was generated by a "
        "decompiler (IDA Pro / Ghidra) and may contain artifacts like "
        "stack cookie checks, register-based variables, inline assembly, "
        "and compiler-inserted guards. Cover: (1) True purpose (ignore "
        "decompiler artifacts), (2) Recovered logic flow, (3) Compiler "
        "optimizations that may obscure intent, (4) Anomalies suggesting "
        "obfuscation.\n\nCode:\n{code}"
    ),
    # 恶意代码判读 — 不是每个样本都是 APT，但每个样本都值得被审视
    ExplanationLevel.MALWARE_TRIAGE: (
        "You are a malware reverse engineer. Analyze this pseudocode for "
        "malicious indicators. Cover: (1) Probable purpose (dropper, "
        "keylogger, ransomware, RAT, etc.), (2) Suspicious API calls and "
        "their MITRE ATT&CK technique mappings, (3) C2 communication "
        "patterns, (4) Persistence mechanisms, (5) Anti-analysis tricks, "
        "(6) Process injection or hooking indicators.\n\nCode:\n{code}"
    ),
}

# 通用解释模板 —— level 与 code 占位符由调用方填充
PSEUDOCODE_EXPLANATION_TEMPLATE: str = (
    "Explain the following pseudocode at {level} level.\n"
    "Cover: purpose, control flow, and key operations.\n\nCode:\n{code}"
)

SECURITY_PATTERNS: List[Tuple[str, str, str]] = [
    (r'\bstrcpy\s*\(', 'strcpy', 'Unbounded string copy - buffer overflow risk'),
    (r'\bstrcat\s*\(', 'strcat', 'Unbounded string concatenation - buffer overflow risk'),
    (r'\bsprintf\s*\(', 'sprintf', 'Unbounded format string - buffer overflow risk'),
    (r'\bgets\s*\(', 'gets', 'No bounds checking - buffer overflow guaranteed'),
    (r'\bscanf\s*\([^)]*%s', 'scanf(%s)', 'Unbounded string read - buffer overflow risk'),
    (r'\bmalloc\s*\([^)]*\)(?!.*\bfree\b)', 'malloc', 'Possible memory leak - no corresponding free detected'),
    (r'\bfree\s*\((\w+)\)[^}]*\1', 'free+use', 'Potential use-after-free detected'),
    (r'\bsystem\s*\(', 'system()', 'Command injection risk if input not sanitized'),
    (r'\bpopen\s*\(', 'popen()', 'Command injection risk'),
    (r'\bexec[lv]p?[e]?\s*\(', 'exec()', 'Code execution risk'),
    (r'(?<!_)memcpy\s*\(', 'memcpy', 'Check buffer size validation'),
    (r'\bgetsockname\s*\(', 'getsockname', 'TOCTOU race condition risk'),
    (r'\baccess\s*\([^)]*\)[^}]*\bopen\s*\(', 'access+open', 'TOCTOU race condition between access check and open'),
]

# 恶意行为特征 — 单一API并不说明恶意性，但组合出现时命中率骤升
MALWARE_INDICATORS: List[Tuple[str, str, str]] = [
    (r'\bVirtualAlloc(?:Ex)?\s*\(', 'VirtualAlloc', 'Dynamic memory allocation - may precede code injection'),
    (r'\bWriteProcessMemory\s*\(', 'WriteProcessMemory', 'Cross-process memory write - process injection indicator'),
    (r'\bCreateRemoteThread\s*\(', 'CreateRemoteThread', 'Remote thread creation - classic DLL injection'),
    (r'\bNtQueueApcThread\s*\(', 'NtQueueApcThread', 'APC injection via alertable thread'),
    (r'\bSetWindowsHookEx\w*\s*\(', 'SetWindowsHookEx', 'Global hook installation - keylogging capability'),
    (r'\bRegSetValueEx\w*\s*\(.*\\Run', 'Registry Run key', 'Persistence via Run registry key'),
    (r'\bNtQuerySystemInformation\s*\(', 'NtQuerySystemInformation', 'Process enumeration - may seek target/sandbox'),
    (r'\bIsDebuggerPresent\s*\(', 'IsDebuggerPresent', 'Anti-debugging check'),
    (r'\bNtSetInformationThread\s*\(', 'NtSetInformationThread', 'Thread hiding - anti-analysis'),
    (r'\bCryptAcquireContext\w*\s*\(', 'CryptAcquireContext', 'Crypto context - possible ransomware'),
    (r'\bInternetOpen(?:Url)?\w*\s*\(', 'WinInet API', 'Network communication - possible C2'),
    (r'\bURLDownloadToFile\w*\s*\(', 'URLDownloadToFile', 'Download and execute pattern - dropper'),
]


class PseudocodeExplainer:
    """智能模型+启发式分析反编译伪码。"""

    def __init__(
        self,
        model_name: str = "claude-sonnet-4-20250514",
        api_key: Optional[str] = None,
        # 真正的后端地址 — 不填就退回纯启发式，绝不凭空捏造
        api_base_url: Optional[str] = None,
        max_tokens: int = 4096,
        request_timeout: float = 60.0,
        output_dir: Optional[str] = None,
    ) -> None:
        self.model_name = model_name
        self.api_key = api_key
        self.api_base_url = api_base_url
        self.max_tokens = max_tokens
        self.request_timeout = request_timeout
        self.output_dir = output_dir
        self._explanation_cache: Dict[str, CodeExplanation] = {}

    def explain_code(
        self,
        pseudocode: str,
        level: ExplanationLevel = ExplanationLevel.STANDARD,
        use_ai: bool = False,
    ) -> CodeExplanation:
        cache_key = f"{hash(pseudocode)}:{level.value}"
        if cache_key in self._explanation_cache:
            return self._explanation_cache[cache_key]

        if use_ai:
            explanation = self._explain_via_ai(pseudocode, level)
        else:
            explanation = self._explain_via_heuristics(pseudocode, level)

        self._explanation_cache[cache_key] = explanation
        return explanation

    def _explain_with_rules(self, code: str,
                            level: ExplanationLevel) -> CodeExplanation:
        """基于规则生成解释 —— 不依赖外部模型。"""
        return self._explain_via_heuristics(code, level)

    def _detect_security_patterns(self, code: str) -> List[str]:
        """返回命中的危险函数名列表。"""
        return [name for _, name, _ in self._scan_security_patterns(code)]

    def _analyze_function_signature(self, signature: str) -> Dict[str, str]:
        """从函数签名解析函数名。"""
        match = re.match(r'(?:\w[\w\s*]*?\s+)?(\w+)\s*\(', signature.strip())
        return {'function_name': match.group(1) if match else ''}

    def save_explanation(self, explanation: CodeExplanation, name: str) -> str:
        """将解释结果序列化为 JSON 文件，返回文件路径。"""
        import json as _json
        out_dir = self.output_dir or os.getcwd()
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, f"{name}.json")
        with open(path, "w", encoding="utf-8") as fh:
            _json.dump(explanation.to_dict(), fh, ensure_ascii=False, indent=2)
        return path

    def _explain_via_heuristics(
        self, pseudocode: str, level: ExplanationLevel
    ) -> CodeExplanation:
        lines = pseudocode.strip().split('\n')
        non_empty = [l.strip() for l in lines if l.strip()]

        purpose = self._infer_purpose(non_empty)
        logic_flow = self._describe_flow(non_empty)
        key_vars = self._extract_key_variables(pseudocode)
        security = self._scan_security_patterns(pseudocode)
        complexity = self._estimate_complexity(pseudocode)

        # 当指定恶意代码判读级别时，叠加恶意指标扫描
        suggestions: List[str] = []
        if level == ExplanationLevel.MALWARE_TRIAGE:
            suggestions = self._scan_malware_indicators(pseudocode)

        return CodeExplanation(
            original_code=pseudocode,
            natural_language_explanation=f"This code {purpose}. Flow: {logic_flow}",
            line_annotations={},
            security_notes=[s[2] for s in security],
            complexity=complexity,
            confidence=0.6,
            summary=f"This code {purpose}",
            purpose=purpose,
            logic_flow=logic_flow,
            key_variables=key_vars,
            security_concerns=[s[2] for s in security],
            complexity_notes=complexity,
            suggestions=suggestions,
        )

    def _explain_via_ai(
        self, pseudocode: str, level: ExplanationLevel
    ) -> CodeExplanation:
        """使用智能模型构造解释。

        当 api_key 和 api_base_url 都配置时，走真正的 HTTP 调用；
        否则退化成占位回复 — 不编造，宁愿沉默也不瞎说。
        """
        template = EXPLANATION_TEMPLATES.get(level, EXPLANATION_TEMPLATES[ExplanationLevel.STANDARD])
        prompt = template.format(code=pseudocode)
        fn_name = self._analyze_function_signature(pseudocode).get('function_name', '')

        if self.api_key or self.api_base_url:
            try:
                raw = self._call_llm_api(prompt)
                # 尝试从 LLM 响应中解析 JSON findings 并映射到 7 字段 Schema
                llm_findings = self._parse_findings_from_response(raw, fn_name)
                return CodeExplanation(
                    summary=self._extract_section(raw, "SUMMARY") or "unavailable (see raw_response)",
                    purpose=self._extract_section(raw, "PURPOSE") or "See raw_response",
                    logic_flow=self._extract_section(raw, "FLOW") or "See raw_response",
                    raw_response=raw,
                    simulation=False,
                    findings=llm_findings,
                )
            except Exception as exc:
                # 降级为启发式，标记 simulation=True
                heuristic = self._explain_via_heuristics(pseudocode, level)
                heuristic.simulation = True
                heuristic.raw_response = str(exc)
                heuristic.findings = self._build_findings_from_heuristics(pseudocode, fn_name)
                return heuristic

        # 未配置模型 — 降级并标记 simulation=True
        heuristic = self._explain_via_heuristics(pseudocode, level)
        heuristic.simulation = True
        heuristic.raw_response = f"[Would call {self.model_name} with prompt: {prompt[:200]}...]"
        heuristic.findings = self._build_findings_from_heuristics(pseudocode, fn_name)
        return heuristic

    @staticmethod
    def _parse_findings_from_response(raw: str, function_name: str) -> List[Dict[str, str]]:
        """从 LLM 响应中提取 JSON findings 并映射到 7 字段 Schema

        模型可能返回 ```json ... ``` 包裹的列表，也可能返回纯 JSON 数组。
        """
        if not raw:
            return []
        text = raw.strip()
        # 剥离 markdown 代码块
        if text.startswith('```'):
            first_newline = text.find('\n')
            if first_newline != -1:
                text = text[first_newline + 1:]
            if text.rstrip().endswith('```'):
                text = text.rstrip()[:-3]
            text = text.strip()

        # 尝试解析 JSON 数组或含 findings 键的对象
        parsed = None
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            # 尝试提取文本中第一个 JSON 数组
            arr_match = re.search(r'\[.*\]', text, re.DOTALL)
            if arr_match:
                try:
                    parsed = json.loads(arr_match.group(0))
                except (json.JSONDecodeError, ValueError):
                    pass

        if isinstance(parsed, dict) and 'findings' in parsed:
            parsed = parsed['findings']
        if not isinstance(parsed, list):
            return []

        mapped: List[Dict[str, str]] = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            mapped.append({
                'function': item.get('function') or item.get('function_name') or function_name,
                'evidence_address': item.get('evidence_address') or item.get('address', ''),
                'input_source': item.get('input_source', 'pseudocode'),
                'dangerous_op': item.get('dangerous_op') or item.get('op') or item.get('vulnerability', '') or item.get('type', ''),
                'confidence': item.get('confidence', 'low'),
                'evidence_snippet': item.get('evidence_snippet') or item.get('snippet', ''),
                'review_status': item.get('review_status', 'pending'),
            })
        return mapped

    def _build_findings_from_heuristics(self, pseudocode: str, function_name: str) -> List[Dict[str, str]]:
        """将启发式扫描结果映射到 7 字段 Schema"""
        raw_findings = self._scan_security_patterns(pseudocode)
        mapped: List[Dict[str, str]] = []
        for pattern, name, description in raw_findings:
            mapped.append({
                'function': function_name,
                'evidence_address': '',
                'input_source': 'pseudocode',
                'dangerous_op': name,
                'confidence': 'low',
                'evidence_snippet': description,
                'review_status': 'pending',
            })
        return mapped

    def _call_llm_api(self, prompt: str) -> str:
        """通过统一适配层调用 LLM

        走 modules.llm_client.call_llm_simple，支持 ollama/deepseek/openai 三后端。
        """
        from modules.llm_client import call_llm_simple

        result = call_llm_simple(
            prompt=prompt,
            system_prompt="You are an expert reverse engineer and security analyst. Provide structured, concise analysis.",
            model=self.model_name,
            max_tokens=self.max_tokens,
            temperature=0.2,
            use_cache=True,
        )

        if result.get('simulation'):
            raise RuntimeError(f"AI backend unavailable: {result.get('error', 'simulation mode')}")

        raw = result.get('text', '')

        # markdown 代码块容错 — 模型可能把 JSON 包在 ```json ... ``` 中
        raw = raw.strip()
        if raw.startswith('```'):
            first_newline = raw.find('\n')
            if first_newline != -1:
                raw = raw[first_newline + 1:]
            if raw.rstrip().endswith('```'):
                raw = raw.rstrip()[:-3]

        return raw

    # LLM段落抽取
    @staticmethod
    def _extract_section(text: str, label: str) -> Optional[str]:
        # 匹配常见的段落标题格式
        patterns = [
            rf'(?:^|\n)#*\s*{re.escape(label)}[:\s]*\n(.*?)(?:\n#+\s|\n\s*\n[A-Z]|\Z)',
            rf'(?:^|\n){re.escape(label)}:\s*(.*?)(?:\n[A-Z]|\n\n|\Z)',
        ]
        for pat in patterns:
            m = re.search(pat, text, re.DOTALL | re.IGNORECASE)
            if m:
                return m.group(1).strip()
        return text[:200] if text else None

    # 推断代码块目的
    @staticmethod
    def _infer_purpose(lines: List[str]) -> str:
        if not lines:
            return "is an empty block"

        first_line = lines[0].lower()

        if 'sub_' in first_line or 'function' in first_line or '(' in first_line:
            return "defines a function that processes inputs and returns a result"
        if any(kw in first_line for kw in ('if', 'else', 'switch')):
            return "implements conditional logic for decision making"
        if any(kw in first_line for kw in ('while', 'for', 'do')):
            return "contains a loop for iterative processing"
        if 'memcpy' in first_line or 'memmove' in first_line:
            return "performs memory manipulation"
        if 'malloc' in first_line or 'alloc' in first_line:
            return "allocates dynamic memory"
        if 'return' in first_line:
            return "computes and returns a value"

        return "performs data processing operations"

    @staticmethod
    def _describe_flow(lines: List[str]) -> str:
        has_condition = any(
            kw in l for l in lines for kw in ('if', 'else', 'switch')
        )
        has_loop = any(
            kw in l for l in lines for kw in ('while', 'for', 'do')
        )
        has_return = any('return' in l for l in lines)
        has_calls = any('(' in l and not l.strip().startswith('//') for l in lines)

        parts: List[str] = []
        if has_condition:
            parts.append("conditional branching")
        if has_loop:
            parts.append("iterative loops")
        if has_calls:
            parts.append("function calls")
        if has_return:
            parts.append("a return statement")
        if not parts:
            parts.append("sequential execution")

        return "The code follows " + ", ".join(parts) + "."

    @staticmethod
    def _extract_key_variables(code: str) -> Dict[str, str]:
        variables: Dict[str, str] = {}
        patterns = [
            (r'(?:int|long|char|float|double|void|bool|DWORD|BYTE|WORD|QWORD)\s*\*?\s+(\w+)',
             "typed variable"),
            (r'\b(\w+)\s*=\s*malloc\s*\(', "heap allocation"),
            (r'\b(\w+)\s*=\s*realloc\s*\(', "heap reallocation"),
            (r'\b(\w+)\s*=\s*strlen\s*\(', "string length"),
            (r'\b(\w+)\s*=\s*atoi\s*\(', "integer conversion"),
            (r'\b(\w+)\s*=\s*\w+\(', "function result"),
        ]
        for pattern, role in patterns:
            for match in re.finditer(pattern, code):
                var_name = match.group(1) if match.lastindex else match.group(0)
                if var_name not in variables:
                    variables[var_name] = role

        return variables

    @staticmethod
    def _scan_security_patterns(
        code: str,
    ) -> List[Tuple[str, str, str]]:
        findings: List[Tuple[str, str, str]] = []
        for pattern, name, description in SECURITY_PATTERNS:
            if re.search(pattern, code):
                findings.append((pattern, name, description))
        return findings

    @staticmethod
    def _scan_malware_indicators(code: str) -> List[str]:
        """扫描恶意行为特征，返回人类可读的发现列表 — 不一定恶意，但值得审视."""
        hits: List[str] = []
        for pattern, name, description in MALWARE_INDICATORS:
            if re.search(pattern, code):
                hits.append(f"[{name}] {description}")
        return hits

    @staticmethod
    def _estimate_complexity(code: str) -> str:
        lines = code.split('\n')
        depth = 0
        max_depth = 0
        loop_count = 0
        nested_loops = 0
        branch_count = 0
        recursion_hints = 0

        # 收集所有被调用函数名，用于递归检测
        called_funcs: set = set()

        for line in lines:
            if '{' in line:
                depth += 1
                max_depth = max(max_depth, depth)
            if '}' in line:
                depth = max(0, depth - 1)
            if re.search(r'\b(while|for|do)\b', line):
                loop_count += 1
                if depth > 1:
                    nested_loops += 1
            if re.search(r'\b(if|else if|switch)\b', line):
                branch_count += 1

            # 提取函数调用名用于递归检测
            call_matches = re.findall(r'\b(\w+)\s*\(', line)
            called_funcs.update(call_matches)

        # 递归检测 — 在完整代码中搜索与可能函数名相同的调用
        # 剥离返回类型和参数列表，提取可能的函数名
        func_name_match = re.search(
            r'(?:\w[\w\s*]*\s+)?(\w+)\s*\([^)]*\)\s*\{',
            code
        )
        if func_name_match:
            func_name_candidate = func_name_match.group(1)
            if func_name_candidate in called_funcs and func_name_candidate != 'if':
                recursion_hints += 1
                # 进一步确认：查找同名的裸调用
                if re.search(rf'\b{re.escape(func_name_candidate)}\s*\(', code.split('{', 1)[-1] if '{' in code else code):
                    recursion_hints += 1

        # 分治模式检测 — mid = (lo + hi) / 2 这类二分搜索/归并排序指纹
        has_binary_split = bool(re.search(
            r'(\w+)\s*=\s*\((\w+)\s*\+\s*(\w+)\)\s*/\s*2|'
            r'(\w+)\s*=\s*(\w+)\s*\+\s*\((\w+)\s*-\s*(\w+)\)\s*/\s*2|'
            r'\bmid\b.*=', code
        ))
        has_dnc = bool(re.search(r'\b(merge_sort|quick_sort|divide|conquer)\b', code, re.IGNORECASE))
        # 归并/快排的递归形态
        if recursion_hints >= 2 and has_binary_split:
            return "medium"  # O(n log n) 递归分治

        # 尾递归 / 线性递归
        if recursion_hints == 1 and nested_loops == 0:
            return "medium"  # O(n) 线性递归

        # 多路递归 (e.g. O(2^n) for naive Fibonacci)
        if recursion_hints >= 2:
            return "high"  # O(2^n) 多路递归

        if nested_loops >= 2:
            return "high"  # O(n^k) 嵌套循环
        elif loop_count > 0:
            return "medium"  # O(n) 线性循环
        elif 'sort' in code.lower() or 'qsort' in code:
            return "medium"  # O(n log n) 排序
        elif branch_count > 5:
            return "low"  # O(1) 高圈复杂度
        else:
            return "low"  # O(1) 无循环

    def analyze_function(
        self,
        name: str,
        pseudocode: str,
    ) -> FunctionAnalysis:
        sig_match = re.match(r'(\w[\w\s*]*?\s+)?(\w+)\s*\(([^)]*)\)', pseudocode.split('\n')[0] if pseudocode else '')
        signature = sig_match.group(0) if sig_match else name + '()'

        params: Dict[str, str] = {}
        if sig_match and sig_match.lastindex and sig_match.lastindex >= 3:
            param_str = sig_match.group(3)
            for p in param_str.split(','):
                p = p.strip()
                if p:
                    parts = p.rsplit(None, 1)
                    param_name = parts[-1].lstrip('*')
                    param_type = parts[0] if len(parts) > 1 else 'unknown'
                    params[param_name] = param_type

        explanation = self.explain_code(pseudocode, ExplanationLevel.SECURITY_FOCUSED)
        security_issues = [
            {'type': issue.split(':')[0] if ':' in issue else issue,
             'severity': 'warning',
             'description': issue}
            for issue in explanation.security_concerns
        ]

        calls = re.findall(r'\b(\w+)\s*\(', pseudocode)

        return FunctionAnalysis(
            name=name,
            signature=signature,
            summary=explanation.summary,
            parameters=params,
            security_issues=security_issues,
            complexity=self._estimate_complexity(pseudocode),
            calls=calls,
        )

    def batch_explain(
        self,
        functions: Dict[str, str],
        level: ExplanationLevel = ExplanationLevel.STANDARD,
    ) -> Dict[str, FunctionAnalysis]:
        results: Dict[str, FunctionAnalysis] = {}
        for name, code in functions.items():
            results[name] = self.analyze_function(name, code)
        return results

    def security_analysis(
        self,
        pseudocode: str,
    ):
        """对伪代码做安全分析，返回含安全发现的结构化结果。"""
        findings = self._scan_security_patterns(pseudocode)
        notes = [description for _, name, description in findings]
        return {
            'original_code': pseudocode,
            'security_notes': notes,
            'findings': [
                {
                    'type': name,
                    'severity': 'high' if any(
                        kw in description.lower()
                        for kw in ('overflow', 'injection', 'execution', 'use-after-free')
                    ) else 'medium',
                    'description': description,
                    'pattern': pattern,
                }
                for pattern, name, description in findings
            ],
        }

    def diff_explain(
        self,
        old_pseudocode: str,
        new_pseudocode: str,
        function_name: str = "",
    ) -> DiffSummary:
        old_lines = [l.strip() for l in old_pseudocode.split('\n') if l.strip()]
        new_lines = [l.strip() for l in new_pseudocode.split('\n') if l.strip()]

        old_set = set(old_lines)
        new_set = set(new_lines)

        added = [l for l in new_lines if l not in old_set]
        removed = [l for l in old_lines if l not in new_set]

        # 提取API调用变更 — 新增/移除的敏感调用比普通行变更更有信号量
        old_calls = set(re.findall(r'\b(\w+)\s*\(', old_pseudocode))
        new_calls = set(re.findall(r'\b(\w+)\s*\(', new_pseudocode))

        new_apis = sorted(new_calls - old_calls)
        removed_apis = sorted(old_calls - new_calls)

        # 评估风险增量 — 新增高危API=风险升高，移除高危API=风险降低
        old_risk_patterns = self._scan_security_patterns(old_pseudocode)
        new_risk_patterns = self._scan_security_patterns(new_pseudocode)

        old_risk_names = {r[1] for r in old_risk_patterns}
        new_risk_names = {r[1] for r in new_risk_patterns}

        risk_added = new_risk_names - old_risk_names
        risk_removed = old_risk_names - new_risk_names

        if risk_added and not risk_removed:
            risk_delta = "elevated"
        elif risk_removed and not risk_added:
            risk_delta = "reduced"
        elif risk_added and risk_removed:
            risk_delta = "shifted"
        else:
            risk_delta = "unchanged"

        # 构建语义摘要
        scope = f"in {function_name}" if function_name else ""
        parts = []
        if added:
            parts.append(f"{len(added)} lines added")
        if removed:
            parts.append(f"{len(removed)} lines removed")
        if new_apis:
            parts.append(f"new calls: {', '.join(new_apis[:8])}")
        if removed_apis:
            parts.append(f"removed calls: {', '.join(removed_apis[:8])}")
        if risk_delta != "unchanged":
            parts.append(f"security risk {risk_delta}")

        summary_text = f"Diff {scope}: " + "; ".join(parts) + "." if parts else f"No structural changes detected {scope}."

        # 识别被修改的代码块 — 行数相近且共享token的视为同一块的变体
        modified_blocks: List[Dict[str, str]] = []
        for rl in removed:
            rl_tokens = set(re.findall(r'\w+', rl))
            if len(rl_tokens) < 3:
                continue
            for al in added:
                al_tokens = set(re.findall(r'\w+', al))
                overlap = rl_tokens & al_tokens
                if len(overlap) >= max(2, len(rl_tokens) * 0.4):
                    modified_blocks.append({"old": rl, "new": al})
                    break

        return DiffSummary(
            added_lines=added,
            removed_lines=removed,
            modified_blocks=modified_blocks,
            new_calls=new_apis,
            removed_calls=removed_apis,
            risk_delta=risk_delta,
            summary=summary_text,
        )

    def generate_report(
        self,
        analyses,
        format: str = "text",
    ) -> str:
        """生成分析报告。analyses 可为单条 CodeExplanation 或函数分析映射。"""
        if isinstance(analyses, CodeExplanation):
            expl = analyses
            lines = [
                "伪代码解释报告",
                "=" * 40,
                f"代码: {expl.original_code}",
                f"解释: {expl.natural_language_explanation}",
                f"复杂度: {expl.complexity}",
            ]
            if expl.security_notes:
                lines.append("安全发现:")
                lines.extend(f"  - {n}" for n in expl.security_notes)
            return '\n'.join(lines)

        if format == "json":
            report_data = {
                name: {
                    'signature': a.signature,
                    'summary': a.summary,
                    'parameters': a.parameters,
                    'complexity': a.complexity,
                    'security_issues': a.security_issues,
                    'calls': a.calls,
                }
                for name, a in analyses.items()
            }
            return json.dumps(report_data, indent=2)

        if format == "markdown":
            lines = ["# Pseudocode Analysis Report\n"]
            for name, a in analyses.items():
                lines.append(f"## {name}\n")
                lines.append(f"**Signature:** `{a.signature}`\n")
                lines.append(f"**Summary:** {a.summary}\n")
                lines.append(f"**Complexity:** {a.complexity}\n")
                if a.security_issues:
                    lines.append("\n### Security Issues\n")
                    for issue in a.security_issues:
                        lines.append(f"- [{issue.get('severity', 'unknown').upper()}] "
                                     f"{issue.get('description', 'N/A')}\n")
                lines.append("")
            return '\n'.join(lines)

        lines = ["PSEUDOCODE ANALYSIS REPORT", "=" * 40, ""]
        for name, a in analyses.items():
            lines.append(f"Function: {name}")
            lines.append(f"  Signature: {a.signature}")
            lines.append(f"  Summary: {a.summary}")
            lines.append(f"  Complexity: {a.complexity}")
            lines.append(f"  Calls: {', '.join(a.calls) if a.calls else 'none'}")
            if a.security_issues:
                lines.append("  Security Issues:")
                for issue in a.security_issues:
                    lines.append(
                        f"    [{issue.get('severity', '?').upper()}] "
                        f"{issue.get('description', 'N/A')}"
                    )
            lines.append("")
        return '\n'.join(lines)
