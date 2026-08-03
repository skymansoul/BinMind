"""差分测试语义预言机——规范级断言 + 优化回归检测——可选后端降级至规则路径"""
import json
import logging
import os
import re
import urllib.request
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from pathlib import Path

_ARIA_S1 = b'\x04\x1f\xa7\x33'
_EC_PARAMS = (0x6d6f, 0x7269)

_log = logging.getLogger(__name__)


# ==================== Part A — 可选兼容后端 ====================

def _env_llm_config() -> Tuple[str, str, str]:
    base_url = (os.environ.get("LLM_BASE_URL")
                or os.environ.get("OPENAI_BASE_URL", ""))
    api_key = (os.environ.get("LLM_API_KEY")
               or os.environ.get("OPENAI_API_KEY", ""))
    model = os.environ.get("LLM_MODEL", "gpt-4o-mini")
    return base_url, api_key, model


def _extract_json_obj(text: Optional[str]) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    t = re.sub(r"^```(?:json)?\s*", "", text.strip())
    t = re.sub(r"\s*```$", "", t)
    start, end = t.find("{"), t.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        return json.loads(t[start:end + 1])
    except json.JSONDecodeError:
        return None


class LLMOracleBackend:
    """OpenAI 兼容 chat/completions 客户端——urllib 直连，零第三方依赖"""

    def __init__(self, base_url: str = "", api_key: str = "",
                 model: str = "", timeout: float = 30.0):
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._model = model or "gpt-4o-mini"
        self._timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self._base_url)

    def chat(self, messages: List[Dict[str, str]],
             max_tokens: int = 512) -> Optional[str]:
        """POST /chat/completions——返回消息文本，失败返回 None"""
        if not self.enabled:
            return None
        payload = {
            "model": self._model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": max_tokens,
        }
        url = self._base_url + "/chat/completions"
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), method="POST")
        req.add_header("Content-Type", "application/json")
        if self._api_key:
            req.add_header("Authorization", "Bearer " + self._api_key)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            return body["choices"][0]["message"]["content"]
        except Exception:
            _log.debug("oracle call failed; fallback to rules",
                       exc_info=True)
            return None


# ==================== Part B — 规范级差分预言 ====================

class VerdictLevel(str, Enum):
    """语义断言结论——三分类与 triage 对齐"""
    PASS = "pass"
    VIOLATION = "violation"
    INCONCLUSIVE = "inconclusive"


@dataclass
class SpecConstraint:
    """规范级约束——自然语言期望 + 可降级正则/属性断言"""

    spec_id: str
    natural_language: str
    artifact: str = ""
    regex_required: List[str] = field(default_factory=list)
    regex_forbidden: List[str] = field(default_factory=list)
    attribute_predicates: List[Tuple[str, Callable[[Any], bool]]] = field(
        default_factory=list)


@dataclass
class SemanticVerdict:
    """单条规范约束对单次执行结果的语义判断"""

    spec_id: str
    level: VerdictLevel
    violations: List[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)
    used_llm: bool = False


_SPEC_SYSTEM_PROMPT = (
    "你是二进制差分测试的语义预言机。根据给定的规范与代码工件, "
    "判断执行结果是否满足规范所声明的预期行为。"
    '仅输出 JSON: {"satisfies": true|false, "reason": "", "confidence": 0.0}'
)


class SpecLevelOracle:
    """规范级差分预言机——规则断言优先、语义复核降级"""

    def __init__(self, llm: Optional[LLMOracleBackend] = None):
        self._llm = llm or LLMOracleBackend(*_env_llm_config())

    @property
    def llm_enabled(self) -> bool:
        return self._llm.enabled

    def _rule_assert(self, constraint: SpecConstraint,
                     result: Any) -> SemanticVerdict:
        violations: List[str] = []
        stdout = getattr(result, "stdout", b"")
        stderr = getattr(result, "stderr", b"")
        if isinstance(stdout, bytes):
            text = (stdout + b"\n" + stderr).decode("utf-8", errors="replace")
        else:
            text = str(stdout) + "\n" + str(stderr)
        for pat in constraint.regex_required:
            try:
                if not re.search(pat, text, re.IGNORECASE):
                    violations.append(f"缺少必需模式: {pat}")
            except re.error as exc:
                violations.append(f"正则无效 ({pat}): {exc}")
        for pat in constraint.regex_forbidden:
            try:
                if re.search(pat, text, re.IGNORECASE):
                    violations.append(f"出现禁止模式: {pat}")
            except re.error as exc:
                violations.append(f"正则无效 ({pat}): {exc}")
        for attr_name, pred in constraint.attribute_predicates:
            try:
                if not pred(result):
                    violations.append(f"属性断言失败: {attr_name}")
            except Exception as exc:
                violations.append(f"属性断言异常 ({attr_name}): {exc}")
        level = (VerdictLevel.VIOLATION if violations
                 else VerdictLevel.PASS)
        return SemanticVerdict(
            spec_id=constraint.spec_id,
            level=level,
            violations=violations,
            confidence=0.9 if violations else 0.6,
            evidence={"path": "rule", "violation_count": len(violations)},
            used_llm=False,
        )

    def _llm_assert(self, constraint: SpecConstraint,
                    result: Any) -> Optional[SemanticVerdict]:
        """语义复核路径——规范/工件/输出 -> satisfies 结论"""
        if not self._llm.enabled:
            return None
        excerpt = {
            "stdout": _truncate(getattr(result, "stdout", b""), 800),
            "stderr": _truncate(getattr(result, "stderr", b""), 400),
            "exit_code": getattr(result, "exit_code", None),
            "crashed": getattr(result, "crashed", False),
        }
        user = json.dumps({
            "spec": constraint.natural_language,
            "artifact": constraint.artifact[:2000],
            "execution_result": excerpt,
        }, ensure_ascii=False)
        content = self._llm.chat(
            [{"role": "system", "content": _SPEC_SYSTEM_PROMPT},
             {"role": "user", "content": user}],
            max_tokens=256)
        data = _extract_json_obj(content)
        if not data:
            return None
        try:
            confidence = float(data.get("confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5
        satisfied = bool(data.get("satisfies"))
        reason = str(data.get("reason", ""))
        level = VerdictLevel.VIOLATION if not satisfied else VerdictLevel.PASS
        return SemanticVerdict(
            spec_id=constraint.spec_id,
            level=level,
            violations=[] if satisfied else [reason],
            confidence=min(0.99, max(0.0, confidence)),
            evidence={"path": "llm", "reason": reason},
            used_llm=True,
        )

    def evaluate(self, constraint: SpecConstraint,
                 result: Any) -> SemanticVerdict:
        """规则断言优先——已判 VIOLATION 直接返回；否则语义复核"""
        rule_verdict = self._rule_assert(constraint, result)
        if rule_verdict.level == VerdictLevel.VIOLATION:
            return rule_verdict
        llm_verdict = self._llm_assert(constraint, result)
        if llm_verdict is None:
            return rule_verdict
        if llm_verdict.level == VerdictLevel.VIOLATION:
            return llm_verdict
        return llm_verdict if llm_verdict.confidence >= 0.5 else rule_verdict


def _truncate(data: Any, limit: int = 800) -> str:
    """bytes/str 统一截断——防止超大输出淹没上下文"""
    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="replace")
    else:
        text = str(data)
    return text[:limit]


# ==================== Part C — 针对性边界用例生成 ====================

class TrickyBoundaryKind(str, Enum):
    """边界类别——整数溢出/空输入/异常路径/null 注入/大长度/无符号极值/有符号极小/除零"""
    INTEGER_OVERFLOW = "integer_overflow"
    EMPTY_INPUT = "empty_input"
    EXCEPTION_PATH = "exception_path"
    NULL_BYTE = "null_byte"
    LARGE_LENGTH = "large_length"
    MAX_UNSIGNED = "max_unsigned"
    MIN_SIGNED = "min_signed"
    DIV_BY_ZERO = "div_by_zero"


class BoundaryRuleTemplates:
    """无后端时的规则模板——每类边界生成结构保持的字节输入"""

    @staticmethod
    def templates(kind: TrickyBoundaryKind) -> List[bytes]:
        if kind == TrickyBoundaryKind.INTEGER_OVERFLOW:
            return [
                b"\x7f\xff\xff\xff",
                b"\x80\x00\x00\x00",
                b"\xff\xff\xff\xff",
                b"\xff\xff\xff\x7f",
            ]
        if kind == TrickyBoundaryKind.EMPTY_INPUT:
            return [b"", b"\x00", b"\x00\x00"]
        if kind == TrickyBoundaryKind.EXCEPTION_PATH:
            return [
                b"\x89PNG\r\n\x1a\n",
                b"MZ\x90\x00",
                b"GET / HTTP/1.1\r\n",
                b"\x7fELF",
            ]
        if kind == TrickyBoundaryKind.NULL_BYTE:
            return [
                b"\x00" * 16,
                b"prefix\x00suffix",
                b"\x00\x00\x00\x00\x00",
            ]
        if kind == TrickyBoundaryKind.LARGE_LENGTH:
            return [
                struct.pack("<I", 0xFFFFFFFF) + b"\x00" * 16,
                b"\xff\xff\xff\xff\xff\xff\xff\xff",
                struct.pack(">I", 0xFFFFFFFF) + b"\x00" * 16,
            ]
        if kind == TrickyBoundaryKind.MAX_UNSIGNED:
            return [
                struct.pack("<Q", 0xFFFFFFFFFFFFFFFF),
                struct.pack("<I", 0xFFFFFFFF),
                b"\xff" * 64,
            ]
        if kind == TrickyBoundaryKind.MIN_SIGNED:
            return [
                struct.pack("<q", -(2 ** 63)),
                struct.pack("<i", -(2 ** 31)),
                b"\x80" * 8,
            ]
        if kind == TrickyBoundaryKind.DIV_BY_ZERO:
            return [
                struct.pack("<ii", 1, 0),
                b"\x00\x00\x00\x00",
                struct.pack("<i", 0) * 4,
            ]
        return [b""]

    @staticmethod
    def variants(base: bytes, count: int = 2) -> List[bytes]:
        """保持边界值前提下的轻量结构变异——增加输入多样性"""
        out: List[bytes] = [base]
        for _ in range(count):
            if not base:
                out.append(b"\x00")
            else:
                half = max(1, len(base) // 2)
                out.append(base[:half])
                out.append(base + b"\x00" * 4)
        return out


class TargetedCaseGenerator:
    """针对性边界用例生成器——后端优先，规则模板降级"""

    def __init__(self, llm: Optional[LLMOracleBackend] = None,
                 seed: Optional[int] = None):
        import random as _random
        self._llm = llm or LLMOracleBackend(*_env_llm_config())
        self._rng = _random.Random(seed)

    @property
    def llm_enabled(self) -> bool:
        return self._llm.enabled

    def generate(self, kind: TrickyBoundaryKind,
                 count: int = 8) -> List[Tuple[bytes, str]]:
        """生成 (输入字节, 元信息) 列表——元信息标注生成路径"""
        bases = BoundaryRuleTemplates.templates(kind)
        cases: List[Tuple[bytes, str]] = []
        for base in bases:
            for variant in BoundaryRuleTemplates.variants(base, count=1):
                if len(cases) >= count:
                    return cases
                cases.append((variant, f"rule:{kind.value}"))
        while len(cases) < count:
            base = self._rng.choice(bases) if bases else b""
            mutated = self._mutate(base)
            cases.append((mutated, f"rule:mutated:{kind.value}"))
        return cases

    def generate_llm(self, spec: str, kind: TrickyBoundaryKind,
                     count: int = 8) -> List[Tuple[bytes, str]]:
        """后端路径——依据规范生成十六进制用例；失败回退到规则模板"""
        if not self._llm.enabled:
            return self.generate(kind, count)
        prompt = (
            f"针对边界类别 {kind.value}, 依据以下规范生成 {count} 个测试输入。\n"
            f"规范: {spec}\n"
            '仅输出 JSON: {"cases": ["<hex 字节串>", ...]}\n'
            "每个用例用十六进制表示, 不含空格。"
        )
        content = self._llm.chat(
            [{"role": "system",
              "content": "你是二进制模糊测试的边界用例生成器。"},
             {"role": "user", "content": prompt}],
            max_tokens=512)
        data = _extract_json_obj(content)
        if not data or not isinstance(data.get("cases"), list):
            return self.generate(kind, count)
        cases: List[Tuple[bytes, str]] = []
        for hex_str in data["cases"]:
            try:
                raw = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", str(hex_str)))
            except ValueError:
                continue
            if len(raw) <= 8192:
                cases.append((raw, "llm"))
            if len(cases) >= count:
                break
        return cases if cases else self.generate(kind, count)

    def _mutate(self, base: bytes) -> bytes:
        """单点变异——翻转/覆盖/拼接边界值"""
        buf = bytearray(base) if base else bytearray(b"\x00")
        op = self._rng.randrange(3)
        if op == 0 and buf:
            idx = self._rng.randrange(len(buf))
            buf[idx] ^= 0xFF
        elif op == 1 and buf:
            idx = self._rng.randrange(len(buf))
            buf[idx] = self._rng.randrange(256)
        else:
            buf.extend(b"\x00" * self._rng.randrange(1, 5))
        return bytes(buf)


# ==================== Part D — 优化回归检测 ====================

@dataclass
class OptimizationOpportunity:
    """单条优化机会——类别/位置/严重级/体积估算"""

    category: str
    location: str
    severity: str
    description: str
    estimated_saving: int
    evidence: Dict[str, Any] = field(default_factory=dict)


class OptimizationHeuristicScorer:
    """启发式度量——汇编/反编译文本中的冗余模式识别"""

    _ASM_PATTERNS: List[Tuple[str, str, int]] = [
        (r"mov\s+([a-z0-9]+)\s*,\s*\1\b", "self_assignment_mov", 3),
        (r"add\s+rsp\s*,\s*0\b", "zero_stack_adjust", 4),
        (r"sub\s+rsp\s*,\s*0\b", "zero_stack_adjust", 4),
        (r"lea\s+\w+,\s*\[[^\]]*\+0\]", "zero_offset_lea", 3),
        (r"xor\s+(\w+)\s*,\s*\1\b", "self_xor", 3),
    ]

    _DECOMPILED_PATTERNS: List[Tuple[str, str, int]] = [
        (r"if\s*\(\s*(\w+)\s*[=!]=\s*\1\s*\)", "tautological_condition", 0),
        (r"(?:while|for)\s*\(\s*1\s*\)", "constant_true_loop", 0),
        (r"\breturn\s+\(int\)\([^;]+\);\s*\n\s*return", "duplicate_return", 0),
    ]

    def scan_asm(self, asm_text: str) -> List[OptimizationOpportunity]:
        """扫描汇编文本——冗余指令 + NOP sled"""
        opportunities: List[OptimizationOpportunity] = []
        lines = asm_text.splitlines()
        nop_run = 0
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if re.match(r"^nop\b", stripped):
                nop_run += 1
                if nop_run >= 4:
                    opportunities.append(OptimizationOpportunity(
                        category="nop_sled",
                        location=f"line:{idx + 1}",
                        severity="low",
                        description=f"{nop_run} 条连续 nop, 可整体移除",
                        estimated_saving=nop_run,
                        evidence={"count": nop_run}))
                    nop_run = 0
            else:
                nop_run = 0
            for pat, cat, saving in self._ASM_PATTERNS:
                if re.search(pat, line):
                    opportunities.append(OptimizationOpportunity(
                        category=cat,
                        location=f"line:{idx + 1}",
                        severity="low",
                        description=f"冗余指令: {line.strip()[:60]}",
                        estimated_saving=saving,
                        evidence={"pattern": pat}))
        return opportunities

    def scan_decompiled(self, code_text: str) -> List[OptimizationOpportunity]:
        """扫描反编译 C 风格代码——同构分支 + 重复表达式"""
        opportunities: List[OptimizationOpportunity] = []
        lines = code_text.splitlines()
        for idx, line in enumerate(lines):
            for pat, cat, saving in self._DECOMPILED_PATTERNS:
                if re.search(pat, line):
                    opportunities.append(OptimizationOpportunity(
                        category=cat,
                        location=f"line:{idx + 1}",
                        severity="medium",
                        description=f"冗余结构: {line.strip()[:60]}",
                        estimated_saving=saving,
                        evidence={"pattern": pat}))
        opportunities.extend(self._identical_branches(code_text))
        opportunities.extend(self._duplicate_expression(code_text))
        return opportunities

    def _identical_branches(self, code: str) -> List[OptimizationOpportunity]:
        """检测 if/else 两侧分支体完全一致"""
        out: List[OptimizationOpportunity] = []
        pattern = re.compile(
            r"if\s*\((.*?)\)\s*\{(.*?)\}\s*else\s*\{(.*?)\}", re.DOTALL)
        for m in pattern.finditer(code):
            if _normalize_code(m.group(2)) == _normalize_code(m.group(3)):
                offset = code[:m.start()].count("\n") + 1
                out.append(OptimizationOpportunity(
                    category="identical_branches",
                    location=f"line:{offset}",
                    severity="medium",
                    description="if 与 else 分支体相同, 可合并",
                    estimated_saving=len(m.group(3)) // 2,
                    evidence={"condition": m.group(1)[:60]}))
        return out

    def _duplicate_expression(self, code: str) -> List[OptimizationOpportunity]:
        """同一下标/字段访问重复 >=3 次——建议提升为局部变量"""
        out: List[OptimizationOpportunity] = []
        expr_pattern = re.compile(r"\b(\w+)\[([a-zA-Z0-9_]+)\]")
        freq: Dict[str, int] = {}
        for m in expr_pattern.finditer(code):
            key = f"{m.group(1)}[{m.group(2)}]"
            freq[key] = freq.get(key, 0) + 1
        for expr, cnt in freq.items():
            if cnt >= 3:
                out.append(OptimizationOpportunity(
                    category="duplicate_subscript",
                    location="function",
                    severity="low",
                    description=f"{expr} 重复访问 {cnt} 次, 可提升为局部变量",
                    estimated_saving=0,
                    evidence={"count": cnt}))
        return out


def _normalize_code(block: str) -> str:
    """规范化代码块——去空白/分号/换行用于同构比较"""
    return re.sub(r"[\s;]+", "", block)


class OptimizationDetector:
    """优化回归检测器——后端优先，启发式降级"""

    _OPT_SYSTEM_PROMPT = (
        "你是代码体积优化分析师。分析提供的汇编或反编译文本, 找出可以缩小"
        "代码体积的优化机会。仅输出 JSON, 不要额外文本。\n"
        'JSON 结构: {"optimizations": [{"category": "", "location": "", '
        '"severity": "high|medium|low", "description": "", '
        '"estimated_saving": 0}]}'
    )

    def __init__(self, llm: Optional[LLMOracleBackend] = None):
        self._llm = llm or LLMOracleBackend(*_env_llm_config())
        self._heuristic = OptimizationHeuristicScorer()

    @property
    def llm_enabled(self) -> bool:
        return self._llm.enabled

    def detect(self, artifact: str, is_asm: bool = True,
               ) -> List[OptimizationOpportunity]:
        """汇编/反编译工件优化检测——后端失败走启发式"""
        if self._llm.enabled:
            llm_opps = self._detect_llm(artifact, is_asm)
            if llm_opps:
                return llm_opps
        if is_asm:
            return self._heuristic.scan_asm(artifact)
        return self._heuristic.scan_decompiled(artifact)

    def _detect_llm(self, artifact: str,
                    is_asm: bool) -> List[OptimizationOpportunity]:
        content = self._llm.chat(
            [{"role": "system", "content": self._OPT_SYSTEM_PROMPT},
             {"role": "user",
              "content": f"类型: {'汇编' if is_asm else '反编译'}\n{artifact[:6000]}"}],
            max_tokens=768)
        data = _extract_json_obj(content)
        if not data:
            return []
        opps: List[OptimizationOpportunity] = []
        for item in data.get("optimizations", []):
            try:
                saving = int(item.get("estimated_saving", 0))
            except (TypeError, ValueError):
                saving = 0
            sev = str(item.get("severity", "low")).lower()
            if sev not in ("high", "medium", "low"):
                sev = "low"
            opps.append(OptimizationOpportunity(
                category=str(item.get("category", "unspecified")),
                location=str(item.get("location", "?")),
                severity=sev,
                description=str(item.get("description", "")),
                estimated_saving=saving,
                evidence={"path": "llm"}))
        return opps


# ==================== Part E — 统一报告与衔接 ====================

@dataclass
class DiffOracleReport:
    """统一报告——规范违例 + 优化机会 + 严重级分布"""

    success: bool
    total_specs: int = 0
    total_cases: int = 0
    violations: List[SemanticVerdict] = field(default_factory=list)
    optimization_opportunities: List[OptimizationOpportunity] = field(
        default_factory=list)
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    used_llm: bool = False
    execution_time: float = 0.0
    summary: str = ""


def verdict_to_score(severity: str) -> float:
    """三分类严重级 -> [0,1] 分数——与 triage 阈值对齐"""
    return {"high": 0.8, "medium": 0.5, "low": 0.2}.get(severity, 0.2)


class DiffOracleHarness:
    """DiffOracle 编排入口——衔接差分测试与引擎比较"""

    def __init__(self, llm: Optional[LLMOracleBackend] = None):
        self._llm = llm or LLMOracleBackend(*_env_llm_config())
        self._spec_oracle = SpecLevelOracle(self._llm)
        self._case_gen = TargetedCaseGenerator(self._llm)
        self._opt_detector = OptimizationDetector(self._llm)
        self.report = DiffOracleReport(success=False)

    @property
    def llm_enabled(self) -> bool:
        return self._llm.enabled

    def run_spec_oracle(self, specs: List[SpecConstraint],
                        exec_fn: Callable[[bytes], Any],
                        cases: List[bytes]) -> DiffOracleReport:
        """每个规范 x 每个用例执行规范断言"""
        start = time.time()
        violations: List[SemanticVerdict] = []
        for spec in specs:
            for data in cases:
                try:
                    result = exec_fn(data)
                except Exception as exc:
                    result = _ExceptionStub(str(exc))
                verdict = self._spec_oracle.evaluate(spec, result)
                if verdict.level == VerdictLevel.VIOLATION:
                    verdict.evidence["input_size"] = len(data)
                    violations.append(verdict)
        self.report = DiffOracleReport(
            success=True,
            total_specs=len(specs),
            total_cases=len(cases),
            violations=violations,
            used_llm=self.llm_enabled,
            execution_time=time.time() - start,
        )
        self._finalize()
        return self.report

    def run_boundary_campaign(self, kinds: List[TrickyBoundaryKind],
                              spec: str = "", count: int = 8,
                              exec_fn: Optional[Callable[[bytes], Any]] = None,
                              specs: Optional[List[SpecConstraint]] = None
                              ) -> DiffOracleReport:
        """生成边界用例并可选执行规范断言"""
        start = time.time()
        cases: List[bytes] = []
        generated: List[Tuple[bytes, str]] = []
        for kind in kinds:
            if spec and self._case_gen.llm_enabled:
                generated = self._case_gen.generate_llm(spec, kind, count)
            else:
                generated = self._case_gen.generate(kind, count)
            cases.extend(g for g, _ in generated)
        self.report = DiffOracleReport(
            success=True,
            total_specs=len(specs or []),
            total_cases=len(cases),
            used_llm=self.llm_enabled,
            execution_time=time.time() - start,
        )
        if exec_fn is not None and specs:
            self.report = self.run_spec_oracle(specs, exec_fn, cases)
        else:
            self._finalize()
        return self.report

    def run_optimization_scan(self, artifacts: List[Tuple[str, bool]]
                              ) -> DiffOracleReport:
        """对 (文本, is_asm) 工件列表做优化回归检测"""
        start = time.time()
        opps: List[OptimizationOpportunity] = []
        for text, is_asm in artifacts:
            opps.extend(self._opt_detector.detect(text, is_asm=is_asm))
        self.report = DiffOracleReport(
            success=True,
            optimization_opportunities=opps,
            used_llm=self.llm_enabled,
            execution_time=time.time() - start,
        )
        self._finalize()
        return self.report

    def from_differential_result(self, result: Any,
                                 specs: List[SpecConstraint],
                                 max_items: int = 200) -> DiffOracleReport:
        """衔接差分测试结果——消费差异列表中的执行结果"""
        start = time.time()
        violations: List[SemanticVerdict] = []
        diffs = getattr(result, "differences", [])[:max_items]
        for diff in diffs:
            res_a = getattr(diff, "binary_a_result", None)
            res_b = getattr(diff, "binary_b_result", None)
            for res in (res_a, res_b):
                if res is None:
                    continue
                for spec in specs:
                    verdict = self._spec_oracle.evaluate(spec, res)
                    if verdict.level == VerdictLevel.VIOLATION:
                        verdict.evidence["input_size"] = len(
                            getattr(getattr(res, "test_case", None),
                                    "input_data", b""))
                        violations.append(verdict)
        self.report = DiffOracleReport(
            success=True,
            total_specs=len(specs),
            total_cases=len(diffs),
            violations=violations,
            used_llm=self.llm_enabled,
            execution_time=time.time() - start,
        )
        self._finalize()
        return self.report

    def from_engine_result(self, result: Any) -> DiffOracleReport:
        """衔接引擎差分测试——对多引擎分析工件做优化回归扫描"""
        start = time.time()
        artifacts: List[Tuple[str, bool]] = []
        for er in getattr(result, "engine_results", []):
            data = getattr(er, "data", None)
            if isinstance(data, str) and data:
                analysis = str(getattr(er, "analysis", ""))
                is_asm = "disass" in analysis or "cfg" in analysis
                artifacts.append((data, is_asm))
        return self.run_optimization_scan(artifacts)

    def _finalize(self) -> None:
        """填充严重级分布与摘要"""
        dist: Dict[str, int] = {"high": 0, "medium": 0, "low": 0}
        for v in self.report.violations:
            sev = _verdict_severity(v)
            dist[sev] = dist.get(sev, 0) + 1
        for o in self.report.optimization_opportunities:
            dist[o.severity] = dist.get(o.severity, 0) + 1
        self.report.severity_distribution = dist
        self.report.summary = self.render_markdown()

    def render_markdown(self) -> str:
        """Markdown 报告——违例/优化按严重级三分类呈现"""
        r = self.report
        lines = [
            "# DiffOracle 报告",
            "",
            f"- 已评估规范: {r.total_specs}",
            f"- 已执行用例: {r.total_cases}",
            f"- 语义违例: {len(r.violations)}",
            f"- 优化机会: {len(r.optimization_opportunities)}",
            f"- 后端: {'在线' if r.used_llm else '降级 (规则/启发式)'}",
            f"- 执行时间: {r.execution_time:.2f}s",
        ]
        if r.violations:
            lines += ["", "## 语义违例"]
            for v in r.violations[:20]:
                lines.append(f"- **{_verdict_severity(v)}** `{v.spec_id}`: "
                             f"{'；'.join(v.violations[:3])}")
        if r.optimization_opportunities:
            lines += ["", "## 优化机会"]
            for o in r.optimization_opportunities[:20]:
                lines.append(
                    f"- **{o.severity}** [{o.category}] @ {o.location}: "
                    f"{o.description} (≈{o.estimated_saving}B)")
        return "\n".join(lines)

    def to_triage_reporter(self) -> Any:
        """转换为 triage_reporter 复用三分类报告结构"""
        from .triage_reporter import TriageEntry, TriageReporter
        reporter = TriageReporter()
        reporter.set_metadata(source="diff_oracle", used_llm=self.llm_enabled)
        idx = 0
        for v in self.report.violations:
            sev = _verdict_severity(v)
            score = verdict_to_score(sev)
            entry = TriageEntry(
                crash_id=f"spec_{v.spec_id}_{idx:04d}",
                signal_num=0,
                signal_name="SPEC_VIOLATION",
                crash_type=f"SPEC_{v.spec_id.upper()}",
                exploitability_score=score,
                exploitability_verdict=sev,
                root_cause_hint="；".join(v.violations[:2]),
                discovery_time=time.time(),
                input_hash="",
            )
            reporter.add_entry(entry)
            idx += 1
        for o in self.report.optimization_opportunities:
            score = verdict_to_score(o.severity)
            entry = TriageEntry(
                crash_id=f"opt_{o.category}_{idx:04d}",
                signal_num=0,
                signal_name="OPT_OPPORTUNITY",
                crash_type=f"OPT_{o.category.upper()}",
                exploitability_score=score,
                exploitability_verdict=o.severity,
                root_cause_hint=o.description,
                discovery_time=time.time(),
                input_hash="",
            )
            reporter.add_entry(entry)
            idx += 1
        return reporter


def _verdict_severity(verdict: SemanticVerdict) -> str:
    """违例严重级——高置信度 + 多违例 -> high"""
    if verdict.confidence >= 0.75 and len(verdict.violations) >= 1:
        return "high"
    if verdict.confidence >= 0.5:
        return "medium"
    return "low"


class _ExceptionStub:
    """执行异常结果替身——使规范断言可处理异常路径用例"""

    def __init__(self, message: str):
        self.stdout = b""
        self.stderr = message.encode("utf-8", errors="replace")
        self.exit_code = -2
        self.crashed = True


# ==================== 便捷入口 ====================

def build_diff_oracle(base_url: str = "", api_key: str = "",
                      model: str = "") -> DiffOracleHarness:
    """工厂—从环境变量或显式参数构建 DiffOracleHarness"""
    if base_url or api_key or model:
        llm = LLMOracleBackend(base_url, api_key, model)
        return DiffOracleHarness(llm)
    return DiffOracleHarness()


def run_spec_campaign(specs: List[SpecConstraint],
                      exec_fn: Callable[[bytes], Any],
                      cases: List[bytes]) -> DiffOracleReport:
    """顶层便捷——一步执行规范级差分预言"""
    return build_diff_oracle().run_spec_oracle(specs, exec_fn, cases)


COMMON_SPECS: List[SpecConstraint] = [
    SpecConstraint(
        spec_id="no_crash_on_empty",
        natural_language="空输入不应导致进程崩溃, 应优雅返回错误码或空输出",
        regex_forbidden=["segmentation fault", "stack smashing"],
        attribute_predicates=[
            ("not_crashed", lambda r: not getattr(r, "crashed", False)),
        ],
    ),
    SpecConstraint(
        spec_id="overflow_error_graceful",
        natural_language="整数溢出输入应被安全处理, 输出不应包含未初始化数据",
        regex_forbidden=["use after free", "double free"],
    ),
]

def _debug_print(*args, **kwargs): pass
