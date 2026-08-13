import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class InputConstraint:
    field: str
    constraint_type: str
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ContradictoryInput:
    fields: Dict[str, Any]
    contradictions: List[str]
    target_function: str = "target"


@dataclass
class FuzzingResult:
    success: bool
    inputs: List[ContradictoryInput]
    total_generated: int = 0
    grammar: Optional[Dict[str, Any]] = None     # 协议语法提取结果
    semantic_scores: Optional[List[float]] = None  # 语义多样性评分


# LLM 驱动的协议语法提取
# Meng et al., "ChatAFL: Large Language Model guided 协议 模糊测试"
# 核心方法: 将协议消息序列输入 LLM, 让 LLM 提取结构化的文法规则（字段名/类型/约束）
# 本实现提供语法提取的骨架——在实际部署中，LLM prompt 由外部调用者注入


class GrammarRule:
    """单条语法规则：non-terminal → production"""
    __slots__ = ('name', 'productions', 'field_type', 'constraint')

    def __init__(self, name: str, productions: List[str], field_type: str = "bytes",
                 constraint: Optional[InputConstraint] = None):
        self.name = name
        self.productions = productions
        self.field_type = field_type
        self.constraint = constraint


class ProtocolGrammarExtractor:
    """从消息迹中提取协议语法——ChatAFL 启发的语法推断器
    通过分析消息样本的结构特征（定长/变长字段、分隔符、TLV模式）
    构建一个可用于指导结构化变异的 BNF 风格文法
    """

    _TLV_PATTERN = __import__('re').compile(
        rb'(..)(..)', re.DOTALL  # 简化的 TLV: 1B type + 1B length + value
    )
    _DELIMITER_BYTE = 0x00  # 以 NUL 分隔的 C 字符串字段

    def __init__(self):
        self._rules: Dict[str, GrammarRule] = {}

    def infer_from_samples(self, samples: List[bytes]) -> Dict[str, GrammarRule]:
        """从一组消息样本推断文法——分析每个偏移位置的字节分布
        将固定位置归为 'constant'，变化位置归为 'variable' 并推断其范围
        """
        if not samples:
            return self._rules
        min_len = min(len(s) for s in samples)
        max_len = max(len(s) for s in samples)

        # 对每个偏移位置统计观察到的字节集合
        for offset in range(min_len):
            byte_set: Set[int] = set()
            for s in samples:
                if offset < len(s):
                    byte_set.add(s[offset])
            field_name = f"field_{offset}"
            if len(byte_set) <= 2:
                # 固定字段——可能是类型标记或魔数
                val = list(byte_set)[0] if byte_set else 0
                self._rules[field_name] = GrammarRule(
                    field_name, [f"0x{val:02x}"], "constant",
                    InputConstraint(field_name, "enum", {"allowed_values": list(byte_set)})
                )
            else:
                lo, hi = min(byte_set), max(byte_set)
                self._rules[field_name] = GrammarRule(
                    field_name, [f"[{lo},{hi}]"], "variable",
                    InputConstraint(field_name, "range", {"min": lo, "max": hi})
                )

        # 处理变长部分——超出最小长度的字节归为可变长度 payload
        if max_len > min_len:
            self._rules["payload"] = GrammarRule(
                "payload", ["<variable_length>"], "bytes",
                InputConstraint("payload", "length", {"min_len": 0, "max_len": max_len - min_len})
            )
        return self._rules

    def to_bnf(self) -> str:
        """导出 BNF 风格的文法字符串，可直接用于指导 fuzzer 的变异策略"""
        lines = ["<message> ::= " + " ".join(f"<{n}>" for n in self._rules)]
        for name, rule in self._rules.items():
            prods = " | ".join(rule.productions)
            lines.append(f"<{name}> ::= {prods}  ; type={rule.field_type}")
        return "\n".join(lines)


# 语义反馈驱动的种子排序
# arXiv 2511.03995, "Hybrid 模糊测试 LLM-Guided Input
# 变异 Semantic Feedback"
# 使用嵌入向量的余弦相似度评估输入的"行为新颖性"——覆盖路径之外的语义信号


class SemanticNoveltyScorer:
    """基于语义新颖性的种子排序器
    将每个输入映射到低维特征向量（长度、熵、字节分布矩等）
    使用余弦相似度量化输入之间的行为多样性
    """

    _FEATURE_DIMS = 5  # 特征维度：len, byte_entropy, mean, variance, unique_ratio

    def __init__(self):
        self._seen_features: List[List[float]] = []

    def _extract_features(self, payload: bytes) -> List[float]:
        """从载荷提取轻量语义特征向量——不依赖执行迹"""
        n = len(payload) if payload else 1
        mean_v = sum(payload) / n if payload else 0.0
        variance = sum((b - mean_v) ** 2 for b in payload) / n if payload else 0.0
        # 字节熵——编码了结构 vs 随机的程度
        byte_counts: Dict[int, int] = {}
        for b in payload:
            byte_counts[b] = byte_counts.get(b, 0) + 1
        entropy = -sum((c / n) * _math_log2(c / n)
                       for c in byte_counts.values() if c > 0)
        unique_ratio = len(byte_counts) / n if n else 0.0
        return [float(n), entropy, float(mean_v), float(variance), unique_ratio]

    def novelty_score(self, payload: bytes) -> float:
        """返回该载荷相对于已见过的所有载荷的语义新颖度（0-1）
        得分 1.0 = 全新行为，0.0 = 完全重复
        """
        features = self._extract_features(payload)
        if not self._seen_features:
            self._seen_features.append(features)
            return 1.0
        # 与最近邻的余弦距离作为新颖度度量
        max_sim = 0.0
        for seen in self._seen_features[-100:]:  # 滑动窗口
            dot = sum(a * b for a, b in zip(features, seen))
            norm_a = _math_sqrt(sum(a * a for a in features))
            norm_b = _math_sqrt(sum(a * a for a in seen))
            if norm_a > 0 and norm_b > 0:
                sim = dot / (norm_a * norm_b)
                if sim > max_sim:
                    max_sim = sim
        self._seen_features.append(features)
        return 1.0 - max_sim


# math 模块函数——避免重复 import
_math_log2 = __import__('math').log2 if hasattr(__import__('math'), 'log2') else lambda x: __import__('math').log(x, 2)
_math_sqrt = __import__('math').sqrt


class FormatParser:
    TYPE_MAP = {
        "uint": ("range", {"min": 0, "max": 0xFFFFFFFF}),
        "int": ("range", {"min": -0x80000000, "max": 0x7FFFFFFF}),
        "uint8": ("range", {"min": 0, "max": 255}),
        "uint16": ("range", {"min": 0, "max": 65535}),
        "uint32": ("range", {"min": 0, "max": 0xFFFFFFFF}),
        "uint64": ("range", {"min": 0, "max": 0xFFFFFFFFFFFFFFFF}),
        "int8": ("range", {"min": -128, "max": 127}),
        "int16": ("range", {"min": -32768, "max": 32767}),
        "int32": ("range", {"min": -0x80000000, "max": 0x7FFFFFFF}),
        "int64": ("range", {"min": -0x8000000000000000, "max": 0x7FFFFFFFFFFFFFFF}),
        "str": ("length", {"min_len": 0, "max_len": 1024}),
        "bytes": ("length", {"min_len": 0, "max_len": 4096}),
        "bool": ("enum", {"allowed_values": [0, 1]}),
    }

    def __init__(self, format_spec: str):
        self.format_spec = format_spec
        self.constraints: List[InputConstraint] = []
        self._grammar_extractor = ProtocolGrammarExtractor()

    def parse(self):
        for token in self.format_spec.split(","):
            token = token.strip()
            if not token or ":" not in token:
                continue
            field_name, type_spec = token.split(":", 1)
            field_name = field_name.strip()
            type_spec = type_spec.strip().lower()

            if type_spec in self.TYPE_MAP:
                ct, params = self.TYPE_MAP[type_spec]
                self.constraints.append(InputConstraint(
                    field=field_name, constraint_type=ct, parameters=params.copy()
                ))
            elif type_spec.startswith("enum:"):
                values_str = type_spec[5:]
                values = [v.strip() for v in values_str.split(",") if v.strip()]
                self.constraints.append(InputConstraint(
                    field=field_name, constraint_type="enum",
                    parameters={"allowed_values": values}
                ))
            elif type_spec.startswith("length:"):
                range_part = type_spec[7:].strip()
                try:
                    mn, mx = map(int, range_part.split("-"))
                except Exception:
                    mn, mx = 0, 1024
                self.constraints.append(InputConstraint(
                    field=field_name, constraint_type="length",
                    parameters={"min_len": mn, "max_len": mx}
                ))
            elif type_spec.startswith("dependency:"):
                dep_field = type_spec.split(":", 2)[-1] if ":" in type_spec else ""
                self.constraints.append(InputConstraint(
                    field=field_name, constraint_type="dependency",
                    parameters={"depends_on": dep_field}
                ))
            else:
                logger.warning("Unrecognized field type: %s. Skipping %s.", type_spec, field_name)

    def infer_grammar_from_samples(self, samples: List[bytes]) -> str:
        """从字节样本推断协议语法并导出 BNF——ChatAFL 启发的语法自动提取"""
        rules = self._grammar_extractor.infer_from_samples(samples)
        return self._grammar_extractor.to_bnf()


class ContradictionGenerator:
    def __init__(self, constraints: List[InputConstraint]):
        self.constraints = constraints

    def generate(self, count: int = 10) -> List[ContradictoryInput]:
        inputs = []
        strategies = ["exceed_max", "below_min", "too_long", "too_short", "invalid_enum", "null_value"]
        for i in range(count):
            fields: Dict[str, Any] = {}
            contradictions = []
            strategy = strategies[i % len(strategies)]

            for c in self.constraints:
                if c.constraint_type == "range":
                    if strategy == "exceed_max":
                        fields[c.field] = c.parameters.get("max", 0xFFFFFFFF) + 1
                        contradictions.append(f"{c.field} exceeds max ({c.parameters.get('max')})")
                    elif strategy == "below_min":
                        fields[c.field] = c.parameters.get("min", 0) - 1
                        contradictions.append(f"{c.field} below min ({c.parameters.get('min')})")
                    elif strategy == "null_value":
                        fields[c.field] = 0
                        contradictions.append(f"{c.field} is zero/null")
                    else:
                        fields[c.field] = c.parameters.get("max", 0xFFFFFFFF) + i + 1
                        contradictions.append(f"{c.field} exceeds max")

                elif c.constraint_type == "length":
                    max_len = c.parameters.get("max_len", 1024)
                    min_len = c.parameters.get("min_len", 0)
                    if strategy == "too_long":
                        fields[c.field] = "A" * (max_len + 100)
                        contradictions.append(f"{c.field} length {max_len+100} exceeds max {max_len}")
                    elif strategy == "too_short" and min_len > 0:
                        fields[c.field] = "A" * max(0, min_len - 1)
                        contradictions.append(f"{c.field} length {min_len-1} below min {min_len}")
                    elif strategy == "null_value":
                        fields[c.field] = ""
                        contradictions.append(f"{c.field} is empty string")
                    else:
                        fields[c.field] = "A" * (max_len + i * 10 + 1)
                        contradictions.append(f"{c.field} length too long")

                elif c.constraint_type == "enum":
                    allowed = c.parameters.get("allowed_values", [])
                    if allowed:
                        fields[c.field] = "invalid_value"
                        contradictions.append(f"{c.field} not in allowed list {allowed}")
                    else:
                        fields[c.field] = "any"

                elif c.constraint_type == "dependency":
                    fields[c.field] = -1
                    contradictions.append(f"{c.field} violates dependency on {c.parameters.get('depends_on')}")

                else:
                    fields[c.field] = "violation"
                    contradictions.append(f"{c.field} generic violation")

            inputs.append(ContradictoryInput(
                fields=fields, contradictions=contradictions, target_function="target"))
        return inputs


class StructuredInputFuzzer:
    """Structured input 模糊测试器: 解析 格式化, injects contradictions
    2025 升级: 融合 ChatAFL 的协议语法提取 + 语义新颖度排序
    """

    def __init__(self, format_spec: str = "field1:uint,field2:str"):
        self.parser = FormatParser(format_spec)
        self.parser.parse()
        self._novelty_scorer = SemanticNoveltyScorer()

    def run(self, count: int = 10, seed_samples: List[bytes] = None) -> FuzzingResult:
        try:
            gen = ContradictionGenerator(self.parser.constraints)
            inputs = gen.generate(count)

            # 语义新颖度评分——对生成的输入计算行为多样性
            semantic_scores: List[float] = []
            for inp in inputs:
                payload = str(inp.fields).encode('utf-8')
                score = self._novelty_scorer.novelty_score(payload)
                semantic_scores.append(score)

            # 协议语法提取（如果提供了样本）
            grammar: Optional[Dict[str, Any]] = None
            if seed_samples:
                bnf_str = self.parser.infer_grammar_from_samples(seed_samples)
                grammar = {"bnf": bnf_str, "extracted": True}

            return FuzzingResult(
                success=True, inputs=inputs, total_generated=len(inputs),
                grammar=grammar, semantic_scores=semantic_scores
            )
        except Exception as e:
            logger.error("Fuzzing run aborted: %s", e)
            return FuzzingResult(success=False, inputs=[])


def create_structured_input_fuzzer(format_spec: str = "field1:uint,field2:str") -> StructuredInputFuzzer:
    """工厂 for StructuredInput模糊测试器"""
    return StructuredInputFuzzer(format_spec)
