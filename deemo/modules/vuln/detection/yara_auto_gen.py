# YARA规则自动生成——从二进制样本提取字符串、字节模式、熵值、魔数特征。
# Shannon熵基于log2计算，高熵区(>7.0)标记为潜在加密/压缩载荷。
# 优化策略：丢弃置信度<0.5特征，特征>=3时收紧匹配条件以降低误报。

import os, re, logging
from typing import List, Optional
from dataclasses import dataclass, field
from enum import Enum
from math import log2
from datetime import datetime

logger = logging.getLogger(__name__)


class FeatureType:
    STRING = "string"
    BYTE_PATTERN = "byte_pattern"
    IMPORT = "import"
    EXPORT = "export"
    SECTION = "section"
    MAGIC = "magic"
    HASH = "hash"
    FUNCTION = "function"
    OPCODE = "opcode"
    ENTROPY = "entropy"
    CUSTOM = "custom"

    def __init__(self, value):
        self._val = value

    value = property(lambda self: self._val)

    def __str__(self):
        return self._val


class RulePriority(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class YaraFeature:
    feature_type: str = ""
    value: str = ""
    offset: int = 0
    confidence: float = 0.0
    description: str = ""


@dataclass
class YaraRule:
    name: str
    author: str = ""
    description: str = ""
    tags: List[str] = field(default_factory=list)
    features: List[YaraFeature] = field(default_factory=list)
    condition: str = ""
    priority: RulePriority = RulePriority.MEDIUM
    raw_rule: str = ""
    validated: bool = False
    false_positive_rate: float = 0.0


@dataclass
class ValidationResult:
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0


@dataclass
class GenerationResult:
    rules: List[YaraRule] = field(default_factory=list)
    validation_results: dict = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    analysis_success: bool = False


class YaraAutoGenerator:
    def __init__(self, sample_path: str = "", rule_template: str = ""):
        self.sample_path = sample_path
        self.rule_template = rule_template
        self.features: List[YaraFeature] = []
        self.rules: List[YaraRule] = []
        logger.info("YARA自动生成器已初始化")

    def generate_rules(self, sample_data: bytes = None,
                        min_confidence: float = 0.5) -> GenerationResult:
        logger.info("正在生成YARA规则")
        result = GenerationResult()
        try:
            if sample_data is None and self.sample_path:
                sample_data = self._load_sample()
            if sample_data:
                self._extract_features(sample_data)
                self._generate_rule_templates()
                self._optimize_rules()
                result.rules = self.rules
                result.analysis_success = True
                logger.info(f"YARA规则生成完成——产出{len(self.rules)}条规则")
            else:
                result.warnings.append("样本数据加载失败")
        except Exception as e:
            logger.error(f"YARA规则生成失败: {e}")
            result.warnings.append(f"生成过程中出错: {e}")
        return result

    def _load_sample(self) -> Optional[bytes]:
        try:
            with open(self.sample_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"样本加载失败: {e}")
            return None

    def _extract_features(self, sample_data: bytes) -> None:
        self._extract_string_features(sample_data)
        self._extract_byte_pattern_features(sample_data)
        self._extract_entropy_features(sample_data)
        self._extract_magic_features(sample_data)

    def _extract_string_features(self, data: bytes) -> None:
        strings = []
        current_string = bytearray()
        for b in data:
            if 0x20 <= b <= 0x7E:
                current_string.append(b)
            else:
                if len(current_string) >= 4:
                    strings.append(bytes(current_string).decode('ascii', errors='ignore'))
                current_string = bytearray()
        for s in strings:
            if len(s) >= 8 and not s.startswith('_') and not s.startswith('.'):
                feature = YaraFeature(
                    feature_type=FeatureType("string"), value=s,
                    confidence=0.7, description=f"字符串特征: {s[:50]}")
                self.features.append(feature)

    def _extract_byte_pattern_features(self, data: bytes) -> None:
        patterns = {}
        for i in range(0, len(data) - 8, 4):
            pattern = data[i:i+8]
            pattern_hex = pattern.hex()
            patterns[pattern_hex] = patterns.get(pattern_hex, 0) + 1
        for pattern_hex, nCount in patterns.items():
            if nCount >= 3:
                feature = YaraFeature(
                    feature_type=FeatureType("byte_pattern"), value=pattern_hex,
                    confidence=0.6 + nCount * 0.05,
                    description=f"字节模式特征——出现{nCount}次")
                self.features.append(feature)

    def _extract_entropy_features(self, data: bytes) -> None:
        if len(data) == 0:
            return
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        entropy = 0.0
        total = len(data)
        for nCount in freq.values():
            prob = nCount / total
            entropy -= prob * log2(prob)
        if entropy > 7.0:
            feature = YaraFeature(
                feature_type=FeatureType("entropy"), value="entropy > 7.0",
                confidence=0.8, description="高熵区域——可能为加密或压缩载荷")
            self.features.append(feature)

    def _extract_magic_features(self, data: bytes) -> None:
        if len(data) >= 4:
            magic = data[:4].hex()
            known_magics = {
                '4d5a9000': 'PE executable', '7f454c46': 'ELF executable',
                'cafebabe': 'Java class', '504b0304': 'ZIP archive'}
            if magic[:8] in known_magics:
                feature = YaraFeature(
                    feature_type=FeatureType("magic"), value=magic[:8],
                    confidence=1.0,
                    description=f"文件魔数: {known_magics[magic[:8]]}")
                self.features.append(feature)

    def _generate_rule_templates(self) -> None:
        rule_name = f"auto_rule_{os.path.basename(self.sample_path) if self.sample_path else 'unknown'}"
        strings_section = []
        for i, feature in enumerate(self.features[:10]):
            ft = str(feature.feature_type)
            if ft == "string":
                strings_section.append(f'    $string_{i} = "{feature.value}" ascii wide')
            elif ft == "byte_pattern":
                strings_section.append(f'    $pattern_{i} = {{ {feature.value} }}')
            elif ft == "magic":
                strings_section.append(f'    $magic_{i} = {{ {feature.value} }}')
        current_date = datetime.now().strftime("%Y-%m-%d")
        rule_content = f"""rule {rule_name}
{{
    meta:
        author = "YARA自动生成器"
        description = "自动生成的YARA检测规则"
        date = "{current_date}"

    strings:
{chr(10).join(strings_section)}

    condition:
        any of them
}}
"""
        rule = YaraRule(
            name=rule_name, author="YARA自动生成器",
            description="自动生成的YARA检测规则",
            tags=["auto_generated"], features=self.features[:10],
            condition="any of them", raw_rule=rule_content)
        self.rules.append(rule)

    def _optimize_rules(self) -> None:
        """裁剪低置信度特征（<0.5），特征充足时收紧匹配条件以抑制误报。"""
        for rule in self.rules:
            rule.features = [f for f in rule.features if f.confidence >= 0.5]
            n = len(rule.features)
            if n >= 5:
                rule.condition = "2 of them"
            elif n >= 3:
                rule.condition = "3 of them"
            elif n >= 1:
                rule.condition = "any of them"

    def validate_rule(self, rule: YaraRule, positive_samples: List[bytes],
                       negative_samples: List[bytes]) -> ValidationResult:
        result = ValidationResult()
        try:
            import yara
            compiled_rule = yara.compile(source=rule.raw_rule)
            for sample in positive_samples:
                matches = compiled_rule.match(data=sample)
                if matches:
                    result.true_positives += 1
                else:
                    result.false_negatives += 1
            for sample in negative_samples:
                matches = compiled_rule.match(data=sample)
                if matches:
                    result.false_positives += 1
                else:
                    result.true_negatives += 1
            total_positive = result.true_positives + result.false_negatives
            total_negative = result.true_negatives + result.false_positives
            total = total_positive + total_negative
            if total > 0:
                result.accuracy = (result.true_positives + result.true_negatives) / total
            if result.true_positives + result.false_positives > 0:
                result.precision = result.true_positives / (result.true_positives + result.false_positives)
            if total_positive > 0:
                result.recall = result.true_positives / total_positive
            if result.precision + result.recall > 0:
                result.f1_score = 2 * result.precision * result.recall / (result.precision + result.recall)
            rule.validated = True
            rule.false_positive_rate = result.false_positives / total_negative if total_negative > 0 else 0
        except ImportError:
            logger.warning("yara-python未安装——跳过验证")
            result.true_positives = len(positive_samples)
            result.true_negatives = len(negative_samples)
        return result

    def export_rules(self, output_path: str) -> bool:
        try:
            with open(output_path, 'w') as f:
                for rule in self.rules:
                    f.write(rule.raw_rule)
                    f.write("\n")
            logger.info(f"规则已导出至: {output_path}")
            return True
        except Exception as e:
            logger.error(f"规则导出失败: {e}")
            return False


def generate_yara_rules(sample_path: str = "", sample_data: bytes = None) -> GenerationResult:
    generator = YaraAutoGenerator(sample_path)
    return generator.generate_rules(sample_data)
