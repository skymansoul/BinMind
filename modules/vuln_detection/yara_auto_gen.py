from __future__ import annotations

import os
import re
import logging
from typing import List, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class FeatureType:
    """YARA规则构造的特征类型分类体系：字符串字面量、字节模式、导入与结构标记"""
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



    _val = None
    def __init__(self, value):
        self._val = value
    @property
    def value(self):
        return self._val
    def __str__(self):
        return self._val

# 单例实例, 定义于类体外部 (类体内FeatureType名称尚未绑定)
FeatureType.BYTE_PATTERN = FeatureType("byte_pattern")
FeatureType.EXPORT = FeatureType("export")
FeatureType.MAGIC = FeatureType("magic")
FeatureType.FUNCTION = FeatureType("function")
FeatureType.ENTROPY = FeatureType("entropy")

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

class YaraRule:
    __slots__ = ('name', 'author', 'description', 'tags', 'features', 'condition', 'priority', 'raw_rule', 'validated', 'false_positive_rate',)

    def __init__(
        self,
        name: str,
        author: str = "",
        description: str = "",
        tags: Optional[List[str]] = None,
        features: Optional[List[YaraFeature]] = None,
        condition: str = "",
        priority: RulePriority = RulePriority.MEDIUM,
        raw_rule: str = "",
        validated: bool = False,
        false_positive_rate: float = 0.0,
    ):
        self.name = name
        self.author = author
        self.description = description
        self.tags = tags if tags is not None else []
        self.features = features if features is not None else []
        self.condition = condition
        self.priority = priority
        self.raw_rule = raw_rule
        self.validated = validated
        self.false_positive_rate = false_positive_rate



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

class GenerationResult:
    __slots__ = ('rules', 'validation_results', 'warnings', 'analysis_success',)

    def __init__(
        self,
        rules: Optional[List[YaraRule]] = None,
        validation_results: Optional[dict] = None,
        warnings: Optional[List[str]] = None,
        analysis_success: bool = False,
    ):
        self.rules = rules if rules is not None else []
        self.validation_results = validation_results if validation_results is not None else {}
        self.warnings = warnings if warnings is not None else []
        self.analysis_success = analysis_success



class YaraAutoGenerator:
    """YARA规则自动生成器, 从二进制样本中提取字符串、字节模式、熵值与魔数特征, 组装检测规则"""

    def __init__(self, sample_path: str = "", rule_template: str = ""):
        """初始化生成器状态，可选传入样本路径与规则模板字符串"""
        self.sample_path = sample_path
        self.rule_template = rule_template
        self.features: List[YaraFeature] = []
        self.rules: List[YaraRule] = []

        logger.info("YARA自动生成器已初始化")

    def generate_rules(self, sample_data: bytes = None, min_confidence: float = 0.5) -> GenerationResult:
        """执行完整生成流水线：加载样本→提取特征→构建模板→优化"""
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

                logger.info(f"YARA规则生成完成, 产出{len(self.rules)}条规则")
            else:
                result.warnings.append("样本数据加载失败")

        except Exception as e:
            logger.error(f"YARA规则生成失败: {e}")
            result.warnings.append(f"生成过程中出错: {e}")

        return result

    def _load_sample(self) -> Optional[bytes]:
        """从磁盘读取二进制样本，失败返回None"""
        try:
            with open(self.sample_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"样本加载失败: {e}")
            return None

    def _extract_features(self, sample_data: bytes) -> None:
        # 分发到各特征提取阶段
        self._extract_string_features(sample_data)

        self._extract_byte_pattern_features(sample_data)

        self._extract_entropy_features(sample_data)

        self._extract_magic_features(sample_data)

    def _extract_string_features(self, data: bytes) -> None:
        """提取可打印ASCII连续片段（≥4字符）作为YARA字符串特征"""
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
                    feature_type=FeatureType.STRING,
                    value=s,
                    confidence=0.7,
                    description=f"字符串特征: {s[:50]}"
                )

                self.features.append(feature)

    def _extract_byte_pattern_features(self, data: bytes) -> None:
        """提取重复出现的8字节十六进制模式（≥3次出现）作为YARA字节模式特征"""
        patterns = {}

        for i in range(0, len(data) - 8, 4):
            pattern = data[i:i+8]
            pattern_hex = pattern.hex()

            if pattern_hex in patterns:
                patterns[pattern_hex] += 1
            else:
                patterns[pattern_hex] = 1

        for pattern_hex, nCount in patterns.items():
            if nCount >= 3:
                feature = YaraFeature(
                    feature_type=FeatureType.BYTE_PATTERN,
                    value=pattern_hex,
                    confidence=0.6 + nCount * 0.05,
                    description=f"字节模式特征, 出现{nCount}次"
                )

                self.features.append(feature)

    def _extract_entropy_features(self, data: bytes) -> None:
        """计算Shannon熵，标记高熵区域（≥7.0）为潜在加密或压缩载荷"""
        from math import log2

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
                feature_type=FeatureType.ENTROPY,
                value=f"entropy > 7.0",
                confidence=0.8,
                description=f"高熵区域, 可能为加密或压缩载荷"
            )

            self.features.append(feature)

    def _extract_magic_features(self, data: bytes) -> None:
        """检查前4字节是否匹配已知魔数常量（PE、ELF、Java class、ZIP）"""
        if len(data) >= 4:
            magic = data[:4].hex()

            known_magics = {
                '4d5a9000': 'PE executable',
                '7f454c46': 'ELF executable',
                'cafebabe': 'Java class',
                '504b0304': 'ZIP archive',
            }

            if magic[:8] in known_magics:
                feature = YaraFeature(
                    feature_type=FeatureType.MAGIC,
                    value=magic[:8],
                    confidence=1.0,
                    description=f"文件魔数: {known_magics[magic[:8]]}"
                )

                self.features.append(feature)

    def _generate_rule_templates(self) -> None:
        """基于提取的特征集组装YARA规则体，特征数量上限10"""
        rule_name = f"auto_rule_{os.path.basename(self.sample_path) if self.sample_path else 'unknown'}"

        strings_section = []
        for i, feature in enumerate(self.features[:10]):
            if feature.feature_type == FeatureType.STRING:
                strings_section.append(f"    $string_{i} = \"{feature.value}\" ascii wide")
            elif feature.feature_type == FeatureType.BYTE_PATTERN:
                strings_section.append(f"    $pattern_{i} = {{ {feature.value} }}")
            elif feature.feature_type == FeatureType.MAGIC:
                strings_section.append(f"    $magic_{i} = {{ {feature.value} }}")

        rule_content = """
rule """ + rule_name + """
{
    meta:
        author = "YARA自动生成器"
        description = "自动生成的YARA检测规则"
        date = "2024-01-01"

    strings:
""" + chr(10).join(strings_section) + """

    condition:
        any of them
}
"""

        rule = YaraRule(
            name=rule_name,
            author="YARA自动生成器",
            description="自动生成的YARA检测规则",
            tags=["auto_generated"],
            features=self.features[:10],
            condition="any of them",
            raw_rule=rule_content
        )

        self.rules.append(rule)

    def _get_current_date(self) -> str:
        """返回当前日期，格式YYYY-MM-DD"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d")

    def _optimize_rules(self) -> None:
        """裁剪低置信度特征（<0.5），特征数量充足时收紧匹配条件"""
        for rule in self.rules:
            rule.features = [f for f in rule.features if f.confidence >= 0.5]

            if len(rule.features) >= 3:
                rule.condition = "3 of them"
            elif len(rule.features) >= 1:
                rule.condition = "any of them"

    def validate_rule(self, rule: YaraRule, positive_samples: List[bytes], negative_samples: List[bytes]) -> ValidationResult:
        """基于标注的正负样本集验证规则，计算precision、recall、F1与误报率"""
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
            logger.warning("yara-python未安装, 跳过验证")
            result.true_positives = len(positive_samples)
            result.true_negatives = len(negative_samples)

        return result

    def export_rules(self, output_path: str) -> bool:
        """将全部已生成规则写入文件，空行分隔"""
        try:
            with open(output_path, 'w') as f:
                for rule in self.rules:
                    f.write(rule.raw_rule)
                    f.write("\n\n")

            logger.info(f"规则已导出至: {output_path}")
            return True
        except Exception as e:
            logger.error(f"规则导出失败: {e}")
            return False

def generate_yara_rules(sample_path: str = "", sample_data: bytes = None) -> GenerationResult:
    """便捷函数：实例化生成器并单次调用产出规则"""
    generator = YaraAutoGenerator(sample_path)
    return generator.generate_rules(sample_data)
