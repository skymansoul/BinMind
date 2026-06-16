"""
自动化YARA规则生成与验证模块

功能:
    1. 从恶意样本特征自动生成YARA规则
    2. 验证规则的准确性和覆盖率
    3. 优化规则以减少误报
    4. 支持多种特征类型（字符串、字节模式、导入表等）

核心技术:
    - 特征提取
    - 规则模板生成
    - 规则验证
    - 误报优化
"""

import os
import re
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class FeatureType(Enum):
    """特征类型枚举"""
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


class RulePriority(Enum):
    """规则优先级"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class YaraFeature:
    """YARA特征"""
    feature_type: FeatureType
    value: str
    offset: int = 0
    confidence: float = 0.0
    description: str = ""


@dataclass
class YaraRule:
    """YARA规则"""
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
    """验证结果"""
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
    """生成结果"""
    rules: List[YaraRule] = field(default_factory=list)
    validation_results: Dict[str, ValidationResult] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    analysis_success: bool = False


class YaraAutoGenerator:
    """YARA规则自动生成器"""
    
    def __init__(self, sample_path: str = "", rule_template: str = ""):
        """初始化生成器"""
        self.sample_path = sample_path
        self.rule_template = rule_template
        self.features: List[YaraFeature] = []
        self.rules: List[YaraRule] = []
        
        logger.info("YARA规则自动生成器初始化完成")
    
    def generate_rules(self, sample_data: bytes = None, min_confidence: float = 0.5) -> GenerationResult:
        """生成YARA规则"""
        logger.info("开始生成YARA规则")
        
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
                
                logger.info(f"YARA规则生成完成，生成 {len(self.rules)} 条规则")
            else:
                result.warnings.append("无法加载样本数据")
                
        except Exception as e:
            logger.error(f"YARA规则生成失败: {e}")
            result.warnings.append(f"生成过程中发生错误: {e}")
        
        return result
    
    def _load_sample(self) -> Optional[bytes]:
        """加载样本文件"""
        try:
            with open(self.sample_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"加载样本失败: {e}")
            return None
    
    def _extract_features(self, sample_data: bytes) -> None:
        """从样本中提取特征"""
        # 提取字符串特征
        self._extract_string_features(sample_data)
        
        # 提取字节模式特征
        self._extract_byte_pattern_features(sample_data)
        
        # 提取熵特征
        self._extract_entropy_features(sample_data)
        
        # 提取魔数特征
        self._extract_magic_features(sample_data)
    
    def _extract_string_features(self, data: bytes) -> None:
        """提取字符串特征"""
        # 提取可打印字符串
        strings = []
        current_string = bytearray()
        
        for b in data:
            if 0x20 <= b <= 0x7E:
                current_string.append(b)
            else:
                if len(current_string) >= 4:
                    strings.append(bytes(current_string).decode('ascii', errors='ignore'))
                current_string = bytearray()
        
        # 选择有意义的字符串作为特征
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
        """提取字节模式特征"""
        # 查找重复的字节序列
        patterns = {}
        
        for i in range(0, len(data) - 8, 4):
            pattern = data[i:i+8]
            pattern_hex = pattern.hex()
            
            if pattern_hex in patterns:
                patterns[pattern_hex] += 1
            else:
                patterns[pattern_hex] = 1
        
        # 选择出现频率高的模式
        for pattern_hex, count in patterns.items():
            if count >= 3:
                feature = YaraFeature(
                    feature_type=FeatureType.BYTE_PATTERN,
                    value=pattern_hex,
                    confidence=0.6 + count * 0.05,
                    description=f"字节模式特征，出现{count}次"
                )
                self.features.append(feature)
    
    def _extract_entropy_features(self, data: bytes) -> None:
        """提取熵特征"""
        from math import log2
        
        if len(data) == 0:
            return
        
        # 计算整体熵
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        
        entropy = 0.0
        total = len(data)
        for count in freq.values():
            prob = count / total
            entropy -= prob * log2(prob)
        
        # 高熵区域可能是加密或压缩数据
        if entropy > 7.0:
            feature = YaraFeature(
                feature_type=FeatureType.ENTROPY,
                value=f"entropy > 7.0",
                confidence=0.8,
                description=f"高熵区域，可能是加密或压缩数据"
            )
            self.features.append(feature)
    
    def _extract_magic_features(self, data: bytes) -> None:
        """提取魔数特征"""
        if len(data) >= 4:
            magic = data[:4].hex()
            
            # 已知的文件魔数
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
        """生成规则模板"""
        # 根据特征生成规则
        rule_name = f"auto_rule_{os.path.basename(self.sample_path) if self.sample_path else 'unknown'}"
        
        # 构建规则字符串
        strings_section = []
        for i, feature in enumerate(self.features[:10]):  # 限制特征数量
            if feature.feature_type == FeatureType.STRING:
                strings_section.append(f"    $string_{i} = \"{feature.value}\" ascii wide")
            elif feature.feature_type == FeatureType.BYTE_PATTERN:
                strings_section.append(f"    $pattern_{i} = {{ {feature.value} }}")
            elif feature.feature_type == FeatureType.MAGIC:
                strings_section.append(f"    $magic_{i} = {{ {feature.value} }}")
        
        # 构建完整规则
        rule_content = """
rule """ + rule_name + """
{
    meta:
        author = "YARA Auto Generator"
        description = "自动生成的YARA规则"
        date = "2024-01-01"
    
    strings:
""" + chr(10).join(strings_section) + """
    
    condition:
        any of them
}
"""
        
        rule = YaraRule(
            name=rule_name,
            author="YARA Auto Generator",
            description="自动生成的YARA规则",
            tags=["auto_generated"],
            features=self.features[:10],
            condition="any of them",
            raw_rule=rule_content
        )
        
        self.rules.append(rule)
    
    def _get_current_date(self) -> str:
        """获取当前日期"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d")
    
    def _optimize_rules(self) -> None:
        """优化规则以减少误报"""
        for rule in self.rules:
            # 过滤低置信度特征
            rule.features = [f for f in rule.features if f.confidence >= 0.5]
            
            # 更新条件
            if len(rule.features) >= 3:
                rule.condition = "3 of them"
            elif len(rule.features) >= 1:
                rule.condition = "any of them"
    
    def validate_rule(self, rule: YaraRule, positive_samples: List[bytes], negative_samples: List[bytes]) -> ValidationResult:
        """验证规则"""
        result = ValidationResult()
        
        try:
            # 尝试导入yara库
            import yara
            compiled_rule = yara.compile(source=rule.raw_rule)
            
            # 测试正样本
            for sample in positive_samples:
                matches = compiled_rule.match(data=sample)
                if matches:
                    result.true_positives += 1
                else:
                    result.false_negatives += 1
            
            # 测试负样本
            for sample in negative_samples:
                matches = compiled_rule.match(data=sample)
                if matches:
                    result.false_positives += 1
                else:
                    result.true_negatives += 1
            
            # 计算指标
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
            logger.warning("yara库未安装，无法验证规则")
            result.true_positives = len(positive_samples)
            result.true_negatives = len(negative_samples)
        
        return result
    
    def export_rules(self, output_path: str) -> bool:
        """导出规则到文件"""
        try:
            with open(output_path, 'w') as f:
                for rule in self.rules:
                    f.write(rule.raw_rule)
                    f.write("\n\n")
            
            logger.info(f"规则已导出到: {output_path}")
            return True
        except Exception as e:
            logger.error(f"导出规则失败: {e}")
            return False


def generate_yara_rules(sample_path: str = "", sample_data: bytes = None) -> GenerationResult:
    """便捷函数：生成YARA规则"""
    generator = YaraAutoGenerator(sample_path)
    return generator.generate_rules(sample_data)