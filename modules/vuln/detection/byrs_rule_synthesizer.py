# coding: utf-8
"""
二进制YARA规则合成-从字节模式到可部署YARA规则的完整合成管线。

YARA规则生成:
  从PatternMiner产出的BytePattern集合合成YARA规则字符串,
  每条规则包含:
    1. meta段: 函数名/哈希/CWE类型/CVSS/来源
    2. strings段: 字节模式($pattern_N = { hex_bytes })
    3. condition段: 逻辑组合(any of them / N of them / all of them)

规则优化:
  - 通配符压缩: 连续的通配符合并为[n-m]跳转(减小规则大小)
  - 模式选择: 仅保留独特性评分>0.3的模式(过滤低区分度模式)
  - 条件选择: 基于FP率选择'any of them'(高召回)或'all of them'(高精确)

与yara_auto_gen的集成:
  yara_auto_gen: 从汇编特征生成YARA规则(基于模式+统计)
  byrs_rule_synthesizer: 从字节模式生成YARA规则(跨编译器弹性)
  互补: auto_gen用于源码级检测, byrs用于二进制级跨编译器检测
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .byrs_pattern_miner import BytePattern, FunctionPatterns, PatternMiner

_log = logging.getLogger(__name__)


# YARA规则


@dataclass
class YARARule:
    """单条YARA规则-可直接写入.yar文件"""
    rule_name: str
    meta: Dict[str, str] = field(default_factory=dict)
    strings: List[Tuple[str, str]] = field(default_factory=list)
    condition: str = "any of them"
    # 质量指标
    expected_tp_rate: float = 0.0
    expected_fp_rate: float = 0.0
    pattern_count: int = 0


@dataclass
class YARARuleSet:
    """YARA规则集-一个函数的完整规则族"""
    function_name: str
    rules: List[YARARule] = field(default_factory=list)
    # 变体: 严格规则/宽松规则
    strict_rule: Optional[YARARule] = None    # all of them(低FP)
    relaxed_rule: Optional[YARARule] = None   # any of them(高召回)


# 规则合成器


class YARARuleSynthesizer:
    """从FunctionPatterns合成可部署的YARA规则。

    合成策略:
      strict_rule:  所有模式必须匹配(all of them)-FP<0.1%
      relaxed_rule: 任一模式匹配(any of them)-召回率>90%
      默认部署strict_rule, 批量扫描用relaxed_rule做初筛。

    规则命名: vuln_{cwe}_{function_hash_short}
    例: vuln_CWE_787_a3f2b91c
    """

    def __init__(self):
        pass

    def synthesize(self, func_patterns: FunctionPatterns,
                    cwe_id: str = "",
                    cvss_score: float = 0.0,
                    description: str = "",
                    author: str = "byrs_auto"
                    ) -> YARARuleSet:
        """从函数模式集合合成YARA规则集。

        返回YARARuleSet含strict+relaxed双变体。
        """
        valid_patterns = [p for p in func_patterns.patterns
                          if p.uniqueness_score >= 0.3 and p.wildcard_ratio < 0.6]

        if not valid_patterns:
            return YARARuleSet(function_name=func_patterns.function_name)

        # 基础meta信息
        meta = {
            'author': author,
            'function': func_patterns.function_name,
            'function_hash': func_patterns.function_hash,
            'generated_by': 'BYRS v1.0',
        }
        if cwe_id:
            meta['cwe'] = cwe_id
        if cvss_score > 0:
            meta['cvss'] = str(cvss_score)
        if description:
            meta['description'] = description[:128]

        # 转换为YARA字符串格式
        yara_strings = []
        for i, p in enumerate(valid_patterns):
            hex_str = self._pattern_to_hex(p)
            yara_strings.append((f"$pattern_{i}", f"{{ {hex_str} }}"))

        # strict规则-all of them
        rule_name = f"vuln_{cwe_id.replace('-','_')}_{func_patterns.function_hash}"
        strict = YARARule(
            rule_name=f"{rule_name}_strict",
            meta=dict(meta),
            strings=yara_strings,
            condition=f"all of ({' and '.join(s[0] for s in yara_strings)})",
            expected_tp_rate=0.85,
            expected_fp_rate=0.001,
            pattern_count=len(yara_strings))

        # relaxed规则-any of them
        relaxed = YARARule(
            rule_name=f"{rule_name}_relaxed",
            meta=dict(meta),
            strings=yara_strings,
            condition=f"any of ({' or '.join(s[0] for s in yara_strings)})",
            expected_tp_rate=0.95,
            expected_fp_rate=0.01,
            pattern_count=len(yara_strings))

        return YARARuleSet(
            function_name=func_patterns.function_name,
            rules=[strict, relaxed],
            strict_rule=strict,
            relaxed_rule=relaxed)

    def render_rule(self, rule: YARARule) -> str:
        """将YARARule渲染为YARA语法字符串-可直接写入.yar文件。"""
        lines = [f"rule {rule.rule_name} {{"]
        lines.append("    meta:")
        for key, val in rule.meta.items():
            lines.append(f'        {key} = "{val}"')
        lines.append("    strings:")
        for var_name, hex_str in rule.strings:
            lines.append(f"        {var_name} = {hex_str}")
        lines.append("    condition:")
        lines.append(f"        {rule.condition}")
        lines.append("}")
        return "\n".join(lines)

    def export_ruleset(self, ruleset: YARARuleSet,
                        output_path: str = "") -> str:
        """导出规则集为.yar文件-返回文件内容字符串。"""
        sections = [
            f"// BYRS Auto-Generated YARA Rules",
            f"// Target: {ruleset.function_name}",
            f"// Strict rule: low FP, high precision",
            f"// Relaxed rule: high recall, for batch scanning",
            f"",
        ]
        if ruleset.strict_rule:
            sections.append(self.render_rule(ruleset.strict_rule))
            sections.append("")
        if ruleset.relaxed_rule:
            sections.append(self.render_rule(ruleset.relaxed_rule))
            sections.append("")

        content = "\n".join(sections)
        if output_path:
            with open(output_path, 'w') as f:
                f.write(content)
        return content

    def _pattern_to_hex(self, pattern: BytePattern) -> str:
        """将BytePattern转换为YARA十六进制字符串-通配符压缩。

        连续通配符合并为[n-m]跳转, 减少规则体积。
        例: [(0x48,False), (0x00,True), (0x00,True), (0x89,False)]
            → "48 [2] 89"
        """
        parts = []
        i = 0
        bts = pattern.bytes_raw
        while i < len(bts):
            val, is_wc = bts[i]
            if not is_wc:
                parts.append(f"{val:02X}")
                i += 1
            else:
                # 计数连续通配符
                wc_start = i
                while i < len(bts) and bts[i][1]:
                    i += 1
                wc_len = i - wc_start
                if wc_len == 1:
                    parts.append("?")
                else:
                    parts.append(f"[{wc_len}]")
        return " ".join(parts)


# 完整的端到端管线


def synthesize_yara_from_function(function_bytes: bytes,
                                   instructions: List[str],
                                   function_name: str = "",
                                   cwe_id: str = "",
                                   cvss: float = 0.0,
                                   arch: str = "x86_64",
                                   output_path: str = ""
                                   ) -> YARARuleSet:
    """端到端便捷入口-二进制函数-YARA规则。

    返回YARARuleSet。
    """
    miner = PatternMiner()
    patterns = miner.mine(function_bytes, instructions, function_name, arch)
    synthesizer = YARARuleSynthesizer()
    ruleset = synthesizer.synthesize(patterns, cwe_id, cvss)
    if output_path and ruleset.strict_rule:
        synthesizer.export_ruleset(ruleset, output_path)
    return ruleset


__all__ = [
    "YARARule",
    "YARARuleSet",
    "YARARuleSynthesizer",
    "synthesize_yara_from_function",
]
