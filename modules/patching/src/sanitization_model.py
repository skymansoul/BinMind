# 净化操作识别模型 — 识别输入清洗/验证代码模式

"""Sanitization Model — 二进制级输入净化操作识别。

借鉴 OctopusTaint 的净化检测模块设计：
  不是静态规则列表，而是对汇编指令序列做模式匹配，
  识别常见的输入清洗/验证操作。

净化类别：

1. 长度检查 (length_check):
   cmp len_reg, MAX; ja .error → 限制输入长度

2. 范围钳制 (range_clamp):
   cmp val, MIN; jl .clamp; cmp val, MAX; jg .clamp

3. 字符过滤 (char_filter):
   and char, ~0x20 → 转小写
   cmp char, 'a'; jb .reject; cmp char, 'z'; ja .reject

4. 空值检查 (null_check):
   test ptr, ptr; jz .error

5. 格式验证 (fmt_validation):
   调用 isalnum/isdigit/isprint 等进行字符类别验证

净化强度评分 (0..1):
  1.0 = 输入完全清洗（如长度限制 + 字符过滤）
  0.0 = 无净化（未检测到任何清洗操作）
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

_log = logging.getLogger(__name__)


@dataclass
class SanitizationMatch:
    """单条净化操作匹配结果。"""
    category: str = ""               # length_check | range_clamp | char_filter | null_check | fmt_validation
    instruction: str = ""
    line_index: int = 0
    strength: float = 0.0             # 此操作的净化强度 0..1
    description: str = ""


# 净化模式库

# (正则模式, 类别, 强度, 描述模板)
_SANITIZATION_PATTERNS = [
    # cmp size, MAX; jbe/ja → 长度检查
    (re.compile(r'\bcmp\s+(\w+),?\s*(0x[0-9a-f]+|\d{2,})\b', re.I),
     'length_check', 0.7, "长度比较: 值限制为 ≤%s"),

    # cmp ptr, 0; je → 空指针检查
    (re.compile(r'\btest\s+(\w+),?\s*\1\b', re.I),
     'null_check', 0.8, "空指针检查: test %s,%s"),

    # and char, ~mask → 字符过滤
    (re.compile(r'\band\s+(\w+),?\s*~(0x[0-9a-f]+)\b', re.I),
     'char_filter', 0.6, "字符过滤: 掩码 ~%s"),

    # and char, 0xDF → ASCII 大写化
    (re.compile(r'\band\s+\w+,?\s*0xDF\b', re.I),
     'char_filter', 0.4, "字符规范化: ASCII toupper"),

    # cmp char, 'a'; jb; cmp char, 'z'; ja → 字母范围检查
    (re.compile(r'\bcmp\s+\w+,?\s*0x[46][0-9a-f]\b', re.I),
     'range_clamp', 0.5, "字符范围检查"),

    # call isalnum/isdigit/isprint → 格式验证
    (re.compile(r'\bcall\s+(isalnum|isdigit|isprint|isascii|isalpha|isxdigit)\b', re.I),
     'fmt_validation', 0.75, "字符类别验证: %s"),
]


class SanitizationModel:
    """净化操作检测模型。

    用法:
        model = SanitizationModel()
        matches = model.detect(asm_lines)
        if model.is_sanitization(instruction):
            ...
    """

    def detect(self, asm_lines: List[str]) -> List[SanitizationMatch]:
        """扫描所有净化操作。"""
        matches = []
        for i, line in enumerate(asm_lines):
            stripped = line.strip().lower().replace(',', ' ')
            for pattern, cat, strength, desc_tmpl in _SANITIZATION_PATTERNS:
                m = pattern.search(stripped)
                if m:
                    groups = m.groups()
                    try:
                        desc = desc_tmpl % groups
                    except TypeError:
                        desc = desc_tmpl
                    matches.append(SanitizationMatch(
                        category=cat, instruction=line.strip(),
                        line_index=i, strength=strength, description=desc))
                    break  # 一行匹配第一个模式
        return matches

    def is_sanitization(self, instruction: str) -> bool:
        """快速判断单条指令是否为净化操作。"""
        stripped = instruction.strip().lower().replace(',', ' ')
        for pattern, _, _, _ in _SANITIZATION_PATTERNS:
            if pattern.search(stripped):
                return True
        return False

    def compute_strength(self, matches: List[SanitizationMatch]) -> float:
        """计算一组净化操作的组合强度。

        多维度净化（长度+字符+格式）叠加后 > 0.9。
        单一维度最多 0.8。
        使用互补概率融合: S = 1 - Π(1 - s_i)。
        """
        if not matches:
            return 0.0
        product = 1.0
        for m in matches:
            product *= (1.0 - m.strength)
        return 1.0 - product

    def is_adequate(self, matches: List[SanitizationMatch],
                    sink_risk: float = 0.5) -> bool:
        """判断净化是否足以消除风险。"""
        strength = self.compute_strength(matches)
        # 高风险 sink 需要更高净化强度
        required = 0.3 + sink_risk * 0.5
        return strength >= required
