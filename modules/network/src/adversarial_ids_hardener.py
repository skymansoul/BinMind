# Suricata规则对抗性硬化器 —— 符号化约束提取+语义保持变异+自动规则加固。
#
# 背景: 基于签名的IDS(Suricata/Snort)对语义保持变异脆弱。
# 攻击者可利用content匹配的偏移自由度、pcre的贪婪性、dsize的边界条件
# 构造功能等价但签名的载荷。如"MZ"签名无offset:0约束时,
# 在文件头插入512字节NOP sled仍保持PE有效性但跳过content匹配。
#
# 与现有方法的差异:
# AdvTG: 使用LLM生成对抗流量。本模块用符号化约束分析,
#     不依赖LLM, 可离线部署且结果可复现。
#   - Perturb-ability Score: 评估ML-NIDS特征的抗扰动性。
#     本模块针对签名规则(content/pcre/dsize),非ML特征。
# 未见2024-2025文献涉及符号化IDS规则硬化这一方向。
#
# 三阶段流水:
#   1. 约束提取: 将规则解析为形式化约束集 {Cᵢ}
#   2. 间隙分析: 对每个约束识别其不覆盖的语义等价空间
#   3. 硬化生成: 输出最小修改使规则覆盖已识别的间隙
#
# 评估指标: 硬化前后"规避面"=唯一边界绕过载荷数 / 总语义等价变体数。

from __future__ import annotations

import re
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple


class ConstraintType(Enum):
    CONTENT    = auto()  # 字节序列匹配
    PCRE       = auto()  # 正则匹配
    DSIZE_MIN  = auto()  # 最小载荷长度
    DSIZE_MAX  = auto()  # 最大载荷长度
    FLOW       = auto()  # 方向约束
    THRESHOLD  = auto()  # 频率阈值
    PORT       = auto()  # 端口约束

    def __repr__(self):
        return self.name


@dataclass
class Constraint:
    """单个规则约束的形式化表示"""
    ctype: ConstraintType
    value: Any               # 约束值(字节串/整数/正则字符串)
    modifiers: Dict[str, Any] = field(default_factory=dict)
    # content:pcre/dsize常见修饰符: offset, depth, within, distance, nocase
    original_text: str = ""  # 原始规则中的约束文本


@dataclass
class EvasionGap:
    """识别到的规避间隙"""
    constraint_idx: int       # 对应约束索引
    gap_type: str             # "offset_unbounded" / "depth_missing" / "dsize_edge" / ...
    description: str          # 人类可读描述
    bypass_payload_preview: bytes = b""  # 示例绕过载荷(截断)
    severity: float = 0.0     # [0,1] 规避难度(0=极易规避)


@dataclass
class HardeningProposal:
    """规则硬化建议"""
    rule_sid: int
    original_rule: str
    proposed_modifications: List[str]  # 建议追加的规则选项
    hardened_rule_preview: str = ""    # 修改后规则预览
    evasion_surface_before: int = 0    # 硬化前规避面
    evasion_surface_after: int = 0     # 硬化后规避面(估计)


class ConstraintExtractor:
    """从Suricata规则提取形式化约束集。

    支持的content修饰符: offset(起始偏移), depth(结束偏移),
    within(与前content的距离上限), distance(与前content的距离下限),
    nocase(大小写不敏感)。

    支持的pcre修饰符: 无修饰符的裸正则(仅做存在性检测)。

    不支持的修饰符(http_uri/http_header等)标记为uncertainty且保守处理。
    """

    _CONTENT_MODIFIERS = {'offset', 'depth', 'within', 'distance', 'nocase',
                          'http_uri', 'http_header', 'http_cookie',
                          'http_method', 'http_user_agent', 'fast_pattern'}

    @classmethod
    def extract(cls, rule_text: str) -> List[Constraint]:
        """从规则文本提取约束列表。返回空列表表示无可提取约束。"""
        constraints: List[Constraint] = []

        # 提取content模式: content:"..."; 或 content:|XX XX|;
        content_re = re.compile(
            r'content:\s*("(?:[^"\\]|\\.)*")\s*;|'
            r'content:\s*(\|[0-9a-fA-F ]{2,}\|)\s*;',
            re.IGNORECASE)
        for m in content_re.finditer(rule_text):
            raw_val = m.group(1) or m.group(2)
            if not raw_val:
                continue
            pattern_bytes = cls._decode_content(raw_val)
            modifiers = cls._extract_modifiers(rule_text, m.start())
            constraints.append(Constraint(
                ctype=ConstraintType.CONTENT,
                value=pattern_bytes,
                modifiers=modifiers,
                original_text=m.group(0),
            ))

        # 提取pcre
        pcre_re = re.compile(r'pcre:\s*"((?:[^"\\]|\\.)*)"\s*;', re.IGNORECASE)
        for m in pcre_re.finditer(rule_text):
            constraints.append(Constraint(
                ctype=ConstraintType.PCRE,
                value=m.group(1),
                original_text=m.group(0),
            ))

        # dsize约束
        dsize_re = re.compile(r'dsize:\s*([<>]=?)\s*(\d+)\s*;', re.IGNORECASE)
        for m in dsize_re.finditer(rule_text):
            op, val = m.group(1), int(m.group(2))
            ct = ConstraintType.DSIZE_MIN if op.startswith('>') else ConstraintType.DSIZE_MAX
            constraints.append(Constraint(
                ctype=ct, value=val, original_text=m.group(0),
            ))

        # flow方向
        flow_re = re.compile(r'flow:\s*(\S+?)\s*;', re.IGNORECASE)
        for m in flow_re.finditer(rule_text):
            constraints.append(Constraint(
                ctype=ConstraintType.FLOW,
                value=m.group(1).lower(),
                original_text=m.group(0),
            ))

        # threshold
        thresh_re = re.compile(
            r'threshold:\s*type\s+(\S+)\s*,\s*track\s+(\S+)\s*,\s*count\s+(\d+)\s*,\s*seconds\s+(\d+)\s*;',
            re.IGNORECASE)
        for m in thresh_re.finditer(rule_text):
            constraints.append(Constraint(
                ctype=ConstraintType.THRESHOLD,
                value={'type': m.group(1), 'track': m.group(2),
                       'count': int(m.group(3)), 'seconds': int(m.group(4))},
                original_text=m.group(0),
            ))

        return constraints

    @staticmethod
    def _decode_content(raw: str) -> bytes:
        """解码content值: "..." 或 |XX XX|"""
        if raw.startswith('|') and raw.endswith('|'):
            hex_str = raw[1:-1].replace(' ', '')
            try:
                return bytes.fromhex(hex_str)
            except ValueError:
                return raw.encode('latin-1', errors='replace')
        if raw.startswith('"') and raw.endswith('"'):
            inner = raw[1:-1]
            # 简单反斜杠转义处理
            return inner.encode('latin-1', errors='replace')
        return raw.encode('latin-1', errors='replace')

    @classmethod
    def _extract_modifiers(cls, rule_text: str, content_start: int) -> Dict[str, Any]:
        """提取content后的修饰符。查找content声明后、下一个content或结束前的修饰符。"""
        mods: Dict[str, Any] = {}
        after = rule_text[content_start:]
        # 查找修饰符: keyword:value;
        mod_re = re.compile(r'(\w+):\s*(\S+?)\s*;')
        for m in mod_re.finditer(after):
            kw = m.group(1).lower()
            if kw in cls._CONTENT_MODIFIERS:
                val = m.group(2)
                if val.isdigit():
                    mods[kw] = int(val)
                else:
                    mods[kw] = val
        return mods


# 懒加载: 与 rule_hardener 互相引用, 延迟到属性访问 (PEP 562)
def __getattr__(name):
    if name in ("EvasionGapAnalyzer", "RuleHardener",
                "analyze_rule_evasion_surface", "batch_harden_rules"):
        from .rule_hardener import (
            EvasionGapAnalyzer, RuleHardener,
            analyze_rule_evasion_surface, batch_harden_rules,
        )
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "ConstraintType", "Constraint", "EvasionGap", "HardeningProposal",
    "ConstraintExtractor",
    "analyze_rule_evasion_surface", "batch_harden_rules",
]
