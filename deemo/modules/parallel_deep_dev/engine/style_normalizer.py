"""
创建: 2025-03-03
修改:
  2025-08-01 - 检测器/加权统计/自动修正委托给 style_detectors.py
共识驱动的跨模块代码风格归一化。

与 black/ruff 的固定预设规则不同，本模块从多 worker 产出中自动发现主导风格
（加权众数/中位数），将离群文件归一化到共识。文献中未见同类方案。
"""

from __future__ import annotations

import ast
import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum


class QuoteStyle(Enum):
    SINGLE = "single"
    DOUBLE = "double"
    MIXED = "mixed"

class ImportStyle(Enum):
    GROUPED = "grouped"       # import 集中在文件顶部
    SEPARATE = "separate"     # import 分散在各处
    MIXED = "mixed"

class NamingStyle(Enum):
    SNAKE = "snake_case"
    CAMEL = "camelCase"
    MIXED = "mixed"


@dataclass
class StyleProfile:
    """单个文件的风格画像。"""
    filepath: str
    file_size: int           # 字节数，用于加权投票
    quote_style: str = "unknown"
    import_style: str = "unknown"
    naming_style: str = "unknown"
    docstring_style: str = "none"
    indent_spaces: int = 4
    uses_tabs: bool = False
    trailing_comma: bool = False
    max_line_length: int = 80
    blank_lines_between_funcs: int = 1
    has_shebang: bool = False
    encoding_declared: bool = False


@dataclass
class ConsensusStyle:
    """从所有文件中提取的共识风格画像。"""
    quote_style: str = "double"
    import_style: str = "grouped"
    naming_style: str = "snake_case"
    docstring_style: str = "triple_double"
    indent_spaces: int = 4
    uses_tabs: bool = False
    trailing_comma: float = 0.0      # 使用尾随逗号的文件比例
    median_line_length: int = 88
    blank_lines_between_funcs: int = 1
    total_files_analyzed: int = 0
    # 每个分类特征的文件分布
    distributions: dict = field(default_factory=dict)


@dataclass
class StyleDeviation:
    """单个文件与共识的偏差报告。"""
    filepath: str
    deviation_score: float       # 0.0-1.0
    mismatches: list[str]        # 不匹配的特征列表
    consensus_values: dict       # 共识值（供修正参考）


class StyleNormalizer:
    """共识驱动的代码风格归一化器。

    典型用法：
      norm = StyleNormalizer()
      profiles = norm.extract_profiles(file_list)
      consensus = norm.compute_consensus(profiles)
      deviations = norm.find_deviations(profiles, consensus)
      fixed = norm.auto_correct(deviations, dry_run=True)
    """

    def __init__(self, deviation_threshold: float = 0.3):
        self.deviation_threshold = deviation_threshold

    # 阶段 1: 风格提取

    def extract_profiles(self, filepaths: list[str]) -> list[StyleProfile]:
        """从文件列表中提取风格画像。非 Python 文件自动跳过。"""
        profiles: list[StyleProfile] = []
        for fpath in filepaths:
            if not fpath.endswith(".py"):
                continue
            profile = self._profile_file(fpath)
            if profile is not None:
                profiles.append(profile)
        return profiles

    def _profile_file(self, filepath: str) -> StyleProfile | None:
        try:
            file_size = os.path.getsize(filepath)
        except OSError:
            return None
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except OSError:
            return None
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return None

        profile = StyleProfile(filepath=filepath, file_size=file_size)
        profile.quote_style = detect_quote_style(source)
        profile.import_style = detect_import_style(tree, source)
        profile.naming_style = detect_naming_style(tree)
        profile.docstring_style = detect_docstring_style(tree, source)
        profile.indent_spaces = detect_indent(source)
        profile.uses_tabs = "\t" in source[:5000]
        profile.trailing_comma = has_trailing_commas(source)
        profile.max_line_length = max_line_len(source)
        profile.blank_lines_between_funcs = blank_lines_between_funcs(source)
        profile.has_shebang = source.startswith("#!")
        profile.encoding_declared = "coding" in source[:200].lower()

        return profile

    # 阶段 2: 共识计算

    def compute_consensus(self, profiles: list[StyleProfile]) -> ConsensusStyle:
        """从风格画像列表计算共识风格。

        分类特征：加权众数（文件大小加权——大文件投票权更高）。
        连续特征：加权中位数。"""
        if not profiles:
            return ConsensusStyle()

        total_size = sum(p.file_size for p in profiles)
        weights = [p.file_size / total_size for p in profiles] if total_size > 0 else None

        cs = ConsensusStyle(total_files_analyzed=len(profiles))

        # 分类特征：加权计数
        cs.quote_style = weighted_mode(
            [p.quote_style for p in profiles], weights, "double",
        )
        cs.import_style = weighted_mode(
            [p.import_style for p in profiles], weights, "grouped",
        )
        cs.naming_style = weighted_mode(
            [p.naming_style for p in profiles], weights, "snake_case",
        )
        cs.docstring_style = weighted_mode(
            [p.docstring_style for p in profiles], weights, "triple_double",
        )

        # 连续特征：加权中位数
        cs.indent_spaces = weighted_median(
            [p.indent_spaces for p in profiles], weights, 4,
        )
        cs.median_line_length = weighted_median(
            [p.max_line_length for p in profiles], weights, 88,
        )
        cs.blank_lines_between_funcs = weighted_median(
            [p.blank_lines_between_funcs for p in profiles], weights, 1,
        )
        cs.uses_tabs = weighted_mode_bool(
            [p.uses_tabs for p in profiles], weights,
        )
        cs.trailing_comma = (
            sum(1 for p in profiles if p.trailing_comma) / len(profiles)
        )

        # 分布记录
        cs.distributions = {
            "quote_style": dict(Counter(p.quote_style for p in profiles)),
            "import_style": dict(Counter(p.import_style for p in profiles)),
            "naming_style": dict(Counter(p.naming_style for p in profiles)),
            "docstring_style": dict(Counter(p.docstring_style for p in profiles)),
        }

        return cs

    # 阶段 3: 偏差检测

    def find_deviations(
        self,
        profiles: list[StyleProfile],
        consensus: ConsensusStyle,
    ) -> list[StyleDeviation]:
        """找出与共识风格偏差较大的文件。"""
        deviations: list[StyleDeviation] = []
        for p in profiles:
            mismatches: list[str] = []
            if p.quote_style != consensus.quote_style and p.quote_style != "unknown":
                mismatches.append(f"引号: {p.quote_style} → {consensus.quote_style}")
            if p.import_style != consensus.import_style and p.import_style != "unknown":
                mismatches.append(f"import: {p.import_style} → {consensus.import_style}")
            if p.naming_style != consensus.naming_style and p.naming_style != "unknown":
                mismatches.append(f"命名: {p.naming_style} → {consensus.naming_style}")
            if p.docstring_style != consensus.docstring_style:
                mismatches.append(f"文档字符串: {p.docstring_style} → {consensus.docstring_style}")
            if abs(p.indent_spaces - consensus.indent_spaces) >= 2:
                mismatches.append(f"缩进: {p.indent_spaces} → {consensus.indent_spaces}")
            if p.uses_tabs != consensus.uses_tabs:
                mismatches.append(f"缩进类型: {'tabs' if p.uses_tabs else 'spaces'}")

            # 偏差分数 = 不匹配特征数 / 总特征数
            total_features = 8
            score = len(mismatches) / total_features

            if score >= self.deviation_threshold:
                deviations.append(StyleDeviation(
                    filepath=p.filepath,
                    deviation_score=round(score, 3),
                    mismatches=mismatches,
                    consensus_values={
                        "quote_style": consensus.quote_style,
                        "import_style": consensus.import_style,
                        "indent_spaces": consensus.indent_spaces,
                        "uses_tabs": consensus.uses_tabs,
                    },
                ))
        return sorted(deviations, key=lambda d: d.deviation_score, reverse=True)

    # 阶段 4: 自动修正

    def auto_correct(
        self,
        deviations: list[StyleDeviation],
        dry_run: bool = True,
    ) -> list[str]:
        """对离群文件执行保守的自动风格修正。

        保守模式：仅修正无歧义的特征（引号统一、缩进类型），
        不修改可能改变语义的特征（如 import 组织）。

        返回实际修改的文件路径列表。"""
        modified: list[str] = []

        for dev in deviations:
            try:
                with open(dev.filepath, "r", encoding="utf-8", errors="replace") as f:
                    source = f.read()
            except OSError:
                continue

            new_source = source

            # 引号风格归一化——仅处理新写入的字符串
            target_quote = dev.consensus_values.get("quote_style", "double")
            new_source = normalize_quotes(new_source, target_quote)

            # Tab → Spaces 转换
            if dev.consensus_values.get("uses_tabs") is False:
                spaces = dev.consensus_values.get("indent_spaces", 4)
                new_source = tabs_to_spaces(new_source, spaces)

            if new_source != source and not dry_run:
                try:
                    with open(dev.filepath, "w", encoding="utf-8") as f:
                        f.write(new_source)
                    modified.append(dev.filepath)
                except OSError:
                    pass
            elif new_source != source:
                modified.append(dev.filepath)

        return modified


# 风格检测委托给 engine/style_detectors.py
from parallel_deep_dev.engine.style_detectors import (
    detect_quote_style, detect_import_style, detect_naming_style,
    detect_docstring_style, detect_indent, has_trailing_commas,
    max_line_len, blank_lines_between_funcs,
    normalize_quotes, tabs_to_spaces,
    weighted_mode, weighted_median, weighted_mode_bool,
)


# 加权统计 + 自动修正委托给 engine/style_detectors.py
