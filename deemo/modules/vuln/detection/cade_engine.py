# coding: utf-8
# 创建: 2026-04-16  |  CADE编排引擎
# 修改: 2026-04-16  |  审计后补充文件头与错误处理
#
"""
代码库自适应偏差引擎——编排器与未知漏洞发现。

管线流程:
  1. 输入: 二进制反汇编(函数列表+基本块+指令)
  2. 画像: 构建每函数的FunctionProfile(统计特征向量)
  3. 常态模型: NormModelBuilder→代码库自适应的统计基线
  4. 异常评分: AnomalyScorer→每函数的多维偏差评分
  5. 排序: 按异常评分降序→Top-K最异常函数
  6. 关联: 与已知漏洞检测结果交叉验证→区分已知/未知异常

  已知异常: 评分高+已知检测器也标记→已知漏洞模式(高置信)
  未知异常: 评分高+已知检测器未标记→潜在未知漏洞(需人工审查)

输出:
  Top-K异常函数列表(含异常分数+每特征偏差+已知检测器交叉标记)

与现有检测器的根本差异:
  - 基于规则/ML的检测器: 寻找"像X的东西"(已知模式)
  - CADE: 寻找"不像其他东西的东西"(代码库内偏差)
  - 后者可以捕获前者永远无法捕获的未知漏洞类型

使用场景:
  固件安全审计: 无CVE数据库可参考的专有RTOS/嵌入式系统
  定制协议解析器: 无已知漏洞模式的私有二进制协议
  老旧代码库: 历史积累的非典型函数→可能是遗留漏洞
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .cade_norm_model import (
    FunctionProfile, CodebaseNorm,
    NormModelBuilder, AnomalyScorer,
)

_log = logging.getLogger(__name__)


@dataclass
class AnomalyFinding:
    """单条异常发现"""
    function_name: str
    address: int
    anomaly_score: float
    per_feature_scores: Dict[str, float] = field(default_factory=dict)
    # 交叉标记
    known_detector_flagged: bool = False  # 已知检测器是否也标记
    flagged_by: List[str] = field(default_factory=list)
    # 分类
    anomaly_type: str = "unknown"  # known_pattern | structural_outlier | unknown
    # 审查建议
    review_priority: str = "LOW"   # HIGH | MEDIUM | LOW


@dataclass
class CadeReport:
    """CADE完整报告——代码库异常函数全景"""
    binary_name: str
    total_functions: int
    norm_model: Optional[CodebaseNorm] = None
    findings: List[AnomalyFinding] = field(default_factory=list)
    # 统计
    anomaly_count: int = 0         # 超出阈值的函数数
    known_anomalies: int = 0       # 已知检测器也标记的
    unknown_anomalies: int = 0     # 仅CADE标记的(潜在未知漏洞)
    # 推荐
    top_unknown_review: List[str] = field(default_factory=list)


# CADE引擎


class CadeEngine:
    """代码库自适应偏差引擎。

    使用示例:
        engine = CadeEngine(mad_multiplier=3.0)
        report = engine.analyze(function_profiles, known_findings=[...])
    """

    def __init__(self, mad_multiplier: float = 3.0,
                  anomaly_threshold: float = 0.5):
        self._mad_mult = mad_multiplier
        self._threshold = anomaly_threshold
        self._builder = NormModelBuilder()
        self._scorer = AnomalyScorer()

    def analyze(self, profiles: List[FunctionProfile],
                 known_findings: Dict[str, List[str]] = None,
                 binary_name: str = ""
                 ) -> CadeReport:
        """分析代码库的函数异常。

        参数:
          profiles: 函数画像列表
          known_findings: {函数名: [检测器名称]}——其他检测器的输出
          binary_name: 二进制名称

        返回CadeReport。
        """
        if not profiles:
            return CadeReport(binary_name=binary_name, total_functions=0)

        known = known_findings or {}

        # 构建常态模型
        norm = self._builder.build(profiles, self._mad_mult)

        # 评分
        findings = []
        for p in profiles:
            score, per_feat = self._scorer.score(p, norm)
            if score < self._threshold * 0.5:  # 低于半阈值→跳过
                continue

            flagged_by = known.get(p.function_name, [])
            is_known = len(flagged_by) > 0

            # 异常分类
            if is_known:
                atype = "known_pattern"
            elif score > self._threshold:
                atype = "unknown"
            else:
                atype = "structural_outlier"

            priority = ("HIGH" if atype == "unknown" and score > self._threshold
                        else "MEDIUM" if score > self._threshold * 0.7
                        else "LOW")

            findings.append(AnomalyFinding(
                function_name=p.function_name, address=p.address,
                anomaly_score=score, per_feature_scores=per_feat,
                known_detector_flagged=is_known, flagged_by=flagged_by,
                anomaly_type=atype, review_priority=priority))

        # 排序
        findings.sort(key=lambda f: f.anomaly_score, reverse=True)

        # 统计
        anomaly_count = sum(1 for f in findings
                            if f.anomaly_score >= self._threshold)
        known_anomalies = sum(1 for f in findings
                              if f.known_detector_flagged
                              and f.anomaly_score >= self._threshold)
        unknown_anomalies = anomaly_count - known_anomalies

        # 未知异常Top-5
        unknown = [f for f in findings
                   if f.anomaly_type == "unknown"][:5]
        top_review = [f"{uf.function_name}(score={uf.anomaly_score:.3f})"
                      for uf in unknown]

        return CadeReport(
            binary_name=binary_name,
            total_functions=len(profiles),
            norm_model=norm,
            findings=findings,
            anomaly_count=anomaly_count,
            known_anomalies=known_anomalies,
            unknown_anomalies=unknown_anomalies,
            top_unknown_review=top_review)

    def quick_scan(self, profiles: List[FunctionProfile],
                    top_k: int = 10) -> List[AnomalyFinding]:
        """快速扫描——仅返回Top-K异常函数(跳过完整报告)"""
        report = self.analyze(profiles)
        return report.findings[:top_k]


# 便捷入口


def scan_for_anomalies(profiles: List[FunctionProfile],
                        known: Dict[str, List[str]] = None,
                        top_k: int = 10
                        ) -> List[AnomalyFinding]:
    """代码库异常扫描便捷入口"""
    return CadeEngine().quick_scan(profiles, top_k=top_k)


def profile_from_graph(func_name: str, func_addr: int,
                        bb_count: int, insn_count: int,
                        complexity: int, in_deg: int, out_deg: int,
                        arith_r: float = 0.3, branch_r: float = 0.2,
                        mem_r: float = 0.3, call_r: float = 0.1,
                        dangerous: bool = False,
                        ptr_arith: bool = False,
                        inline_asm: bool = False) -> FunctionProfile:
    """从GraphBinaryEmbedder的图统计创建FunctionProfile"""
    return FunctionProfile(
        function_name=func_name, address=func_addr,
        instruction_count=insn_count, basic_block_count=bb_count,
        cyclomatic_complexity=complexity,
        in_degree=in_deg, out_degree=out_deg,
        arithmetic_ratio=arith_r, branch_ratio=branch_r,
        memory_ratio=mem_r, call_ratio=call_r,
        uses_dangerous_api=dangerous,
        has_pointer_arithmetic=ptr_arith,
        uses_inline_assembly=inline_asm)


__all__ = [
    "AnomalyFinding",
    "CadeReport",
    "CadeEngine",
    "scan_for_anomalies",
    "profile_from_graph",
]
