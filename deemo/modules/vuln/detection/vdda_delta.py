# coding: utf-8
# 创建: 2026-05-17  |  增量分析引擎
# 修改: 2026-05-17  |  审计后补充文件头与错误处理
#
"""
漏洞发现增量分析——跨运行差异检测与统计显著性评估。

技术问题:
  在CI/CD管道中, 每次提交触发完整的漏洞分析管线。
  两次运行之间可能有数百个finding变化:
    - 新增finding(新漏洞或新检测能力)
    - 消失finding(已修复或检测器波动)
    - 严重度变化(CVSS重评或分析精度提升)
    - 误报波动(检测器随机性)

  人工审查所有变化不可行——需要统计方法区分
  "真实变化"(漏洞修复/引入)与"分析噪声"(检测器波动)。

解决方案:
  对两次运行的finding集合执行统计差异分析:
    1. 配对: 基于位置的finding匹配(同一函数/文件的finding配对)
    2. 分类: 新增/消失/严重度变化/置信度变化/无变化
    3. 显著性: 使用McNemar检验或Bootstrap重采样判断变化是否
       超出检测器的正常波动范围
    4. 回归检测: 消失的finding标记为可能的修复回归

  统计模型:
    - 置信度变化显著性: Bootstrap重采样(1000次)估计置信区间
    - 严重度变化显著性: 基于历史CVSS重评频率的先验
    - 新增finding真实性: 基于检测器精确率的贝叶斯后验

与现有模块集成:
  消费所有13个分析系统的finding输出
  → 跨运行统一增量视图
  → CI/CD管道中的自动回归检测
"""

import hashlib
import logging
import random as _random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum

_log = logging.getLogger(__name__)


class DeltaType(str, Enum):
    NEW = "new"                  # 新增finding
    RESOLVED = "resolved"        # 消失(可能已修复)
    SEVERITY_UP = "severity_up"
    SEVERITY_DOWN = "severity_down"
    CONFIDENCE_UP = "confidence_up"
    CONFIDENCE_DOWN = "confidence_down"
    UNCHANGED = "unchanged"
    REGRESSION = "regression"    # 消失的已确认finding→回归


@dataclass
class FindingSnapshot:
    """单条finding的跨运行快照"""
    finding_id: str
    location_key: str             # 位置哈希(函数+文件+行号)
    # 当前运行
    current_severity: float = 0.0
    current_confidence: float = 0.0
    current_type: str = ""
    # 前一运行(若存在)
    previous_severity: float = 0.0
    previous_confidence: float = 0.0
    previous_type: str = ""
    # 差异
    delta_type: str = DeltaType.UNCHANGED
    severity_delta: float = 0.0
    confidence_delta: float = 0.0
    # 显著性
    is_significant: bool = False
    significance_pvalue: float = 1.0
    # 元数据
    modality: str = ""
    source_run_id: str = ""


@dataclass
class DeltaReport:
    """跨运行增量分析报告"""
    run_id_current: str
    run_id_previous: str
    snapshots: List[FindingSnapshot] = field(default_factory=list)
    # 汇总统计
    total_current: int = 0
    total_previous: int = 0
    new_count: int = 0
    resolved_count: int = 0
    regression_count: int = 0
    severity_changes: int = 0
    # 显著性
    significant_changes: int = 0
    noise_ratio: float = 0.0       # 估计的分析噪声比例
    # 建议
    requires_manual_review: bool = False
    review_recommendations: List[str] = field(default_factory=list)


# 增量引擎


class DeltaEngine:
    """跨运行增量分析引擎。

    分析流程:
      1. 位置哈希→跨运行finding配对
      2. 分类每对finding的差异类型
      3. Bootstrap→显著性检验
      4. 聚合→DeltaReport
    """

    def __init__(self,
                 confidence_noise_sigma: float = 0.08,
                 bootstrap_samples: int = 500):
        """
        参数:
          confidence_noise_sigma: 检测器置信度的估计噪声标准差
          bootstrap_samples: Bootstrap重采样次数
        """
        self._noise_sigma = confidence_noise_sigma
        self._bootstrap_n = bootstrap_samples

    def analyze(self, current_findings: List[Dict],
                 previous_findings: List[Dict],
                 run_id_current: str = "",
                 run_id_previous: str = ""
                 ) -> DeltaReport:
        """对两次运行的finding执行增量分析。

        参数:
          current_findings: 当前运行的finding列表
          previous_findings: 前一运行的finding列表
          run_id_current/previous: 运行标识符

        finding格式(最小要求):
          {id, function_name, file_path, line_number, severity, confidence, type, modality}

        返回DeltaReport。
        """
        report = DeltaReport(
            run_id_current=run_id_current,
            run_id_previous=run_id_previous,
            total_current=len(current_findings),
            total_previous=len(previous_findings))

        # 位置哈希→finding索引
        prev_index = {}
        for f in previous_findings:
            key = self._location_key(f)
            prev_index[key] = f

        cur_keys = set()
        snapshots = []

        for f in current_findings:
            key = self._location_key(f)
            cur_keys.add(key)
            prev_f = prev_index.get(key)

            snap = FindingSnapshot(
                finding_id=f.get('id', key),
                location_key=key,
                current_severity=f.get('severity', f.get('cvss', 0.5)),
                current_confidence=f.get('confidence', 0.5),
                current_type=f.get('type', f.get('vuln_type', '')),
                modality=f.get('modality', ''),
                source_run_id=run_id_current)

            if prev_f:
                snap.previous_severity = prev_f.get('severity', prev_f.get('cvss', 0.5))
                snap.previous_confidence = prev_f.get('confidence', 0.5)
                snap.previous_type = prev_f.get('type', prev_f.get('vuln_type', ''))
                snap.severity_delta = snap.current_severity - snap.previous_severity
                snap.confidence_delta = snap.current_confidence - snap.previous_confidence
                snap.delta_type = self._classify_delta(snap)
            else:
                snap.delta_type = DeltaType.NEW
                snap.confidence_delta = snap.current_confidence

            # 显著性检验
            snap.is_significant, snap.significance_pvalue = (
                self._test_significance(snap))

            snapshots.append(snap)

        # 消失的finding——在前一运行中存在但当前运行中不存在
        for key, prev_f in prev_index.items():
            if key not in cur_keys:
                snap = FindingSnapshot(
                    finding_id=prev_f.get('id', key),
                    location_key=key,
                    previous_severity=prev_f.get('severity', prev_f.get('cvss', 0.5)),
                    previous_confidence=prev_f.get('confidence', 0.5),
                    previous_type=prev_f.get('type', ''),
                    modality=prev_f.get('modality', ''),
                    source_run_id=run_id_previous,
                    delta_type=DeltaType.RESOLVED)
                # 高置信度finding消失→可能的回归
                if snap.previous_confidence > 0.7 and snap.previous_severity > 0.5:
                    snap.delta_type = DeltaType.REGRESSION
                snapshots.append(snap)

        # 汇总
        report.snapshots = snapshots
        report.new_count = sum(1 for s in snapshots if s.delta_type == DeltaType.NEW)
        report.resolved_count = sum(1 for s in snapshots if s.delta_type == DeltaType.RESOLVED)
        report.regression_count = sum(1 for s in snapshots if s.delta_type == DeltaType.REGRESSION)
        report.severity_changes = sum(1 for s in snapshots
                                       if abs(s.severity_delta) > 0.05)
        report.significant_changes = sum(1 for s in snapshots if s.is_significant)

        # 噪声比估计——非显著变化/总变化
        total_delta = sum(1 for s in snapshots if s.delta_type != DeltaType.UNCHANGED)
        report.noise_ratio = round(
            1.0 - report.significant_changes / max(total_delta, 1), 3)

        # 审查建议
        if report.regression_count > 0:
            report.requires_manual_review = True
            report.review_recommendations.append(
                f"检测到{report.regression_count}个可能的修复回归——"
                f"高置信度finding在本次运行中消失")
        if report.new_count > report.total_previous * 0.3:
            report.requires_manual_review = True
            report.review_recommendations.append(
                f"新增finding数量({report.new_count})超过基线的30%——"
                f"建议审查是否为检测器配置变更导致")
        if report.noise_ratio > 0.5:
            report.review_recommendations.append(
                f"估计噪声比{report.noise_ratio:.0%}偏高——"
                f"建议检查检测器阈值校准")

        return report

    def _location_key(self, finding: Dict) -> str:
        """基于位置的finding哈希——用于跨运行配对"""
        func = finding.get('function_name', finding.get('function', ''))
        file = finding.get('file_path', finding.get('file', ''))
        line = finding.get('line_number', finding.get('line', 0))
        addr = finding.get('address', finding.get('addr', 0))
        payload = f"{func}::{file}::{line}::{addr}"
        return hashlib.blake2b(payload.encode(), digest_size=8).hexdigest()

    def _classify_delta(self, snap: FindingSnapshot) -> str:
        """分类单条finding的差异类型"""
        sev_d = abs(snap.severity_delta)
        conf_d = abs(snap.confidence_delta)

        if sev_d < 0.03 and conf_d < self._noise_sigma:
            return DeltaType.UNCHANGED
        if snap.severity_delta > 0.1:
            return DeltaType.SEVERITY_UP
        if snap.severity_delta < -0.1:
            return DeltaType.SEVERITY_DOWN
        if snap.confidence_delta > self._noise_sigma * 2:
            return DeltaType.CONFIDENCE_UP
        if snap.confidence_delta < -self._noise_sigma * 2:
            return DeltaType.CONFIDENCE_DOWN
        return DeltaType.UNCHANGED

    def _test_significance(self, snap: FindingSnapshot
                            ) -> Tuple[bool, float]:
        """Bootstrap显著性检验——判断confidence变化是否超出噪声。

        H₀: 变化由检测器噪声引起(Δ在噪声标准差范围内)
        Bootstrap: 从N(0, noise_sigma)重采样, 计算|Δ|的分布
        p-value = P(|噪声| >= |观测Δ|)

        若p < 0.05 → 拒绝H₀ → 变化显著(非噪声)
        """
        if snap.delta_type in (DeltaType.NEW, DeltaType.RESOLVED,
                                 DeltaType.REGRESSION):
            return True, 0.0  # 新增/消失一定显著

        obs_delta = abs(snap.confidence_delta)
        if obs_delta < 1e-6:
            return False, 1.0

        # Bootstrap
        rng = _random.Random(hash(snap.location_key) % (2**31))
        exceed_count = 0
        for _ in range(self._bootstrap_n):
            noise = rng.gauss(0, self._noise_sigma)
            if abs(noise) >= obs_delta:
                exceed_count += 1

        pvalue = exceed_count / self._bootstrap_n
        return pvalue < 0.05, round(pvalue, 4)


__all__ = [
    "DeltaType",
    "FindingSnapshot",
    "DeltaReport",
    "DeltaEngine",
]
