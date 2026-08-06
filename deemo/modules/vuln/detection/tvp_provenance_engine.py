# -*- coding: utf-8 -*-
# 创建: 2026-07-31  |  溯源编排引擎
# 修改: 2026-08-04  |  审计后补充文件头与错误处理
#
"""
时态漏洞溯源引擎——编排git追溯、程序切片、贝叶斯推断的完整管线。

管线流程:
  1. 程序切片: 定位漏洞函数代码范围 → 限定blame区域
  2. Git追溯: blame切片区域 → 候选提交 + 因果特征
  3. 因果推断: 贝叶斯模型 → 提交后验概率 → 时间窗口
  4. 多信号融合: BMA聚合git+static+LLM证据
  5. 审计导出: JSON序列化完整溯源轨迹

专利创新点（独立权利要求级别）:
  (a) 程序切片约束下的git blame——降低非相关代码变更的误归因
  (b) 贝叶斯结构因果模型——概率性溯源替代确定性归因
  (c) 后门准则混淆因子调整——校正团队协作偏差
  (d) 多源信号BMA融合——综合历史+静态+语义的证据强度
"""

import os
import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timezone

from .tvp_causal_types import ProvenanceHypothesis
from .tvp_bayesian_engine import (
    TemporalProvenanceEstimator,
    VulnerabilityCausalModel,
    aggregate_provenance_signals,
)
from .tvp_git_tracer import CommitFeatureExtractor, RepositoryTemporalAnalyzer
from .tvp_slicer import HeuristicSlicer, SliceRegion

_log = logging.getLogger(__name__)


@dataclass
class ProvenanceReport:
    """溯源报告——完整管线的序列化输出"""
    vulnerability_id: str
    function_name: str
    file_path: str
    cve_id: str
    estimated_intro_date: str
    credible_interval_dates: Tuple[str, str]
    ranked_commits: List[Dict[str, Any]] = field(default_factory=list)
    total_candidates: int = 0
    model_evidence: float = 0.0
    confidence: str = "LOW"
    aggregated_signals: Dict[str, float] = field(default_factory=dict)
    pipeline_steps: List[str] = field(default_factory=list)


def _parse_date(date_str: str) -> float:
    """ISO 8601日期→Unix时间戳"""
    if not date_str:
        return datetime.now(timezone.utc).timestamp()
    for fmt in ('%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M:%SZ'):
        try:
            dt = datetime.strptime(date_str.replace('Z', '+0000'), fmt)
            return dt.replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return datetime.now(timezone.utc).timestamp()


def _ts_to_date(ts: float) -> str:
    """Unix时间戳→ISO日期"""
    if ts <= 0:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d')


class TemporalProvenanceEngine:
    """时态漏洞溯源引擎——完整管线编排。

    使用示例:
        engine = TemporalProvenanceEngine('/path/to/repo')
        report = engine.trace('parse_packet', 'src/parser.c',
                              cve_id='CVE-2024-12345', vuln_report_date='2024-06-15')
    """

    def __init__(self, repo_path: str, time_decay_days: float = 90.0):
        if not os.path.isdir(repo_path):
            raise ValueError(f"仓库路径不存在: {repo_path}")
        self._repo = repo_path
        self._extractor = CommitFeatureExtractor(repo_path)
        self._repo_analyzer = RepositoryTemporalAnalyzer(repo_path)
        self._slicer = HeuristicSlicer()
        self._estimator = TemporalProvenanceEstimator(time_decay_days)
        self._causal_model = VulnerabilityCausalModel()

    def trace(self, function_name: str, file_path: str,
              cve_id: str = "", vuln_report_date: str = "",
              static_hints: Dict[str, float] = None,
              llm_signals: Dict[str, float] = None,
              confounders: Dict[str, float] = None) -> ProvenanceReport:
        """执行完整溯源管线——单漏洞。

        参数:
          function_name: 漏洞函数名
          file_path: 相对仓库根的文件路径
          cve_id: CVE编号（可选）
          vuln_report_date: 漏洞报告日期（ISO 8601）
          static_hints: {commit_hash: score} 外部静态分析信号
          llm_signals: {commit_hash: score} LLM语义信号
          confounders: 混淆因子值（团队压力指数等）

        返回ProvenanceReport。
        """
        steps = []
        full_path = os.path.join(self._repo, file_path)

        # Step 1: 程序切片
        steps.append("程序切片")
        region = self._slicer.locate_function(full_path, function_name)
        if region is None:
            _log.warning("函数%s未定位——回退全文件追溯", function_name)
            region = SliceRegion(file_path=file_path, start_line=1,
                                  end_line=9999, function_name=function_name,
                                  slice_type='fallback', confidence=0.3)

        dangerous = self._slicer.find_dangerous_lines(region)
        if dangerous:
            steps.append(f"危险行: {len(dangerous)}行")

        # Step 2: Git追溯
        steps.append(f"blame: {file_path}:{region.start_line}-{region.end_line}")
        hypotheses = self._extractor.extract_commits_for_lines(
            file_path, region.start_line, region.end_line)

        if not hypotheses:
            return ProvenanceReport(
                vulnerability_id=f"{function_name}@{file_path}",
                function_name=function_name, file_path=file_path,
                cve_id=cve_id, estimated_intro_date="",
                credible_interval_dates=("", ""),
                pipeline_steps=steps + ["无候选提交——中止"])

        steps.append(f"候选提交: {len(hypotheses)}")

        # Step 3: 注入仓库级特征
        file_age = self._repo_analyzer.get_file_age_days(file_path)
        freq = self._repo_analyzer.get_commit_freq_weekly(file_path)
        sec_sensitive = self._repo_analyzer.is_security_sensitive(file_path)

        eff_conf = dict(confounders or {})
        eff_conf.setdefault('file_age_days', file_age)
        eff_conf.setdefault('commit_frequency', freq)
        eff_conf.setdefault('security_sensitive', 1.0 if sec_sensitive else 0.0)

        # Step 4: 贝叶斯推断
        steps.append("贝叶斯因果推断")
        report_ts = _parse_date(vuln_report_date)
        result = self._estimator.estimate(hypotheses, report_ts, confounders=eff_conf)

        # Step 5: 多信号BMA融合
        ranked = []
        agg = {}
        if static_hints or llm_signals:
            steps.append("多信号BMA聚合")
            agg = aggregate_provenance_signals(result.hypotheses, static_hints, llm_signals)
            for h in result.hypotheses:
                h.posterior_prob = (0.7 * h.posterior_prob +
                                     0.3 * agg.get(h.commit_hash, h.posterior_prob))
            total = sum(h.posterior_prob for h in result.hypotheses)
            for h in result.hypotheses:
                h.posterior_prob /= max(total, 1e-10)
            result.hypotheses.sort(key=lambda h: h.posterior_prob, reverse=True)

        for rank, h in enumerate(result.hypotheses[:20]):
            ranked.append({
                'rank': rank + 1,
                'commit': h.commit_hash[:12],
                'posterior': round(h.posterior_prob, 4),
                'timestamp': datetime.fromtimestamp(
                    h.commit_timestamp, tz=timezone.utc).isoformat(),
                'causal_path': h.causal_path,
                'churn': round(h.code_churn, 3),
                'expertise': round(h.author_expertise, 3),
                'aggregated': round(agg.get(h.commit_hash, 0.0), 4),
            })

        steps.append(f"完成: 置信度={result.confidence_level}, "
                      f"MAP={result.top_commit[:12]}")

        return ProvenanceReport(
            vulnerability_id=f"{function_name}@{file_path}",
            function_name=function_name, file_path=file_path,
            cve_id=cve_id,
            estimated_intro_date=_ts_to_date(result.estimated_intro_time),
            credible_interval_dates=(_ts_to_date(result.time_credible_interval[0]),
                                      _ts_to_date(result.time_credible_interval[1])),
            ranked_commits=ranked,
            total_candidates=len(result.hypotheses),
            model_evidence=round(result.model_evidence, 4),
            confidence=result.confidence_level,
            aggregated_signals=agg,
            pipeline_steps=steps)

    def batch_trace(self, vulns: List[Dict[str, str]],
                     report_date: str = "") -> List[ProvenanceReport]:
        """批量溯源——对多个漏洞依次执行管线"""
        reports = []
        for v in vulns:
            try:
                reports.append(self.trace(
                    function_name=v['function'], file_path=v['file'],
                    cve_id=v.get('cve', ''), vuln_report_date=report_date))
            except Exception as e:
                _log.error("批量溯源失败 [%s]: %s", v.get('function', '?'), e)
        return reports

    def export_audit(self, report: ProvenanceReport) -> Dict:
        """导出审计就绪JSON——含完整溯源轨迹"""
        return {
            'vulnerability': {
                'id': report.vulnerability_id,
                'function': report.function_name,
                'file': report.file_path,
                'cve': report.cve_id,
            },
            'temporal': {
                'estimated_intro': report.estimated_intro_date,
                'credible_interval': list(report.credible_interval_dates),
                'confidence': report.confidence,
                'model_evidence': report.model_evidence,
            },
            'ranked_commits': report.ranked_commits,
            'signals': {k: round(v, 4) for k, v in report.aggregated_signals.items()},
            'audit_trail': report.pipeline_steps,
            'metadata': {
                'repo': os.path.basename(self._repo),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'engine': 'tvp_v1.0.0',
            },
        }

    def get_adjustment_set(self) -> List[str]:
        """返回因果模型的最小充分调整集——供外部审计"""
        return self._causal_model.get_adjustment_set('code_churn', 'vuln_introduction')


def trace_vulnerability_provenance(repo_path: str, function_name: str,
                                    file_path: str, cve_id: str = "",
                                    report_date: str = "") -> ProvenanceReport:
    """漏洞溯源便捷入口——单行调用"""
    return TemporalProvenanceEngine(repo_path).trace(
        function_name=function_name, file_path=file_path,
        cve_id=cve_id, vuln_report_date=report_date)


__all__ = [
    "ProvenanceReport",
    "TemporalProvenanceEngine",
    "trace_vulnerability_provenance",
]
