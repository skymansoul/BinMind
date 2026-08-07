"""
实验追踪器 —— 生命周期管理：创建、记录产出、完成与四维指标计算。
"""


import json
import logging
import sqlite3
from datetime import datetime
from typing import Any, Dict, Optional

_log = logging.getLogger(__name__)


class _LifecycleMixin:
    """管理实验的开始、结果记录与完成时的指标结算。"""

    db_path: str

    def _connect(self) -> sqlite3.Connection:  # type: ignore[override]
        ...  # 由 _ExperimentDBMixin 提供

    def start_experiment(
        self,
        name: str,
        sample_id: str = '',
        sample_path: str = '',
        binfo: Optional[Dict[str, Any]] = None,
        checksec: Optional[Dict[str, Any]] = None,
        pipeline_config: Optional[Dict[str, Any]] = None,
        tags: Optional[list] = None,
        notes: str = '',
    ) -> int:
        # 写入即创建行，返回自增 ID 供后续 record/finish 引用
        conn = self._connect()
        cur = conn.execute(
            """INSERT INTO experiments
               (experiment_name, sample_id, sample_path, binary_format,
                arch, bits, checksec_json, pipeline_config,
                started_at, status, tags, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?)""",
            (
                name,
                sample_id,
                sample_path,
                binfo.get('format', '') if binfo else '',
                binfo.get('arch', '') if binfo else '',
                binfo.get('bits', 64) if binfo else 64,
                json.dumps(checksec or {}),
                json.dumps(pipeline_config or {}),
                datetime.now().isoformat(),
                json.dumps(tags or []),
                notes,
            ),
        )
        exp_id = cur.lastrowid
        conn.commit()
        conn.close()
        _log.info("Experiment #%d started: %s", exp_id, name)
        return exp_id

    def record_result(
        self,
        exp_id: int,
        total_vulns: int = 0,
        critical_vulns: int = 0,
        high_vulns: int = 0,
        medium_vulns: int = 0,
        low_vulns: int = 0,
        false_positives: int = 0,
        llm_contributions: int = 0,
        report_md_path: str = '',
        report_json_path: str = '',
        exploit_script_path: str = '',
    ) -> None:
        # 空串保留旧值，COALESCE+NULLIF 实现增量更新语义
        conn = self._connect()
        conn.execute(
            """UPDATE experiments SET
               total_vulns=?, critical_vulns=?, high_vulns=?,
               medium_vulns=?, low_vulns=?, false_positives=?,
               llm_contributions=?,
               report_md_path=COALESCE(NULLIF(?, ''), report_md_path),
               report_json_path=COALESCE(NULLIF(?, ''), report_json_path),
               exploit_script_path=COALESCE(NULLIF(?, ''), exploit_script_path)
               WHERE id=?""",
            (
                total_vulns, critical_vulns, high_vulns,
                medium_vulns, low_vulns, false_positives,
                llm_contributions,
                report_md_path, report_json_path, exploit_script_path,
                exp_id,
            ),
        )
        conn.commit()
        conn.close()

    def finish_experiment(
        self,
        exp_id: int,
        status: str = 'completed',
        elapsed_sec: float = 0.0,
    ) -> None:
        # 完成时结算四维指标，指标不可再变
        metrics = self._compute_metrics(exp_id)

        conn = self._connect()
        conn.execute(
            """UPDATE experiments SET
               finished_at=?, status=?, elapsed_sec=?,
               discovery_efficiency=?,
               result_quality_score=?,
               llm_assistance_score=?,
               applicability_score=?
               WHERE id=?""",
            (
                datetime.now().isoformat(),
                status,
                elapsed_sec,
                metrics['discovery_efficiency'],
                metrics['result_quality_score'],
                metrics['llm_assistance_score'],
                metrics['applicability_score'],
                exp_id,
            ),
        )
        conn.commit()
        conn.close()
        _log.info("Experiment #%d finished: %s (%.1fs)", exp_id, status, elapsed_sec)

    def _compute_metrics(self, exp_id: int) -> Dict[str, float]:
        """
        计算四维评估指标。

        维度定义（对应申报书 §5.3 第四条）:
          1. discovery_efficiency:   发现效率 = vulns / elapsed_sec
          2. result_quality_score:   结果质量 = 1 - (false_positives / max(vulns, 1))
          3. llm_assistance_score:   LLM 辅助效果 = llm_contributions / max(vulns, 1)
          4. applicability_score:    适用范围 = 基于架构和漏洞类型多样性

        各维度归一化为 0.0–1.0。
        """
        conn = self._connect()
        row = conn.execute(
            "SELECT * FROM experiments WHERE id=?", (exp_id,)
        ).fetchone()
        conn.close()

        if not row:
            return {
                'discovery_efficiency': 0.0,
                'result_quality_score': 0.0,
                'llm_assistance_score': 0.0,
                'applicability_score': 0.0,
            }

        r = dict(row)
        elapsed = r.get('elapsed_sec', 1.0) or 1.0
        total_v = max(r.get('total_vulns', 0), 1)
        fp = r.get('false_positives', 0)
        llm_c = r.get('llm_contributions', 0)

        # 发现效率: vulns per second，sigmoid 上限归一化
        eff = min(1.0, (total_v / max(elapsed, 1.0)) / 5.0)

        # 结果质量: 真阳性率
        quality = max(0.0, 1.0 - fp / total_v)

        # LLM 辅助效果: 贡献度占比
        llm_score = min(1.0, llm_c / total_v)

        # 适用范围: 单实验信息有限，取保守中值，批量汇总时再调整
        applicability = 0.5

        return {
            'discovery_efficiency': round(eff, 2),
            'result_quality_score': round(quality, 2),
            'llm_assistance_score': round(llm_score, 2),
            'applicability_score': round(applicability, 2),
        }
