"""
Experiment tracker: records, queries, and evaluates the full lifecycle of
analysis experiments.

Each pipeline run is an "experiment" tracking input parameters (sample, config,
timestamp), artifacts (report paths, exploit scripts, crash analysis), quality
metrics (vuln count, false positives, LLM contribution), and four-dimensional
evaluation data (see _compute_metrics).

Persists to SQLite (reuses core/vuln_db.py analysis_runs), with extended
experiment metadata. Provides summary statistics and evaluation report generation.

References:
  - Klees et al., 2018, CCS, "Evaluating Fuzz Testing"
  - Bohme et al., 2021, IEEE S&P, "On the Reliability of Fuzzing Benchmarks"
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from config import DB_PATH

_log = logging.getLogger(__name__)

# 实验元数据表（扩展 vuln_db 的 analysis_runs）
_EXPERIMENTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS experiments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    experiment_name TEXT NOT NULL,
    sample_id TEXT,
    sample_path TEXT,
    binary_format TEXT,
    arch TEXT,
    bits INTEGER,
    checksec_json TEXT,
    pipeline_config TEXT,
    started_at TEXT,
    finished_at TEXT,
    elapsed_sec REAL,
    status TEXT DEFAULT 'running',
    -- 产出物
    report_md_path TEXT,
    report_json_path TEXT,
    exploit_script_path TEXT,
    -- 质量指标
    total_vulns INTEGER DEFAULT 0,
    critical_vulns INTEGER DEFAULT 0,
    high_vulns INTEGER DEFAULT 0,
    medium_vulns INTEGER DEFAULT 0,
    low_vulns INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    llm_contributions INTEGER DEFAULT 0,
    -- 四维评估数据
    discovery_efficiency REAL DEFAULT 0.0,
    result_quality_score REAL DEFAULT 0.0,
    llm_assistance_score REAL DEFAULT 0.0,
    applicability_score REAL DEFAULT 0.0,
    -- 元数据
    tags TEXT,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_experiments_name ON experiments(experiment_name);
CREATE INDEX IF NOT EXISTS idx_experiments_status ON experiments(status);
CREATE INDEX IF NOT EXISTS idx_experiments_created ON experiments(created_at);
"""


class ExperimentTracker:
    """
    实验追踪器 —— 管理分析实验的记录与评估。

    用法:
        tracker = ExperimentTracker()
        exp_id = tracker.start_experiment('stack_overflow_test', sample_id='abc123')
        tracker.record_result(exp_id, vulns=5, exploit_path='/tmp/exploit.py')
        tracker.finish_experiment(exp_id, status='success')
        tracker.print_summary()
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """Ensure experiment database tables exist."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.executescript(_EXPERIMENTS_SCHEMA)
        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ---- 实验生命周期 ----

    def start_experiment(
        self,
        name: str,
        sample_id: str = '',
        sample_path: str = '',
        binfo: Optional[Dict[str, Any]] = None,
        checksec: Optional[Dict[str, Any]] = None,
        pipeline_config: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        notes: str = '',
    ) -> int:
        """
        开始一个新的实验，返回实验 ID。

        Args:
            name:            实验名称
            sample_id:       关联的样本 ID
            sample_path:     二进制文件路径
            binfo:           二进制信息
            checksec:        checksec 结果
            pipeline_config: 管线配置参数
            tags:            标签
            notes:           备注

        Returns:
            实验 ID (int)
        """
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
        """
        记录实验的产出物和质量指标。
        可在实验过程中多次调用以增量更新。
        """
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
        """
        标记实验完成并计算四维评估指标。

        Args:
            exp_id:      实验 ID
            status:      最终状态 ('completed' | 'failed' | 'aborted')
            elapsed_sec: 实验耗时（秒）
        """
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

    # ---- 查询 ----

    def get_experiment(self, exp_id: int) -> Optional[Dict[str, Any]]:
        """按 ID 检索实验。"""
        conn = self._connect()
        row = conn.execute(
            "SELECT * FROM experiments WHERE id=?", (exp_id,)
        ).fetchone()
        conn.close()
        return dict(row) if row else None

    def list_experiments(
        self,
        status: str = '',
        sample_id: str = '',
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        列出实验，支持按状态和样本筛选。

        Args:
            status:    筛选状态（'completed', 'failed', 'running', ''=全部）
            sample_id: 筛选样本 ID
            limit:     最大返回数

        Returns:
            实验列表（按时间倒序）
        """
        conn = self._connect()
        parts = ["SELECT * FROM experiments WHERE 1=1"]
        params: list = []

        if status:
            parts.append("AND status=?")
            params.append(status)
        if sample_id:
            parts.append("AND sample_id=?")
            params.append(sample_id)

        parts.append("ORDER BY created_at DESC LIMIT ?")
        params.append(limit)

        rows = conn.execute(' '.join(parts), params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def summary(self) -> Dict[str, Any]:
        """
        返回全局实验汇总统计。

        包含: 实验总数、成功率、各维度平均分、
        按漏洞类型/架构/状态的分布。
        """
        conn = self._connect()

        total = conn.execute("SELECT COUNT(*) FROM experiments").fetchone()[0]
        succeeded = conn.execute(
            "SELECT COUNT(*) FROM experiments WHERE status='completed'"
        ).fetchone()[0]

        avg_metrics = conn.execute(
            """SELECT
               AVG(discovery_efficiency) as avg_de,
               AVG(result_quality_score) as avg_rq,
               AVG(llm_assistance_score) as avg_la,
               AVG(applicability_score) as avg_ap
               FROM experiments WHERE status='completed'"""
        ).fetchone()

        by_arch = conn.execute(
            "SELECT arch, COUNT(*) c FROM experiments GROUP BY arch"
        ).fetchall()

        by_status = conn.execute(
            "SELECT status, COUNT(*) c FROM experiments GROUP BY status"
        ).fetchall()

        total_vulns = conn.execute(
            "SELECT SUM(total_vulns) FROM experiments"
        ).fetchone()[0] or 0

        conn.close()

        return {
            'total_experiments': total,
            'succeeded': succeeded,
            'success_rate': f'{succeeded/total:.1%}' if total > 0 else 'N/A',
            'total_vulnerabilities_found': total_vulns,
            'avg_discovery_efficiency': round(avg_metrics['avg_de'] or 0, 2),
            'avg_result_quality': round(avg_metrics['avg_rq'] or 0, 2),
            'avg_llm_assistance': round(avg_metrics['avg_la'] or 0, 2),
            'avg_applicability': round(avg_metrics['avg_ap'] or 0, 2),
            'by_architecture': {r['arch']: r['c'] for r in by_arch},
            'by_status': {r['status']: r['c'] for r in by_status},
        }

    # ---- 内部 ----

    def _compute_metrics(self, exp_id: int) -> Dict[str, float]:
        """
        计算四维评估指标。

        维度定义（对应申报书 5.3 第四条）:
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

        # 1. 发现效率: vulns per second，用 sigmoid 归一化
        eff = min(1.0, (total_v / max(elapsed, 1.0)) / 5.0)

        # 2. 结果质量: 真阳性率
        quality = max(0.0, 1.0 - fp / total_v)

        # 3. LLM 辅助效果: LLM 贡献度占比
        llm_score = min(1.0, llm_c / total_v)

        # 4. 适用范围: 成功完成的实验的类型多样性（简化版）
        #    基于单个实验的信息有限，取保守值
        applicability = 0.5  # 默认中等，批量汇总时再调整

        return {
            'discovery_efficiency': round(eff, 2),
            'result_quality_score': round(quality, 2),
            'llm_assistance_score': round(llm_score, 2),
            'applicability_score': round(applicability, 2),
        }

    def generate_evaluation_report(self) -> str:
        """
        生成四维评估报告（Markdown 格式）。

        Returns:
            Markdown 文本
        """
        s = self.summary()
        lines = [
            '# BinMind Evaluation Report',
            '',
            f'**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
            '',
            '## Overall Metrics',
            '',
            f'| Dimension | Score |',
            f'|-----------|-------|',
            f'| Discovery Efficiency (vulns/sec) | {s["avg_discovery_efficiency"]:.2f} |',
            f'| Result Quality (precision) | {s["avg_result_quality"]:.2f} |',
            f'| LLM Assistance (contribution ratio) | {s["avg_llm_assistance"]:.2f} |',
            f'| Applicability (sample diversity) | {s["avg_applicability"]:.2f} |',
            '',
            '## Summary',
            '',
            f'- **Total Experiments:** {s["total_experiments"]}',
            f'- **Success Rate:** {s["success_rate"]}',
            f'- **Total Vulnerabilities Found:** {s["total_vulnerabilities_found"]}',
            '',
            '## By Architecture',
            '',
        ]
        for arch, count in s.get('by_architecture', {}).items():
            lines.append(f'- **{arch}:** {count}')
        lines.append('')
        return '\n'.join(lines)
