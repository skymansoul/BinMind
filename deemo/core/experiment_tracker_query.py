"""
实验追踪器 —— 查询、汇总统计与评估报告生成。
"""


import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional


class _QueryMixin:
    """提供实验检索、全局汇总与 Markdown 评估报告能力。"""

    db_path: str

    def _connect(self) -> sqlite3.Connection:  # type: ignore[override]
        ...  # 由 _ExperimentDBMixin 提供

    # 查询

    def get_experiment(self, exp_id: int) -> Optional[Dict[str, Any]]:
        # 单行检索，缺失返回 None
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
        # 动态拼接 WHERE 条件，避免空参数产生无效过滤
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
        按架构/状态的分布。
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

    def generate_evaluation_report(self) -> str:
        # 汇总数据驱动 Markdown 生成，不依赖单实验状态
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
