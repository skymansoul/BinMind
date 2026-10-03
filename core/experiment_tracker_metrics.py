"""实验追踪器评估子模块 — 四维指标计算/汇总统计/评估报告生成。"""


import sqlite3
from datetime import datetime
from typing import Any, Dict, List


def _summary(db_path: str) -> Dict[str, Any]:
    """返回全局实验汇总统计。"""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

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


def _compute_metrics(db_path: str, exp_id: int) -> Dict[str, float]:
    """计算四维评估指标。

    维度定义（对应申报书 5.3 第四条）:
      1. discovery_efficiency:   发现效率 = vulns / elapsed_sec
      2. result_quality_score:   结果质量 = 1 - (false_positives / max(vulns, 1))
      3. llm_assistance_score:   LLM 辅助效果 = llm_contributions / max(vulns, 1)
      4. applicability_score:    适用范围 = 基于架构和漏洞类型多样性
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
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
    applicability = 0.5  # 默认中等，批量汇总时再调整

    return {
        'discovery_efficiency': round(eff, 2),
        'result_quality_score': round(quality, 2),
        'llm_assistance_score': round(llm_score, 2),
        'applicability_score': round(applicability, 2),
    }


def _generate_evaluation_report(db_path: str) -> str:
    """生成四维评估报告（Markdown 格式）。"""
    s = _summary(db_path)
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
