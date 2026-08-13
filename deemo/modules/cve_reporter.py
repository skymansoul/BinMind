# 兼容入口：实现迁移至 binary_analysis/cve_reporter，此处聚合重导出。
from modules.binary_analysis.cve_reporter import (
    CVSSSeverity,
    CVEStatus,
    VulnerabilityDetail,
    CVEReporter,
    generate_cve_report,
)

__all__ = [
    'CVSSSeverity',
    'CVEStatus',
    'VulnerabilityDetail',
    'CVEReporter',
    'generate_cve_report',
]
