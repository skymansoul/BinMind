"""
堆写模式验证 benchmark 漏洞样本定义 — 从 heap_write_sample_defs.py 中提取 VULN 样本.

文档路径清单引用此文件作为漏洞样本独立入口,
实际样本数据统一在 heap_write_sample_defs.py 的 SAMPLES_DEF 中管理.
本模块提供 VULN_SAMPLES 子集供直接引用.
"""

from tests.hosv_benchmark.heap_write_sample_defs import SAMPLES_DEF, LABEL_TO_VERDICT

VULN_SAMPLES = [s for s in SAMPLES_DEF if s[3] == 'VULN']
SAFE_SAMPLES = [s for s in SAMPLES_DEF if s[3] == 'SAFE']

__all__ = ['VULN_SAMPLES', 'SAFE_SAMPLES', 'SAMPLES_DEF', 'LABEL_TO_VERDICT']
