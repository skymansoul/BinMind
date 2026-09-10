"""
FP 过滤第4阶段: C 源码级证明义务 — 委托到 fp_filter_stages.py.

双向约束传播阶段, 实际逻辑在 fp_filter_stages.stage4_proof_obligations.
文档路径清单引用此文件, 本模块重导出保持路径有效.
"""

from analysis.fp_filter_stages import stage4_proof_obligations

__all__ = ['stage4_proof_obligations']
