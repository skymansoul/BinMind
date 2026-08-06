# [DEPRECATED] — 功能已迁移至 modules/info/analysis/taint_simplifier.py 或 src/taint_simplifier.py
# 若确认无外部引用, 可安全删除
"""简化污点传播路径 — 从 core/detection_shared.py 和 core/taint_tracker.py 组装。"""
from core.detection_shared import TaintSource, TaintSink, TaintPath, is_source, is_sink
from core.taint_tracker import track_taint_intraprocedural, filter_by_taint
