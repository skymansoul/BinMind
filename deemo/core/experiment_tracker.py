# 实验追踪器入口 — 从experiment_tracker_schema/base/lifecycle/query拆分.
# 原实现已按职责分散到子模块, 此文件通过mixin组合还原API.
# 创建: 2026-05-08 (拆分)

from config import DB_PATH
from .experiment_tracker_schema import _EXPERIMENTS_SCHEMA
from .experiment_tracker_base import _ExperimentDBMixin, default_db_path
from .experiment_tracker_lifecycle import _LifecycleMixin
from .experiment_tracker_query import _QueryMixin


class ExperimentTracker(_ExperimentDBMixin, _LifecycleMixin, _QueryMixin):
    """实验追踪器 —— mixin组合还原全部功能."""
    pass


__all__ = [
    "ExperimentTracker", "default_db_path",
    "_EXPERIMENTS_SCHEMA", "DB_PATH",
]
