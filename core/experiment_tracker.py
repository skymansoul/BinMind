# 实验追踪器入口 — 原实现已按职责拆分到 schema/base/lifecycle/query 子模块,
# 此文件通过 mixin 组合还原完整 API。

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
