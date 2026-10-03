# 样本管理器入口 - 从sample_manager_types/crud/batch/dirs拆分.
# 原实现已按职责分散到子模块, 此文件通过mixin组合还原API.

from .sample_manager_types import (
    DEFAULT_SAMPLE_DB, SAMPLE_DIRS,
    find_binaries, guess_format, infer_vuln_type,
)
from .sample_manager_crud import _CrudMixin
from .sample_manager_batch import _BatchMixin
from .sample_manager_dirs import init_sample_directories


class SampleManager(_CrudMixin, _BatchMixin):
    """样本管理器 - mixin组合还原全部功能。"""

    def __init__(self, db_path: str = DEFAULT_SAMPLE_DB):
        self.db_path = db_path
        self._samples: dict = {}
        self._load()


__all__ = [
    "SampleManager", "init_sample_directories",
    "DEFAULT_SAMPLE_DB", "SAMPLE_DIRS",
    "find_binaries", "guess_format", "infer_vuln_type",
]
