"""
实验追踪器 —— DB 初始化与连接管理。
"""


import os
import sqlite3

from .config import DB_PATH
from .experiment_tracker_schema import _EXPERIMENTS_SCHEMA


class _ExperimentDBMixin:
    """封装 SQLite 连接生命周期，供 ExperimentTracker 组合复用。"""

    db_path: str

    def _init_db(self) -> None:
        # 建表为幂等操作，确保实验库就绪
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.executescript(_EXPERIMENTS_SCHEMA)
        conn.commit()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn


def default_db_path() -> str:
    """暴露默认 DB 路径，供入口文件构造器回退使用。"""
    return DB_PATH
