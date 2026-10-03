# 测试路径引导：将本模块目录置顶于 sys.path，
# 使测试以顶层 `src.xxx` 形式导入本模块的 src 子包。
# pytest 在 conftest 加载后会重排 sys.path，故在 pytest_configure 阶段再次置顶。

import sys
from pathlib import Path

_MOD = Path(__file__).resolve().parent.parent
_MOD_STR = str(_MOD)


def _ensure_front():
    if _MOD_STR in sys.path:
        sys.path.remove(_MOD_STR)
    sys.path.insert(0, _MOD_STR)


_ensure_front()


def pytest_configure(config):
    _ensure_front()
