# 测试路径引导：将 modules/ 置顶于 sys.path，
# 使测试以顶层 `analysis.static.<sub>` 形式导入本模块。
# pytest 在 conftest 加载后会重排 sys.path，故在 pytest_configure 阶段再次置顶。

import sys
from pathlib import Path

_MODULES = Path(__file__).resolve().parent.parent.parent.parent.parent
_MODULES_STR = str(_MODULES)


def _ensure_front():
    if _MODULES_STR in sys.path:
        sys.path.remove(_MODULES_STR)
    sys.path.insert(0, _MODULES_STR)


_ensure_front()


def pytest_configure(config):
    _ensure_front()
