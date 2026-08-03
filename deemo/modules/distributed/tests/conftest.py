# conftest: 确保 distributed 包可被导入
# 兄弟包 platform/ 覆盖了 stdlib 的 'platform'，导致 pytest 在 sessionstart
# 期间调用 platform.python_version() 失败。
# 解决：使用 --override-ini="addopts=" 运行测试并设置 PYTHONDONTWRITEBYTECODE
# 以避免 .pyc 噪音，或使用 --rootdir 标志指向 distributed 包。
#
# 从 modules/ 父目录运行：
#   python -m pytest deemo/modules/distributed/tests/
# 可避免路径污染，因为 sys.path[0] 将为 '' 而非 'modules/'。
#
# 下方的 pytest_configure 钩子将 modules/ 父目录提前加入 sys.path，
# 使相对导入 (from ..src.xxx) 正确解析。
import sys
import os


def pytest_configure(config):
    """将 modules 目录加入导入路径，避免覆盖 stdlib 符号。"""
    modules_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if modules_dir not in sys.path:
        sys.path.insert(0, modules_dir)
