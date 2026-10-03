#!/usr/bin/env python3
"""patching CLI 入口 —— 委托至 src/cli.py。"""

import sys
import os as _os

# 脚本直跑场景需把 patching 根目录加入 sys.path 才能定位 src 包
_curdir = _os.path.dirname(_os.path.abspath(__file__))
if _curdir not in sys.path:
    sys.path.insert(0, _curdir)

# python -m patching.main 走包内相对导入；直跑时回退为顶层 src 绝对导入
try:
    from .src.cli import main as _cli_main
except ImportError:
    from src.cli import main as _cli_main


def main():
    return _cli_main()


if __name__ == "__main__":
    sys.exit(main())
