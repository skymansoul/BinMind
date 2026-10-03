# main.py - 向后兼容入口, 转发至 binmind.py 主 CLI。
# 原实现已删除, 新调用请直接使用 binmind.py。
from binmind import _run as _cli_main

if __name__ == '__main__':
    import sys as _sys
    _sys.exit(_cli_main())
