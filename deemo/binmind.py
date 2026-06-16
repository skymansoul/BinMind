#!/usr/bin/env python3
"""
二进制分析平台主入口
"""

import sys

if __name__ == "__main__":
    from modules.cli import app
    sys.exit(app())
