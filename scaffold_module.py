#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""模块脚手架生成器 - create_module.py 的全新实现。

原 create_module.py 的远程基线内容为 git 错误文本（75 字节），任何分支、
提交链与 worktree 中均无有效版本，且当前文件按决策保持原样不动。
本文件为独立新实现，按 modules/<name>/ 目录约定生成骨架：

  modules/<name>/__init__.py      — 懒加载导出（与 patching/network 一致）
  modules/<name>/<name>.py        — 主实现占位
  modules/<name>/tests/__init__.py
  modules/<name>/tests/test_<name>.py — unittest 骨架

约束：目标目录已存在时中止；模块名必须是合法 Python 标识符。
"""
import argparse
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
MODULES_DIR = os.path.join(REPO_ROOT, "modules")

_IDENT_RE = re.compile(r"^[a-z][a-z0-9_]*$")

_INIT_TMPL = '''# -*- coding: utf-8 -*-
"""{title} 模块 - 自动生成骨架，待填充实现。"""

__version__ = "0.1.0"

# 按项目约定使用懒加载；实现就绪后在此处登记导出名
__all__ = []
'''

_MAIN_TMPL = '''# -*- coding: utf-8 -*-
"""{title} 主实现占位。

按项目其余模块的约定组织：数据类/枚举在前，检测或分析入口在后，
模块级 logger 与 __all__ 一并补齐。
"""

import logging

logger = logging.getLogger(__name__)

__all__ = []


def placeholder() -> None:
    """占位入口，实现模块功能后替换或删除。"""
    logger.debug("scaffold placeholder for {name}")
'''

_TEST_TMPL = '''# -*- coding: utf-8 -*-
"""{title} 基础骨架测试。"""

import unittest

from modules.{name} import __version__


class TestScaffold(unittest.TestCase):
    def test_version_present(self):
        self.assertTrue(__version__)


if __name__ == "__main__":
    unittest.main()
'''


def fail(msg: str) -> None:
    print("error: %s" % msg, file=sys.stderr)
    sys.exit(1)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="按 modules/<name>/ 约定生成模块骨架")
    parser.add_argument("name", help="模块名（小写标识符，如 'sig_scan'）")
    parser.add_argument("--title", default=None,
                        help="模块中文标题，缺省时用模块名")
    args = parser.parse_args(argv)

    name = args.name.strip()
    if not _IDENT_RE.match(name):
        fail("模块名必须是 ^[a-z][a-z0-9_]*$ 形式的标识符，收到: %r" % name)
    title = args.title or name

    mod_dir = os.path.join(MODULES_DIR, name)
    if os.path.exists(mod_dir):
        fail("目标目录已存在，为避免覆盖中止: %s" % mod_dir)

    files = {
        os.path.join(mod_dir, "__init__.py"):
            _INIT_TMPL.format(title=title),
        os.path.join(mod_dir, "%s.py" % name):
            _MAIN_TMPL.format(title=title, name=name),
        os.path.join(mod_dir, "tests", "__init__.py"):
            "# -*- coding: utf-8 -*-\n",
        os.path.join(mod_dir, "tests", "test_%s.py" % name):
            _TEST_TMPL.format(title=title, name=name),
    }
    for path, content in files.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
    print("created %s (%d files)" % (mod_dir, len(files)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
