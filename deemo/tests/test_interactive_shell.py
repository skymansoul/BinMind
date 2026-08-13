# -*- coding: utf-8 -*-

import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestInteractiveReversingShell(unittest.TestCase):

    def test_do_quit(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("interactive_shell", os.path.join(BASE_DIR, "modules", "interactive_shell.py"))
        interactive_shell = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(interactive_shell)

        # 扁平入口 modules/interactive_shell.py 当前经 compat 层导出 v2.1 的
        # InteractiveShell（旧名 InteractiveReversingShell 已随 v2.1 重构改名）。
        shell = interactive_shell.InteractiveShell.__new__(interactive_shell.InteractiveShell)

        result = shell.do_quit('')
        self.assertTrue(result)

    def test_do_exit(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("interactive_shell", os.path.join(BASE_DIR, "modules", "interactive_shell.py"))
        interactive_shell = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(interactive_shell)

        # 扁平入口 modules/interactive_shell.py 当前经 compat 层导出 v2.1 的
        # InteractiveShell（旧名 InteractiveReversingShell 已随 v2.1 重构改名）。
        shell = interactive_shell.InteractiveShell.__new__(interactive_shell.InteractiveShell)

        result = shell.do_exit('')
        self.assertTrue(result)

    def test_emptyline(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("interactive_shell", os.path.join(BASE_DIR, "modules", "interactive_shell.py"))
        interactive_shell = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(interactive_shell)

        # 扁平入口 modules/interactive_shell.py 当前经 compat 层导出 v2.1 的
        # InteractiveShell（旧名 InteractiveReversingShell 已随 v2.1 重构改名）。
        shell = interactive_shell.InteractiveShell.__new__(interactive_shell.InteractiveShell)

        result = shell.emptyline()
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
