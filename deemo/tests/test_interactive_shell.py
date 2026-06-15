import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)


class TestInteractiveReversingShell(unittest.TestCase):
    
    def test_do_quit(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("interactive_shell", os.path.join(BASE_DIR, "modules", "interactive_shell.py"))
        interactive_shell = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(interactive_shell)
        
        shell = interactive_shell.InteractiveReversingShell.__new__(interactive_shell.InteractiveReversingShell)
        
        result = shell.do_quit('')
        self.assertTrue(result)
    
    def test_do_exit(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("interactive_shell", os.path.join(BASE_DIR, "modules", "interactive_shell.py"))
        interactive_shell = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(interactive_shell)
        
        shell = interactive_shell.InteractiveReversingShell.__new__(interactive_shell.InteractiveReversingShell)
        
        result = shell.do_exit('')
        self.assertTrue(result)
    
    def test_emptyline(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("interactive_shell", os.path.join(BASE_DIR, "modules", "interactive_shell.py"))
        interactive_shell = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(interactive_shell)
        
        shell = interactive_shell.InteractiveReversingShell.__new__(interactive_shell.InteractiveReversingShell)
        
        result = shell.emptyline()
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()