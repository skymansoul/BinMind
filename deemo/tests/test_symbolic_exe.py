<<<<<<< HEAD
=======

>>>>>>> d81973a (精简冗余模块)
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestSymbolicExecutor(unittest.TestCase):

    def setUp(self):
        if 'modules.symbolic_exe' in sys.modules:
            del sys.modules['modules.symbolic_exe']
        if 'angr' in sys.modules:
            del sys.modules['angr']
        if 'claripy' in sys.modules:
            del sys.modules['claripy']

    def test_load_project(self):
        mock_angr = MagicMock()
        mock_project = MagicMock()
        mock_arch = MagicMock()
        mock_arch.name = 'AMD64'
        mock_arch.bits = 64
        mock_arch.memory_endness = 'Iend_LE'
        mock_arch.ip_offset = 16
        mock_arch.sp_offset = 7
        mock_project.arch = mock_arch
        mock_project.entry = 0x400000
        mock_angr.Project.return_value = mock_project
        mock_claripy = MagicMock()

        with patch.dict('sys.modules', {'angr': mock_angr, 'claripy': mock_claripy}):
            from modules.symbolic_exe import SymbolicExecutor

            executor = SymbolicExecutor('fake_binary')
<<<<<<< HEAD
            
=======

lass字段完整性$/d
>>>>>>> d81973a (精简冗余模块)
            self.assertTrue(mock_angr.Project.called)

            args, kwargs = mock_angr.Project.call_args
            self.assertEqual(args[0], 'fake_binary')
            self.assertEqual(kwargs.get('auto_load_libs'), False)
            self.assertEqual(kwargs.get('main_opts'), {'base_addr': 0})

    def test_load_project_with_target_arch(self):
        mock_angr = MagicMock()
        mock_project = MagicMock()
        mock_arch = MagicMock()
        mock_arch.name = 'AMD64'
        mock_arch.bits = 64
        mock_arch.memory_endness = 'Iend_LE'
        mock_arch.ip_offset = 16
        mock_arch.sp_offset = 7
        mock_project.arch = mock_arch
        mock_project.entry = 0x400000
        mock_angr.Project.return_value = mock_project
        mock_claripy = MagicMock()

        with patch.dict('sys.modules', {'angr': mock_angr, 'claripy': mock_claripy}):
            from modules.symbolic_exe import SymbolicExecutor

            executor = SymbolicExecutor('fake_binary', target_arch='x86')
<<<<<<< HEAD
            
=======

>>>>>>> d81973a (精简冗余模块)
            self.assertTrue(mock_angr.Project.called)

            args, kwargs = mock_angr.Project.call_args
            self.assertEqual(args[0], 'fake_binary')
            self.assertEqual(kwargs.get('auto_load_libs'), False)

            main_opts = kwargs.get('main_opts', {})
            self.assertEqual(main_opts.get('base_addr'), 0)
            self.assertEqual(main_opts.get('arch'), 'x86')

    def test_load_project_sets_available_flag(self):
        mock_angr = MagicMock()
        mock_project = MagicMock()
        mock_arch = MagicMock()
        mock_arch.name = 'AMD64'
        mock_arch.bits = 64
        mock_arch.memory_endness = 'Iend_LE'
        mock_arch.ip_offset = 16
        mock_arch.sp_offset = 7
        mock_project.arch = mock_arch
        mock_project.entry = 0x400000
        mock_angr.Project.return_value = mock_project
        mock_claripy = MagicMock()

        with patch.dict('sys.modules', {'angr': mock_angr, 'claripy': mock_claripy}):
            from modules.symbolic_exe import SymbolicExecutor

            executor = SymbolicExecutor('fake_binary')

            self.assertIsNotNone(executor.project)
            self.assertTrue(executor.is_available())

    def test_load_project_angr_not_available(self):
        with patch.dict('sys.modules', {'angr': None}):
            from modules.symbolic_exe import SymbolicExecutor

            executor = SymbolicExecutor('fake_binary')

            self.assertIsNone(executor.project)
            self.assertFalse(executor.is_available())

    def test_load_project_fails_gracefully(self):
        mock_angr = MagicMock()
        mock_angr.Project.side_effect = Exception('Load failed')
        mock_claripy = MagicMock()

        with patch.dict('sys.modules', {'angr': mock_angr, 'claripy': mock_claripy}):
            from modules.symbolic_exe import SymbolicExecutor

            executor = SymbolicExecutor('fake_binary')

            self.assertTrue(mock_angr.Project.called)
            self.assertIsNone(executor.project)


<<<<<<< HEAD
=======

>>>>>>> d81973a (精简冗余模块)
if __name__ == '__main__':
    unittest.main()
