
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestStaticDataFlowAnalyzer(unittest.TestCase):

    def setUp(self):
        # 全量运行中先前的测试可能已按子目录路径导入该模块并绑定真实 angr；
        # 同时清理子目录键，保证本测试的 fresh import 命中 sys.modules 补丁
        for mod in ['modules.static_analysis',
                    'modules.analysis.static.static_analysis',
                    'angr', 'angr.analyses',
                    'angr.knowledge_plugins', 'angr.knowledge_plugins.functions']:
            if mod in sys.modules:
                del sys.modules[mod]

    def _create_angr_mocks(self):
        mock_angr = MagicMock()
        mock_analyses = MagicMock()
        mock_angr.analyses = mock_analyses
        mock_knowledge_plugins = MagicMock()
        mock_angr.knowledge_plugins = mock_knowledge_plugins
        mock_project = MagicMock()
        mock_project.analyses.CFGFast.return_value = MagicMock(functions={})
        mock_angr.Project.return_value = mock_project
        return mock_angr, mock_analyses, mock_knowledge_plugins, mock_project

    def test_load_binary(self):
        mock_angr, mock_analyses, mock_kp, mock_project = self._create_angr_mocks()

        with patch('os.path.exists', return_value=True):
            with patch.dict('sys.modules', {
                'angr': mock_angr,
                'angr.analyses': mock_analyses,
                'angr.knowledge_plugins': mock_kp,
                'angr.knowledge_plugins.functions': MagicMock()
            }):
                from modules.analysis.static.static_analysis import StaticDataFlowAnalyzer

                analyzer = StaticDataFlowAnalyzer('fake_binary', use_angr=True)

                call_args = mock_angr.Project.call_args
                self.assertIsNotNone(call_args)
                args, kwargs = call_args
                self.assertEqual(args[0], 'fake_binary')
                self.assertEqual(kwargs.get('auto_load_libs'), False)

    def test_load_binary_file_not_exists(self):
        mock_angr, mock_analyses, mock_kp, mock_project = self._create_angr_mocks()

        with patch('os.path.exists', return_value=False):
            with patch.dict('sys.modules', {
                'angr': mock_angr,
                'angr.analyses': mock_analyses,
                'angr.knowledge_plugins': mock_kp,
                'angr.knowledge_plugins.functions': MagicMock()
            }):
                from modules.analysis.static.static_analysis import StaticDataFlowAnalyzer

                analyzer = StaticDataFlowAnalyzer('nonexistent_file', use_angr=True)

                self.assertFalse(mock_angr.Project.called)
                self.assertFalse(analyzer.use_angr)
                self.assertIsNone(analyzer.project)

    def test_load_binary_sets_project(self):
        mock_angr, mock_analyses, mock_kp, mock_project = self._create_angr_mocks()

        with patch('os.path.exists', return_value=True):
            with patch.dict('sys.modules', {
                'angr': mock_angr,
                'angr.analyses': mock_analyses,
                'angr.knowledge_plugins': mock_kp,
                'angr.knowledge_plugins.functions': MagicMock()
            }):
                from modules.analysis.static.static_analysis import StaticDataFlowAnalyzer

                analyzer = StaticDataFlowAnalyzer('fake_binary', use_angr=True)

                self.assertIsNotNone(analyzer.project)
                self.assertTrue(analyzer.use_angr)

    def test_load_binary_angr_not_available(self):
        with patch('os.path.exists', return_value=True):
            with patch.dict('sys.modules', {'angr': None}):
                from modules.analysis.static.static_analysis import StaticDataFlowAnalyzer

                analyzer = StaticDataFlowAnalyzer('fake_binary', use_angr=True)

                self.assertFalse(analyzer.use_angr)
                self.assertIsNone(analyzer.project)

    def test_default_taint_sources_configured(self):
        mock_angr, mock_analyses, mock_kp, mock_project = self._create_angr_mocks()

        with patch('os.path.exists', return_value=False):
            with patch.dict('sys.modules', {
                'angr': mock_angr,
                'angr.analyses': mock_analyses,
                'angr.knowledge_plugins': mock_kp,
                'angr.knowledge_plugins.functions': MagicMock()
            }):
                from modules.analysis.static.static_analysis import StaticDataFlowAnalyzer

                analyzer = StaticDataFlowAnalyzer('fake_binary', use_angr=True)

                self.assertGreater(len(analyzer.taint_sources), 0)
                self.assertGreater(len(analyzer.taint_sinks), 0)

                source_names = [s.name for s in analyzer.taint_sources]
                self.assertIn('read', source_names)
                self.assertIn('recv', source_names)

                sink_names = [s.name for s in analyzer.taint_sinks]
                self.assertIn('system', sink_names)
                self.assertIn('printf', sink_names)



if __name__ == '__main__':
    unittest.main()
