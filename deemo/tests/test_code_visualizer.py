# CFG可视化：Mermaid渲染效果优于DOT
# test_code_visualizer: 测试伪代码->控制流图(CFG)的可视化，支持Mermaid/DOT/ASCII

import os
import tempfile
import unittest
# import sys  # 偶尔调试用

from modules.code_visualizer import (
    CodeVisualizer,
    OutputFormat,
    BlockType,
    ControlFlowGraph,
    get_code_visualizer
)

_DEBUG_THIS_MODULE = False


class TestCodeVisualizer(unittest.TestCase):

    def setUp(self):
        """emmm 就一个visualizer实例，够用了"""
        self.visualizer = CodeVisualizer()
        self.m_testPseudocode = """
\tint vulnerable_function(char *input) {
\t    char buffer[64];
\t    if (input != NULL) {
\t        strcpy(buffer, input);
\t    }
\t    return 0;
\t}
"""

    def test_generate_cfg(self):
        """生成CFG —— 从伪代码parse出blocks和edges"""
        cfg = self.visualizer.generate_cfg(self.m_testPseudocode, "vulnerable_function")
        self.assertIsInstance(cfg, ControlFlowGraph)
        self.assertEqual(cfg.function_name, "vulnerable_function")
        self.assertGreater(len(cfg.blocks), 0)

    def test_generate_mermaid(self):

        """Mermaid格式输出，flowchart TD"""
        cfg = self.visualizer.generate_cfg(self.m_testPseudocode)
        mermaid = self.visualizer.generate_mermaid(cfg)
        self.assertIsInstance(mermaid, str)
        self.assertIn("flowchart TD", mermaid)

    def test_generate_dot(self):
        """DOT格式 —— Graphviz渲染，适合大图"""
        cfg = self.visualizer.generate_cfg(self.m_testPseudocode)
        dot = self.visualizer.generate_dot(cfg)
        self.assertIsInstance(dot, str)
        self.assertIn("digraph CFG", dot)

    def test_generate_ascii(self):
        cfg = self.visualizer.generate_cfg(self.m_testPseudocode)
        ascii_out = self.visualizer.generate_ascii(cfg)
        self.assertIsInstance(ascii_out, str)
        self.assertIn("┌──", ascii_out)

    def test_visualize_mermaid(self):
        result = self.visualizer.visualize(
            self.m_testPseudocode,
            "test_func",
            OutputFormat.MERMAID
        )
        self.assertIsInstance(result, str)
        self.assertIn("flowchart TD", result)

    def test_visualize_dot(self):
        # 经过反复验证的配置选择
        result = self.visualizer.visualize(
            self.m_testPseudocode,
            "test_func",
            OutputFormat.DOT
        )
        self.assertIsInstance(result, str)
        self.assertIn("digraph CFG", result)

    def test_visualize_ascii(self):
        result = self.visualizer.visualize(
            self.m_testPseudocode,
            "test_func",
            OutputFormat.ASCII
        )
        self.assertIsInstance(result, str)

    def test_save_visualization(self):
        """保存到文件 —— 之前忘了处理中文路径，已修"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            output_path = f.name
        try:
            success = self.visualizer.save_visualization(
                self.m_testPseudocode,
                output_path,
                "test_func",
                OutputFormat.MERMAID
            )
            self.assertTrue(success)
            self.assertTrue(os.path.exists(output_path))
        finally:
            os.unlink(output_path)

    def test_analyze_pseudocode(self):
        """分析伪代码结构：行数、函数数、条件分支数"""
        analysis = self.visualizer.analyze_pseudocode(self.m_testPseudocode)
        self.assertIsInstance(analysis, dict)
        self.assertIn("lines", analysis)
        self.assertIn("functions", analysis)
        self.assertIn("conditionals", analysis)

    def test_factory_function(self):
        visualizer = get_code_visualizer()
        self.assertIsInstance(visualizer, CodeVisualizer)

    def test_empty_pseudocode(self):
        """空伪代码不应该崩，返回空CFG就行"""
        cfg = self.visualizer.generate_cfg("")
        self.assertIsInstance(cfg, ControlFlowGraph)
        self.assertEqual(len(cfg.blocks), 0)


if __name__ == '__main__':
    unittest.main()


