import unittest
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.code_visualizer import (
    CodeVisualizer,
    OutputFormat,
    BlockType,
    ControlFlowGraph,
    get_code_visualizer
)


class TestCodeVisualizer(unittest.TestCase):
    """测试代码可视化器"""

    def setUp(self):
        """设置测试环境"""
        self.visualizer = CodeVisualizer()
        self.test_pseudocode = """
int vulnerable_function(char *input) {
    char buffer[64];
    if (input != NULL) {
        strcpy(buffer, input);
    }
    return 0;
}
"""

    def test_generate_cfg(self):
        """测试生成控制流图"""
        cfg = self.visualizer.generate_cfg(self.test_pseudocode, "vulnerable_function")
        self.assertIsInstance(cfg, ControlFlowGraph)
        self.assertEqual(cfg.function_name, "vulnerable_function")
        self.assertGreater(len(cfg.blocks), 0)

    def test_generate_mermaid(self):
        """测试生成Mermaid格式"""
        cfg = self.visualizer.generate_cfg(self.test_pseudocode)
        mermaid = self.visualizer.generate_mermaid(cfg)
        self.assertIsInstance(mermaid, str)
        self.assertIn("flowchart TD", mermaid)

    def test_generate_dot(self):
        """测试生成DOT格式"""
        cfg = self.visualizer.generate_cfg(self.test_pseudocode)
        dot = self.visualizer.generate_dot(cfg)
        self.assertIsInstance(dot, str)
        self.assertIn("digraph CFG", dot)

    def test_generate_ascii(self):
        """测试生成ASCII格式"""
        cfg = self.visualizer.generate_cfg(self.test_pseudocode)
        ascii_out = self.visualizer.generate_ascii(cfg)
        self.assertIsInstance(ascii_out, str)
        self.assertIn("┌──", ascii_out)

    def test_visualize_mermaid(self):
        """测试可视化Mermaid格式"""
        result = self.visualizer.visualize(
            self.test_pseudocode,
            "test_func",
            OutputFormat.MERMAID
        )
        self.assertIsInstance(result, str)
        self.assertIn("flowchart TD", result)

    def test_visualize_dot(self):
        """测试可视化DOT格式"""
        result = self.visualizer.visualize(
            self.test_pseudocode,
            "test_func",
            OutputFormat.DOT
        )
        self.assertIsInstance(result, str)
        self.assertIn("digraph CFG", result)

    def test_visualize_ascii(self):
        """测试可视化ASCII格式"""
        result = self.visualizer.visualize(
            self.test_pseudocode,
            "test_func",
            OutputFormat.ASCII
        )
        self.assertIsInstance(result, str)

    def test_save_visualization(self):
        """测试保存可视化结果"""
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            output_path = f.name
        
        try:
            success = self.visualizer.save_visualization(
                self.test_pseudocode,
                output_path,
                "test_func",
                OutputFormat.MERMAID
            )
            self.assertTrue(success)
            self.assertTrue(os.path.exists(output_path))
        finally:
            os.unlink(output_path)

    def test_analyze_pseudocode(self):
        """测试分析伪代码结构"""
        analysis = self.visualizer.analyze_pseudocode(self.test_pseudocode)
        self.assertIsInstance(analysis, dict)
        self.assertIn("lines", analysis)
        self.assertIn("functions", analysis)
        self.assertIn("conditionals", analysis)

    def test_factory_function(self):
        """测试工厂函数"""
        visualizer = get_code_visualizer()
        self.assertIsInstance(visualizer, CodeVisualizer)

    def test_empty_pseudocode(self):
        """测试空伪代码"""
        cfg = self.visualizer.generate_cfg("")
        self.assertIsInstance(cfg, ControlFlowGraph)
        self.assertEqual(len(cfg.blocks), 0)


if __name__ == '__main__':
    unittest.main()