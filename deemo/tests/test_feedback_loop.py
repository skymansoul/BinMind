"""
feedback_loop 模块测试 —— LLM 驱动的 exploit 迭代修正。

测试覆盖:
  - run_feedback_loop 基本调用
  - 缺少 API Key 时的降级行为
  - 历史记录结构
  - 超时和迭代次数控制
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.feedback_loop import run_feedback_loop


class TestFeedbackLoop(unittest.TestCase):
    """反馈迭代环基础测试。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='binmind_test_fb_')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_script(self, content):
        path = os.path.join(self.tmpdir, 'test_exploit.py')
        with open(path, 'w') as f:
            f.write(content)
        return path

    def test_run_without_api_key(self):
        """无 API Key 时应降级，但仍返回有效结构。"""
        # 确保 OPENAI_API_KEY 为空
        old_key = os.environ.get('OPENAI_API_KEY', '')
        os.environ.pop('OPENAI_API_KEY', None)

        try:
            script = self._write_script('print("hello world")\n')
            with open(script) as f:
                content = f.read()

            result = run_feedback_loop(
                binary_path=sys.executable,
                initial_script=content,
                max_iterations=2,
                timeout=10,
            )
            self.assertIsInstance(result, dict)
            self.assertIn('success', result)
            self.assertIn('iterations', result)
            self.assertIn('history', result)
            self.assertIsInstance(result['history'], list)
        finally:
            if old_key:
                os.environ['OPENAI_API_KEY'] = old_key

    def test_result_structure(self):
        """返回 dict 包含所有预期字段。"""
        script = self._write_script('print("test")\n')
        with open(script) as f:
            content = f.read()

        result = run_feedback_loop(
            binary_path=sys.executable,
            initial_script=content,
            max_iterations=1,
            timeout=10,
        )
        for key in ('success', 'final_script', 'iterations', 'history',
                     'best_result', 'root_cause'):
            self.assertIn(key, result, f'Result should contain key: {key}')

    def test_max_iterations_respected(self):
        """迭代次数不超过 max_iterations。"""
        script = self._write_script('import sys; sys.exit(1)\n')
        with open(script) as f:
            content = f.read()

        result = run_feedback_loop(
            binary_path=sys.executable,
            initial_script=content,
            max_iterations=2,
            timeout=10,
        )
        self.assertLessEqual(result['iterations'], 2)

    def test_nonexistent_binary(self):
        """不存在的目标文件仍应返回有效结果。"""
        result = run_feedback_loop(
            binary_path='/nonexistent/target',
            initial_script='print("test")',
            max_iterations=1,
            timeout=5,
        )
        self.assertIsInstance(result, dict)
        self.assertFalse(result.get('success', True))


if __name__ == '__main__':
    unittest.main()
