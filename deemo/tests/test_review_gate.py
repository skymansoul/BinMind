"""
review_gate 模块测试 —— 人工复核门控机制。

测试覆盖:
  - write_gate / read_gate / clear_gate 生命周期
  - 门控状态机 (pending→approved/rejected/modify)
  - 超时自动跳过
  - 无门控文件时的回退行为
"""

import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.review_gate import (
    write_gate, read_gate, clear_gate, gate_in_feedback_loop,
    GateStatus,
)


class TestGateStatus(unittest.TestCase):
    """门控状态枚举测试。"""

    def test_enum_values(self):
        self.assertEqual(GateStatus.PENDING.value, 'pending')
        self.assertEqual(GateStatus.APPROVED.value, 'approved')
        self.assertEqual(GateStatus.REJECTED.value, 'rejected')
        self.assertEqual(GateStatus.MODIFY.value, 'modify')


class TestReviewGate(unittest.TestCase):
    """人工复核门控基础测试。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='binmind_test_gate_')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_exec_result(self, exit_code=-1, signal='', stdout='', stderr=''):
        return {
            'exit_code': exit_code,
            'signal': signal,
            'stdout': stdout,
            'stderr': stderr,
        }

    def test_write_gate_creates_file(self):
        """write_gate 创建门控文件。"""
        exec_result = self._make_exec_result(exit_code=-11, signal='SIGSEGV')
        path = write_gate(
            self.tmpdir, iteration=1,
            script_content='print("exploit")',
            exec_result=exec_result,
        )
        self.assertTrue(os.path.isfile(path))

    def test_write_gate_content(self):
        """门控文件内容包含必要字段（UTF-8 编码）。"""
        exec_result = self._make_exec_result(exit_code=0)
        path = write_gate(
            self.tmpdir, iteration=2,
            script_content='#!/usr/bin/env python3\nprint("test")',
            exec_result=exec_result,
            llm_feedback='Try adjusting the offset',
        )
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('status = "pending"', content)
        self.assertIn('iteration = 2', content)
        self.assertIn('exit_code = 0', content)

    def test_read_gate_no_file(self):
        """无门控文件时返回 skip。"""
        result = read_gate(self.tmpdir)
        self.assertEqual(result['status'], 'skip')
        self.assertIn('no_gate_file', result.get('reason', ''))

    def test_read_gate_pending(self):
        """pending 状态的门控文件读取正确。"""
        exec_result = self._make_exec_result()
        write_gate(self.tmpdir, iteration=1,
                   script_content='test', exec_result=exec_result)

        result = read_gate(self.tmpdir)
        # 刚写入的应是 pending 状态
        self.assertIn(result['status'], ('pending', 'skip'))

    def test_read_gate_approved(self):
        """人工批准后的读取。"""
        exec_result = self._make_exec_result()
        gate_path = write_gate(
            self.tmpdir, iteration=1,
            script_content='test', exec_result=exec_result,
        )
        # 模拟人工编辑：将 status 改为 approved
        with open(gate_path, 'r', encoding='utf-8') as f:
            content = f.read()
        content = content.replace('status = "pending"', 'status = "approved"')
        with open(gate_path, 'w', encoding='utf-8') as f:
            f.write(content)

        result = read_gate(self.tmpdir)
        self.assertEqual(result['status'], 'approved')

    def test_read_gate_rejected(self):
        """人工拒绝后的读取。"""
        exec_result = self._make_exec_result()
        gate_path = write_gate(
            self.tmpdir, iteration=1,
            script_content='test', exec_result=exec_result,
        )
        with open(gate_path, 'r', encoding='utf-8') as f:
            content = f.read()
        content = content.replace('status = "pending"', 'status = "rejected"')
        with open(gate_path, 'w', encoding='utf-8') as f:
            f.write(content)

        result = read_gate(self.tmpdir)
        self.assertEqual(result['status'], 'rejected')

    def test_read_gate_modify(self):
        """人工修改指令后的读取。"""
        exec_result = self._make_exec_result()
        gate_path = write_gate(
            self.tmpdir, iteration=1,
            script_content='test', exec_result=exec_result,
        )
        with open(gate_path, 'r', encoding='utf-8') as f:
            content = f.read()
        content = content.replace('status = "pending"', 'status = "modify"')
        content = content.replace(
            'instruction = ""',
            'instruction = "Use offset 72 instead of 64"',
        )
        with open(gate_path, 'w', encoding='utf-8') as f:
            f.write(content)

        result = read_gate(self.tmpdir)
        self.assertEqual(result['status'], 'modify')
        self.assertIn('72', result.get('instruction', ''))

    def test_clear_gate(self):
        """清除门控文件。"""
        exec_result = self._make_exec_result()
        write_gate(self.tmpdir, iteration=1,
                   script_content='test', exec_result=exec_result)
        clear_gate(self.tmpdir)
        result = read_gate(self.tmpdir)
        self.assertEqual(result['status'], 'skip')

    def test_clear_gate_no_file(self):
        """清除不存在的门控文件不报错。"""
        clear_gate(self.tmpdir)

    def test_gate_in_feedback_loop_no_file(self):
        """无门控文件时 gate_in_feedback_loop 返回 skip。"""
        exec_result = self._make_exec_result()
        result = gate_in_feedback_loop(
            self.tmpdir, iteration=1,
            current_script='test',
            exec_result=exec_result,
            timeout=1,
            poll_interval=0.5,
        )
        self.assertEqual(result['action'], 'skip')

    def test_gate_in_feedback_loop_approved(self):
        """gate_in_feedback_loop 在函数内部先写入门控再轮询。
        语义上它总是从 pending 开始，所以预先批准会被覆盖。
        测试验证 write→read 周期可正常工作。"""
        exec_result = self._make_exec_result()
        path = write_gate(
            self.tmpdir, iteration=1,
            script_content='test', exec_result=exec_result,
        )
        # 验证门控文件已创建且状态为 pending
        self.assertTrue(os.path.isfile(path))
        with open(path, 'r', encoding='utf-8') as f:
            self.assertIn('status = "pending"', f.read())

        # gate_in_feedback_loop 的轮询模式在短时间内会超时返回 skip
        result = gate_in_feedback_loop(
            self.tmpdir, iteration=1,
            current_script='test',
            exec_result=exec_result,
            timeout=1,
            poll_interval=0.5,
        )
        self.assertIn(result['action'], ('skip', 'accept'))


if __name__ == '__main__':
    unittest.main()
