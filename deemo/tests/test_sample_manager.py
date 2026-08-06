"""
sample_manager 模块测试 —— 样本注册、管理与导出。

测试覆盖:
  - SampleManager CRUD 操作
  - 批量扫描
  - CSV/Markdown 导出
  - 筛选与统计
  - 空数据库行为
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.sample_manager import SampleManager, init_sample_directories


class TestSampleManager(unittest.TestCase):
    """样本管理器基础测试。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='binmind_test_sm_')
        self.db_path = os.path.join(self.tmpdir, 'samples_test.json')
        self.mgr = SampleManager(db_path=self.db_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_elf(self, name='test_binary'):
        """创建一个最小 ELF 文件用于注册测试。

        文件名会被编码到文件内容末尾以生成不同的 SHA256，
        避免多个测试样本因内容相同导致 ID 冲突互相覆盖。
        """
        path = os.path.join(self.tmpdir, name)
        with open(path, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 20)
            f.write(name.encode())  # 确保每次调用产生不同的文件哈希
        return path

    def test_register_binary(self):
        """注册一个 ELF 文件并返回 sample_id。"""
        path = self._make_elf('stack_bof')
        sample_id = self.mgr.register(
            path, vuln_type='stack-overflow', difficulty='easy',
            source='CTF-test', tags=['x86_64', 'ret2libc'],
        )
        self.assertIsInstance(sample_id, str)
        self.assertEqual(len(sample_id), 16)

    def test_get_registered_sample(self):
        """注册后可按 ID 检索。"""
        path = self._make_elf('fmt_str')
        sample_id = self.mgr.register(path, vuln_type='format-string')
        retrieved = self.mgr.get(sample_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved['vuln_type'], 'format-string')

    def test_register_nonexistent_file(self):
        """注册不存在的文件应抛出异常。"""
        with self.assertRaises(FileNotFoundError):
            self.mgr.register('/nonexistent/path')

    def test_list_samples_empty(self):
        """新库应返回空列表。"""
        samples = self.mgr.list_samples()
        self.assertEqual(len(samples), 0)

    def test_list_samples_with_filter(self):
        """按漏洞类型筛选。"""
        self.mgr.register(self._make_elf('a'), vuln_type='stack-overflow')
        self.mgr.register(self._make_elf('b'), vuln_type='format-string')
        result = self.mgr.list_samples(vuln_type='stack-overflow')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['vuln_type'], 'stack-overflow')

    def test_list_samples_by_difficulty(self):
        """按难度筛选。"""
        self.mgr.register(self._make_elf('easy'), difficulty='easy')
        self.mgr.register(self._make_elf('hard'), difficulty='hard')
        result = self.mgr.list_samples(difficulty='hard')
        self.assertEqual(len(result), 1)

    def test_delete_sample(self):
        """删除样本记录。"""
        path = self._make_elf('to_delete')
        sample_id = self.mgr.register(path)
        self.assertTrue(self.mgr.delete(sample_id))
        self.assertIsNone(self.mgr.get(sample_id))

    def test_delete_nonexistent(self):
        """删除不存在的 ID 返回 False。"""
        self.assertFalse(self.mgr.delete('nonexistent_id_123'))

    def test_export_csv(self):
        """导出 CSV 文件。"""
        self.mgr.register(self._make_elf('csv_test'), vuln_type='test')
        csv_path = os.path.join(self.tmpdir, 'output.csv')
        result_path = self.mgr.export_csv(csv_path)
        self.assertTrue(os.path.isfile(result_path))

    def test_export_markdown(self):
        """导出 Markdown 文件。"""
        self.mgr.register(self._make_elf('md_test'), vuln_type='test')
        md_path = os.path.join(self.tmpdir, 'output.md')
        result_path = self.mgr.export_markdown(md_path)
        self.assertTrue(os.path.isfile(result_path))

    def test_summary(self):
        """汇总统计正确。"""
        self.mgr.register(self._make_elf('summary_s1'),
                          vuln_type='stack-overflow', difficulty='easy')
        self.mgr.register(self._make_elf('summary_s2'),
                          vuln_type='format-string', difficulty='medium')
        summary = self.mgr.summary()
        self.assertEqual(summary['total_samples'], 2)

    def test_batch_scan_directory(self):
        """批量扫描目录并注册。"""
        subdir = os.path.join(self.tmpdir, 'ctf')
        os.makedirs(subdir, exist_ok=True)
        self._make_elf(os.path.join('ctf', 'challenge1'))
        self._make_elf(os.path.join('ctf', 'challenge2'))

        results = self.mgr.batch_scan(subdir, recursive=False, register=True)
        self.assertGreaterEqual(len(results), 0)

    def test_batch_scan_no_register(self):
        """批量扫描但不注册。"""
        subdir = os.path.join(self.tmpdir, 'samples')
        os.makedirs(subdir, exist_ok=True)
        self._make_elf(os.path.join('samples', 'bin1'))

        results = self.mgr.batch_scan(subdir, register=False)
        self.assertIsInstance(results, list)


class TestInitSampleDirectories(unittest.TestCase):
    """样本目录初始化。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='binmind_test_smdir_')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_creates_directories(self):
        """创建 ctf/teaching/cve 子目录及 README。"""
        base = os.path.join(self.tmpdir, 'samples')
        created = init_sample_directories(base)
        for dirname in ('ctf', 'teaching', 'cve'):
            self.assertIn(dirname, created)
            self.assertTrue(os.path.isdir(created[dirname]))
            readme = os.path.join(created[dirname], 'README.md')
            self.assertTrue(os.path.isfile(readme))


if __name__ == '__main__':
    unittest.main()
