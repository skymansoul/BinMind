import os
import sys
import unittest
import tempfile
import shutil
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.fuzzing.fuzz_integration import (
    FuzzManager,
    create_fuzz_manager,
    list_available_fuzzers,
    FUZZER_TYPE_LIBFUZZER,
    FUZZER_TYPE_AFL,
    FUZZER_TYPE_AFLPP,
    FUZZER_TYPE_AUTO,
    FUZZER_STATUS_IDLE,
    FUZZER_STATUS_RUNNING,
    FUZZER_STATUS_COMPLETED,
    VALID_FUZZER_TYPES
)



class TestFuzzManagerStatus(unittest.TestCase):
    """测试状态管理测试"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.binary_path = os.path.join(self.test_dir, 'test_binary')
        with open(self.binary_path, 'wb') as f:
            f.write(b'\x7fELF')
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('modules.fuzz_integration.validate_binary_path')
    def test_initial_status(self, mock_validate):
        mock_validate.return_value = self.binary_path
        
        fm = FuzzManager(
            binary_path=self.binary_path,
            fuzzer_type='libfuzzer',
            use_sandbox=False
        )
        
        self.assertEqual(fm.status, FUZZER_STATUS_IDLE)
    
    @patch('modules.fuzz_integration.validate_binary_path')
    def test_get_status_initial(self, mock_validate):
        mock_validate.return_value = self.binary_path
        
        fm = FuzzManager(
            binary_path=self.binary_path,
            fuzzer_type='libfuzzer',
            use_sandbox=False
        )
        
        status = fm.get_status()
        
        self.assertIn('session_id', status)
        self.assertIn('status', status)
        self.assertIn('binary_path', status)
        self.assertIn('fuzzer_type', status)
        self.assertIn('output_dir', status)
        self.assertIn('crashes_found', status)
        self.assertIn('stats', status)
        self.assertIn('runtime', status)
        self.assertEqual(status['status'], FUZZER_STATUS_IDLE)
    
    @patch('modules.fuzz_integration.validate_binary_path')
    def test_get_crashes_empty(self, mock_validate):
        mock_validate.return_value = self.binary_path
        
        fm = FuzzManager(
            binary_path=self.binary_path,
            fuzzer_type='libfuzzer',
            use_sandbox=False
        )
        
        crashes = fm.get_crashes()
        
        self.assertIsInstance(crashes, list)
        self.assertEqual(len(crashes), 0)
    
    @patch('modules.fuzz_integration.validate_binary_path')
    def test_get_crash_invalid_index(self, mock_validate):
        mock_validate.return_value = self.binary_path
        
        fm = FuzzManager(
            binary_path=self.binary_path,
            fuzzer_type='libfuzzer',
            use_sandbox=False
        )
        
        crash = fm.get_crash(0)
        
        self.assertIsNone(crash)


class TestFuzzManagerProcessCommands(unittest.TestCase):
    """测试进程命令构建测试"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.binary_path = os.path.join(self.test_dir, 'test_binary')
        with open(self.binary_path, 'wb') as f:
            f.write(b'\x7fELF')
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('modules.fuzz_integration.validate_binary_path')
    def test_build_libfuzzer_command(self, mock_validate):
        mock_validate.return_value = self.binary_path
        
        fm = FuzzManager(
            binary_path=self.binary_path,
            fuzzer_type='libfuzzer',
            use_sandbox=False
        )
        
        cmd = fm._build_libfuzzer_command(
            timeout=3600,
            max_crashes=None,
            cpu_limit=1,
            memory_limit=2048,
            additional_args=None
        )
        
        self.assertIsInstance(cmd, list)
        self.assertIn(self.binary_path, cmd[0])
        self.assertIn('-max_total_time=3600', cmd)
        self.assertIn('-jobs=1', cmd)
        self.assertIn('-rss_limit_mb=2048', cmd)
    
    @patch('modules.fuzz_integration.validate_binary_path')
    def test_build_afl_command(self, mock_validate):
        mock_validate.return_value = self.binary_path
        
        fm = FuzzManager(
            binary_path=self.binary_path,
            fuzzer_type='afl',
            use_sandbox=False
        )
        
        cmd = fm._build_afl_command(
            timeout=3600,
            max_crashes=None,
            cpu_limit=1,
            memory_limit=2048,
            additional_args=None
        )
        
        self.assertIsInstance(cmd, list)
        self.assertEqual(cmd[0], 'afl-fuzz')
        self.assertIn('-i', cmd)
        self.assertIn('-o', cmd)
        self.assertIn('-m', cmd)
        self.assertIn(self.binary_path, cmd)
        self.assertIn('@@', cmd)


class TestListAvailableFuzzers(unittest.TestCase):
    """测试可用 Fuzzer 列表测试"""
    
    @patch('modules.fuzz_integration.subprocess.run')
    def test_list_available_fuzzers(self, mock_run):
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = ''
        mock_run.return_value = mock_process
        
        result = list_available_fuzzers()
        
        self.assertIn('available', result)
        self.assertIn('unavailable', result)
        self.assertIn('details', result)
        
        self.assertIsInstance(result['available'], list)
        self.assertIsInstance(result['unavailable'], list)
        self.assertIsInstance(result['details'], dict)


class TestCreateFuzzManager(unittest.TestCase):
    """测试 create_fuzz_manager 便捷函数测试"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.binary_path = os.path.join(self.test_dir, 'test_binary')
        with open(self.binary_path, 'wb') as f:
            f.write(b'\x7fELF')
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('modules.fuzz_integration.validate_binary_path')
    def test_create_fuzz_manager(self, mock_validate):
        mock_validate.return_value = self.binary_path
        
        fm = create_fuzz_manager(
            binary_path=self.binary_path,
            fuzzer_type='libfuzzer',
            corpus_path=None,
            output_dir=self.test_dir,
            use_sandbox=False
        )
        
        self.assertIsInstance(fm, FuzzManager)
        self.assertEqual(fm.binary_path, self.binary_path)
        self.assertEqual(fm.fuzzer_type, 'libfuzzer')


class TestFuzzManagerCrashMonitoring(unittest.TestCase):
    """测试崩溃监控测试"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.binary_path = os.path.join(self.test_dir, 'test_binary')
        with open(self.binary_path, 'wb') as f:
            f.write(b'\x7fELF')
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('modules.fuzz_integration.validate_binary_path')
    def test_export_results(self, mock_validate):
        mock_validate.return_value = self.binary_path
        
        fm = FuzzManager(
            binary_path=self.binary_path,
            fuzzer_type='libfuzzer',
            use_sandbox=False
        )
        
        output_file = os.path.join(self.test_dir, 'results.json')
        
        success = fm.export_results(output_file)
        
        self.assertTrue(success)
        self.assertTrue(os.path.exists(output_file))
        
        import json
        with open(output_file, 'r') as f:
            data = json.load(f)
        
        self.assertIn('session_id', data)
        self.assertIn('binary_path', data)
        self.assertIn('fuzzer_type', data)
        self.assertIn('status', data)
        self.assertIn('crashes_count', data)


if __name__ == '__main__':
    unittest.main()
