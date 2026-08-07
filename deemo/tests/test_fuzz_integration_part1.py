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


class TestFuzzIntegrationConstants(unittest.TestCase):
    """测试模糊测试集成常量测试"""
    
    def test_fuzzer_type_constants(self):
        self.assertEqual(FUZZER_TYPE_LIBFUZZER, 'libfuzzer')
        self.assertEqual(FUZZER_TYPE_AFL, 'afl')
        self.assertEqual(FUZZER_TYPE_AFLPP, 'afl++')
        self.assertEqual(FUZZER_TYPE_AUTO, 'auto')
    
    def test_valid_fuzzer_types(self):
        self.assertIn('libfuzzer', VALID_FUZZER_TYPES)
        self.assertIn('afl', VALID_FUZZER_TYPES)
        self.assertIn('afl++', VALID_FUZZER_TYPES)
        self.assertIn('auto', VALID_FUZZER_TYPES)
    
    def test_status_constants(self):
        self.assertEqual(FUZZER_STATUS_IDLE, 'idle')
        self.assertEqual(FUZZER_STATUS_RUNNING, 'running')
        self.assertEqual(FUZZER_STATUS_COMPLETED, 'completed')


class TestFuzzManagerValidation(unittest.TestCase):
    """测试 FuzzManager 验证测试"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.binary_path = os.path.join(self.test_dir, 'test_binary')
        with open(self.binary_path, 'wb') as f:
            f.write(b'\x7fELF')
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('modules.fuzz_integration.validate_binary_path')
    def test_validate_fuzzer_type_valid(self, mock_validate):
        mock_validate.return_value = self.binary_path
        
        fm = FuzzManager(
            binary_path=self.binary_path,
            fuzzer_type='libfuzzer',
            use_sandbox=False
        )
        
        self.assertEqual(fm.fuzzer_type, 'libfuzzer')
    
    @patch('modules.fuzz_integration.validate_binary_path')
    def test_validate_fuzzer_type_invalid(self, mock_validate):
        mock_validate.return_value = self.binary_path
        
        with self.assertRaises(ValueError):
            FuzzManager(
                binary_path=self.binary_path,
                fuzzer_type='invalid_type',
                use_sandbox=False
            )
    
    @patch('modules.fuzz_integration.validate_binary_path')
    def test_validate_fuzzer_type_case_insensitive(self, mock_validate):
        mock_validate.return_value = self.binary_path
        
        fm = FuzzManager(
            binary_path=self.binary_path,
            fuzzer_type='LIBFUZZER',
            use_sandbox=False
        )
        
        self.assertEqual(fm.fuzzer_type, 'libfuzzer')
    
    @patch('modules.fuzz_integration.validate_binary_path')
    def test_output_dir_creation(self, mock_validate):
        mock_validate.return_value = self.binary_path
        
        fm = FuzzManager(
            binary_path=self.binary_path,
            fuzzer_type='libfuzzer',
            use_sandbox=False
        )
        
        self.assertTrue(os.path.exists(fm.output_dir))
        self.assertTrue(os.path.exists(os.path.join(fm.output_dir, 'crashes')))
        self.assertTrue(os.path.exists(os.path.join(fm.output_dir, 'corpus')))
        self.assertTrue(os.path.exists(os.path.join(fm.output_dir, 'logs')))
        self.assertTrue(os.path.exists(os.path.join(fm.output_dir, 'analysis')))
    
    @patch('modules.fuzz_integration.validate_binary_path')
    def test_session_id_generation(self, mock_validate):
        mock_validate.return_value = self.binary_path
        
        fm1 = FuzzManager(
            binary_path=self.binary_path,
            fuzzer_type='libfuzzer',
            use_sandbox=False
        )
        
        fm2 = FuzzManager(
            binary_path=self.binary_path,
            fuzzer_type='libfuzzer',
            use_sandbox=False
        )
        
        self.assertIsNotNone(fm1.session_id)
        self.assertIsNotNone(fm2.session_id)
        self.assertNotEqual(fm1.session_id, fm2.session_id)


class TestFuzzManagerHarnessGeneration(unittest.TestCase):
    """测试 Harness 代码生成测试"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.binary_path = os.path.join(self.test_dir, 'test_binary')
        with open(self.binary_path, 'wb') as f:
            f.write(b'\x7fELF')
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('modules.fuzz_integration.validate_binary_path')
    def test_generate_harness_code(self, mock_validate):
        mock_validate.return_value = self.binary_path
        
        fm = FuzzManager(
            binary_path=self.binary_path,
            fuzzer_type='libfuzzer',
            use_sandbox=False
        )
        
        harness = fm.generate_harness(target_function='main')
        
        self.assertIsInstance(harness, str)
        self.assertGreater(len(harness), 0)
        self.assertIn('LLVMFuzzerTestOneInput', harness)
        self.assertIn('stdint.h', harness)
        self.assertIn('stddef.h', harness)
    
    @patch('modules.fuzz_integration.validate_binary_path')
    def test_generate_harness_with_target_function(self, mock_validate):
        mock_validate.return_value = self.binary_path
        
        fm = FuzzManager(
            binary_path=self.binary_path,
            fuzzer_type='libfuzzer',
            use_sandbox=False
        )
        
        harness = fm.generate_harness(target_function='vuln_function')
        
        self.assertIsInstance(harness, str)
        self.assertIn('LLVMFuzzerTestOneInput', harness)
    
    @patch('modules.fuzz_integration.validate_binary_path')
    def test_generate_harness_to_file(self, mock_validate):
        mock_validate.return_value = self.binary_path
        
        fm = FuzzManager(
            binary_path=self.binary_path,
            fuzzer_type='libfuzzer',
            use_sandbox=False
        )
        
        output_file = os.path.join(self.test_dir, 'harness.c')
        result = fm.generate_harness(
            target_function='main',
            output_path=output_file
        )
        
        self.assertEqual(result, output_file)
        self.assertTrue(os.path.exists(output_file))
        
        with open(output_file, 'r') as f:
            content = f.read()
        
        self.assertIn('LLVMFuzzerTestOneInput', content)


