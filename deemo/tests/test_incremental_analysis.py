#!/usr/bin/env python3
"""
增量分析缓存模块测试
"""
import os
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.incremental_analysis import (
    IncrementalAnalysisCache, IncrementalAnalysisResult,
    FunctionCacheEntry, BinaryCacheEntry, CacheStatus, CacheInvalidationReason
)


class TestIncrementalAnalysisCache(unittest.TestCase):
    """增量分析缓存管理器测试类"""

    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.cache = IncrementalAnalysisCache(cache_dir=self.temp_dir)

    def tearDown(self):
        """测试后清理"""
        self.cache.close()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_cache_status_enum(self):
        """测试缓存状态枚举"""
        self.assertEqual(CacheStatus.VALID.value, 'valid')
        self.assertEqual(CacheStatus.INVALIDATED.value, 'invalidated')
        self.assertEqual(CacheStatus.EXPIRED.value, 'expired')
        self.assertEqual(CacheStatus.NOT_FOUND.value, 'not_found')

    def test_cache_invalidation_reason_enum(self):
        """测试缓存失效原因枚举"""
        self.assertEqual(CacheInvalidationReason.ANALYSIS_OPTIONS_CHANGED.value, 'analysis_options_changed')
        self.assertEqual(CacheInvalidationReason.BINARY_MODIFIED.value, 'binary_modified')
        self.assertEqual(CacheInvalidationReason.CACHE_EXPIRED.value, 'cache_expired')

    def test_compute_binary_hash(self):
        """测试计算二进制哈希"""
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'Hello World')
        
        hash1 = self.cache.compute_binary_hash(test_file)
        hash2 = self.cache.compute_binary_hash(test_file)
        
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)  # SHA256

    def test_compute_semantic_hash(self):
        """测试计算语义哈希"""
        code1 = 'int main() { return 0; }'
        code2 = 'int main() { return 0; }'
        code3 = 'int main() { return 1; }'
        
        hash1 = self.cache.compute_semantic_hash(code1)
        hash2 = self.cache.compute_semantic_hash(code2)
        hash3 = self.cache.compute_semantic_hash(code3)
        
        self.assertEqual(hash1, hash2)
        self.assertNotEqual(hash1, hash3)

    def test_function_cache_entry_dataclass(self):
        """测试 FunctionCacheEntry 数据类"""
        entry = FunctionCacheEntry(
            function_name='main',
            function_address=0x401000,
            semantic_hash='abc123',
            analysis_result={'vulns': []},
            analysis_timestamp='2024-01-01',
            binary_hash='hash123',
            analysis_options={'level': 'full'},
            status=CacheStatus.VALID
        )
        
        self.assertEqual(entry.function_name, 'main')
        self.assertEqual(entry.function_address, 0x401000)
        self.assertEqual(entry.status, CacheStatus.VALID)

    def test_function_cache_entry_to_dict(self):
        """测试 FunctionCacheEntry 转换为字典"""
        entry = FunctionCacheEntry(
            function_name='func',
            function_address=0x402000,
            semantic_hash='hash',
            analysis_result={},
            analysis_timestamp='2024-01-01',
            binary_hash='bin_hash',
            analysis_options={}
        )
        
        result = entry.to_dict()
        
        self.assertIn('function_name', result)
        self.assertIn('function_address', result)
        self.assertIn('semantic_hash', result)

    def test_binary_cache_entry_dataclass(self):
        """测试 BinaryCacheEntry 数据类"""
        entry = BinaryCacheEntry(
            binary_path='/test/bin',
            binary_hash='hash123',
            functions=[0x401000, 0x401100],
            cache_timestamp='2024-01-01',
            version='1.0'
        )
        
        self.assertEqual(entry.binary_path, '/test/bin')
        self.assertEqual(len(entry.functions), 2)

    def test_binary_cache_entry_to_dict(self):
        """测试 BinaryCacheEntry 转换为字典"""
        entry = BinaryCacheEntry(
            binary_path='/test/bin',
            binary_hash='hash',
            functions=[0x401000],
            cache_timestamp='2024-01-01'
        )
        
        result = entry.to_dict()
        
        self.assertIn('binary_path', result)
        self.assertIn('functions', result)

    def test_get_binary_cache(self):
        """测试获取二进制缓存"""
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'content')
        
        # 先保存缓存
        entry = BinaryCacheEntry(
            binary_path=test_file,
            binary_hash=self.cache.compute_binary_hash(test_file),
            functions=[0x401000],
            cache_timestamp='2024-01-01'
        )
        self.cache.save_binary_cache(entry)
        
        # 再获取缓存
        retrieved = self.cache.get_binary_cache(test_file)
        
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.binary_path, test_file)

    def test_save_and_get_function_cache(self):
        """测试保存和获取函数缓存"""
        entry = FunctionCacheEntry(
            function_name='test_func',
            function_address=0x401000,
            semantic_hash='abc',
            analysis_result={'vulns': []},
            analysis_timestamp='2024-01-01',
            binary_hash='bin_hash',
            analysis_options={}
        )
        
        self.cache.save_function_cache(entry)
        retrieved = self.cache.get_function_cache(0x401000)
        
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.function_name, 'test_func')

    def test_is_cache_valid(self):
        """测试检查缓存有效性"""
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'content')
        
        # 保存缓存
        entry = BinaryCacheEntry(
            binary_path=test_file,
            binary_hash=self.cache.compute_binary_hash(test_file),
            functions=[0x401000],
            cache_timestamp='2024-01-01'
        )
        self.cache.save_binary_cache(entry)
        
        # 检查有效性
        current_hash = self.cache.compute_binary_hash(test_file)
        valid = self.cache.is_cache_valid(test_file, current_hash)
        
        self.assertTrue(valid)

    def test_is_cache_invalid_when_modified(self):
        """测试文件修改后缓存失效"""
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'content')
        
        # 保存缓存
        original_hash = self.cache.compute_binary_hash(test_file)
        entry = BinaryCacheEntry(
            binary_path=test_file,
            binary_hash=original_hash,
            functions=[0x401000],
            cache_timestamp='2024-01-01'
        )
        self.cache.save_binary_cache(entry)
        
        # 修改文件
        with open(test_file, 'wb') as f:
            f.write(b'modified')
        
        # 检查有效性
        new_hash = self.cache.compute_binary_hash(test_file)
        valid = self.cache.is_cache_valid(test_file, new_hash)
        
        self.assertFalse(valid)

    def test_analyze_incrementally(self):
        """测试增量分析"""
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'content')
        
        functions = [
            {"address": 0x401000, "name": "func1", "pseudocode": "int func1() { return 0; }"},
            {"address": 0x401100, "name": "func2", "pseudocode": "int func2() { return 1; }"},
        ]
        
        def mock_analysis(func):
            return {"name": func["name"], "analyzed": True}
        
        result = self.cache.analyze_incrementally(
            test_file,
            functions,
            {"level": "full"},
            mock_analysis
        )
        
        self.assertIsInstance(result, IncrementalAnalysisResult)
        self.assertEqual(result.total_functions, 2)
        self.assertEqual(result.new_functions, 2)

    def test_incremental_analysis_cache_hit(self):
        """测试增量分析缓存命中"""
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'content')
        
        functions = [
            {"address": 0x401000, "name": "func1", "pseudocode": "int func1() { return 0; }"},
        ]
        
        def mock_analysis(func):
            return {"name": func["name"], "analyzed": True}
        
        # 第一次分析
        result1 = self.cache.analyze_incrementally(
            test_file,
            functions,
            {"level": "full"},
            mock_analysis
        )
        
        # 第二次分析（相同代码）
        result2 = self.cache.analyze_incrementally(
            test_file,
            functions,
            {"level": "full"},
            mock_analysis
        )
        
        self.assertEqual(result1.new_functions, 1)
        self.assertEqual(result2.cached_functions, 1)
        self.assertEqual(result2.skipped_functions, 1)

    def test_get_cache_statistics(self):
        """测试获取缓存统计"""
        stats = self.cache.get_cache_statistics()
        
        self.assertIn('function_cache_count', stats)
        self.assertIn('binary_cache_count', stats)
        self.assertIsInstance(stats['function_cache_count'], int)

    def test_invalidate_cache(self):
        """测试失效缓存"""
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'content')
        
        # 保存缓存
        entry = BinaryCacheEntry(
            binary_path=test_file,
            binary_hash=self.cache.compute_binary_hash(test_file),
            functions=[0x401000],
            cache_timestamp='2024-01-01'
        )
        self.cache.save_binary_cache(entry)
        
        # 失效缓存
        self.cache.invalidate_cache(test_file, CacheInvalidationReason.MANUAL_INVALIDATION)
        
        # 检查缓存是否被删除
        retrieved = self.cache.get_binary_cache(test_file)
        self.assertIsNone(retrieved)

    def test_generate_report(self):
        """测试生成报告"""
        result = IncrementalAnalysisResult(
            binary_path='/test/bin',
            total_functions=10,
            cached_functions=5,
            new_functions=3,
            modified_functions=2,
            skipped_functions=5,
            analysis_duration=1.5,
            cache_hits=5,
            cache_misses=5,
            timestamp='2024-01-01'
        )
        
        report = self.cache.generate_report(result)
        
        self.assertIn('增量分析报告', report)
        self.assertIn('10', report)

    def test_save_result(self):
        """测试保存结果"""
        result = IncrementalAnalysisResult(
            binary_path='/test/bin',
            total_functions=1,
            cached_functions=0,
            new_functions=1,
            modified_functions=0,
            skipped_functions=0,
            analysis_duration=0.5,
            cache_hits=0,
            cache_misses=1,
            timestamp='2024-01-01'
        )
        
        saved_path = self.cache.save_result(result, 'test_incremental')
        
        self.assertTrue(os.path.exists(saved_path))


class TestIncrementalAnalysisResult(unittest.TestCase):
    """IncrementalAnalysisResult 数据类测试"""

    def test_incremental_analysis_result_dataclass(self):
        """测试增量分析结果"""
        result = IncrementalAnalysisResult(
            binary_path='/test/bin',
            total_functions=10,
            cached_functions=5,
            new_functions=3,
            modified_functions=2,
            skipped_functions=5,
            analysis_duration=1.0,
            cache_hits=5,
            cache_misses=5,
            timestamp='2024-01-01'
        )
        
        self.assertEqual(result.total_functions, 10)
        self.assertEqual(result.cache_hits, 5)

    def test_incremental_analysis_result_to_dict(self):
        """测试转换为字典"""
        result = IncrementalAnalysisResult(
            binary_path='/test/bin',
            total_functions=1,
            cached_functions=0,
            new_functions=1,
            modified_functions=0,
            skipped_functions=0,
            analysis_duration=0.5,
            cache_hits=0,
            cache_misses=1
        )
        
        data = result.to_dict()
        
        self.assertIn('binary_path', data)
        self.assertIn('total_functions', data)
        self.assertIn('cache_hits', data)


if __name__ == '__main__':
    unittest.main()