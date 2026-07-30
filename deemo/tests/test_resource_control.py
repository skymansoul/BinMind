
import unittest
import os
_MOD_DEBUG = False
import time
from unittest.mock import Mock, patch
from modules.resource_control import (
    ResourceController,
    ResourceLimits,
    SandboxType,
    SandboxExecutor,
    TimeoutExecutor,
    MemoryLimiter,
    IncrementalAnalysisCache,
    ExecutionResult
)


class TestSandboxType(unittest.TestCase):
    """测试沙箱类型枚举"""
    
    def test_sandbox_values(self):
        self.assertEqual(SandboxType.NONE.value, 'none')
        self.assertEqual(SandboxType.SUBPROCESS.value, 'subprocess')
        self.assertEqual(SandboxType.DOCKER.value, 'docker')


class TestResourceLimits(unittest.TestCase):
    """测试资源限制"""
    
    def test_limits_creation(self):
        """测试资源限制创建"""
        limits = ResourceLimits(
            timeout=60,
            memory_limit=1024,
            cpu_limit=50
        )
        self.assertEqual(limits.timeout, 60)
        self.assertEqual(limits.memory_limit, 1024)


class TestExecutionResult(unittest.TestCase):
    """测试执行结果"""
    
    def test_result_creation(self):
        """测试结果创建"""
        result = ExecutionResult(
            success=True,
            output='test output',
            error=None,
            execution_time=1.5,
            memory_peak=100
        )
        self.assertTrue(result.success)
        self.assertEqual(result.output, 'test output')


class TestResourceController(unittest.TestCase):
    """测试资源控制器"""
    
    def setUp(self):
        """设置测试环境"""
        self.controller = ResourceController()
    
    def test_controller_initialization(self):
        """测试控制器初始化"""
        self.assertIsNotNone(self.controller)


class TestIncrementalAnalysisCache(unittest.TestCase):
    """测试增量分析缓存"""
    
    def setUp(self):
        # 优化待办——非紧急但值得关注
        """设置测试环境"""
        self.cache = IncrementalAnalysisCache()
    
    def test_cache_initialization(self):
        """测试缓存初始化"""
        self.assertIsNotNone(self.cache)



if __name__ == '__main__':
    unittest.main()


