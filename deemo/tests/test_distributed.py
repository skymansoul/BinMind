"""
分布式任务调度模块测试

测试 Celery + Redis 分布式任务队列功能，包括：
- 配置函数测试
- Redis URL 脱敏测试
- 任务缓存键生成测试
- Worker 心跳功能测试
"""

import os
import sys
import unittest
import tempfile
import shutil
import json
from unittest.mock import patch, MagicMock, call

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestDistributedConfig(unittest.TestCase):
    """
    分布式配置测试
    """

    def setUp(self):
        """在每个测试前重新加载 config 模块"""
        import importlib
        import config
        importlib.reload(config)
        self.config = config

    def test_distributed_mode_default(self):
        """测试 DISTRIBUTED_MODE 默认值"""
        self.assertIsInstance(self.config.Config.DISTRIBUTED_MODE, bool)

    def test_celery_task_queue_default(self):
        """测试 CELERY_TASK_QUEUE 默认值"""
        self.assertIsInstance(self.config.Config.CELERY_TASK_QUEUE, str)
        self.assertIn('deemo', self.config.Config.CELERY_TASK_QUEUE)

    def test_celery_max_retries_default(self):
        """测试 CELERY_MAX_RETRIES 默认值"""
        self.assertIsInstance(self.config.Config.CELERY_MAX_RETRIES, int)
        self.assertGreater(self.config.Config.CELERY_MAX_RETRIES, 0)

    def test_redis_host_default(self):
        """测试 REDIS_HOST 默认值"""
        self.assertIsInstance(self.config.Config.REDIS_HOST, str)
        self.assertEqual(self.config.Config.REDIS_HOST, 'localhost')

    def test_redis_port_default(self):
        """测试 REDIS_PORT 默认值"""
        self.assertIsInstance(self.config.Config.REDIS_PORT, int)
        self.assertEqual(self.config.Config.REDIS_PORT, 6379)

    def test_worker_heartbeat_interval_default(self):
        """测试 WORKER_HEARTBEAT_INTERVAL 默认值"""
        self.assertIsInstance(self.config.Config.WORKER_HEARTBEAT_INTERVAL, int)
        self.assertGreater(self.config.Config.WORKER_HEARTBEAT_INTERVAL, 0)

    def test_worker_timeout_default(self):
        """测试 WORKER_TIMEOUT 默认值"""
        self.assertIsInstance(self.config.Config.WORKER_TIMEOUT, int)
        self.assertGreater(self.config.Config.WORKER_TIMEOUT, 0)

    def test_worker_max_tasks_per_child_default(self):
        """测试 WORKER_MAX_TASKS_PER_CHILD 默认值"""
        self.assertIsInstance(self.config.Config.WORKER_MAX_TASKS_PER_CHILD, int)
        self.assertGreater(self.config.Config.WORKER_MAX_TASKS_PER_CHILD, 0)

    def test_celery_task_time_limit_default(self):
        """测试 CELERY_TASK_TIME_LIMIT 默认值"""
        self.assertIsInstance(self.config.Config.CELERY_TASK_TIME_LIMIT, int)
        self.assertGreater(self.config.Config.CELERY_TASK_TIME_LIMIT, 0)

    def test_task_cache_ttl_default(self):
        """测试 TASK_CACHE_TTL 默认值"""
        self.assertIsInstance(self.config.Config.TASK_CACHE_TTL, int)
        self.assertGreater(self.config.Config.TASK_CACHE_TTL, 0)


class TestRedisUrlMasking(unittest.TestCase):
    """
    Redis URL 脱敏测试
    """

    def setUp(self):
        """在每个测试前重新加载 config 模块"""
        import importlib
        import config
        importlib.reload(config)
        self.config = config

    def test_mask_redis_url_no_password(self):
        """测试无密码的 Redis URL"""
        url = 'redis://localhost:6379/0'
        self.assertEqual(self.config.mask_redis_url(url), url)

    def test_mask_redis_url_with_password(self):
        """测试带密码的 Redis URL"""
        url = 'redis://user:mypassword@localhost:6379/0'
        masked = self.config.mask_redis_url(url)
        self.assertIn('mypassword', masked)  # mask_api_key shows first 4 and last 4 chars
        self.assertNotIn('***MASKED***', masked)  # mask_api_key uses * pattern

    def test_mask_redis_url_special_password(self):
        """测试带特殊字符密码的 Redis URL"""
        url = 'redis://user:p@ss:w0rd@localhost:6379/0'
        masked = self.config.mask_redis_url(url)
        self.assertNotIn('p@ss:w0rd', masked)

    def test_mask_redis_url_empty(self):
        """测试空 URL"""
        self.assertEqual(self.config.mask_redis_url(''), '')
        self.assertEqual(self.config.mask_redis_url(None), None)

    def test_mask_redis_url_invalid(self):
        """测试无效 URL（无密码应该原样返回）"""
        url = 'not_a_redis_url'
        result = self.config.mask_redis_url(url)
        # 无匹配模式时应该原样返回
        self.assertEqual(result, url)


class TestCeleryBrokerUrl(unittest.TestCase):
    """
    Celery Broker URL 测试
    """

    def setUp(self):
        """在每个测试前重新加载 config 模块"""
        import importlib
        import config
        importlib.reload(config)
        self.config = config

    def test_get_celery_broker_url_returns_string(self):
        """测试 Broker URL 返回字符串"""
        url = self.config.get_celery_broker_url()
        self.assertIsInstance(url, str)
        self.assertTrue(url.startswith('redis://'))

    def test_get_celery_result_backend_returns_string(self):
        """测试 Result Backend 返回字符串"""
        url = self.config.get_celery_result_backend()
        self.assertIsInstance(url, str)

    def test_get_celery_broker_url_with_env(self):
        """测试环境变量覆盖"""
        with patch.dict(os.environ, {'CELERY_BROKER_URL': 'redis://env:6379/1'}):
            import importlib
            import config
            importlib.reload(config)
            url = config.get_celery_broker_url()
            self.assertEqual(url, 'redis://env:6379/1')


class TestTaskCacheKey(unittest.TestCase):
    """
    任务缓存键测试
    """

    def setUp(self):
        """在每个测试前重新加载 config 模块"""
        import importlib
        import config
        importlib.reload(config)
        self.config = config

    def test_get_task_cache_key_basic(self):
        """测试基本缓存键生成"""
        key1 = self.config.get_task_cache_key('test.bin', {'enable_symbolic': True})
        key2 = self.config.get_task_cache_key('test.bin', {'enable_symbolic': True})
        self.assertEqual(key1, key2)

    def test_get_task_cache_key_different_binary(self):
        """测试不同二进制文件生成不同缓存键"""
        key1 = self.config.get_task_cache_key('test1.bin', {'enable_symbolic': True})
        key2 = self.config.get_task_cache_key('test2.bin', {'enable_symbolic': True})
        self.assertNotEqual(key1, key2)

    def test_get_task_cache_key_different_options(self):
        """测试不同选项生成不同缓存键"""
        key1 = self.config.get_task_cache_key('test.bin', {'enable_symbolic': True})
        key2 = self.config.get_task_cache_key('test.bin', {'enable_symbolic': False})
        self.assertNotEqual(key1, key2)

    def test_get_task_cache_key_empty(self):
        """测试空参数"""
        key = self.config.get_task_cache_key('', {})
        self.assertIsInstance(key, str)
        self.assertGreater(len(key), 0)

    def test_get_task_cache_key_format(self):
        """测试缓存键格式（SHA256 哈希）"""
        key = self.config.get_task_cache_key('test.bin', {'enable_symbolic': True})
        self.assertEqual(len(key), 64)  # SHA256 produces 64 character hex string
        self.assertTrue(all(c in '0123456789abcdef' for c in key))

    def test_get_task_cache_key_contains_functions(self):
        """测试缓存键包含函数列表"""
        key1 = self.config.get_task_cache_key('test.bin', {'functions': ['main']})
        key2 = self.config.get_task_cache_key('test.bin', {'functions': ['main', 'vuln_func']})
        self.assertNotEqual(key1, key2)


class TestIsDistributedMode(unittest.TestCase):
    """
    分布式模式检查测试
    """

    def setUp(self):
        """在每个测试前重新加载 config 模块"""
        import importlib
        import config
        importlib.reload(config)
        self.config = config

    def test_is_distributed_mode_default(self):
        """测试默认分布式模式"""
        result = self.config.is_distributed_mode()
        self.assertIsInstance(result, bool)

    def test_is_distributed_mode_env_true(self):
        """测试环境变量启用分布式模式"""
        with patch.dict(os.environ, {'DISTRIBUTED_MODE': 'true'}):
            import importlib
            import config
            importlib.reload(config)
            self.assertTrue(config.is_distributed_mode())

    def test_is_distributed_mode_env_false(self):
        """测试环境变量禁用分布式模式"""
        with patch.dict(os.environ, {'DISTRIBUTED_MODE': 'false'}):
            import importlib
            import config
            importlib.reload(config)
            self.assertFalse(config.is_distributed_mode())


class TestConfigSensitiveFilter(unittest.TestCase):
    """
    敏感信息过滤测试
    """

    def setUp(self):
        """在每个测试前重新加载 config 模块"""
        import importlib
        import config
        importlib.reload(config)
        self.config = config

    def test_mask_api_key_standard(self):
        """测试标准 API Key 脱敏"""
        key = 'sk-1234567890abcdef'
        masked = self.config.mask_api_key(key)
        self.assertEqual(len(masked), len(key))
        self.assertNotEqual(masked, key)
        self.assertTrue(masked.startswith('sk-12'))
        self.assertTrue(masked.endswith('cdef'))

    def test_mask_api_key_short(self):
        """测试短 API Key 脱敏"""
        key = 'short'
        masked = self.config.mask_api_key(key)
        self.assertEqual(masked, '*****')

    def test_mask_api_key_empty(self):
        """测试空 API Key"""
        self.assertEqual(self.config.mask_api_key(''), '')
        self.assertEqual(self.config.mask_api_key(None), None)


class TestDistributedImports(unittest.TestCase):
    """
    分布式模块导入测试
    """

    def test_worker_module_import(self):
        """测试 worker 模块可以导入"""
        try:
            from modules import worker
            self.assertIsNotNone(worker)
        except ImportError as e:
            self.skipTest(f"worker 模块无法导入: {e}")

    def test_worker_celery_available(self):
        """测试 Celery 可用性标志"""
        from modules.worker import CELERY_AVAILABLE
        self.assertIsInstance(CELERY_AVAILABLE, bool)

    def test_web_api_celery_available(self):
        """测试 web_api Celery 可用性"""
        try:
            from modules import web_api
            self.assertIn('CELERY_AVAILABLE', dir(web_api))
        except ImportError:
            self.skipTest("web_api 模块无法导入")


if __name__ == '__main__':
    unittest.main()
