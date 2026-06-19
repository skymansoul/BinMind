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

    def test_distributed_enabled_default(self):
        """测试 DISTRIBUTED_ENABLED 默认值"""
        self.assertIsInstance(self.config.Config.DISTRIBUTED_ENABLED, bool)

    def test_celery_task_queue_default(self):
        """测试 CELERY_TASK_QUEUE 默认值"""
        self.assertIsInstance(self.config.Config.CELERY_TASK_QUEUE, str)
        self.assertIn('deemo', self.config.Config.CELERY_TASK_QUEUE)

    def test_celery_max_retries_default(self):
        """测试 CELERY_MAX_RETRIES 默认值"""
        self.assertIsInstance(self.config.Config.CELERY_MAX_RETRIES, int)
        self.assertGreater(self.config.Config.CELERY_MAX_RETRIES, 0)

    def test_redis_url_default(self):
        """测试 REDIS_URL 默认值"""
        self.assertIsInstance(self.config.Config.REDIS_URL, str)
        self.assertTrue(self.config.Config.REDIS_URL.startswith('redis://'))

    def test_worker_heartbeat_interval_default(self):
        """测试 WORKER_HEARTBEAT_INTERVAL 默认值"""
        self.assertIsInstance(self.config.Config.WORKER_HEARTBEAT_INTERVAL, int)
        self.assertGreater(self.config.Config.WORKER_HEARTBEAT_INTERVAL, 0)

    def test_worker_timeout_default(self):
        """测试 WORKER_TIMEOUT 默认值"""
        self.assertIsInstance(self.config.Config.WORKER_TIMEOUT, int)
        self.assertGreater(self.config.Config.WORKER_TIMEOUT, 0)


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
        self.assertIn('***MASKED***', masked)
        self.assertNotIn('mypassword', masked)

    def test_mask_redis_url_special_password(self):
        """测试带特殊字符密码的 Redis URL"""
        url = 'redis://user:p@ss:w0rd@localhost:6379/0'
        masked = self.config.mask_redis_url(url)
        self.assertIn('***MASKED***', masked)
        self.assertNotIn('p@ss:w0rd', masked)

    def test_mask_redis_url_empty(self):
        """测试空 URL"""
        self.assertEqual(self.config.mask_redis_url(''), '')
        self.assertEqual(self.config.mask_redis_url(None), '')

    def test_mask_redis_url_invalid(self):
        """测试无效 URL"""
        url = 'not_a_redis_url'
        self.assertEqual(self.config.mask_redis_url(url), url)


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
        """测试缓存键格式"""
        key = self.config.get_task_cache_key('test.bin', {'enable_symbolic': True})
        self.assertTrue(key.startswith('deemo:cache:task:'))

    def test_get_task_cache_key_contains_functions(self):
        """测试缓存键包含函数列表"""
        key1 = self.config.get_task_cache_key('test.bin', {'functions': ['main']})
        key2 = self.config.get_task_cache_key('test.bin', {'functions': ['main', 'vuln_func']})
        self.assertNotEqual(key1, key2)


class TestAnalysisTaskManagerStandalone(unittest.TestCase):
    """
    分析任务管理器独立测试（不依赖 web_api 模块）
    """

    def setUp(self):
        """设置测试环境"""
        self.temp_dir = tempfile.mkdtemp()
        os.environ['DATA_DIR'] = self.temp_dir
        
    def tearDown(self):
        """清理测试环境"""
        if 'DATA_DIR' in os.environ:
            del os.environ['DATA_DIR']
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_task_manager_import_works(self):
        """测试 web_api 可以导入"""
        try:
            import modules.web_api
            self.assertIsNotNone(modules.web_api)
        except Exception as e:
            self.skipTest(f"web_api 模块无法导入，可能缺少依赖: {e}")

    def test_config_functions_work(self):
        """测试 config 函数工作正常"""
        import importlib
        import config
        importlib.reload(config)
        
        # 测试 mask_redis_url
        self.assertEqual(config.mask_redis_url(''), '')
        
        # 测试 get_task_cache_key
        key = config.get_task_cache_key('test', {})
        self.assertIsInstance(key, str)
        self.assertTrue(len(key) > 0)


if __name__ == '__main__':
    unittest.main()
