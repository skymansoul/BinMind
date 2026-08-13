import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    Config,
    AI_PROVIDER_OPENAI,
    AI_PROVIDER_AZURE,
    AI_PROVIDER_OLLAMA,
    AI_PROVIDER_LLAMACPP,
    AI_PROVIDER_CUSTOM,
    check_openai_api_key,
    ensure_directories,
    validate_crash_data,
    get_crash_data_example,
    get_current_ai_model,
)


class TestConfig(unittest.TestCase):

    def setUp(self):
        pass

    def test_ai_provider_constants(self):
        """五种provider：openai/azure/ollama/llamacpp/custom"""
        self.assertEqual(AI_PROVIDER_OPENAI, 'openai')
        self.assertEqual(AI_PROVIDER_AZURE, 'azure')
        self.assertEqual(AI_PROVIDER_OLLAMA, 'ollama')
        self.assertEqual(AI_PROVIDER_LLAMACPP, 'llamacpp')
        self.assertEqual(AI_PROVIDER_CUSTOM, 'custom')

    def test_check_openai_api_key_not_set(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(check_openai_api_key())

    def test_check_openai_api_key_set(self):
        # check_openai_api_key 读取 Config.OPENAI_API_KEY（类属性），不读环境变量
        with patch('config.Config.OPENAI_API_KEY', 'sk-test123456'):
            self.assertTrue(check_openai_api_key())

    def test_check_openai_api_key_empty(self):
        """空字符串跟不设一样"""
        with patch.dict(os.environ, {'OPENAI_API_KEY': ''}):
            self.assertFalse(check_openai_api_key())

    def test_ensure_directories(self):
        with patch('os.makedirs') as mock_makedirs, \
             patch('os.path.exists', return_value=False):
            ensure_directories()

            called_dirs = {call.args[0] for call in mock_makedirs.call_args_list}

            self.assertIn(Config.LOGS_DIR, called_dirs)
            self.assertIn(Config.REPORTS_DIR, called_dirs)
            self.assertIn(Config.EXPLOITS_DIR, called_dirs)
            self.assertIn(Config.DB_DIR, called_dirs)
            self.assertIn(Config.CACHE_DIR, called_dirs)
            self.assertIn(Config.CORPUS_DIR, called_dirs)

    def test_validate_crash_data_valid_dict(self):
        crash_data = {
            'registers': {'rax': '0x0'},
            'stack_trace': ['#0 main']
        }
        is_valid, error = validate_crash_data(crash_data)
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_validate_crash_data_invalid_type(self):
        is_valid, error = validate_crash_data('not a dict')
        self.assertFalse(is_valid)
        self.assertIn('字典', error)

    def test_validate_crash_data_missing_fields(self):
        is_valid, error = validate_crash_data({})
        self.assertFalse(is_valid)
        self.assertIn('字段', error)

    def test_validate_crash_data_only_registers(self):
        is_valid, error = validate_crash_data({'registers': {'rax': '0x0'}})
        self.assertTrue(is_valid)

    def test_validate_crash_data_only_stack_trace(self):
        is_valid, error = validate_crash_data({'stack_trace': ['#0 main']})
        self.assertTrue(is_valid)

    def test_get_crash_data_example_structure(self):
        example = get_crash_data_example()
        self.assertIsInstance(example, dict)
        self.assertIn('registers', example)
        self.assertIn('stack_trace', example)
        self.assertIn('output', example)
        self.assertIn('signal', example)

    def test_config_default_values(self):
        """确保所有必需的目录都设了默认值"""
        self.assertIsNotNone(Config.LOGS_DIR)
        self.assertIsNotNone(Config.REPORTS_DIR)
        self.assertIsNotNone(Config.EXPLOITS_DIR)
        self.assertIsNotNone(Config.DB_DIR)
        self.assertIsNotNone(Config.DB_PATH)
        self.assertEqual(Config.MAX_ITERATIONS, 5)
        self.assertEqual(Config.DEFAULT_DECOMPILER, os.environ.get('DEFAULT_DECOMPILER', 'auto'))

    def test_timeout_configs(self):
        """各工具超时时间都要大于0"""
        self.assertGreater(Config.SUBPROCESS_TIMEOUT, 0)
        self.assertGreater(Config.RADARE2_TIMEOUT, 0)
        self.assertGreater(Config.GHIDRA_TIMEOUT, 0)
        self.assertGreater(Config.IDA_TIMEOUT, 0)
        self.assertGreater(Config.ANGR_TIMEOUT, 0)


class TestAIProviderConfig(unittest.TestCase):

    def test_openai_config(self):
        self.assertEqual(Config.AI_PROVIDER, os.environ.get('AI_PROVIDER', 'openai'))
        self.assertIsNotNone(Config.OPENAI_MODEL)

    def test_get_current_ai_model_default(self):
        """默认openai，走OPENAI_MODEL"""
        with patch.dict(os.environ, {'AI_PROVIDER': 'openai', 'OPENAI_MODEL': 'gpt-4'}):
            model = get_current_ai_model()
            self.assertEqual(model, 'gpt-4')

    def test_get_current_ai_model_ollama(self):
        # get_current_ai_model 读取 Config 类属性，不读环境变量
        with patch('config.Config.AI_PROVIDER', AI_PROVIDER_OLLAMA), \
             patch('config.Config.OLLAMA_MODEL', 'llama2'):
            model = get_current_ai_model()
            self.assertEqual(model, 'llama2')

    def test_get_current_ai_model_azure(self):
        # get_current_ai_model 读取 Config 类属性，不读环境变量
        with patch('config.Config.AI_PROVIDER', AI_PROVIDER_AZURE), \
             patch('config.Config.AZURE_DEPLOYMENT', 'my-gpt4-deployment'):
            model = get_current_ai_model()
            self.assertEqual(model, 'my-gpt4-deployment')

    def test_ollama_config_defaults(self):
        self.assertIsNotNone(Config.OLLAMA_HOST)
        self.assertIsNotNone(Config.OLLAMA_MODEL)

    def test_llamacpp_config_defaults(self):
        self.assertIsNotNone(Config.LLAMACPP_HOST)


class TestDecompilerConfig(unittest.TestCase):

    def test_default_decompiler(self):
        """默认反编译器 —— auto会按优先级尝试"""
        default = Config.DEFAULT_DECOMPILER
        self.assertIn(default, ['auto', 'radare2', 'ghidra', 'ida'])

    def test_symbolic_execution_config(self):
        """符号执行开关 —— 默认可能是True也可能是False，看环境"""
        self.assertIsInstance(Config.ENABLE_SYMBOLIC_EXECUTION, bool)


if __name__ == '__main__':
    unittest.main()
