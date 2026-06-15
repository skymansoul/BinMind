import os
import sys
import unittest
from unittest.mock import patch, MagicMock, mock_open

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.instrumentation import (
    InstrumentationManager, InstrumentationMode, HookTemplateType,
    HookTemplate, FRIDA_AVAILABLE
)


class TestInstrumentationManager(unittest.TestCase):
    """二进制插桩管理器测试类"""

    def setUp(self):
        """测试前准备"""
        self.test_dir = os.path.dirname(__file__)
        self.logs_dir = os.path.join(self.test_dir, '..', 'logs', 'instrumentation')
        os.makedirs(self.logs_dir, exist_ok=True)

    def test_is_frida_available(self):
        """测试 Frida 是否可用"""
        manager = InstrumentationManager()
        result = manager.is_frida_available()
        self.assertEqual(result, FRIDA_AVAILABLE)

    def test_generate_anti_debug_script(self):
        """测试生成反调试脚本"""
        manager = InstrumentationManager()
        script = manager._generate_anti_debug_script()
        
        self.assertIsInstance(script, str)
        self.assertIn('Interceptor.attach', script)
        self.assertIn('ptrace', script)
        self.assertIn('waitpid', script)
        self.assertIn('getpid', script)

    def test_generate_ret_override_script(self):
        """测试生成返回值修改脚本"""
        manager = InstrumentationManager()
        script = manager._generate_ret_override_script('test_func', 0x1337)
        
        self.assertIsInstance(script, str)
        self.assertIn('test_func', script)
        self.assertIn('0x1337', script)
        self.assertIn('Interceptor.attach', script)

    def test_generate_syscall_monitor_script(self):
        """测试生成系统调用监控脚本"""
        manager = InstrumentationManager()
        script = manager._generate_syscall_monitor_script()
        
        self.assertIsInstance(script, str)
        self.assertIn('open', script)
        self.assertIn('read', script)
        self.assertIn('write', script)
        self.assertIn('execve', script)
        self.assertIn('fork', script)
        self.assertIn('socket', script)

    def test_generate_memory_dump_script(self):
        """测试生成内存 dump 脚本"""
        manager = InstrumentationManager()
        script = manager._generate_memory_dump_script('0x1000', 0x100)
        
        self.assertIsInstance(script, str)
        self.assertIn('0x1000', script)
        self.assertIn('256', script)  # 0x100 = 256
        self.assertIn('readByteArray', script)
        self.assertIn('hexdump', script)

    def test_generate_argument_replace_script(self):
        """测试生成参数替换脚本"""
        manager = InstrumentationManager()
        script = manager._generate_argument_replace_script('test_func', 0, 0xdeadbeef)
        
        self.assertIsInstance(script, str)
        self.assertIn('test_func', script)
        self.assertIn('3735928559', script)  # 0xdeadbeef in decimal
        self.assertIn('Interceptor.attach', script)

    def test_generate_function_trace_script(self):
        """测试生成函数追踪脚本"""
        manager = InstrumentationManager()
        script = manager._generate_function_trace_script()
        
        self.assertIsInstance(script, str)
        self.assertIn('malloc', script)
        self.assertIn('free', script)
        self.assertIn('calloc', script)
        self.assertIn('realloc', script)

    def test_generate_template_script_anti_debug(self):
        """测试生成反调试模板脚本"""
        manager = InstrumentationManager()
        script = manager.generate_template_script('anti_debug')
        
        self.assertIsInstance(script, str)
        self.assertIn('Interceptor.attach', script)

    def test_generate_template_script_ret_override(self):
        """测试生成返回值修改模板脚本"""
        manager = InstrumentationManager()
        params = {'func_name': 'exit', 'return_value': 0}
        script = manager.generate_template_script('ret_override', params)
        
        self.assertIsInstance(script, str)
        self.assertIn('exit', script)

    def test_generate_template_script_syscall_monitor(self):
        """测试生成系统调用监控模板脚本"""
        manager = InstrumentationManager()
        script = manager.generate_template_script('syscall_monitor')
        
        self.assertIsInstance(script, str)
        self.assertIn('monitoredCalls', script)

    def test_generate_template_script_memory_dump(self):
        """测试生成内存 dump 模板脚本"""
        manager = InstrumentationManager()
        params = {'address': '0x1000', 'size': 256}
        script = manager.generate_template_script('memory_dump', params)
        
        self.assertIsInstance(script, str)
        self.assertIn('0x1000', script)

    def test_generate_template_script_argument_replace(self):
        """测试生成参数替换模板脚本"""
        manager = InstrumentationManager()
        params = {'func_name': 'open', 'arg_index': 0, 'new_value': 0}
        script = manager.generate_template_script('argument_replace', params)
        
        self.assertIsInstance(script, str)
        self.assertIn('open', script)

    def test_generate_template_script_function_trace(self):
        """测试生成函数追踪模板脚本"""
        manager = InstrumentationManager()
        script = manager.generate_template_script('function_trace')
        
        self.assertIsInstance(script, str)
        self.assertIn('functionTrace', script)

    def test_generate_template_script_unknown(self):
        """测试生成未知模板脚本"""
        manager = InstrumentationManager()
        script = manager.generate_template_script('unknown_template')
        
        self.assertIsNone(script)

    def test_load_custom_script_valid(self):
        """测试加载有效的自定义脚本"""
        test_script_path = os.path.join(self.logs_dir, 'test_script.js')
        test_content = 'console.log("test");'
        
        with open(test_script_path, 'w') as f:
            f.write(test_content)
        
        manager = InstrumentationManager()
        script = manager.load_custom_script(test_script_path)
        
        self.assertEqual(script, test_content)
        
        os.remove(test_script_path)

    def test_load_custom_script_nonexistent(self):
        """测试加载不存在的脚本"""
        manager = InstrumentationManager()
        script = manager.load_custom_script('/nonexistent/path/script.js')
        
        self.assertIsNone(script)

    def test_list_available_templates(self):
        """测试列出可用的钩子模板"""
        manager = InstrumentationManager()
        templates = manager.list_available_templates()
        
        self.assertIsInstance(templates, list)
        self.assertGreater(len(templates), 0)
        
        template_names = [t['name'] for t in templates]
        self.assertIn('anti_debug', template_names)
        self.assertIn('ret_override', template_names)
        self.assertIn('syscall_monitor', template_names)
        self.assertIn('memory_dump', template_names)
        self.assertIn('argument_replace', template_names)
        self.assertIn('function_trace', template_names)

    def test_parse_template_args_simple(self):
        """测试解析简单的模板参数"""
        manager = InstrumentationManager()
        templates, params = manager.parse_template_args('anti_debug,syscall_monitor')
        
        self.assertEqual(templates, ['anti_debug', 'syscall_monitor'])
        self.assertEqual(params, {})

    def test_parse_template_args_with_params(self):
        """测试解析带参数的模板"""
        manager = InstrumentationManager()
        templates, params = manager.parse_template_args(
            'ret_override,syscall_monitor,ret_override:func_name=exit,ret_override:return_value=0'
        )
        
        self.assertEqual(templates, ['ret_override', 'syscall_monitor'])
        self.assertIn('ret_override', params)
        self.assertEqual(params['ret_override']['func_name'], 'exit')
        self.assertEqual(params['ret_override']['return_value'], 0)

    def test_parse_template_args_empty(self):
        """测试解析空参数"""
        manager = InstrumentationManager()
        templates, params = manager.parse_template_args('')
        
        self.assertEqual(templates, [])
        self.assertEqual(params, {})

    def test_parse_template_args_none(self):
        """测试解析 None 参数"""
        manager = InstrumentationManager()
        templates, params = manager.parse_template_args(None)
        
        self.assertEqual(templates, [])
        self.assertEqual(params, {})

    def test_parse_param_value_integer(self):
        """测试解析整数值"""
        manager = InstrumentationManager()
        
        self.assertEqual(manager._parse_param_value('42'), 42)
        self.assertEqual(manager._parse_param_value('0x10'), 16)
        self.assertEqual(manager._parse_param_value('-1'), -1)

    def test_parse_param_value_float(self):
        """测试解析浮点数值"""
        manager = InstrumentationManager()
        
        self.assertEqual(manager._parse_param_value('3.14'), 3.14)
        self.assertEqual(manager._parse_param_value('-2.5'), -2.5)

    def test_parse_param_value_boolean(self):
        """测试解析布尔值"""
        manager = InstrumentationManager()
        
        self.assertTrue(manager._parse_param_value('true'))
        self.assertTrue(manager._parse_param_value('True'))
        self.assertFalse(manager._parse_param_value('false'))
        self.assertFalse(manager._parse_param_value('False'))

    def test_parse_param_value_string(self):
        """测试解析字符串值"""
        manager = InstrumentationManager()
        
        self.assertEqual(manager._parse_param_value('test'), 'test')
        self.assertEqual(manager._parse_param_value('hello_world'), 'hello_world')

    def test_ensure_output_dir(self):
        """测试确保输出目录存在"""
        test_dir = os.path.join(self.logs_dir, 'test_subdir')
        manager = InstrumentationManager()
        manager.output_dir = test_dir
        
        self.assertFalse(os.path.exists(test_dir))
        manager._ensure_output_dir()
        self.assertTrue(os.path.exists(test_dir))
        
        os.rmdir(test_dir)

    def test_detach_without_session(self):
        """测试在没有会话的情况下分离"""
        manager = InstrumentationManager()
        manager.frida_session = None
        
        # 应该不会抛出异常
        manager.detach()

    def test_spawn_process_frida_available(self):
        """测试启动进程（Frida 可用时）- 模拟 frida 已安装"""
        original_frida_available = FRIDA_AVAILABLE
        import modules.instrumentation
        modules.instrumentation.FRIDA_AVAILABLE = True
        
        mock_frida = MagicMock()
        mock_frida.spawn.return_value = 12345
        modules.instrumentation.frida = mock_frida
        
        manager = InstrumentationManager()
        result = manager.spawn_process('/bin/ls')
        
        self.assertTrue(result)
        self.assertEqual(manager.target_process, 12345)
        self.assertEqual(manager.mode, InstrumentationMode.SPAWN)
        
        modules.instrumentation.FRIDA_AVAILABLE = original_frida_available

    def test_spawn_process_frida_error(self):
        """测试启动进程失败"""
        original_frida_available = FRIDA_AVAILABLE
        import modules.instrumentation
        modules.instrumentation.FRIDA_AVAILABLE = True
        
        mock_frida = MagicMock()
        mock_frida.spawn.side_effect = Exception('Spawn failed')
        modules.instrumentation.frida = mock_frida
        
        manager = InstrumentationManager()
        result = manager.spawn_process('/bin/ls')
        
        self.assertFalse(result)
        
        modules.instrumentation.FRIDA_AVAILABLE = original_frida_available

    def test_attach_process(self):
        """测试附加到进程"""
        original_frida_available = FRIDA_AVAILABLE
        import modules.instrumentation
        modules.instrumentation.FRIDA_AVAILABLE = True
        
        mock_frida = MagicMock()
        mock_session = MagicMock()
        mock_frida.attach.return_value = mock_session
        modules.instrumentation.frida = mock_frida
        
        manager = InstrumentationManager()
        result = manager.attach_process(12345)
        
        self.assertTrue(result)
        self.assertEqual(manager.frida_session, mock_session)
        self.assertEqual(manager.mode, InstrumentationMode.ATTACH)
        
        modules.instrumentation.FRIDA_AVAILABLE = original_frida_available

    def test_run_instrumentation_no_frida(self):
        """测试在 Frida 不可用时运行插桩"""
        original_frida_available = FRIDA_AVAILABLE
        import modules.instrumentation
        modules.instrumentation.FRIDA_AVAILABLE = False
        
        manager = InstrumentationManager()
        result = manager.run_instrumentation(target_path='/bin/ls')
        
        self.assertFalse(result['success'])
        self.assertIn('Frida 未安装', result['errors'])
        
        modules.instrumentation.FRIDA_AVAILABLE = original_frida_available

    def test_save_logs(self):
        """测试保存插桩日志"""
        manager = InstrumentationManager()
        manager.target_process = 12345
        manager.mode = InstrumentationMode.SPAWN
        manager.scripts = ['test script']
        
        log_path = manager.save_logs()
        
        self.assertIsNotNone(log_path)
        self.assertTrue(os.path.exists(log_path))
        
        os.remove(log_path)


if __name__ == '__main__':
    unittest.main()
