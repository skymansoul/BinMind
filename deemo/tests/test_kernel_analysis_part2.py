

class TestKernelExploitGenerator(unittest.TestCase):
    """
    测试内核利用策略生成功能
    """

    def setUp(self):
        self.binary_info = {
            'binary_path': './test_module.ko',
            'format': 'KO',
            'arch': 'x64',
            'bits': 64,
            'endian': 'little',
            'module_name': 'test_module',
            'module_type': 'Linux Kernel Module',
            'is_kernel_module': True
        }

    def test_is_kernel_module_detection(self):
        from modules.exploit.exploit_gen import ExploitGenerator

        with patch('modules.exploit_gen.ROPChainBuilder') as mock_rop:
            mock_instance = MagicMock()
            mock_rop.return_value = mock_instance

            generator = ExploitGenerator(
                './test_module.ko',
                self.binary_info,
                openai_client=None
            )

            self.assertTrue(generator.is_kernel_module())

    def test_is_not_kernel_module(self):
        """
        测试非内核模块检测
        """
        from modules.exploit.exploit_gen import ExploitGenerator

        userland_info = {
            'binary_path': './test_binary',
            'format': 'ELF',
            'arch': 'x64',
            'bits': 64,
            'endian': 'little'
        }

        with patch('modules.exploit_gen.ROPChainBuilder') as mock_rop:
            mock_instance = MagicMock()
            mock_rop.return_value = mock_instance

            generator = ExploitGenerator(
                './test_binary',
                userland_info,
                openai_client=None
            )

            self.assertFalse(generator.is_kernel_module())

    def test_get_module_type_linux(self):
        """
        测试获取Linux内核模块类型
        """
        from modules.exploit.exploit_gen import ExploitGenerator

        with patch('modules.exploit_gen.ROPChainBuilder') as mock_rop:
            mock_instance = MagicMock()
            mock_rop.return_value = mock_instance

            generator = ExploitGenerator(
                './test_module.ko',
                self.binary_info,
                openai_client=None
            )

            module_type = generator.get_module_type()
            self.assertEqual(module_type, 'KO')

    def test_get_module_type_windows(self):
        """
        测试获取Windows驱动类型
        """
        from modules.exploit.exploit_gen import ExploitGenerator

        windows_info = {
            'binary_path': './test_driver.sys',
            'format': 'SYS',
            'arch': 'x64',
            'bits': 64,
            'is_windows_driver': True,
            'module_name': 'test_driver',
            'module_type': 'Windows Driver'
        }

        with patch('modules.exploit_gen.ROPChainBuilder') as mock_rop:
            mock_instance = MagicMock()
            mock_rop.return_value = mock_instance

            generator = ExploitGenerator(
                './test_driver.sys',
                windows_info,
                openai_client=None
            )

            module_type = generator.get_module_type()
            self.assertEqual(module_type, 'SYS')

    def test_kernel_exploit_strategy_contains_disclaimer(self):
        """
        测试内核利用策略包含免责声明
        """
        from modules.exploit.exploit_gen import ExploitGenerator

        with patch('modules.exploit_gen.ROPChainBuilder') as mock_rop:
            mock_instance = MagicMock()
            mock_rop.return_value = mock_instance

            generator = ExploitGenerator(
                './test_module.ko',
                self.binary_info,
                openai_client=None
            )

            vulnerability_info = {
                'type': 'Buffer Overflow',
                'description': '内核栈缓冲区溢出',
                'location': 'ioctl_handler+0x50',
                'severity': 'Critical'
            }

            strategy = generator.generate_kernel_exploit_strategy(
                vulnerability_info,
                use_ai=False
            )

            self.assertIn('is_kernel_module', strategy)
            self.assertTrue(strategy['is_kernel_module'])
            self.assertIn('disclaimer', strategy)
            self.assertIn('内核漏洞利用高度依赖', strategy['disclaimer'])


class TestKernelCommandLineArgs(unittest.TestCase):
    """
    测试内核模块分析命令行参数
    """

    def test_kernel_argument_exists(self):
        """
        测试--kernel参数是否已添加到解析器
        """
        import io
        import sys
        import main

        original_argv = sys.argv.copy()
        sys.argv = ['main.py']

        try:
            parsed = main.parse_arguments()
            self.assertTrue(hasattr(parsed, 'kernel'))
        finally:
            sys.argv = original_argv

    def test_kernel_argument_default_value(self):
        """
        测试--kernel参数默认值为False
        """
        import main

        original_argv = sys.argv.copy()
        sys.argv = ['main.py']

        try:
            parsed = main.parse_arguments()
            self.assertFalse(parsed.kernel)
        finally:
            sys.argv = original_argv

    def test_kernel_argument_with_flag(self):
        """
        测试--kernel参数设置后为True
        """
        import sys
        import main

        original_argv = sys.argv.copy()
        sys.argv = ['main.py', '--kernel']

        try:
            parsed = main.parse_arguments()
            self.assertTrue(parsed.kernel)
        finally:
            sys.argv = original_argv


class TestForceKernelMode(unittest.TestCase):
    """
    测试强制内核模式功能
    """

    def setUp(self):
        """
        测试前初始化
        """
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """
        测试后清理
        """
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_get_binary_info_force_kernel_parameter(self):
        from modules.info.info_collect import get_binary_info

        elf_path = os.path.join(self.temp_dir, 'test_elf.elf')
        with open(elf_path, 'wb') as f:
            f.write(b'\x7fELF' + b'\x00' * 100)

        with patch('modules.info_collect.validate_file') as mock_validate:
            mock_validate.return_value = (True, None)

            with patch('modules.info_collect.detect_binary_format') as mock_detect:
                mock_detect.return_value = 'ELF'

                with patch('modules.info_collect.load_elf') as mock_load_elf:
                    mock_elf = MagicMock()
                    mock_load_elf.return_value = mock_elf

                    with patch('modules.info_collect.get_checksec_elf') as mock_checksec:
                        mock_checksec.return_value = {'nx': True}

                        with patch('modules.info_collect.get_imported_functions') as mock_imports:
                            mock_imports.return_value = {'all_imports': {}, 'dangerous_functions': []}

                            with patch('modules.info_collect.get_key_strings') as mock_strings:
                                mock_strings.return_value = []

                                with patch('modules.info_collect.get_symbols') as mock_symbols:
                                    mock_symbols.return_value = {}

                                    with patch('modules.info_collect.get_functions') as mock_funcs:
                                        mock_funcs.return_value = []

                                        info = get_binary_info(elf_path, force_kernel=False)
                                        self.assertIsInstance(info, dict)


def run_tests():
    """
    运行所有测试
    """
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestKernelBinaryFormatDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestKernelDangerousFunctions))
    suite.addTests(loader.loadTestsFromTestCase(TestKernelPrompts))
    suite.addTests(loader.loadTestsFromTestCase(TestKernelExploitGenerator))
    suite.addTests(loader.loadTestsFromTestCase(TestKernelCommandLineArgs))
    suite.addTests(loader.loadTestsFromTestCase(TestForceKernelMode))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
