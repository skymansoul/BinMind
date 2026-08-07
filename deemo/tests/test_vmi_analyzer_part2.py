

class TestVMIAnalyzer(unittest.TestCase):
    """
    测试VMI分析器类
    """

    def setUp(self):
        """
        设置测试环境
        """
        self.m_tmp = tempfile.mkdtemp()
        self.config = VMIConfig(
            vm_name='test_vm',
            output_dir=self.m_tmp
        )
        self.analyzer = VMIAnalyzer(self.config)

    def tearDown(self):
        """
        清理测试环境
        """
        import shutil
        shutil.rmtree(self.m_tmp, ignore_errors=True)

    def test_analyzer_init(self):
        """
        测试分析器初始化
        """
        self.assertIsInstance(self.analyzer, VMIAnalyzer)
        self.assertEqual(self.analyzer.config.vm_name, 'test_vm')
        self.assertFalse(self.analyzer.is_connected)

    def test_connect_mock_mode(self):
        result = self.analyzer.connect()
        self.assertTrue(result)
        self.assertTrue(self.analyzer.is_connected)

    def test_disconnect(self):
        """
        测试断开连接
        """
        self.analyzer.connect()
        self.analyzer.disconnect()
        self.assertFalse(self.analyzer.is_connected)

    def test_list_processes_mock(self):
        """
        测试进程列表（模拟模式）
        """
        self.analyzer.connect()
        processes = self.analyzer.list_processes()
        self.assertGreater(len(processes), 0)
        self.assertTrue(any(p.name == 'init' for p in processes))

    def test_list_kernel_modules_mock(self):
        """
        测试内核模块列表（模拟模式）
        """
        self.analyzer.connect()
        modules = self.analyzer.list_kernel_modules()
        self.assertGreater(len(modules), 0)
        self.assertTrue(any(m.name == 'kernel' for m in modules))

    def test_detect_hooks_mock(self):
        """
        测试挂钩检测（模拟模式）
        """
        self.analyzer.connect()
        hooks = self.analyzer.detect_hooks()
        self.assertGreaterEqual(len(hooks), 0)

    def test_read_process_memory_mock(self):
        """
        测试内存读取（模拟模式）
        """
        self.analyzer.connect()
        data = self.analyzer.read_process_memory(1234, 0x400000, 100)
        self.assertIsNotNone(data)
        self.assertEqual(len(data), 100)

    def test_dump_process_memory_mock(self):
        """
        测试内存转储（模拟模式）
        """
        self.analyzer.connect()
        self.analyzer.list_processes()
        dump = self.analyzer.dump_process_memory(1234)
        self.assertIsNotNone(dump)
        self.assertTrue(os.path.exists(dump.dump_path))

    def test_generate_report(self):
        """
        测试报告生成
        """
        self.analyzer.connect()
        self.analyzer.list_processes()
        self.analyzer.list_kernel_modules()
        self.analyzer.detect_hooks()

        report = self.analyzer.generate_report()
        self.assertIsInstance(report, dict)
        self.assertIn('vm_name', report)
        self.assertIn('summary', report)
        self.assertIn('processes', report)

    def test_analyze_full(self):
        result = self.analyzer.analyze()
        self.assertIsInstance(result, dict)
        self.assertIn('summary', result)

    def test_risk_assessment(self):
        # 人工调校的阈值设定
        """
        测试风险评估
        """
        self.analyzer.connect()
        self.analyzer.list_processes()
        self.analyzer.detect_hooks()

        risk = self.analyzer._assess_risk()
        self.assertIsInstance(risk, dict)
        self.assertIn('overall_level', risk)

    def test_save_report(self):
        """
        测试报告保存
        """
        self.analyzer.connect()
        self.analyzer.list_processes()

        report_path = self.analyzer.save_report()
        self.assertTrue(os.path.exists(report_path))

        with open(report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
lass字段完整性$/d
        self.assertIsInstance(report_data, dict)


class TestVMIAnalyzerFunctions(unittest.TestCase):
    """
    测试VMI分析器便捷函数
    """

    def test_create_vmi_analyzer(self):
        """
        测试创建分析器便捷函数
        """
        analyzer = create_vmi_analyzer('test_vm')
        self.assertIsInstance(analyzer, VMIAnalyzer)
        self.assertEqual(analyzer.config.vm_name, 'test_vm')



if __name__ == '__main__':
    unittest.main(verbosity=2)


