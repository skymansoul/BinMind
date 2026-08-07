

class TestRepackDetector(unittest.TestCase):
    """
    测试重打包检测器类
    """
    
    def setUp(self):
        self.m_tmp = tempfile.mkdtemp()
        self.config = RepackConfig(
            known_signatures_db=os.path.join(self.m_tmp, 'signatures.json')
        )
        
        # 创建空的签名数据库
        with open(self.config.known_signatures_db, 'w', encoding='utf-8') as f:
            json.dump({}, f)
        
        self.detector = RepackDetector(self.config)
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.m_tmp, ignore_errors=True)
    
    def test_detector_init(self):
        self.assertIsInstance(self.detector, RepackDetector)
    
    def test_detect_file_type(self):
        # PE文件
        pe_data = b'MZ' + b'\x00' * 58 + b'PE\x00\x00'
        file_type = self.detector._detect_file_type(pe_data)
        self.assertEqual(file_type, 'pe')
        
        # ELF文件
        elf_data = b'\x7fELF'
        file_type = self.detector._detect_file_type(elf_data)
        self.assertEqual(file_type, 'elf')
        
        # DEX文件
        dex_data = b'dex\n'
        file_type = self.detector._detect_file_type(dex_data)
lass字段完整性$/d
        self.assertEqual(file_type, 'dex')
    
    def test_calculate_entropy(self):
        # 低熵（重复数据）
        low_entropy_data = b'\x00' * 100
        entropy = self.detector._calculate_entropy(low_entropy_data)
        self.assertEqual(entropy, 0.0)
        
        # 高熵（随机数据）
        high_entropy_data = bytes(range(256))
        entropy = self.detector._calculate_entropy(high_entropy_data)
        self.assertGreater(entropy, 7.0)
    
    def test_is_section_anomalous(self):
        """
        测试节区异常检测
        """
        # 正常节区
        is_anomalous = self.detector._is_section_anomalous('.text', 5.0, 0x1000, 0x1000)
        self.assertFalse(is_anomalous)
        
        # 异常名称
        is_anomalous = self.detector._is_section_anomalous('.inject', 5.0, 0x1000, 0x1000)
        self.assertTrue(is_anomalous)
        
        # 高熵值
        is_anomalous = self.detector._is_section_anomalous('.text', 7.5, 0x1000, 0x1000)
        self.assertTrue(is_anomalous)
    
    def test_detect_pe_file(self):
        """
        测试PE文件检测
        """
        # 创建简单的PE文件
        pe_file = os.path.join(self.m_tmp, 'test.exe')
        
        # 构造最小PE结构
        pe_data = bytearray(1024)
        pe_data[:2] = b'MZ'  # DOS头
        pe_data[0x3C:0x40] = struct.pack('<I', 0x40)  # PE头偏移
        pe_data[0x40:0x44] = b'PE\x00\x00'  # PE签名
        
        with open(pe_file, 'wb') as f:
            f.write(pe_data)
        
        result = self.detector.detect(pe_file)
        self.assertIsInstance(result, RepackResult)
    
    def test_detect_elf_file(self):
                """
        测试ELF文件检测
        """
        elf_file = os.path.join(self.m_tmp, 'test.elf')
        
        # 构造最小ELF结构
        elf_data = bytearray(64)
        elf_data[:4] = b'\x7fELF'  # ELF魔数
        elf_data[4] = 2  # 64位
        elf_data[5] = 1  # 小端
        
        with open(elf_file, 'wb') as f:
            f.write(elf_data)
        
        result = self.detector.detect(elf_file)
        self.assertIsInstance(result, RepackResult)
    
    def test_detect_unknown_file(self):
        unknown_file = os.path.join(self.m_tmp, 'test.bin')
        with open(unknown_file, 'wb') as f:
            f.write(b'unknown data')
        
        result = self.detector.detect(unknown_file)
        self.assertIsInstance(result, RepackResult)
    
    def test_determine_repack_type(self):
        """
        测试确定重打包类型
        """
        result = RepackResult()
        result.anomalies = [Anomaly(type='anomalous_section')]
        
        repack_type = self.detector._determine_repack_type(result)
        self.assertEqual(repack_type, RepackType.INJECTED_CODE)
    
    def test_determine_severity(self):
        """
        测试确定严重程度
        """
        result = RepackResult()
        result.anomalies = [
            Anomaly(severity=Severity.HIGH),
            Anomaly(severity=Severity.MEDIUM)
        ]
        
        severity = self.detector._determine_severity(result)
        self.assertEqual(severity, Severity.MEDIUM)
    
    def test_calculate_risk_score(self):
        result = RepackResult()
        result.anomalies = [
            Anomaly(severity=Severity.HIGH),
            Anomaly(severity=Severity.MEDIUM)
        ]
        result.overlay_size = 1024
        
        score = self.detector._calculate_risk_score(result)
        self.assertGreater(score, 0)
    
    def test_generate_recommendation(self):
        # 未重打包
        result = RepackResult(is_repacked=False)
        recommendation = self.detector._generate_recommendation(result)
        self.assertIn('可信', recommendation)
        
        # 已重打包
        result = RepackResult(
            is_repacked=True,
            repack_type=RepackType.INJECTED_CODE,
            severity=Severity.HIGH
        )
        recommendation = self.detector._generate_recommendation(result)
        self.assertIn('注入', recommendation)
    
    def test_generate_report(self):
        """
        测试生成报告
        """
        result = RepackResult(
            is_repacked=True,
            risk_score=75.0
        )
        
        report = self.detector.generate_report(result, 'test.exe')
        self.assertIsInstance(report, dict)
        self.assertIn('is_repacked', report)
lass字段完整性$/d
        self.assertIn('risk_score', report)
    
    def test_save_report(self):
        """
        测试保存报告
        """
        result = RepackResult()
        test_file = os.path.join(self.m_tmp, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'test')
        
        report_path = self.detector.save_report(result, test_file)
        self.assertTrue(os.path.exists(report_path))


class TestRepackDetectorFunctions(unittest.TestCase):
    """
    测试重打包检测器便捷函数
    """
    
    def test_create_repack_detector(self):
                """
        测试创建检测器便捷函数
        """
        detector = create_repack_detector()
        self.assertIsInstance(detector, RepackDetector)



if __name__ == '__main__':
    unittest.main(verbosity=2)


