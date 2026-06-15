import os
import sys
import unittest
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.memory_manipulation import (
    MemoryManipulationDetector,
    InjectionIndicator,
    detect_memory_manipulation,
    scan_for_injection_imports,
    analyze_injection_risk
)


class TestMemoryManipulationDetector(unittest.TestCase):
    def setUp(self):
        """创建临时测试文件"""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file_path = self.temp_file.name
        self.temp_file.close()
    
    def tearDown(self):
        """清理临时文件"""
        if os.path.exists(self.temp_file_path):
            os.unlink(self.temp_file_path)
    
    def test_detector_init(self):
        detector = MemoryManipulationDetector(self.temp_file_path)
        self.assertEqual(detector.binary_path, self.temp_file_path)
    
    def test_extract_strings(self):
        detector = MemoryManipulationDetector(self.temp_file_path)
        strings = detector._extract_strings()
        self.assertIsInstance(strings, list)
    
    def test_check_imports(self):
        detector = MemoryManipulationDetector()
        detector._extract_imports = lambda: ['CreateRemoteThread', 'WriteProcessMemory', 'OpenProcess']
        detector._check_imports()
        self.assertGreater(len(detector.suspicious_imports), 0)
    
    def test_check_strings(self):
        detector = MemoryManipulationDetector(self.temp_file_path)
        with open(self.temp_file_path, 'w') as f:
            f.write('RemoteThread Inject Shellcode')
        detector._check_strings()
        self.assertGreater(len(detector.injection_indicators), 0)
    
    def test_detect_injection_sequence(self):
        detector = MemoryManipulationDetector()
        detector._extract_imports = lambda: ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread']
        detector._detect_injection_sequence()
        self.assertGreater(len(detector.injection_indicators), 0)
    
    def test_analyze_empty_binary(self):
        result = detect_memory_manipulation(self.temp_file_path)
        self.assertEqual(result.filename, os.path.basename(self.temp_file_path))
        self.assertEqual(result.injection_risk, 'none')
    
    def test_generate_report(self):
        detector = MemoryManipulationDetector(self.temp_file_path)
        report = detector.generate_report()
        self.assertIsInstance(report, str)
        self.assertIn('内存扫描与注入技术分析报告', report)
    
    def test_calculate_risk(self):
        detector = MemoryManipulationDetector()
        detector.injection_indicators = [
            InjectionIndicator('test', 'high', 'desc', 'ev', 'rec'),
            InjectionIndicator('test', 'high', 'desc', 'ev', 'rec'),
            InjectionIndicator('test', 'medium', 'desc', 'ev', 'rec')
        ]
        score, level = detector._calculate_risk()
        self.assertEqual(score, 40)  # 100 - 25*2 - 10 = 40
        self.assertEqual(level, 'medium')


if __name__ == '__main__':
    unittest.main()