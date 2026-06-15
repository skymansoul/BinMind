import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 直接导入模块，避免触发 __init__.py 的导入
import importlib.util
spec = importlib.util.spec_from_file_location("seh_analyzer", 
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'modules', 'seh_analyzer.py'))
seh_analyzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seh_analyzer)

SEHAnalyzer = seh_analyzer.SEHAnalyzer
SEHAnalysisResult = seh_analyzer.SEHAnalysisResult
SEHChainStatus = seh_analyzer.SEHChainStatus
VEHStatus = seh_analyzer.VEHStatus
SEHRecord = seh_analyzer.SEHRecord
VEHandler = seh_analyzer.VEHandler


class TestSEHAnalyzer(unittest.TestCase):

    def test_init_with_path(self):
        analyzer = SEHAnalyzer(pe_path='test.exe')
        self.assertIsNotNone(analyzer)
        self.assertEqual(analyzer.pe_path, 'test.exe')

    def test_init_with_data(self):
        pe_data = b'MZ' + b'\x00' * 100
        analyzer = SEHAnalyzer(pe_data=pe_data)
        self.assertIsNotNone(analyzer)
        self.assertEqual(analyzer.pe_data[:2], b'MZ')

    def test_is_pe_binary(self):
        pe_data = b'MZ' + b'\x00' * 100
        analyzer = SEHAnalyzer(pe_data=pe_data)
        self.assertTrue(analyzer._is_pe_binary())

    def test_is_not_pe_binary(self):
        analyzer = SEHAnalyzer(pe_data=b'ELF\x7f')
        self.assertFalse(analyzer._is_pe_binary())

    def test_analyze_non_pe(self):
        analyzer = SEHAnalyzer(pe_data=b'not a pe file')
        result = analyzer.analyze()
        self.assertEqual(result.seh_chain_status, SEHChainStatus.UNKNOWN)
        self.assertEqual(result.veh_status, VEHStatus.NONE)

    def test_analyze_empty_data(self):
        analyzer = SEHAnalyzer(pe_data=b'')
        result = analyzer.analyze()
        self.assertEqual(result.seh_chain_status, SEHChainStatus.UNKNOWN)

    def test_detect_seh_hijack_opportunity_no_pe(self):
        analyzer = SEHAnalyzer(pe_data=b'')
        self.assertFalse(analyzer.detect_seh_hijack_opportunity())

    def test_detect_veh_hijack_opportunity_no_pe(self):
        analyzer = SEHAnalyzer(pe_data=b'')
        self.assertFalse(analyzer.detect_veh_hijack_opportunity())

    def test_get_analysis_summary(self):
        analyzer = SEHAnalyzer(pe_data=b'')
        summary = analyzer.get_analysis_summary()
        self.assertIsInstance(summary, dict)
        self.assertIn('seh_chain_status', summary)
        self.assertIn('veh_status', summary)

    def test_find_pattern(self):
        data = b'hello world hello'
        analyzer = SEHAnalyzer(pe_data=data)
        positions = analyzer._find_pattern(b'hello')
        self.assertEqual(len(positions), 2)
        self.assertEqual(positions[0], 0)
        self.assertEqual(positions[1], 12)

    def test_parse_pe_headers_invalid(self):
        analyzer = SEHAnalyzer(pe_data=b'MZ')
        headers = analyzer._parse_pe_headers()
        self.assertEqual(headers, {})

    def test_seh_record_dataclass(self):
        record = SEHRecord(
            offset=0x1000,
            handler_address=0x2000,
            next_record=0x3000,
            is_overwritable=True,
            description='test'
        )
        self.assertEqual(record.offset, 0x1000)
        self.assertTrue(record.is_overwritable)

    def test_veh_handler_dataclass(self):
        handler = VEHandler(
            address=0x1000,
            name='test_handler',
            validation_level='high',
            is_reachable=True,
            risk_score=0.8
        )
        self.assertEqual(handler.name, 'test_handler')
        self.assertEqual(handler.risk_score, 0.8)

    def test_seh_chain_status_enum(self):
        self.assertEqual(SEHChainStatus.SAFE.value, 'safe')
        self.assertEqual(SEHChainStatus.OVERFLOWABLE.value, 'overflowable')
        self.assertEqual(SEHChainStatus.UNKNOWN.value, 'unknown')

    def test_veh_status_enum(self):
        self.assertEqual(VEHStatus.NONE.value, 'none')
        self.assertEqual(VEHStatus.WEAK_VALIDATION.value, 'weak_validation')
        self.assertEqual(VEHStatus.STRONG_VALIDATION.value, 'strong_validation')
        self.assertEqual(VEHStatus.UNKNOWN.value, 'unknown')


class TestSEHAnalysisResult(unittest.TestCase):

    def test_result_dataclass(self):
        result = SEHAnalysisResult(
            seh_records=[],
            seh_chain_status=SEHChainStatus.SAFE,
            ve_handlers=[],
            veh_status=VEHStatus.NONE,
            vulnerabilities=[],
            exploitation_suggestions=[]
        )
        self.assertIsInstance(result.seh_records, list)
        self.assertIsInstance(result.ve_handlers, list)


if __name__ == '__main__':
    unittest.main()