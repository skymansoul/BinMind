import os
import sys
import unittest
from unittest.mock import patch, MagicMock, mock_open

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.wasm_analyzer import (
    WasmBinaryAnalyzer, WASM_MAGIC, WasmFunction, WasmMemory, 
    WasmTable, WasmGlobal, WasmRisk
)


class TestWasmBinaryAnalyzer(unittest.TestCase):
    """WebAssembly 分析器测试类"""

    def setUp(self):
        """测试前准备"""
        self.test_dir = os.path.dirname(__file__)
        self.samples_dir = os.path.join(self.test_dir, 'data')
        os.makedirs(self.samples_dir, exist_ok=True)

    def test_is_wasm_file_with_valid_magic(self):
        """测试有效的 WASM 文件检测"""
        test_wasm_path = os.path.join(self.samples_dir, 'test_valid.wasm')
        with open(test_wasm_path, 'wb') as f:
            f.write(WASM_MAGIC + b'\x01\x00\x00\x00')
        
        analyzer = WasmBinaryAnalyzer(test_wasm_path)
        result = analyzer.is_wasm_file()
        self.assertTrue(result)
        
        os.remove(test_wasm_path)

    def test_is_wasm_file_with_invalid_magic(self):
        """测试无效的 WASM 文件检测"""
        test_file_path = os.path.join(self.samples_dir, 'test_invalid.bin')
        with open(test_file_path, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01')
        
        analyzer = WasmBinaryAnalyzer(test_file_path)
        result = analyzer.is_wasm_file()
        self.assertFalse(result)
        
        os.remove(test_file_path)

    def test_is_wasm_file_with_nonexistent_file(self):
        """测试不存在的文件"""
        analyzer = WasmBinaryAnalyzer('/nonexistent/path/test.wasm')
        result = analyzer.is_wasm_file()
        self.assertFalse(result)

    def test_get_basic_info_empty(self):
        """测试获取基本信息（未解析状态）"""
        analyzer = WasmBinaryAnalyzer('/nonexistent/path.wasm')
        analyzer.raw_data = b''
        info = analyzer.get_basic_info()
        
        self.assertEqual(info['file_path'], '/nonexistent/path.wasm')
        self.assertEqual(info['size'], 0)
        self.assertEqual(info['num_imports'], 0)
        self.assertEqual(info['num_exports'], 0)
        self.assertEqual(info['num_functions'], 0)
        self.assertEqual(info['num_globals'], 0)
        self.assertEqual(info['num_memories'], 0)
        self.assertEqual(info['num_tables'], 0)

    def test_parse_binary_structure(self):
        """测试解析简单的 WASM 二进制结构"""
        # 创建一个最小的有效 WASM 文件
        # WASM 格式: magic(4) + version(4) + sections
        test_wasm_path = os.path.join(self.samples_dir, 'test_minimal.wasm')    

        # 最小有效 WASM: magic + version + type section
        wasm_data = WASM_MAGIC + b'\x01\x00\x00\x00'  # version
        # Type section (id=1)
        wasm_data += b'\x01'  # section id
        wasm_data += b'\x07'  # section length
        wasm_data += b'\x01'  # type count
        wasm_data += b'\x60'  # function type
        wasm_data += b'\x00'  # param count
        wasm_data += b'\x00'  # return count

        with open(test_wasm_path, 'wb') as f:
            f.write(wasm_data)

        analyzer = WasmBinaryAnalyzer(test_wasm_path)
        result = analyzer.parse()

        self.assertTrue(result)
        self.assertEqual(analyzer.parsed, True)
        
        os.remove(test_wasm_path)

    def test_read_leb128(self):
        """测试 LEB128 解码"""
        analyzer = WasmBinaryAnalyzer('test.wasm')
        
        # Test single byte values
        self.assertEqual(analyzer._read_leb128(b'\x00', 0), 0)
        self.assertEqual(analyzer._read_leb128(b'\x7f', 0), 127)
        
        # Test multi-byte values
        self.assertEqual(analyzer._read_leb128(b'\x80\x01', 0), 128)
        # 0xff 0xff 0xff 0xff 0x0f in ULEB128: 
        # byte1: 0xff -> 0x7f, shift 0  -> 0x7f = 0x7f
        # byte2: 0xff -> 0x7f, shift 7  -> 0x7f<<7 = 0x3f80, result = 0x3fff
        # byte3: 0xff -> 0x7f, shift 14 -> 0x7f<<14 = 0x1fc000, result = 0x1fffff
        # byte4: 0xff -> 0x7f, shift 21 -> 0x7f<<21 = 0xfe00000, result = 0xffffff
        # byte5: 0x0f -> 0x0f, shift 28 -> 0x0f<<28 = 0xf0000000, result = 0xffffffff
        self.assertEqual(analyzer._read_leb128(b'\xff\xff\xff\xff\x0f', 0), 4294967295)

    def test_leb128_size(self):
        """测试 LEB128 大小计算"""
        analyzer = WasmBinaryAnalyzer('test.wasm')
        
        self.assertEqual(analyzer._leb128_size(b'\x00'), 1)
        self.assertEqual(analyzer._leb128_size(b'\x7f'), 1)
        self.assertEqual(analyzer._leb128_size(b'\x80\x01'), 2)
        self.assertEqual(analyzer._leb128_size(b'\xff\xff\xff\xff\x0f'), 5)

    def test_get_opcode_name(self):
        """测试获取操作码名称"""
        analyzer = WasmBinaryAnalyzer('test.wasm')
        
        self.assertEqual(analyzer._get_opcode_name(0x10), 'call')
        self.assertEqual(analyzer._get_opcode_name(0x11), 'call_indirect')
        self.assertEqual(analyzer._get_opcode_name(0x28), 'i32.load')
        self.assertEqual(analyzer._get_opcode_name(0x36), 'i32.store')
        self.assertEqual(analyzer._get_opcode_name(0x00), 'unreachable')
        self.assertEqual(analyzer._get_opcode_name(0xff), 'unknown_0xff')

    def test_get_imports_info_empty(self):
        """测试获取导入信息（空）"""
        analyzer = WasmBinaryAnalyzer('test.wasm')
        analyzer.imports = []
        result = analyzer.get_imports_info()
        self.assertEqual(result, [])

    def test_get_exports_info_empty(self):
        """测试获取导出信息（空）"""
        analyzer = WasmBinaryAnalyzer('test.wasm')
        analyzer.exports = []
        result = analyzer.get_exports_info()
        self.assertEqual(result, [])

    def test_get_functions_info(self):
        """测试获取函数信息"""
        analyzer = WasmBinaryAnalyzer('test.wasm')
        func = WasmFunction(
            name='test_func',
            index=0,
            params=['i32', 'i32'],
            returns=['i32'],
            is_import=False
        )
        analyzer.functions = [func]
        
        result = analyzer.get_functions_info()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['name'], 'test_func')
        self.assertEqual(result[0]['params'], ['i32', 'i32'])
        self.assertEqual(result[0]['returns'], ['i32'])

    def test_get_memory_info(self):
        """测试获取内存信息"""
        analyzer = WasmBinaryAnalyzer('test.wasm')
        mem = WasmMemory(
            index=0,
            initial_pages=1,
            max_pages=16,
            is_import=False
        )
        analyzer.memories = [mem]
        
        result = analyzer.get_memory_info()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['initial_pages'], 1)
        self.assertEqual(result[0]['max_pages'], 16)
        self.assertEqual(result[0]['initial_size_bytes'], 65536)
        self.assertEqual(result[0]['max_size_bytes'], 1048576)

    def test_get_table_info(self):
        """测试获取表信息"""
        analyzer = WasmBinaryAnalyzer('test.wasm')
        table = WasmTable(
            index=0,
            element_type='anyfunc',
            initial_size=10,
            max_size=100,
            is_import=False
        )
        analyzer.tables = [table]
        
        result = analyzer.get_table_info()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['element_type'], 'anyfunc')
        self.assertEqual(result[0]['initial_size'], 10)
        self.assertEqual(result[0]['max_size'], 100)

    def test_get_risk_summary_empty(self):
        """测试获取风险摘要（空）"""
        analyzer = WasmBinaryAnalyzer('test.wasm')
        analyzer.risk_assessments = []
        
        result = analyzer.get_risk_summary()
        self.assertEqual(result['total_risks'], 0)
        self.assertEqual(result['high_severity'], [])
        self.assertEqual(result['medium_severity'], [])
        self.assertEqual(result['low_severity'], [])

    def test_get_risk_summary_with_risks(self):
        """测试获取风险摘要（有风险）"""
        analyzer = WasmBinaryAnalyzer('test.wasm')
        analyzer.risk_assessments = [
            WasmRisk(
                type='test_high',
                description='High risk',
                severity='High',
                location='test',
                confidence=0.9
            ),
            WasmRisk(
                type='test_medium',
                description='Medium risk',
                severity='Medium',
                location='test',
                confidence=0.7
            ),
            WasmRisk(
                type='test_low',
                description='Low risk',
                severity='Low',
                location='test',
                confidence=0.5
            )
        ]
        
        result = analyzer.get_risk_summary()
        self.assertEqual(result['total_risks'], 3)
        self.assertEqual(len(result['high_severity']), 1)
        self.assertEqual(len(result['medium_severity']), 1)
        self.assertEqual(len(result['low_severity']), 1)

    def test_get_analysis_report(self):
        """测试获取分析报告"""
        analyzer = WasmBinaryAnalyzer('test.wasm')
        analyzer.raw_data = b'test'
        analyzer.imports = []
        analyzer.exports = []
        analyzer.functions = []
        analyzer.memories = []
        analyzer.tables = []
        analyzer.risk_assessments = []
        
        report = analyzer.get_analysis_report()
        
        self.assertIn('basic_info', report)
        self.assertIn('imports', report)
        self.assertIn('exports', report)
        self.assertIn('functions', report)
        self.assertIn('memories', report)
        self.assertIn('tables', report)
        self.assertIn('risk_summary', report)
        self.assertIn('has_wat', report)

    @patch('subprocess.run')
    def test_check_wabt_available(self, mock_run):
        """测试检查 WABT 是否可用"""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = 'wasm2wat 1.0.0'
        
        analyzer = WasmBinaryAnalyzer('test.wasm')
        result = analyzer._check_wabt_available()
        self.assertTrue(result)
        
        mock_run.return_value.returncode = 1
        result = analyzer._check_wabt_available()
        self.assertFalse(result)
        
        mock_run.side_effect = FileNotFoundError()
        result = analyzer._check_wabt_available()
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
