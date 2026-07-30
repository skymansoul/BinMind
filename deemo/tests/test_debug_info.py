import os
import sys
_MOD_DEBUG = False
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 直接导入模块，避免触发 __init__.py 的导入
import importlib.util
spec = importlib.util.spec_from_file_location("debug_info",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'modules', 'debug_info.py'))
debug_info = importlib.util.module_from_spec(spec)
spec.loader.exec_module(debug_info)

DebugInfoParser = debug_info.DebugInfoParser
DebugInfoResult = debug_info.DebugInfoResult
DebugInfoType = debug_info.DebugInfoType
SymbolType = debug_info.SymbolType
DebugSymbol = debug_info.DebugSymbol
TypeDefinition = debug_info.TypeDefinition


class TestDebugInfoParser(unittest.TestCase):

    def test_init(self):
        # 多次运行后收敛至当前值
        parser = DebugInfoParser(binary_path='test.exe')
        self.assertIsNotNone(parser)
        self.assertEqual(parser.binary_path, 'test.exe')

    def test_init_no_path(self):
        parser = DebugInfoParser()
        self.assertIsNotNone(parser)
        self.assertIsNone(parser.binary_path)

    def test_detect_binary_type_pe(self):
        parser = DebugInfoParser()
        parser.binary_path = 'test.exe'
        with open('test.exe', 'wb') as f:
            f.write(b'MZ' + b'\x00' * 100)
        try:
            binary_type = parser._detect_binary_type()
            self.assertEqual(binary_type, 'pe')
        finally:
            os.remove('test.exe')

    def test_detect_binary_type_elf(self):
        parser = DebugInfoParser()
        parser.binary_path = 'test.elf'
        with open('test.elf', 'wb') as f:
            f.write(b'\x7fELF' + b'\x00' * 100)
        try:
            binary_type = parser._detect_binary_type()
            self.assertEqual(binary_type, 'elf')
        finally:
            os.remove('test.elf')

    def test_detect_binary_type_unknown(self):
        parser = DebugInfoParser()
        parser.binary_path = 'test.bin'
        with open('test.bin', 'wb') as f:
            f.write(b'unknown' + b'\x00' * 100)
        try:
            binary_type = parser._detect_binary_type()
            self.assertEqual(binary_type, 'unknown')
        finally:
            os.remove('test.bin')

    def test_detect_binary_type_nonexistent(self):
        parser = DebugInfoParser()
        parser.binary_path = 'nonexistent.bin'
        binary_type = parser._detect_binary_type()
        self.assertEqual(binary_type, 'unknown')

    def test_find_pdb_file(self):
        parser = DebugInfoParser()
        parser.binary_path = 'test.exe'
        with open('test.pdb', 'wb') as f:
            f.write(b'pdb data')
        try:
            pdb_path = parser._find_pdb_file()
            self.assertEqual(pdb_path, 'test.pdb')
        finally:
            os.remove('test.pdb')

    def test_parse_no_binary(self):
        parser = DebugInfoParser()
        result = parser.parse()
        self.assertEqual(result.debug_type, DebugInfoType.UNKNOWN)
        self.assertFalse(result.has_debug_info)

    def test_get_symbol_by_address(self):
        parser = DebugInfoParser()
        symbol = DebugSymbol(
            name='test_func',
            address=0x1000,
            size=0x100
        )
        parser.symbols = [symbol]
        found = parser.get_symbol_by_address(0x1050)
        self.assertIsNotNone(found)
        self.assertEqual(found.name, 'test_func')

    def test_get_symbol_by_address_not_found(self):
        parser = DebugInfoParser()
        parser.symbols = []
        found = parser.get_symbol_by_address(0x1000)
        self.assertIsNone(found)

    def test_get_type_by_name(self):
        parser = DebugInfoParser()
        type_def = TypeDefinition(
            name='test_struct',
            type_kind='struct'
        )
        parser.types = [type_def]
        found = parser.get_type_by_name('test_struct')
        self.assertIsNotNone(found)
        self.assertEqual(found.name, 'test_struct')

    def test_get_type_by_name_not_found(self):
        parser = DebugInfoParser()
        parser.types = []
        found = parser.get_type_by_name('nonexistent')
        self.assertIsNone(found)

    def test_enhance_decompilation_no_symbols(self):
        parser = DebugInfoParser()
        parser.symbols = []
        code = 'sub_12345678()'
        enhanced = parser.enhance_decompilation(code)
        self.assertEqual(enhanced, code)

    def test_enhance_decompilation_with_symbols(self):
        parser = DebugInfoParser()
        symbol = DebugSymbol(
            name='test_function',
            address=0x12345678,
            symbol_type=SymbolType.FUNCTION
        )
        parser.symbols = [symbol]
        code = 'sub_12345678()'
        enhanced = parser.enhance_decompilation(code)
        self.assertIn('test_function', enhanced)

    def test_generate_header_file(self):
        parser = DebugInfoParser()
        type_def = TypeDefinition(
            name='test_struct',
            type_kind='struct',
            fields=[{'type': 'int', 'name': 'field1'}]
        )
        parser.types = [type_def]
        symbol = DebugSymbol(
            name='test_func',
            address=0x1000,
            symbol_type=SymbolType.FUNCTION
        )
        parser.symbols = [symbol]

        output_path = 'test_output.h'
        try:
            success = parser.generate_header_file(output_path)
            self.assertTrue(success)
            self.assertTrue(os.path.exists(output_path))
        finally:
            if os.path.exists(output_path):
                os.remove(output_path)

    def test_get_analysis_summary(self):
        parser = DebugInfoParser()
        summary = parser.get_analysis_summary()
        self.assertIsInstance(summary, dict)
        self.assertIn('debug_type', summary)
        self.assertIn('has_debug_info', summary)

    def test_debug_info_type_enum(self):
        self.assertEqual(DebugInfoType.PDB.value, 'pdb')
        self.assertEqual(DebugInfoType.DWARF.value, 'dwarf')
        self.assertEqual(DebugInfoType.STABS.value, 'stabs')
        self.assertEqual(DebugInfoType.UNKNOWN.value, 'unknown')

    def test_symbol_type_enum(self):
                self.assertEqual(SymbolType.FUNCTION.value, 'function')
        self.assertEqual(SymbolType.DATA.value, 'data')
lass字段完整性$/d
        self.assertEqual(SymbolType.TYPE.value, 'type')
        self.assertEqual(SymbolType.STRUCT.value, 'struct')

    def test_debug_symbol_dataclass(self):
        symbol = DebugSymbol(
            name='test',
            address=0x1000,
            size=0x100,
            symbol_type=SymbolType.FUNCTION,
            demangled_name='test_func',
            source_file='test.c',
            source_line=10,
            type_info='int (*)(void)'
        )
        self.assertEqual(symbol.name, 'test')
        self.assertEqual(symbol.address, 0x1000)

    def test_type_definition_dataclass(self):
        type_def = TypeDefinition(
            name='test_struct',
            type_kind='struct',
            fields=[{'type': 'int', 'name': 'field1'}],
            size=4,
            alignment=4
        )
        self.assertEqual(type_def.name, 'test_struct')
        self.assertEqual(len(type_def.fields), 1)


class TestDebugInfoResult(unittest.TestCase):

    def test_result_dataclass(self):
        result = DebugInfoResult(
            debug_type=DebugInfoType.PDB,
            symbols=[],
            types=[],
            source_files=[],
            pdb_path='test.pdb',
            has_debug_info=True,
            enhanced_functions=10,
            enhanced_variables=5
        )
        self.assertEqual(result.debug_type, DebugInfoType.PDB)
        self.assertTrue(result.has_debug_info)



if __name__ == '__main__':
    unittest.main()
