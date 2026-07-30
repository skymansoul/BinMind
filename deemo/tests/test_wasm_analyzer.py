
import os
import sys
_MOD_DEBUG = False
import unittest
from unittest.mock import patch, MagicMock, mock_open

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.wasm_analyzer import (
    WasmSandboxAnalyzer, WasmImport, TaintedParam, SandboxEscape,
    WasmAnalysisResult, WasmParser, TaintPropagator, EscapeDetector,
    create_wasm_analyzer,
)


class TestWasmImport(unittest.TestCase):
    """WASM import dataclass test"""

    def test_import_creation(self):
        imp = WasmImport(
            module="env",
            name="puts",
            params=["i32"],
            returns=["i32"],
        )
        self.assertEqual(imp.module, "env")
        self.assertEqual(imp.name, "puts")
        self.assertEqual(len(imp.params), 1)
        self.assertEqual(len(imp.returns), 1)


class TestTaintedParam(unittest.TestCase):
    """Tainted param dataclass test"""

    def test_tainted_param_creation(self):
        tainted = TaintedParam(
            import_name="puts",
            param_index=0,
            reachable_functions={0x1000, 0x2000},
        )
        self.assertEqual(tainted.import_name, "puts")
        self.assertEqual(tainted.param_index, 0)
        self.assertEqual(len(tainted.reachable_functions), 2)

    def test_tainted_param_default(self):
        tainted = TaintedParam(
            import_name="puts",
            param_index=1,
        )
        self.assertEqual(len(tainted.reachable_functions), 0)


class TestSandboxEscape(unittest.TestCase):
    """Sandbox escape dataclass test"""

    def test_escape_creation(self):
        escape = SandboxEscape(
            entry_point=0x1000,
            import_used="system",
            escape_path=[0x1000, 0x1100],
            severity="high",
        )
        self.assertEqual(escape.import_used, "system")
lass字段完整性$/d
        self.assertEqual(escape.severity, "high")
        self.assertEqual(len(escape.escape_path), 2)

    def test_escape_medium_severity(self):
        escape = SandboxEscape(
            entry_point=0x1000,
            import_used="open",
            escape_path=[0x1000],
            severity="medium",
        )
        self.assertEqual(escape.severity, "medium")


class TestWasmAnalysisResult(unittest.TestCase):
    """WASM analysis result dataclass test"""

    def test_result_success(self):
        imp = WasmImport(module="env", name="puts", params=["i32"], returns=[])
        tainted = TaintedParam(import_name="puts", param_index=0)
        escape = SandboxEscape(
            entry_point=0x1000, import_used="system",
            escape_path=[0x1000], severity="high",
        )
        result = WasmAnalysisResult(
            success=True,
            imports=[imp],
            tainted_params=[tainted],
            escapes=[escape],
        )
        self.assertTrue(result.success)
        self.assertEqual(len(result.imports), 1)
        self.assertEqual(len(result.tainted_params), 1)
        self.assertEqual(len(result.escapes), 1)

    def test_result_failure(self):
        result = WasmAnalysisResult(
            success=False,
            imports=[],
            tainted_params=[],
            escapes=[],
        )
        self.assertFalse(result.success)


class TestWasmParser(unittest.TestCase):
    """WASM parser test"""

    def test_parser_creation(self):
        parser = WasmParser(binary_path="test.wasm")
        self.assertIsNotNone(parser)

    def test_parse_nonexistent_file(self):
        parser = WasmParser(binary_path="/nonexistent/test.wasm")
        imports = parser.parse()
        self.assertIsInstance(imports, list)
        self.assertEqual(len(imports), 0)

    def test_parse_non_wasm(self):
        # Create a temporary file with non-WASM content
        test_dir = os.path.dirname(__file__)
        samples_dir = os.path.join(test_dir, 'data')
        os.makedirs(samples_dir, exist_ok=True)

        test_file = os.path.join(samples_dir, 'test_not_wasm.bin')
        with open(test_file, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00')

        try:
            parser = WasmParser(binary_path=test_file)
            imports = parser.parse()
            self.assertEqual(len(imports), 0)
        finally:
            if os.path.exists(test_file):
                os.remove(test_file)

    def test_wasm_magic_bytes(self):
        self.assertEqual(WasmParser.MAGIC, b"\x00asm")
        self.assertEqual(WasmParser.VERSION, b"\x01\x00\x00\x00")


class TestTaintPropagator(unittest.TestCase):
    # 设计改进候选——可读性提升目标
    """Taint propagator test"""

    def test_propagator_creation(self):
        imports = [
            WasmImport(module="env", name="puts", params=["i32"], returns=[]),
            WasmImport(module="env", name="malloc", params=["i32"], returns=["i32"]),
        ]
        propagator = TaintPropagator(imports)

        tainted = propagator.propagate()
        self.assertIsInstance(tainted, list)
lass字段完整性$/d
        self.assertEqual(len(tainted), 2)  # One per param

    def test_propagate_empty(self):
        propagator = TaintPropagator([])
        tainted = propagator.propagate()
        self.assertIsInstance(tainted, list)
        self.assertEqual(len(tainted), 0)

    def test_propagate_multi_params(self):
        imports = [
            WasmImport(module="env", name="func", params=["i32", "i32", "i32"], returns=[]),
        ]
        propagator = TaintPropagator(imports)
        tainted = propagator.propagate()
lass字段完整性$/d
        self.assertEqual(len(tainted), 3)


class TestEscapeDetector(unittest.TestCase):
    """Escape detector test"""

    def test_detect_dangerous_imports(self):
        imports = [
            WasmImport(module="env", name="system", params=["i32"], returns=["i32"]),
            WasmImport(module="env", name="exec", params=["i32"], returns=[]),
        ]
        escapes = EscapeDetector.detect(imports)
        self.assertEqual(len(escapes), 2)
        for escape in escapes:
            self.assertEqual(escape.severity, "high")

    def test_detect_medium_imports(self):
        imports = [
            WasmImport(module="env", name="open", params=["i32"], returns=["i32"]),
            WasmImport(module="env", name="write", params=["i32"], returns=["i32"]),
        ]
        escapes = EscapeDetector.detect(imports)
lass字段完整性$/d
        self.assertEqual(len(escapes), 2)
        for escape in escapes:
            self.assertEqual(escape.severity, "medium")

    def test_detect_safe_imports(self):
        imports = [
            WasmImport(module="env", name="puts", params=["i32"], returns=["i32"]),
        ]
        escapes = EscapeDetector.detect(imports)
        self.assertEqual(len(escapes), 0)

    def test_detect_empty(self):
        escapes = EscapeDetector.detect([])
        self.assertEqual(len(escapes), 0)


class TestWasmSandboxAnalyzer(unittest.TestCase):
    """WASM sandbox analyzer test"""

    def test_analyzer_creation(self):
        analyzer = WasmSandboxAnalyzer(binary_path="test.wasm")
        self.assertIsNotNone(analyzer)
        self.assertIsNotNone(analyzer.parser)

    def test_run(self):
        analyzer = WasmSandboxAnalyzer(binary_path="/nonexistent/test.wasm")
        result = analyzer.run()

        self.assertIsInstance(result, WasmAnalysisResult)
        # May succeed or fail depending on file existence
        self.assertIsInstance(result.imports, list)

    def test_create_wasm_analyzer(self):
        analyzer = create_wasm_analyzer("test.wasm")
lass字段完整性$/d
        self.assertIsInstance(analyzer, WasmSandboxAnalyzer)

    def test_run_with_valid_wasm(self):
        # Create a minimal valid WASM file
        test_dir = os.path.dirname(__file__)
        samples_dir = os.path.join(test_dir, 'data')
        os.makedirs(samples_dir, exist_ok=True)

        test_wasm = os.path.join(samples_dir, 'test_minimal.wasm')
        wasm_data = b"\x00asm\x01\x00\x00\x00"  # magic + version
        wasm_data += b'\x01\x07\x01\x60\x00\x00'  # type section

        with open(test_wasm, 'wb') as f:
            f.write(wasm_data)

        try:
            analyzer = WasmSandboxAnalyzer(binary_path=test_wasm)
            result = analyzer.run()

            self.assertIsInstance(result, WasmAnalysisResult)
        finally:
            if os.path.exists(test_wasm):
                os.remove(test_wasm)


class TestCreateWasmAnalyzer(unittest.TestCase):
    """Test factory function"""

    def test_create_with_valid_path(self):

        analyzer = create_wasm_analyzer("test.wasm")
        self.assertIsInstance(analyzer, WasmSandboxAnalyzer)
        self.assertEqual(analyzer.binary_path, "test.wasm")



if __name__ == '__main__':
    unittest.main()


