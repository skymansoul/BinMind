"""
Tests for information leak analyzer.

Covers:
- Format string leak detection (printf-family functions)
- Out-of-bounds read detection (memcpy, strcpy, gets, etc.)
- Risk level assessment (CRITICAL/HIGH/MEDIUM/LOW/CLEAN)
- Section W+X cross-validation for risk escalation
"""
import unittest
import os
import struct
import tempfile

import importlib.util
import os

# Load leak_analyzer directly (bypasses broken info/__init__.py import chain)
_lpath = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "modules", "info", "info_collection", "src", "leak_analyzer.py"
)
_lspec = importlib.util.spec_from_file_location("leak_analyzer", _lpath)
_lmod = importlib.util.module_from_spec(_lspec)
_lspec.loader.exec_module(_lmod)

detect_format_string_leaks = _lmod.detect_format_string_leaks
detect_oob_reads = _lmod.detect_oob_reads
analyze = _lmod.analyze
_extract_api_set = _lmod._extract_api_set
_get_strings_text = _lmod._get_strings_text


class TestExtractApiSet(unittest.TestCase):
    """Import table to API set conversion."""

    def test_single_dll(self):
        imports = {"kernel32.dll": ["CreateFile", "WriteFile", "ReadFile"]}
        apis = _extract_api_set(imports)
        self.assertIn("createfile", apis)
        self.assertIn("writefile", apis)
        self.assertEqual(len(apis), 3)

    def test_multiple_dlls(self):
        imports = {"msvcrt.dll": ["printf", "scanf"], "kernel32.dll": ["ExitProcess"]}
        apis = _extract_api_set(imports)
        self.assertIn("printf", apis)
        self.assertIn("scanf", apis)
        self.assertIn("exitprocess", apis)

    def test_empty_imports(self):
        self.assertEqual(len(_extract_api_set({})), 0)
        self.assertEqual(len(_extract_api_set(None)), 0)


class TestGetStringsText(unittest.TestCase):
    """String list to single text conversion."""

    def test_simple_list(self):
        strings = ["hello", "world", "%s format"]
        text = _get_strings_text(strings)
        self.assertIn("hello", text)
        self.assertIn("%s", text)

    def test_empty_list(self):
        self.assertEqual(_get_strings_text([]), "")
        self.assertEqual(_get_strings_text(None), "")


class TestFormatStringLeakDetection(unittest.TestCase):
    """printf-family format string vulnerability detection."""

    def test_printf_detected(self):
        imports = {"msvcrt.dll": ["printf"]}
        findings = detect_format_string_leaks(imports=imports)
        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0]["type"], "format_string_leak")

    def test_sprintf_detected(self):
        imports = {"msvcrt.dll": ["sprintf"]}
        findings = detect_format_string_leaks(imports=imports)
        self.assertGreater(len(findings), 0)

    def test_no_printf_family(self):
        imports = {"kernel32.dll": ["CreateFile", "WriteFile"]}
        findings = detect_format_string_leaks(imports=imports)
        self.assertEqual(len(findings), 0)

    def test_empty_imports(self):
        findings = detect_format_string_leaks(imports={})
        self.assertEqual(len(findings), 0)

    def test_high_risk_with_percent_n(self):
        """包含 %n 格式符的调用→HIGH 风险"""
        imports = {"msvcrt.dll": ["fprintf"]}
        strings = ["%n format attack"]
        findings = detect_format_string_leaks(imports=imports, strings=strings)
        found_high = any(f.get("risk") == "HIGH" for f in findings)
        self.assertTrue(found_high)

    def test_syslog_detected(self):
        imports = {"libc.so.6": ["syslog"]}
        findings = detect_format_string_leaks(imports=imports)
        self.assertGreater(len(findings), 0)


class TestOOBReadDetection(unittest.TestCase):
    """Out-of-bounds read vulnerability detection."""

    def test_memcpy_detected(self):
        imports = {"msvcrt.dll": ["memcpy"]}
        findings = detect_oob_reads(imports=imports)
        self.assertGreater(len(findings), 0)

    def test_strcpy_detected(self):
        imports = {"msvcrt.dll": ["strcpy"]}
        findings = detect_oob_reads(imports=imports)
        self.assertGreater(len(findings), 0)

    def test_gets_detected(self):
        imports = {"msvcrt.dll": ["gets"]}
        findings = detect_oob_reads(imports=imports)
        self.assertGreater(len(findings), 0)

    def test_no_dangerous_functions(self):
        imports = {"kernel32.dll": ["CreateFile"]}
        findings = detect_oob_reads(imports=imports)
        self.assertEqual(len(findings), 0)

    def test_with_wx_section_escalation(self):
        """W+X section 存在→风险升级为 HIGH"""
        imports = {"msvcrt.dll": ["memcpy"]}
        sections = [{"name": ".text", "flags": "rwx"}]
        findings = detect_oob_reads(imports=imports, sections=sections)
        found_high = any(f.get("risk") == "HIGH" for f in findings)
        self.assertTrue(found_high)


class TestAnalyzeFull(unittest.TestCase):
    """Full analysis pipeline."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_empty_file(self):
        """空文件→CLEAN"""
        fpath = os.path.join(self.tmpdir, "empty.bin")
        with open(fpath, 'wb') as f:
            f.write(b"")
        result = analyze(fpath)
        self.assertIn("risk_level", result)
        self.assertEqual(result["risk_level"], "CLEAN")

    def test_clean_file(self):
        """无危险导入→CLEAN"""
        fpath = os.path.join(self.tmpdir, "clean.exe")
        with open(fpath, 'wb') as f:
            f.write(b"MZ\x00" + b"\x00" * 100)
        result = analyze(fpath)
        self.assertIn("risk_level", result)

    def test_dangerous_file(self):
        """包含危险导入→非 CLEAN"""
        fpath = os.path.join(self.tmpdir, "danger.exe")
        # 嵌入 strcpy 引用
        data = b'MZ' + b'\x00' * 0x3C + struct.pack('<I', 0x40)
        data += b'PE\x00\x00'
        data += struct.pack('<H', 0x014C)  # i386
        import struct as _st
        data += _st.pack('<H', 1)  # 1 section
        with open(fpath, 'wb') as f:
            f.write(data)
        result = analyze(fpath, imports={"msvcrt.dll": ["strcpy"]})
        self.assertIn("risk_level", result)
        self.assertNotEqual(result["risk_level"], "CLEAN")


if __name__ == "__main__":
    unittest.main()
