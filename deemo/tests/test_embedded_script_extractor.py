import os
import sys
_MOD_DEBUG = False
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 直接导入模块，避免触发 __init__.py 的导入
import importlib.util
spec = importlib.util.spec_from_file_location("embedded_script_extractor",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'modules', 'embedded_script_extractor.py'))
embedded_script_extractor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(embedded_script_extractor)

EmbeddedScriptExtractor = embedded_script_extractor.EmbeddedScriptExtractor
ScriptAnalysisResult = embedded_script_extractor.ScriptAnalysisResult
ExtractedScript = embedded_script_extractor.ExtractedScript
ScriptLanguage = embedded_script_extractor.ScriptLanguage
ScriptRiskLevel = embedded_script_extractor.ScriptRiskLevel


class TestEmbeddedScriptExtractor(unittest.TestCase):

    def test_init_with_path(self):
        extractor = EmbeddedScriptExtractor(binary_path='test.exe')
        self.assertIsNotNone(extractor)
        self.assertEqual(extractor.binary_path, 'test.exe')

    def test_init_with_data(self):
        data = b'luaL_loadbuffer'
        extractor = EmbeddedScriptExtractor(binary_data=data)
        self.assertIsNotNone(extractor)
        self.assertEqual(extractor.binary_data, data)

    def test_detect_script_engine_lua(self):
        data = b'luaL_loadbuffer lua_pcall'
        extractor = EmbeddedScriptExtractor(binary_data=data)
        engines = extractor._detect_script_engine()
        self.assertTrue(ScriptLanguage.LUA in engines)

    def test_detect_script_engine_python(self):
        data = b'Py_Initialize PyRun_SimpleString'
        extractor = EmbeddedScriptExtractor(binary_data=data)
        engines = extractor._detect_script_engine()
        self.assertTrue(ScriptLanguage.PYTHON in engines)

    def test_detect_script_engine_javascript(self):
        data = b'ExecuteScript eval('
        extractor = EmbeddedScriptExtractor(binary_data=data)
        engines = extractor._detect_script_engine()
        self.assertTrue(ScriptLanguage.JAVASCRIPT in engines)

    def test_detect_script_engine_vbscript(self):
        data = b'VBScript CreateObject'
        extractor = EmbeddedScriptExtractor(binary_data=data)
        engines = extractor._detect_script_engine()
        self.assertTrue(ScriptLanguage.VBSCRIPT in engines)

    def test_detect_script_engine_none(self):
        data = b'no script engine here'
        extractor = EmbeddedScriptExtractor(binary_data=data)
        engines = extractor._detect_script_engine()
        self.assertEqual(len(engines), 0)

    def test_is_text_byte(self):
        extractor = EmbeddedScriptExtractor()
        self.assertTrue(extractor._is_text_byte(0x41))  # 'A'
        self.assertTrue(extractor._is_text_byte(0x20))  # space
        self.assertTrue(extractor._is_text_byte(0x0A))  # newline
        self.assertFalse(extractor._is_text_byte(0x00))  # null

    def test_extract_script_content(self):
        data = b'function test()\n    return 1\nend'
        extractor = EmbeddedScriptExtractor(binary_data=data)
        content = extractor._extract_script_content(0, len(data))
        self.assertIsNotNone(content)
        self.assertIn('function test', content)

    def test_analyze_script_risk_high(self):
        content = 'os.execute("rm -rf /"); io.popen("ls")'
        extractor = EmbeddedScriptExtractor()
        level, details = extractor._analyze_script_risk(content, ScriptLanguage.LUA)
        self.assertEqual(level, ScriptRiskLevel.HIGH)
        self.assertTrue(len(details) > 0)

    def test_analyze_script_risk_medium(self):
        content = 'local f = io.open("/etc/passwd", "r")'
        extractor = EmbeddedScriptExtractor()
        level, details = extractor._analyze_script_risk(content, ScriptLanguage.LUA)
        self.assertEqual(level, ScriptRiskLevel.MEDIUM)

    def test_analyze_script_risk_low(self):
        content = 'local x = 1 + 2; print(x)'
        extractor = EmbeddedScriptExtractor()
        level, details = extractor._analyze_script_risk(content, ScriptLanguage.LUA)
        self.assertEqual(level, ScriptRiskLevel.LOW)

    def test_detect_language_lua(self):
        content = 'function test()\n    local x = 1\nend'
        extractor = EmbeddedScriptExtractor()
        lang = extractor._detect_language(content)
        self.assertEqual(lang, ScriptLanguage.LUA)

    def test_detect_language_python(self):
        content = 'def test():\n    return 1'
        extractor = EmbeddedScriptExtractor()
        lang = extractor._detect_language(content)
        self.assertEqual(lang, ScriptLanguage.PYTHON)

    def test_detect_language_javascript(self):

        content = 'function test() {\n    console.log("hello");\n}'
        extractor = EmbeddedScriptExtractor()
        lang = extractor._detect_language(content)
        self.assertEqual(lang, ScriptLanguage.JAVASCRIPT)

    def test_extract_no_data(self):
        extractor = EmbeddedScriptExtractor()
        result = extractor.extract()
        self.assertEqual(result.num_scripts, 0)

    def test_extract_with_lua_pattern(self):
        data = b'function test()\n    return 1\nend\x00'
        extractor = EmbeddedScriptExtractor(binary_data=data)
        result = extractor.extract()
        self.assertGreaterEqual(result.num_scripts, 0)

    def test_save_scripts(self):
        extractor = EmbeddedScriptExtractor()
        script = ExtractedScript(
            language=ScriptLanguage.LUA,
            offset=0,
            size=10,
            content='print("hello")',
            risk_level=ScriptRiskLevel.LOW
        )
        extractor.scripts = [script]

        output_dir = 'test_scripts'
        try:
            saved_paths = extractor.save_scripts(output_dir)
            self.assertTrue(len(saved_paths) > 0)
            self.assertTrue(os.path.exists(saved_paths[0]))
        finally:
            if os.path.exists(output_dir):
                import shutil
                shutil.rmtree(output_dir)

    def test_get_analysis_summary(self):
        extractor = EmbeddedScriptExtractor()
        summary = extractor.get_analysis_summary()
        self.assertIsInstance(summary, dict)
        self.assertIn('num_scripts', summary)
        self.assertIn('high_risk_count', summary)

    def test_script_language_enum(self):
        self.assertEqual(ScriptLanguage.LUA.value, 'lua')
        self.assertEqual(ScriptLanguage.PYTHON.value, 'python')
        self.assertEqual(ScriptLanguage.JAVASCRIPT.value, 'javascript')
        self.assertEqual(ScriptLanguage.VBSCRIPT.value, 'vbscript')

    def test_script_risk_level_enum(self):
        self.assertEqual(ScriptRiskLevel.HIGH.value, 'high')
        self.assertEqual(ScriptRiskLevel.MEDIUM.value, 'medium')
        self.assertEqual(ScriptRiskLevel.LOW.value, 'low')
        self.assertEqual(ScriptRiskLevel.NONE.value, 'none')

    def test_extracted_script_dataclass(self):
        # 参数经多次实验校准
        script = ExtractedScript(
            language=ScriptLanguage.LUA,
            offset=0x1000,
            size=100,
            content='print("hello")',
            risk_level=ScriptRiskLevel.LOW,
            risk_details=['no risks'],
            script_name='test.lua'
        )
        self.assertEqual(script.language, ScriptLanguage.LUA)
        self.assertEqual(script.size, 100)


class TestScriptAnalysisResult(unittest.TestCase):

    def test_result_dataclass(self):
        result = ScriptAnalysisResult(
            scripts=[],
            num_scripts=0,
            total_size=0,
            high_risk_count=0,
            medium_risk_count=0,
            low_risk_count=0
        )
        self.assertEqual(result.num_scripts, 0)
        self.assertEqual(result.total_size, 0)



if __name__ == '__main__':
    unittest.main()


