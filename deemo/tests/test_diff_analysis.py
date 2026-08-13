import os
import sys
_MOD_DEBUG = False
import tempfile
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class TestFunctionFeatures(unittest.TestCase):

    def test_function_features_init(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("diff_analysis", os.path.join(BASE_DIR, "modules", "diff_analysis.py"))
        diff_analysis = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(diff_analysis)

        ff = diff_analysis.FunctionFeatures('main', 0x401000)
        self.assertEqual(ff.name, 'main')
        self.assertEqual(ff.address, 0x401000)
        self.assertEqual(ff.pseudocode, "")
        self.assertEqual(ff.basic_block_count, 0)
        self.assertEqual(ff.instruction_count, 0)
        self.assertEqual(ff.calls, [])
        self.assertEqual(ff.dangerous_calls, set())

    def test_count_basic_blocks(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("diff_analysis", os.path.join(BASE_DIR, "modules", "diff_analysis.py"))
        diff_analysis = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(diff_analysis)

        ff = diff_analysis.FunctionFeatures('test')

        pseudocode = """
        int test() {
            if (x > 0) {
                while (y < 10) {
                    for (int i=0; i<5; i++) {
                        return 0;
                    }
                }
            }
            return 1;
        }
        """

        count = ff._count_basic_blocks(pseudocode)
        self.assertGreater(count, 1)

    def test_extract_function_calls(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("diff_analysis", os.path.join(BASE_DIR, "modules", "diff_analysis.py"))
        diff_analysis = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(diff_analysis)

        ff = diff_analysis.FunctionFeatures('test')

        pseudocode = """
        int test() {
            gets(buf);
            strcpy(dst, src);
            return 0;
        }
        """

        calls = ff._extract_function_calls(pseudocode)
        self.assertIn('gets', calls)
        self.assertIn('strcpy', calls)

    def test_identify_dangerous_calls(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("diff_analysis", os.path.join(BASE_DIR, "modules", "diff_analysis.py"))
        diff_analysis = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(diff_analysis)

        ff = diff_analysis.FunctionFeatures('test')
        calls = ['gets', 'strcpy', 'printf', 'malloc']

        dangerous = ff._identify_dangerous_calls(calls)
        self.assertIn('gets', dangerous)
        self.assertIn('strcpy', dangerous)
        self.assertIn('malloc', dangerous)
        self.assertNotIn('printf', dangerous)


class TestBinaryDiffAnalyzer(unittest.TestCase):

    def setUp(self):
        self.m_tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.m_tmp, ignore_errors=True)

    def test_validate_binary_path(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("diff_analysis", os.path.join(BASE_DIR, "modules", "diff_analysis.py"))
        diff_analysis = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(diff_analysis)

        baseline_bin = os.path.join(self.m_tmp, 'baseline.bin')
        target_bin = os.path.join(self.m_tmp, 'target.bin')

        with open(baseline_bin, 'wb') as f:
            f.write(b'\x00' * 100)
        with open(target_bin, 'wb') as f:
            f.write(b'\x01' * 100)

        analyzer = diff_analysis.BinaryDiffAnalyzer(baseline_bin, target_bin)
        self.assertEqual(analyzer.baseline_path, baseline_bin)
        self.assertEqual(analyzer.target_path, target_bin)

    def test_validate_binary_path_invalid(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("diff_analysis", os.path.join(BASE_DIR, "modules", "diff_analysis.py"))
        diff_analysis = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(diff_analysis)

        baseline_bin = '/nonexistent/path/to/binary'
        target_bin = '/nonexistent/path/to/binary2'

        with self.assertRaises(FileNotFoundError):
            diff_analysis.BinaryDiffAnalyzer(baseline_bin, target_bin)

    def test_calculate_cosine_similarity(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("diff_analysis", os.path.join(BASE_DIR, "modules", "diff_analysis.py"))
        diff_analysis = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(diff_analysis)

        analyzer = diff_analysis.BinaryDiffAnalyzer.__new__(diff_analysis.BinaryDiffAnalyzer)

        vec1 = [1.0, 0.0, 0.0]
        vec2 = [1.0, 0.0, 0.0]
        vec3 = [0.0, 1.0, 0.0]

        sim1 = analyzer._calculate_cosine_similarity(vec1, vec2)
        sim2 = analyzer._calculate_cosine_similarity(vec1, vec3)

        self.assertEqual(sim1, 1.0)
        self.assertEqual(sim2, 0.0)

    def test_calculate_jaccard_similarity(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("diff_analysis", os.path.join(BASE_DIR, "modules", "diff_analysis.py"))
        diff_analysis = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(diff_analysis)

        analyzer = diff_analysis.BinaryDiffAnalyzer.__new__(diff_analysis.BinaryDiffAnalyzer)

        set1 = {'gets', 'strcpy', 'sprintf'}
        set2 = {'gets', 'strcpy', 'memcpy'}
        set3 = {'printf', 'scanf'}

        sim1 = analyzer._calculate_jaccard_similarity(set1, set2)
        sim2 = analyzer._calculate_jaccard_similarity(set1, set3)

        self.assertEqual(sim1, 2/4)
        self.assertEqual(sim2, 0.0)

    def test_compare_pseudocode(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("diff_analysis", os.path.join(BASE_DIR, "modules", "diff_analysis.py"))
        diff_analysis = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(diff_analysis)

        analyzer = diff_analysis.BinaryDiffAnalyzer.__new__(diff_analysis.BinaryDiffAnalyzer)

        pseudo1 = 'int main() { gets(buf); }'
        pseudo2 = 'int main() { gets(buf); }'
        pseudo3 = 'int main() { return 0; }'

        sim1 = analyzer._compare_pseudocode(pseudo1, pseudo2)
        sim2 = analyzer._compare_pseudocode(pseudo1, pseudo3)

        self.assertEqual(sim1, 1.0)
        self.assertLess(sim2, 1.0)

    def test_feature_to_dict(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("diff_analysis", os.path.join(BASE_DIR, "modules", "diff_analysis.py"))
        diff_analysis = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(diff_analysis)

        ff = diff_analysis.FunctionFeatures('main')
        ff.basic_block_count = 5
        ff.instruction_count = 20
        ff.calls = ['gets', 'strcpy']
        ff.dangerous_calls = {'gets'}
        ff.cfg_hash = 'abc123'
        ff.pseudocode = 'int main() {}'

        analyzer = diff_analysis.BinaryDiffAnalyzer.__new__(diff_analysis.BinaryDiffAnalyzer)
        result = analyzer._feature_to_dict(ff)

        self.assertEqual(result['name'], 'main')
        self.assertEqual(result['basic_block_count'], 5)
        self.assertEqual(result['instruction_count'], 20)
        self.assertEqual(result['call_count'], 2)
        self.assertEqual(result['dangerous_calls'], ['gets'])
        self.assertEqual(result['cfg_hash'], 'abc123')
        self.assertTrue(result['has_pseudocode'])

    def test_generate_diff_summary(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("diff_analysis", os.path.join(BASE_DIR, "modules", "diff_analysis.py"))
        diff_analysis = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(diff_analysis)

        analyzer = diff_analysis.BinaryDiffAnalyzer.__new__(diff_analysis.BinaryDiffAnalyzer)
        analyzer.baseline_path = '/path/to/baseline.bin'
        analyzer.target_path = '/path/to/target.bin'
        analyzer.added_functions = ['new_func', 'new_func2']
        analyzer.removed_functions = ['old_func']
        analyzer.modified_functions = [
            {'function_name': 'main', 'similarity': 0.8}
        ]

        summary = analyzer._generate_diff_summary()

        self.assertIn('baseline.bin', summary)
        self.assertIn('target.bin', summary)
        self.assertIn('新增函数', summary)
        self.assertIn('删除函数', summary)
        self.assertIn('修改函数', summary)


class TestBinaryDiffAnalyzerWithMocks(unittest.TestCase):

    def test_check_vulnerability_regression(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("diff_analysis", os.path.join(BASE_DIR, "modules", "diff_analysis.py"))
        diff_analysis = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(diff_analysis)

        analyzer = diff_analysis.BinaryDiffAnalyzer.__new__(diff_analysis.BinaryDiffAnalyzer)

        baseline_func = diff_analysis.FunctionFeatures('main')
        baseline_func.dangerous_calls = {'strcpy'}

        target_func = diff_analysis.FunctionFeatures('main')
        target_func.dangerous_calls = {'strcpy', 'gets'}

        analyzer.baseline_functions = {'main': baseline_func}
        analyzer.target_functions = {'main': target_func}
        analyzer.modified_functions = [{
            'function_name': 'main',
            'similarity': 0.7
        }]

        mock_db = MagicMock()
        mock_db.search_by_function.return_value = []
        analyzer.vuln_db = mock_db

        regressions = analyzer.check_vulnerability_regression()

        self.assertEqual(len(regressions), 1)
        self.assertEqual(regressions[0]['type'], 'new_dangerous_call')
        self.assertIn('gets', regressions[0]['added_calls'])



if __name__ == '__main__':
    unittest.main()
