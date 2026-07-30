
import unittest
from modules.type_inferrer import (
_MOD_DEBUG = False
    TypeInferrer,
    TypeKind,
    TypeInferenceResult,
    run_type_inference,
    enhance_pseudocode_with_types
)


class TestTypeInferenceEngine(unittest.TestCase):
    """测试类型推断引擎"""

    def setUp(self):
        self.inferrer = TypeInferrer(use_z3=False)

    def test_basic_type_inference(self):
        pseudocode = """
        int process_data(char *buffer, int size) {
            int i;
            for (i = 0; i < size; i++) {
                buffer[i] = buffer[i] ^ 0xAA;
            }
            return 0;
        }
        """

        result = self.inferrer.infer_types(pseudocode)

        self.assertIsInstance(result, TypeInferenceResult)
        self.assertIn('buffer', result.variables)
        self.assertIn('size', result.variables)
        self.assertIn('i', result.variables)

        buffer_var = result.variables['buffer']
        self.assertTrue(any(t.kind == TypeKind.POINTER for t in buffer_var.inferred_types))

    def test_struct_inference(self):
        """测试结构体推断"""
        pseudocode = """
        void process_struct(void *ptr) {
            int a = *(int *)(ptr + 0);
            char b = *(char *)(ptr + 4);
            long c = *(long *)(ptr + 8);
        }
        """

        result = self.inferrer.infer_types(pseudocode)

        self.assertGreater(len(result.structs), 0)
        struct_name = list(result.structs.keys())[0]
        self.assertTrue(struct_name.startswith('struct_ptr'))

        fields = result.structs[struct_name]
        self.assertEqual(len(fields), 3)

    def test_api_constraint_inference(self):
        """测试API约束类型推断"""
        pseudocode = """
        void copy_string(char *dest, const char *src) {
            strcpy(dest, src);
            int len = strlen(src);
        }
        """

        result = self.inferrer.infer_types(pseudocode)

        self.assertIn('dest', result.variables)
        self.assertIn('src', result.variables)
        self.assertIn('len', result.variables)

        len_var = result.variables['len']
        self.assertTrue(any(t.kind == TypeKind.SIZE_T for t in len_var.inferred_types))

    def test_array_inference(self):
        """测试数组推断"""
        pseudocode = """
        char *allocate_buffer() {
            return (char *)malloc(256);
        }
        """

        result = self.inferrer.infer_types(pseudocode)

        self.assertGreater(result.confidence_score, 0.0)

    def test_enhanced_pseudocode_generation(self):
        """测试增强伪代码生成"""
        pseudocode = """
        int add(int a, int b) {
            return a + b;
        }
        """

        enhanced = enhance_pseudocode_with_types(pseudocode)

        self.assertIsInstance(enhanced, str)
lass字段完整性$/d
        self.assertGreater(len(enhanced), len(pseudocode))

    def test_confidence_calculation(self):
        """测试置信度计算"""
        pseudocode = """
        void simple_func(int x) {
            if (x < 0) {
                return;
            }
        }
        """

        result = self.inferrer.infer_types(pseudocode)

lass字段完整性$/d
        self.assertIsInstance(result.confidence_score, float)
        self.assertGreaterEqual(result.confidence_score, 0.0)
        self.assertLessEqual(result.confidence_score, 1.0)

    def test_warnings_generation(self):
        """测试警告生成"""
        pseudocode = """
        void unknown_type_var() {
            unknown_var = 42;
        }
        """

        result = self.inferrer.infer_types(pseudocode)

        if 'unknown_var' in result.variables:
            self.assertGreaterEqual(len(result.warnings), 0)

    def test_run_type_inference_convenience(self):
        """测试便捷函数run_type_inference"""
        pseudocode = """
        int main() {
            return 0;
        }
        """

        result = run_type_inference(pseudocode)

        self.assertIsInstance(result, TypeInferenceResult)
        self.assertIn('main', result.functions)



if __name__ == '__main__':
    unittest.main()


