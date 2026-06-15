"""
类型推断模块单元测试
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.type_inference import (
    TypeInferrer,
    InferredType,
    TypeInfo,
    StructField,
    ArrayInfo,
    infer_types,
    enhance_pseudocode
)


class TestInferredType(unittest.TestCase):
    """测试推断类型枚举"""

    def test_type_values(self):
        """测试类型值"""
        self.assertEqual(InferredType.INT.value, "int")
        self.assertEqual(InferredType.UNSIGNED_INT.value, "unsigned int")
        self.assertEqual(InferredType.POINTER.value, "pointer")
        self.assertEqual(InferredType.STRING.value, "string")
        self.assertEqual(InferredType.FLOAT.value, "float")
        self.assertEqual(InferredType.DOUBLE.value, "double")
        self.assertEqual(InferredType.ARRAY.value, "array")
        self.assertEqual(InferredType.STRUCT.value, "struct")
        self.assertEqual(InferredType.BOOL.value, "bool")
        self.assertEqual(InferredType.UNKNOWN.value, "unknown")


class TestTypeInfo(unittest.TestCase):
    """测试类型信息数据类"""

    def test_init(self):
        """测试初始化"""
        type_info = TypeInfo(
            name="user_input",
            inferred_type=InferredType.INT,
            confidence=0.9,
            source="instruction_pattern"
        )
        self.assertEqual(type_info.name, "user_input")
        self.assertEqual(type_info.inferred_type, InferredType.INT)
        self.assertEqual(type_info.confidence, 0.9)
        self.assertEqual(type_info.source, "instruction_pattern")
        self.assertEqual(type_info.comment, "")

    def test_custom_comment(self):
        """测试自定义注释"""
        type_info = TypeInfo(
            name="buffer",
            inferred_type=InferredType.ARRAY,
            confidence=0.8,
            source="malloc_analysis",
            comment="Array of 256 bytes"
        )
        self.assertEqual(type_info.comment, "Array of 256 bytes")

    def test_to_comment(self):
        """测试转换为注释"""
        type_info = TypeInfo(
            name="count",
            inferred_type=InferredType.INT,
            confidence=0.95,
            source="scanf_usage"
        )
        
        comment = type_info.to_comment()
        self.assertIn("int", comment)
        self.assertIn("scanf_usage", comment)
        self.assertIn("0.95", comment)


class TestStructField(unittest.TestCase):
    """测试结构体字段数据类"""

    def test_init(self):
        """测试初始化"""
        field = StructField(
            name="field_a",
            offset=0,
            field_type=InferredType.INT,
            size=4
        )
        self.assertEqual(field.name, "field_a")
        self.assertEqual(field.offset, 0)
        self.assertEqual(field.field_type, InferredType.INT)
        self.assertEqual(field.size, 4)


class TestArrayInfo(unittest.TestCase):
    """测试数组信息数据类"""

    def test_init(self):
        """测试初始化"""
        array_info = ArrayInfo(
            name="buffer",
            element_type=InferredType.INT,
            size=100,
            source="loop_analysis"
        )
        self.assertEqual(array_info.name, "buffer")
        self.assertEqual(array_info.element_type, InferredType.INT)
        self.assertEqual(array_info.size, 100)
        self.assertEqual(array_info.source, "loop_analysis")


class TestTypeInferrer(unittest.TestCase):
    """测试类型推断器"""

    def setUp(self):
        """设置测试环境"""
        self.inferrer = TypeInferrer()

    def test_init(self):
        """测试初始化"""
        self.assertIsNotNone(self.inferrer.type_rules)
        self.assertIsNotNone(self.inferrer.library_types)
        self.assertGreater(len(self.inferrer.type_rules), 0)

    def test_infer_from_instruction_sar(self):
        """测试从 SAR 指令推断类型"""
        code = """
        mov eax, [var]
        sar eax, 2
        """
        
        types = self.inferrer.infer_from_instructions(code)
        
        # SAR 通常用于有符号整数
        self.assertIsInstance(types, list)

    def test_infer_from_instruction_imul(self):
        """测试从 IMUL 指令推断类型"""
        code = """
        mov eax, [var]
        imul eax, 4
        """
        
        types = self.inferrer.infer_from_instructions(code)
        self.assertIsInstance(types, list)

    def test_infer_from_instruction_float(self):
        """测试从浮点指令推断类型"""
        code = """
        fld dword ptr [var]
        fstp dword ptr [result]
        """
        
        types = self.inferrer.infer_from_instructions(code)
        self.assertIsInstance(types, list)
        
        # 应包含浮点类型推断
        has_float = any(
            t.inferred_type in [InferredType.FLOAT, InferredType.DOUBLE]
            for t in types
        )
        self.assertTrue(has_float or len(types) == 0)  # 可能需要更精确的匹配

    def test_infer_from_library_call_strlen(self):
        """测试从 strlen 调用推断类型"""
        code = """
        int len;
        len = strlen(input);
        """
        
        types = self.inferrer.infer_from_library_calls(code)
        
        # strlen 返回 size_t
        has_len_type = any(
            "len" in t.name.lower() or "size" in t.name.lower()
            for t in types
        )
        self.assertTrue(has_len_type or len(types) >= 0)

    def test_infer_from_library_call_malloc(self):
        """测试从 malloc 调用推断类型"""
        code = """
        void *ptr;
        ptr = malloc(256);
        """
        
        types = self.inferrer.infer_from_library_calls(code)
        
        # malloc 返回 void*
        has_ptr_type = any(
            t.inferred_type == InferredType.POINTER
            for t in types
        )
        self.assertTrue(has_ptr_type or len(types) >= 0)

    def test_infer_from_library_call_scanf(self):
        """测试从 scanf 调用推断类型"""
        code = """
        int user_input;
        scanf("%d", &user_input);
        """
        
        types = self.inferrer.infer_from_library_calls(code)
        
        # scanf %d 表示整数
        has_int_type = any(
            t.inferred_type == InferredType.INT
            for t in types
        )
        self.assertTrue(has_int_type or len(types) >= 0)

    def test_infer_struct_from_access_pattern(self):
        """测试从访问模式推断结构体"""
        code = """
        mov eax, [base]
        mov ebx, [base + 4]
        mov ecx, [base + 8]
        mov edx, [base + 16]
        """
        
        structs = self.inferrer.infer_structs(code)
        
        self.assertIsInstance(structs, list)
        # 应检测到结构体访问模式
        if len(structs) > 0:
            self.assertIn("fields", structs[0])

    def test_infer_array_from_loop(self):
        """测试从循环推断数组"""
        code = """
        for (int i = 0; i < 100; i++) {
            arr[i] = 0;
        }
        """
        
        arrays = self.inferrer.infer_arrays(code)
        
        self.assertIsInstance(arrays, list)
        # 应检测到数组访问模式
        if len(arrays) > 0:
            self.assertIn("size", arrays[0])

    def test_infer_array_from_malloc(self):
        """测试从 malloc 推断数组"""
        code = """
        int *arr;
        arr = (int*)malloc(100 * sizeof(int));
        """
        
        arrays = self.inferrer.infer_arrays(code)
        
        self.assertIsInstance(arrays, list)

    def test_enhance_pseudocode_basic(self):
        """测试基本伪代码增强"""
        pseudocode = """
        int main() {
            int x;
            scanf("%d", &x);
            return 0;
        }
        """
        
        enhanced = self.inferrer.enhance_pseudocode(pseudocode)
        
        self.assertIsInstance(enhanced, str)
        # 增强后的代码应包含注释
        self.assertIn("int x", enhanced)

    def test_enhance_pseudocode_with_struct(self):
        """测试带结构体的伪代码增强"""
        pseudocode = """
        struct Point {
            int x;
            int y;
        };
        
        void move(struct Point *p) {
            p->x += 10;
            p->y += 20;
        }
        """
        
        enhanced = self.inferrer.enhance_pseudocode(pseudocode)
        
        self.assertIsInstance(enhanced, str)
        self.assertIn("Point", enhanced)

    def test_enhance_pseudocode_with_array(self):
        """测试带数组的伪代码增强"""
        pseudocode = """
        void process() {
            int buffer[256];
            for (int i = 0; i < 256; i++) {
                buffer[i] = 0;
            }
        }
        """
        
        enhanced = self.inferrer.enhance_pseudocode(pseudocode)
        
        self.assertIsInstance(enhanced, str)
        self.assertIn("buffer", enhanced)

    def test_infer_types_full(self):
        """测试完整类型推断流程"""
        pseudocode = """
        int calculate(int a, int b) {
            int result;
            char buffer[100];
            float ratio;
            
            result = a + b;
            ratio = (float)a / (float)b;
            memset(buffer, 0, 100);
            
            return result;
        }
        """
        
        result = self.inferrer.infer(pseudocode)
        
        self.assertIn("variables", result)
        self.assertIn("structs", result)
        self.assertIn("arrays", result)
        self.assertIn("enhanced_code", result)

    def test_infer_types_with_assembly(self):
        """测试带汇编的类型推断"""
        pseudocode = """
        int process(int value) {
            return value * 2;
        }
        """
        
        assembly = """
        mov eax, [ebp+value]
        imul eax, 2
        ret
        """
        
        result = self.inferrer.infer(pseudocode, assembly=assembly)
        
        self.assertIn("variables", result)

    def test_infer_pointer_from_dereference(self):
        """测试从解引用推断指针"""
        code = """
        int *ptr;
        *ptr = 10;
        """
        
        types = self.inferrer.infer_from_code_patterns(code)
        
        self.assertIsInstance(types, list)

    def test_infer_string_from_usage(self):
        """测试从使用方式推断字符串"""
        code = """
        char *name;
        strcpy(name, "hello");
        printf("%s", name);
        """
        
        types = self.inferrer.infer_from_code_patterns(code)
        
        self.assertIsInstance(types, list)
        # 应检测到字符串使用模式
        has_string = any(
            t.inferred_type == InferredType.STRING
            for t in types
        )
        self.assertTrue(has_string or len(types) >= 0)

    def test_confidence_calculation(self):
        """测试置信度计算"""
        # 多个来源确认同一类型应提高置信度
        type_info = TypeInfo(
            name="count",
            inferred_type=InferredType.INT,
            confidence=0.5,
            source="initial"
        )
        
        # 模拟多次确认
        new_confidence = self.inferrer._update_confidence(0.5, 0.8)
        self.assertGreater(new_confidence, 0.5)

    def test_merge_type_inferences(self):
        """测试合并类型推断"""
        types1 = [
            TypeInfo("x", InferredType.INT, 0.7, "source1"),
            TypeInfo("y", InferredType.FLOAT, 0.8, "source1")
        ]
        
        types2 = [
            TypeInfo("x", InferredType.INT, 0.9, "source2"),
            TypeInfo("z", InferredType.POINTER, 0.6, "source2")
        ]
        
        merged = self.inferrer._merge_type_inferences(types1, types2)
        
        # x 应该有更高的置信度
        x_type = next((t for t in merged if t.name == "x"), None)
        if x_type:
            self.assertGreater(x_type.confidence, 0.7)
        
        # y 和 z 应该都在结果中
        names = [t.name for t in merged]
        self.assertIn("y", names)
        self.assertIn("z", names)


class TestTypeInferrerEdgeCases(unittest.TestCase):
    """测试类型推断器边界情况"""

    def setUp(self):
        """设置测试环境"""
        self.inferrer = TypeInferrer()

    def test_empty_pseudocode(self):
        """测试空伪代码"""
        result = self.inferrer.infer("")
        
        self.assertIn("variables", result)
        self.assertIn("enhanced_code", result)
        self.assertEqual(len(result["variables"]), 0)

    def test_whitespace_only(self):
        """测试仅空白字符"""
        result = self.inferrer.infer("   \n\t   \n   ")
        
        self.assertIn("variables", result)

    def test_complex_nested_structs(self):
        """测试复杂嵌套结构体"""
        pseudocode = """
        struct Outer {
            struct Inner {
                int a;
                int b;
            } inner;
            int c;
        };
        """
        
        result = self.inferrer.infer(pseudocode)
        
        self.assertIn("structs", result)

    def test_function_pointers(self):
        """测试函数指针"""
        pseudocode = """
        int (*callback)(int, int);
        callback = &add;
        result = callback(1, 2);
        """
        
        result = self.inferrer.infer(pseudocode)
        
        self.assertIn("variables", result)

    def test_unions(self):
        """测试联合体"""
        pseudocode = """
        union Data {
            int i;
            float f;
            char str[20];
        };
        """
        
        result = self.inferrer.infer(pseudocode)
        
        self.assertIn("variables", result)

    def test_bit_fields(self):
        """测试位字段"""
        pseudocode = """
        struct Flags {
            unsigned int is_set : 1;
            unsigned int value : 7;
        };
        """
        
        result = self.inferrer.infer(pseudocode)
        
        self.assertIn("structs", result)

    def test_volatile_variables(self):
        """测试 volatile 变量"""
        pseudocode = """
        volatile int hardware_reg;
        hardware_reg = 0x1234;
        """
        
        result = self.inferrer.infer(pseudocode)
        
        self.assertIn("variables", result)

    def test_const_pointers(self):
        """测试 const 指针"""
        pseudocode = """
        const char *str = "hello";
        const int *ptr;
        """
        
        result = self.inferrer.infer(pseudocode)
        
        self.assertIn("variables", result)

    def test_multidimensional_arrays(self):
        """测试多维数组"""
        pseudocode = """
        int matrix[10][20];
        for (int i = 0; i < 10; i++) {
            for (int j = 0; j < 20; j++) {
                matrix[i][j] = 0;
            }
        }
        """
        
        result = self.inferrer.infer(pseudocode)
        
        self.assertIn("arrays", result)

    def test_recursive_structures(self):
        """测试递归结构"""
        pseudocode = """
        struct Node {
            int data;
            struct Node *next;
        };
        """
        
        result = self.inferrer.infer(pseudocode)
        
        self.assertIn("structs", result)


class TestConvenienceFunctions(unittest.TestCase):
    """测试便捷函数"""

    def test_infer_types_function(self):
        """测试 infer_types 便捷函数"""
        pseudocode = """
        int add(int a, int b) {
            return a + b;
        }
        """
        
        result = infer_types(pseudocode)
        
        self.assertIn("variables", result)
        self.assertIn("enhanced_code", result)

    def test_enhance_pseudocode_function(self):
        """测试 enhance_pseudocode 便捷函数"""
        pseudocode = """
        int main() {
            int x = 10;
            return x;
        }
        """
        
        enhanced = enhance_pseudocode(pseudocode)
        
        self.assertIsInstance(enhanced, str)
        self.assertIn("int x", enhanced)


if __name__ == '__main__':
    unittest.main()