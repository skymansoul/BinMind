
import os
import sys
_MOD_DEBUG = False
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 直接导入模块，避免触发 __init__.py 的导入
import importlib.util
spec = importlib.util.spec_from_file_location("struct_recovery",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'modules', 'struct_recovery.py'))
struct_recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(struct_recovery)

StructRecovery = struct_recovery.StructRecovery
StructRecoveryResult = struct_recovery.StructRecoveryResult
FieldType = struct_recovery.FieldType
AccessType = struct_recovery.AccessType
FieldInfo = struct_recovery.FieldInfo
StructDefinition = struct_recovery.StructDefinition
MemoryAccess = struct_recovery.MemoryAccess


class TestStructRecovery(unittest.TestCase):

    def test_init(self):
        recovery = StructRecovery(binary_path='test.exe')
        self.assertIsNotNone(recovery)
        self.assertEqual(recovery.binary_path, 'test.exe')

    def test_add_memory_access(self):
        recovery = StructRecovery()
        access = MemoryAccess(
            address=0x1000,
            offset=0,
            size=4,
            access_type=AccessType.READ,
            instruction_address=0x2000,
            function_name='main',
            context='mov eax, [ebx]'
        )
        recovery.add_memory_access(access)
        self.assertEqual(len(recovery.memory_accesses), 1)

    def test_add_memory_accesses(self):
        recovery = StructRecovery()
        accesses = [
            MemoryAccess(0x1000, 0, 4, AccessType.READ, 0x2000, 'main'),
            MemoryAccess(0x1004, 4, 4, AccessType.WRITE, 0x2004, 'main')
        ]
        recovery.add_memory_accesses(accesses)
        self.assertEqual(len(recovery.memory_accesses), 2)

    def test_extract_access_patterns(self):
        recovery = StructRecovery()
        accesses = [
            MemoryAccess(0x1000, 0, 4, AccessType.READ, 0x2000, 'main'),
            MemoryAccess(0x1004, 4, 4, AccessType.WRITE, 0x2004, 'main'),
            MemoryAccess(0x2000, 0, 4, AccessType.READ, 0x3000, 'main')
        ]
        recovery.add_memory_accesses(accesses)
        patterns = recovery._extract_access_patterns()
        self.assertEqual(len(patterns), 2)

    def test_infer_field_type_by_size(self):
        recovery = StructRecovery()
        access = MemoryAccess(0x1000, 0, 4, AccessType.READ, 0x2000, 'main')
        field_type, confidence = recovery._infer_field_type([access])
        self.assertIn(field_type, [FieldType.INT32, FieldType.UINT32, FieldType.INT, FieldType.UINT, FieldType.FLOAT])
        self.assertEqual(confidence, 0.5)

    def test_infer_field_type_unknown(self):
        recovery = StructRecovery()
        field_type, confidence = recovery._infer_field_type([])
        self.assertEqual(field_type, FieldType.UNKNOWN)
        self.assertEqual(confidence, 0.0)

    def test_cluster_fields(self):
        recovery = StructRecovery()
        accesses = [
            MemoryAccess(0x1000, 0, 4, AccessType.READ, 0x2000, 'main'),
            MemoryAccess(0x1004, 4, 4, AccessType.WRITE, 0x2004, 'main'),
            MemoryAccess(0x1008, 8, 8, AccessType.READ, 0x2008, 'main')
        ]
        recovery.add_memory_accesses(accesses)
        fields = recovery._cluster_fields(accesses)
        self.assertEqual(len(fields), 3)

    def test_calculate_struct_size(self):
        fields = [
            FieldInfo(name='field1', offset=0, size=4),
            FieldInfo(name='field2', offset=4, size=4),
            FieldInfo(name='field3', offset=8, size=8)
        ]
        recovery = StructRecovery()
        size = recovery._calculate_struct_size(fields)
        self.assertEqual(size, 16)

    def test_calculate_struct_size_empty(self):
        recovery = StructRecovery()
        size = recovery._calculate_struct_size([])
        self.assertEqual(size, 0)

    def test_analyze_no_accesses(self):
        recovery = StructRecovery()
        result = recovery.analyze()
        self.assertEqual(result.num_structs, 0)
        self.assertEqual(result.recovered_fields, 0)

    def test_analyze_with_accesses(self):
        recovery = StructRecovery()
        accesses = [
            MemoryAccess(0x1000, 0, 4, AccessType.READ, 0x2000, 'main', 'strcpy'),
            MemoryAccess(0x1004, 4, 4, AccessType.WRITE, 0x2004, 'main'),
            MemoryAccess(0x1008, 8, 8, AccessType.READ, 0x2008, 'main')
        ]
        recovery.add_memory_accesses(accesses)
        result = recovery.analyze()
        self.assertGreaterEqual(result.num_structs, 0)

    def test_generate_c_code(self):
        struct = StructDefinition(
            name='test_struct',
            fields=[
                FieldInfo(name='field1', offset=0, size=4, field_type=FieldType.INT32),
                FieldInfo(name='field2', offset=4, size=8, field_type=FieldType.CHAR_PTR, is_pointer=True)
            ],
            size=12
        )
        recovery = StructRecovery()
        recovery.structs = [struct]
        code = recovery.generate_c_code()
        self.assertIn('struct test_struct', code)
        self.assertIn('int32_t field1', code)
        self.assertIn('char** field2', code)

    def test_generate_header_file(self):
        struct = StructDefinition(
            name='test_struct',
            fields=[FieldInfo(name='field1', offset=0, size=4, field_type=FieldType.INT32)],
            size=4
        )
        recovery = StructRecovery()
        recovery.structs = [struct]

        output_path = 'test_structs.h'
        try:
            success = recovery.generate_header_file(output_path)
            self.assertTrue(success)
            self.assertTrue(os.path.exists(output_path))
        finally:
            if os.path.exists(output_path):
                os.remove(output_path)

    def test_get_struct_by_name(self):
        struct = StructDefinition(name='test_struct', fields=[])
        recovery = StructRecovery()
        recovery.structs = [struct]
        found = recovery.get_struct_by_name('test_struct')
        self.assertIsNotNone(found)
        self.assertEqual(found.name, 'test_struct')

    def test_get_struct_by_name_not_found(self):
        recovery = StructRecovery()
        found = recovery.get_struct_by_name('nonexistent')
        self.assertIsNone(found)

    def test_get_structs_by_function(self):
        struct1 = StructDefinition(name='struct1', fields=[], source_function='main')
        struct2 = StructDefinition(name='struct2', fields=[], source_function='func1')
        recovery = StructRecovery()
        recovery.structs = [struct1, struct2]
        found = recovery.get_structs_by_function('main')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].name, 'struct1')

    def test_get_analysis_summary(self):
        recovery = StructRecovery()
        summary = recovery.get_analysis_summary()
        self.assertIsInstance(summary, dict)
        self.assertIn('num_structs', summary)
        self.assertIn('total_fields', summary)

    def test_refine_struct_name(self):
        struct = StructDefinition(name='old_name', fields=[])
        recovery = StructRecovery()
        recovery.structs = [struct]
        success = recovery.refine_struct_name('old_name', 'new_name')
        self.assertTrue(success)
        self.assertEqual(struct.name, 'new_name')

    def test_refine_struct_name_not_found(self):
        recovery = StructRecovery()
        success = recovery.refine_struct_name('nonexistent', 'new_name')
        self.assertFalse(success)

    def test_refine_field_name(self):
        field = FieldInfo(name='old_field', offset=0, size=4)
        struct = StructDefinition(name='test_struct', fields=[field])
        recovery = StructRecovery()
        recovery.structs = [struct]
        success = recovery.refine_field_name('test_struct', 'old_field', 'new_field')
        self.assertTrue(success)
        self.assertEqual(field.name, 'new_field')

    def test_field_type_enum(self):
        # 历史版本保留——便于理解代码演进
        self.assertEqual(FieldType.INT8.value, 'int8_t')
        self.assertEqual(FieldType.INT32.value, 'int32_t')
        self.assertEqual(FieldType.CHAR.value, 'char')
        self.assertEqual(FieldType.CHAR_PTR.value, 'char*')
        self.assertEqual(FieldType.VOID_PTR.value, 'void*')

    def test_access_type_enum(self):
        self.assertEqual(AccessType.READ.value, 'read')
        self.assertEqual(AccessType.WRITE.value, 'write')
        self.assertEqual(AccessType.READ_WRITE.value, 'read_write')

    def test_field_info_dataclass(self):
        field = FieldInfo(
            name='test_field',
            offset=0,
            size=4,
            field_type=FieldType.INT32,
            is_pointer=False,
            array_size=0,
            access_type=AccessType.READ,
            alignment=4,
            comment='test comment',
            confidence=0.8
        )
        self.assertEqual(field.name, 'test_field')
        self.assertEqual(field.size, 4)

    def test_struct_definition_dataclass(self):
        # 历经多个版本迭代后固定
        struct = StructDefinition(
            name='test_struct',
            fields=[],
            size=16,
            alignment=4,
            is_union=False,
            parent_struct=None,
            nested_structs=['nested1'],
            source_function='main',
            description='test struct'
        )
        self.assertEqual(struct.name, 'test_struct')
        self.assertEqual(struct.size, 16)


class TestStructRecoveryResult(unittest.TestCase):

    def test_result_dataclass(self):
        result = StructRecoveryResult(
            structs=[],
            num_structs=0,
            recovered_fields=0,
            avg_confidence=0.0,
            source_functions=[],
            warnings=[]
        )
        self.assertEqual(result.num_structs, 0)
        self.assertEqual(result.recovered_fields, 0)



if __name__ == '__main__':
    unittest.main()


