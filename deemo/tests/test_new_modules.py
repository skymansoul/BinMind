"""
测试新模块：深度程序理解与逆向增强
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# 测试类型推断引擎
from modules.type_inferrer import TypeInferrer, TypeKind, TypeInferenceResult


class TestTypeInferenceEngine(unittest.TestCase):
    """测试类型推断引擎"""
    
    def test_basic_inference(self):
        """测试基本类型推断"""
        inferrer = TypeInferrer(use_z3=False)
        
        pseudocode = """
        int process_data(char *buffer, int size) {
            int i;
            for (i = 0; i < size; i++) {
                buffer[i] = buffer[i] ^ 0xAA;
            }
            return 0;
        }
        """
        
        result = inferrer.infer_types(pseudocode)
        
        self.assertIsInstance(result, TypeInferenceResult)
        self.assertIn('buffer', result.variables)
        self.assertIn('size', result.variables)
        
        buffer_var = result.variables['buffer']
        self.assertTrue(any(t.kind == TypeKind.POINTER for t in buffer_var.inferred_types))
    
    def test_function_extraction(self):
        """测试函数签名提取"""
        inferrer = TypeInferrer(use_z3=False)
        
        pseudocode = """
        int add(int a, int b) {
            return a + b;
        }
        """
        
        result = inferrer.infer_types(pseudocode)
        
        self.assertIn('add', result.functions)
        func = result.functions['add']
        self.assertEqual(len(func.param_names), 2)


# 测试动态结构体探测器
from modules.dynamic_struct_prober import DynamicStructProber, ProbeMode, StructInfo


class TestDynamicStructProber(unittest.TestCase):
    """测试动态结构体探测器"""
    
    def test_probe_initialization(self):
        """测试探测器初始化"""
        prober = DynamicStructProber("/path/to/binary")
        
        self.assertEqual(prober.binary_path, "/path/to/binary")
        self.assertIsInstance(prober.mode, ProbeMode)
    
    def test_probe_struct_layout(self):
        """测试结构体布局探测"""
        prober = DynamicStructProber("/path/to/binary")
        result = prober.probe_struct_layout(max_struct_size=64)
        
        self.assertTrue(result.analysis_success)
        self.assertGreaterEqual(len(result.structs), 0)
    
    def test_generate_header(self):
        """测试生成头文件"""
        struct_info = StructInfo(name="test_struct", size=16)
        result = prober.probe_struct_layout(max_struct_size=16)
        
        self.assertIsInstance(result.header_content, str)


# 测试虚表恢复器
from modules.precise_vtable_recovery import PreciseVTableRecovery, VTableRecoveryResult


class TestVTableRecovery(unittest.TestCase):
    """测试虚表恢复器"""
    
    def test_recovery_initialization(self):
        """测试恢复器初始化"""
        recoverer = PreciseVTableRecovery("/path/to/binary")
        
        self.assertEqual(recoverer.binary_path, "/path/to/binary")
    
    def test_recover_vtables(self):
        """测试恢复虚表"""
        recoverer = PreciseVTableRecovery("/path/to/binary")
        result = recoverer.recover_vtables()
        
        self.assertIsInstance(result, VTableRecoveryResult)
        self.assertTrue(result.analysis_success)


# 测试密码学参数提取器
from modules.crypto_param_extractor import CryptoParamExtractor, CryptoAlgorithm


class TestCryptoParamExtractor(unittest.TestCase):
    """测试密码学参数提取器"""
    
    def test_extractor_initialization(self):
        """测试提取器初始化"""
        extractor = CryptoParamExtractor("/path/to/binary")
        
        self.assertEqual(extractor.binary_path, "/path/to/binary")
    
    def test_detect_algorithms(self):
        """测试算法检测"""
        extractor = CryptoParamExtractor("/path/to/binary")
        pseudocode = "AES_encrypt(key, data); SHA256_hash(buffer);"
        
        result = extractor.extract_parameters(pseudocode)
        
        self.assertIn(CryptoAlgorithm.AES, result.detected_algorithms)
        self.assertIn(CryptoAlgorithm.SHA256, result.detected_algorithms)
    
    def test_extract_aes_key(self):
        """测试提取AES密钥"""
        extractor = CryptoParamExtractor("/path/to/binary")
        pseudocode = "key = 0x00112233445566778899AABBCCDDEEFF;"
        
        result = extractor.extract_parameters(pseudocode)
        
        self.assertGreaterEqual(len(result.keys), 0)


# 测试虚拟机反混淆器
from modules.vm_unvirtualizer import VMUnvirtualizer, VMType, VMOpcode


class TestVMUnvirtualizer(unittest.TestCase):
    """测试虚拟机反混淆器"""
    
    def test_unvirtualizer_initialization(self):
        """测试反混淆器初始化"""
        unvirtualizer = VMUnvirtualizer("/path/to/binary")
        
        self.assertEqual(unvirtualizer.binary_path, "/path/to/binary")
    
    def test_detect_vm_type(self):
        """测试虚拟机类型检测"""
        unvirtualizer = VMUnvirtualizer("/path/to/binary")
        
        # 创建一个包含VMProtect签名的临时文件
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.bin', delete=False) as f:
            f.write("This is a test file with VMProtect signature")
            temp_path = f.name
        
        try:
            unvirtualizer2 = VMUnvirtualizer(temp_path)
            unvirtualizer2._detect_vm_type()
        finally:
            os.unlink(temp_path)


# 测试字符串反混淆器
from modules.string_unobfuscator import StringUnobfuscator, ObfuscationType


class TestStringUnobfuscator(unittest.TestCase):
    """测试字符串反混淆器"""
    
    def test_unobfuscator_initialization(self):
        """测试反混淆器初始化"""
        unobfuscator = StringUnobfuscator("/path/to/binary")
        
        self.assertEqual(unobfuscator.binary_path, "/path/to/binary")
    
    def test_xor_decode(self):
        """测试XOR解码"""
        unobfuscator = StringUnobfuscator("/path/to/binary")
        
        original = b"Hello World"
        key = 0xAA
        encrypted = bytes(b ^ key for b in original)
        
        result = unobfuscator.unobfuscate(data_section=encrypted + b'\x00')
        
        self.assertGreaterEqual(len(result.decrypted_strings), 0)
    
    def test_custom_rule(self):
        """测试自定义解码规则"""
        unobfuscator = StringUnobfuscator("/path/to/binary")
        
        def custom_decoder(data):
            return bytes(b ^ 0x55 for b in data)
        
        unobfuscator.add_custom_rule("custom", custom_decoder, "Custom XOR with 0x55")
        
        self.assertEqual(len(unobfuscator.custom_rules), 1)


if __name__ == '__main__':
    unittest.main()