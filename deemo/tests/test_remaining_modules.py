"""
测试新模块：内存对象重构、YARA规则生成、反编译增强、自动补丁
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# 测试内存对象重构模块
from modules.memory_object_reconstructor import (
    MemoryObjectReconstructor,
    AllocatorType,
    ObjectType,
    ReconstructionResult
)


class TestMemoryObjectReconstructor(unittest.TestCase):
    """测试内存对象重构器"""
    
    def test_reconstructor_initialization(self):
        """测试重构器初始化"""
        reconstructor = MemoryObjectReconstructor()
        
        self.assertEqual(reconstructor.allocator_type, AllocatorType.UNKNOWN)
    
    def test_reconstruct_with_data(self):
        """测试使用数据重构"""
        reconstructor = MemoryObjectReconstructor()
        
        # 创建测试数据
        test_data = bytes([0x00] * 256)
        
        result = reconstructor.reconstruct(memory_data=test_data)
        
        self.assertIsInstance(result, ReconstructionResult)
        self.assertTrue(result.analysis_success)
    
    def test_detect_allocator_type(self):
        """测试分配器类型检测"""
        reconstructor = MemoryObjectReconstructor()
        
        test_data = bytes([0x00, 0x00, 0x00, 0x00])
        reconstructor._detect_allocator_type(test_data)
        
        self.assertIsInstance(reconstructor.allocator_type, AllocatorType)


# 测试YARA规则生成模块
from modules.yara_auto_gen import (
    YaraAutoGenerator,
    FeatureType,
    YaraRule,
    GenerationResult
)


class TestYaraAutoGenerator(unittest.TestCase):
    """测试YARA规则生成器"""
    
    def test_generator_initialization(self):
        """测试生成器初始化"""
        generator = YaraAutoGenerator()
        
        self.assertEqual(len(generator.features), 0)
    
    def test_extract_string_features(self):
        """测试字符串特征提取"""
        generator = YaraAutoGenerator()
        
        test_data = b"Hello World\x00This is a test\x00"
        generator._extract_string_features(test_data)
        
        self.assertGreater(len(generator.features), 0)
    
    def test_generate_rules(self):
        """测试规则生成"""
        generator = YaraAutoGenerator()
        
        test_data = b"MZ\x90\x00" + bytes([0x00] * 100) + b"test string\x00"
        result = generator.generate_rules(sample_data=test_data)
        
        self.assertIsInstance(result, GenerationResult)
        self.assertTrue(result.analysis_success)
    
    def test_export_rules(self):
        """测试规则导出"""
        generator = YaraAutoGenerator()
        
        # 创建临时规则
        rule = YaraRule(
            name="test_rule",
            raw_rule="rule test_rule { condition: true }"
        )
        generator.rules.append(rule)
        
        # 导出规则
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as f:
            temp_path = f.name
        
        try:
            success = generator.export_rules(temp_path)
            self.assertTrue(success)
        finally:
            os.unlink(temp_path)


# 测试反编译增强模块
from modules.decompiler_enhancements import (
    DecompilerEnhancer,
    ControlFlowType,
    EnhancementResult
)


class TestDecompilerEnhancer(unittest.TestCase):
    """测试反编译增强器"""
    
    def test_enhancer_initialization(self):
        """测试增强器初始化"""
        enhancer = DecompilerEnhancer()
        
        self.assertEqual(len(enhancer.control_flow_nodes), 0)
    
    def test_enhance_pseudocode(self):
        """测试伪代码增强"""
        pseudocode = """
        int add(int a, int b) {
            int result = a + b;
            return result;
        }
        """
        
        enhancer = DecompilerEnhancer(pseudocode)
        result = enhancer.enhance()
        
        self.assertIsInstance(result, EnhancementResult)
        self.assertTrue(result.analysis_success)
    
    def test_parse_control_flow(self):
        """测试控制流解析"""
        pseudocode = """
        if (x > 0) {
            return 1;
        }
        while (i < 10) {
            i++;
        }
        """
        
        enhancer = DecompilerEnhancer(pseudocode)
        enhancer._parse_control_flow()
        
        self.assertGreater(len(enhancer.control_flow_nodes), 0)
    
    def test_extract_variables(self):
        """测试变量提取"""
        pseudocode = "int x = 10; char *buffer = NULL;"
        
        enhancer = DecompilerEnhancer(pseudocode)
        enhancer._extract_variables()
        
        self.assertGreater(len(enhancer.variables), 0)
    
    def test_simplify_expression(self):
        """测试表达式简化"""
        enhancer = DecompilerEnhancer()
        
        simplified = enhancer.simplify_expression("x + 0")
        self.assertEqual(simplified, "x")
        
        simplified = enhancer.simplify_expression("0 + y")
        self.assertEqual(simplified, "y")


# 测试自动补丁模块
from modules.auto_patcher import (
    AutoPatcher,
    VulnerabilityType,
    PatchStrategy,
    PatchResult
)


class TestAutoPatcher(unittest.TestCase):
    """测试自动补丁器"""
    
    def test_patcher_initialization(self):
        """测试补丁器初始化"""
        import tempfile
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            f.write(bytes([0x00] * 256))
            temp_path = f.name
        
        try:
            patcher = AutoPatcher(temp_path)
            self.assertEqual(patcher.binary_path, temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_detect_vulnerabilities(self):
        """测试漏洞检测"""
        import tempfile
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            f.write(bytes([0x00] * 256))
            temp_path = f.name
        
        try:
            patcher = AutoPatcher(temp_path)
            patcher._load_binary()
            patcher._detect_vulnerabilities()
            
            self.assertGreaterEqual(len(patcher.vulnerabilities), 0)
        finally:
            os.unlink(temp_path)
    
    def test_generate_patches(self):
        """测试补丁生成"""
        import tempfile
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            f.write(bytes([0x00] * 256))
            temp_path = f.name
        
        try:
            patcher = AutoPatcher(temp_path)
            
            vuln = VulnerabilityInfo(
                address=0,
                type=VulnerabilityType.BUFFER_OVERFLOW,
                severity=0.8
            )
            patcher.vulnerabilities.append(vuln)
            patcher._load_binary()
            patcher._generate_patches()
            
            self.assertGreaterEqual(len(patcher.patches), 0)
        finally:
            os.unlink(temp_path)
    
    def test_analyze_and_patch(self):
        """测试分析与补丁"""
        import tempfile
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            f.write(bytes([0x00] * 256))
            temp_path = f.name
        
        try:
            patcher = AutoPatcher(temp_path)
            result = patcher.analyze_and_patch()
            
            self.assertIsInstance(result, PatchResult)
            self.assertTrue(result.analysis_success)
        finally:
            os.unlink(temp_path)


if __name__ == '__main__':
    unittest.main()