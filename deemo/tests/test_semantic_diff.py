#!/usr/bin/env python3
"""
跨版本二进制语义差异分析引擎单元测试
"""

import os
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.semantic_diff import (
    SemanticDiffAnalyzer, FunctionMatcher, SymbolicSignatureExtractor,
    MemorySideEffectExtractor, SemanticSignature, FunctionMatch,
    PatchLocation, DiffAnalysisResult, DiffResultType, SemanticSignatureType
)
from modules.ir_lifter import FunctionIR, BasicBlock, IRType


class TestDiffResultTypeEnum(unittest.TestCase):
    """差异结果类型枚举测试"""
    
    def test_diff_result_type_values(self):
        """测试差异结果类型枚举值"""
        self.assertEqual(DiffResultType.FUNCTION_ADDED.value, "function_added")
        self.assertEqual(DiffResultType.FUNCTION_REMOVED.value, "function_removed")
        self.assertEqual(DiffResultType.FUNCTION_MODIFIED.value, "function_modified")
        self.assertEqual(DiffResultType.FUNCTION_UNCHANGED.value, "function_unchanged")
        self.assertEqual(DiffResultType.PATCH_CANDIDATE.value, "patch_candidate")


class TestSemanticSignatureTypeEnum(unittest.TestCase):
    """语义签名类型枚举测试"""
    
    def test_semantic_signature_type_values(self):
        """测试语义签名类型枚举值"""
        self.assertEqual(SemanticSignatureType.SYMBOLIC_INPUT_OUTPUT.value, "symbolic_input_output")
        self.assertEqual(SemanticSignatureType.MEMORY_SIDE_EFFECT.value, "memory_side_effect")
        self.assertEqual(SemanticSignatureType.CONTROL_FLOW_GRAPH.value, "control_flow_graph")


class TestSemanticSignatureDataclass(unittest.TestCase):
    """SemanticSignature数据类测试"""
    
    def test_semantic_signature_creation(self):
        """测试语义签名创建"""
        signature = SemanticSignature(
            function_name="main",
            function_address=0x401000,
            signature_type=SemanticSignatureType.SYMBOLIC_INPUT_OUTPUT,
            signature_data={"inputs": ["eax"], "outputs": ["ebx"]},
            confidence=0.9
        )
        
        self.assertEqual(signature.function_name, "main")
        self.assertEqual(signature.function_address, 0x401000)
        self.assertEqual(signature.signature_type, SemanticSignatureType.SYMBOLIC_INPUT_OUTPUT)
        self.assertEqual(signature.confidence, 0.9)


class TestFunctionMatchDataclass(unittest.TestCase):
    """FunctionMatch数据类测试"""
    
    def test_function_match_creation(self):
        """测试函数匹配创建"""
        old_sig = SemanticSignature(
            function_name="old_func",
            function_address=0x401000,
            signature_type=SemanticSignatureType.SYMBOLIC_INPUT_OUTPUT,
            signature_data={}
        )
        
        new_sig = SemanticSignature(
            function_name="new_func",
            function_address=0x402000,
            signature_type=SemanticSignatureType.SYMBOLIC_INPUT_OUTPUT,
            signature_data={}
        )
        
        match = FunctionMatch(
            old_function=old_sig,
            new_function=new_sig,
            similarity_score=0.85,
            match_type=DiffResultType.FUNCTION_MODIFIED
        )
        
        self.assertEqual(match.similarity_score, 0.85)
        self.assertEqual(match.match_type, DiffResultType.FUNCTION_MODIFIED)


class TestPatchLocationDataclass(unittest.TestCase):
    """PatchLocation数据类测试"""
    
    def test_patch_location_creation(self):
        """测试补丁位置创建"""
        loc = PatchLocation(
            address=0x401000,
            old_bytes=b"\x90\x90",
            new_bytes=b"\x89\xd8",
            description="修复漏洞",
            severity="high"
        )
        
        self.assertEqual(loc.address, 0x401000)
        self.assertEqual(loc.old_bytes, b"\x90\x90")
        self.assertEqual(loc.severity, "high")


class TestDiffAnalysisResultDataclass(unittest.TestCase):
    """DiffAnalysisResult数据类测试"""
    
    def test_diff_analysis_result_creation(self):
        """测试差异分析结果创建"""
        result = DiffAnalysisResult(
            success=True,
            matches=[],
            patch_locations=[],
            diff_count=5,
            warnings=["警告1"],
            errors=[],
            exploit_prototype="test"
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.diff_count, 5)
        self.assertEqual(len(result.warnings), 1)


class TestSymbolicSignatureExtractor(unittest.TestCase):
    """符号签名提取器测试"""
    
    def test_extract_signature(self):
        """测试提取符号签名"""
        extractor = SymbolicSignatureExtractor()
        
        block = BasicBlock(
            start_address=0x401000,
            end_address=0x401008,
            instructions=[]
        )
        func_ir = FunctionIR(
            name="test",
            address=0x401000,
            basic_blocks=[block],
            ir_type=IRType.VEX
        )
        
        signature = extractor.extract(func_ir)
        
        self.assertEqual(signature.function_name, "test")
        self.assertEqual(signature.signature_type, SemanticSignatureType.SYMBOLIC_INPUT_OUTPUT)


class TestMemorySideEffectExtractor(unittest.TestCase):
    """内存副作用提取器测试"""
    
    def test_extract_signature(self):
        """测试提取内存副作用签名"""
        extractor = MemorySideEffectExtractor()
        
        block = BasicBlock(
            start_address=0x401000,
            end_address=0x401008,
            instructions=[]
        )
        func_ir = FunctionIR(
            name="test",
            address=0x401000,
            basic_blocks=[block],
            ir_type=IRType.VEX
        )
        
        signature = extractor.extract(func_ir)
        
        self.assertEqual(signature.signature_type, SemanticSignatureType.MEMORY_SIDE_EFFECT)


class TestFunctionMatcher(unittest.TestCase):
    """函数匹配器测试"""
    
    def test_compute_signature_similarity(self):
        """测试计算签名相似度"""
        matcher = FunctionMatcher()
        
        sig1 = SemanticSignature(
            function_name="func1",
            function_address=0x401000,
            signature_type=SemanticSignatureType.SYMBOLIC_INPUT_OUTPUT,
            signature_data={"inputs": ["eax", "ebx"], "outputs": ["ecx"]}
        )
        
        sig2 = SemanticSignature(
            function_name="func2",
            function_address=0x402000,
            signature_type=SemanticSignatureType.SYMBOLIC_INPUT_OUTPUT,
            signature_data={"inputs": ["eax", "ebx"], "outputs": ["ecx"]}
        )
        
        similarity = matcher.compute_signature_similarity(sig1, sig2)
        
        self.assertGreater(similarity, 0.5)
    
    def test_match_functions(self):
        """测试匹配函数"""
        matcher = FunctionMatcher()
        
        old_sigs = [
            SemanticSignature(
                function_name="func1",
                function_address=0x401000,
                signature_type=SemanticSignatureType.SYMBOLIC_INPUT_OUTPUT,
                signature_data={"inputs": ["eax"], "outputs": ["ebx"]}
            )
        ]
        
        new_sigs = [
            SemanticSignature(
                function_name="func1",
                function_address=0x402000,
                signature_type=SemanticSignatureType.SYMBOLIC_INPUT_OUTPUT,
                signature_data={"inputs": ["eax"], "outputs": ["ebx"]}
            )
        ]
        
        matches = matcher.match_functions(old_sigs, new_sigs)
        
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].match_type, DiffResultType.FUNCTION_UNCHANGED)


class TestSemanticDiffAnalyzer(unittest.TestCase):
    """语义差异分析器测试"""
    
    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """测试后清理"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_analyze_with_missing_files(self):
        """测试分析不存在的文件"""
        analyzer = SemanticDiffAnalyzer()
        
        result = analyzer.analyze("/nonexistent/old.bin", "/nonexistent/new.bin")
        
        self.assertFalse(result.success)
        self.assertEqual(len(result.errors), 1)
    
    def test_analyze_valid_files(self):
        """测试分析有效文件"""
        old_file = os.path.join(self.temp_dir, "old.bin")
        new_file = os.path.join(self.temp_dir, "new.bin")
        
        with open(old_file, "wb") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
        
        with open(new_file, "wb") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
        
        analyzer = SemanticDiffAnalyzer()
        result = analyzer.analyze(old_file, new_file)
        
        self.assertTrue(result.success)
    
    def test_extract_signatures(self):
        """测试提取签名"""
        analyzer = SemanticDiffAnalyzer()
        
        block = BasicBlock(
            start_address=0x401000,
            end_address=0x401008,
            instructions=[]
        )
        func_ir = FunctionIR(
            name="test",
            address=0x401000,
            basic_blocks=[block],
            ir_type=IRType.VEX
        )
        
        signatures = analyzer.extract_signatures([func_ir])
        
        self.assertGreater(len(signatures), 0)
    
    def test_generate_report(self):
        """测试生成报告"""
        analyzer = SemanticDiffAnalyzer()
        
        result = DiffAnalysisResult(
            success=True,
            matches=[],
            patch_locations=[],
            diff_count=0
        )
        
        report = analyzer.generate_report(result)
        
        self.assertIn("跨版本二进制语义差异分析报告", report)
    
    def test_save_result(self):
        """测试保存结果"""
        analyzer = SemanticDiffAnalyzer()
        
        result = DiffAnalysisResult(
            success=True,
            matches=[],
            patch_locations=[],
            diff_count=0
        )
        
        output_path = os.path.join(self.temp_dir, "result.json")
        success = analyzer.save_result(result, output_path)
        
        self.assertTrue(success)
        self.assertTrue(os.path.exists(output_path))


if __name__ == '__main__':
    unittest.main()